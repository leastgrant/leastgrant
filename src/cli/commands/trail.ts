/**
 * `leastgrant trail`
 *
 * What your agents have actually been doing, as a story rather than a log.
 *
 * The ledger is already plain JSONL you can `cat`, so this command earns its
 * place only by being readable: oldest first so the newest line sits nearest
 * the prompt, runs of the same thing folded into one line with a multiplier,
 * and the exceptions repeated at the bottom where someone scanning will look.
 * An audit trail nobody reads is not an audit trail.
 *
 * Three rules this file has to keep:
 *
 *  1. The ledger is append-only text that people are invited to read and edit,
 *     so it will eventually contain a line that is not a well-formed entry.
 *     A damaged line must cost the reader one footnote, never a stack trace.
 *
 *  2. Every count printed here is over the same window, and the denominator
 *     behind a percentage is the number printed beside it. If those two ever
 *     drift apart the command is worse than useless, because it is confident.
 *
 *  3. Every string on the screen that came out of the ledger is text an agent
 *     chose. It gets printed as characters, never as instructions to the
 *     terminal — see {@link oneLine}. A row that can move the cursor can forge
 *     the row above it, and forging rows in the audit trail is the one thing
 *     this command must not make possible.
 */

import * as path from 'node:path';
import type { Decision, LedgerEntry } from '../../core/types.js';
import { friendly } from '../../core/decide.js';
import { loadContext, type CliContext } from '../context.js';
import { readLedger } from '../../store/index.js';
import { ago, bar, c, pad, para, plural, sym, term, truncate, width } from '../ui.js';
import type { Argv } from '../index.js';

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const WEEK = 7 * DAY;

const DEFAULT_SINCE = 24 * HOUR;
const DEFAULT_LIMIT = 40;

/** Ten years. Past this the window is "everything" and the label stops meaning anything. */
const MAX_SINCE = 3650 * DAY;
const MAX_LIMIT = 10_000;

/** The largest value `new Date()` can represent. Beyond it every getter is NaN. */
const MAX_TIME = 8.64e15;

/** How many distinct blocked things the footer lists before it summarises. */
const BLOCKED_SHOWN = 8;

// Row geometry. Kept as named parts so the widths below can be derived rather
// than guessed — a hand-tuned "- 30" is how a table ends up one column too wide
// on exactly the terminal size everyone actually uses.
const INDENT = 2;
const CLOCK_W = 5; // `09:41`
const GLYPH_W = 1;
const GUTTER = 2; // between the body and the right-hand column
const LEFT_W = INDENT + CLOCK_W + 1 + GLYPH_W + 1;
const PROJ_W = 12;
/** The longest label `friendly` produces is 35 characters; 30 fits most of them. */
const KIND_MAX = 30;
const KIND_MIN = 10;
const BODY_MIN = 18;

export function trailCommand(argv: Argv): number {
  const json = Boolean(argv.flags['json']);
  const all = Boolean(argv.flags['all']);
  const askedOnly = Boolean(argv.flags['asked']);

  // A bare `--since` is not a request for the default: the argument parser also
  // lands here for `--since -1h` and `--since --json`, where quietly using 24
  // hours would answer a question nobody asked.
  const sinceRaw = argv.flags['since'];
  if (sinceRaw === true) {
    return fail(json, '--since needs a length of time', 'leastgrant trail --since 6h   (m, h, d, w)');
  }
  const sinceMs = sinceRaw === undefined ? DEFAULT_SINCE : parseDuration(String(sinceRaw));
  if (sinceMs === null) {
    return fail(
      json,
      `"${String(sinceRaw)}" is not a length of time`,
      'leastgrant trail --since 6h   (m, h, d, w)',
    );
  }

  const limitRaw = argv.flags['limit'];
  if (limitRaw === true) {
    return fail(json, '--limit needs a number of actions', 'leastgrant trail --limit 100');
  }
  const limit = limitRaw === undefined ? DEFAULT_LIMIT : parseCount(String(limitRaw));
  if (limit === null) {
    return fail(json, `"${String(limitRaw)}" is not a number of actions`, 'leastgrant trail --limit 100');
  }

  let ctx: CliContext | undefined;
  let ctxError: string | undefined;
  try {
    ctx = loadContext();
  } catch (err) {
    // The usual cause is a working directory that has been deleted out from
    // under the shell, which produces a uv_cwd error nobody can act on.
    ctxError = (err as Error).message;
  }

  // `--all` genuinely does not need to know where we are, so it is the one way
  // out of this and it is offered only here. Suggesting a flag that fails the
  // same way would be worse than the original error.
  if (!ctx && !all) {
    return fail(
      json,
      `could not work out which project this is: ${ctxError ?? 'unknown error'}`,
      'cd somewhere that still exists, or: leastgrant trail --all',
    );
  }

  const key = ctx?.key ?? '';
  const now = Date.now();
  const since = now - sinceMs;

  // Filter --asked ourselves rather than through readLedger, so the limit
  // counts entries you will actually see instead of entries we then discard.
  const raw = readLedger({ project: all ? undefined : key, since });
  const window = raw.filter(readable);
  const unreadable = raw.length - window.length;

  const matched = askedOnly ? window.filter((e) => e.decision !== 'allow') : window;
  const shown = matched.slice(-limit);

  const allowed = window.filter((e) => e.decision === 'allow').length;
  const asked = window.filter((e) => e.decision === 'ask').length;
  const blocked = window.filter((e) => e.decision === 'deny');
  const label = durationLabel(sinceMs);

  if (json) {
    return emit({
      window: { since, until: now, ms: sinceMs, label },
      project: all ? null : key,
      filters: { askedOnly, limit },
      counts: {
        // allowed + asked + blocked === total, always: `readable` drops any
        // entry whose decision is not one of the three, and `unreadable` says
        // how many that was rather than hiding it.
        total: window.length,
        allowed,
        asked,
        blocked: blocked.length,
        shown: shown.length,
        hidden: matched.length - shown.length,
        unreadable,
        // Both are `allowed / total`. The share is exact; the percentage is the
        // integer printed on screen, which never rounds up to 100 while
        // something is still asking. Compare against the share, not the pct.
        ranWithoutAskingShare: window.length ? allowed / window.length : 0,
        ranWithoutAskingPct: percent(allowed, window.length),
      },
      // Every denial in the window, not only the ones inside `--limit`: this is
      // the list the footer draws, and truncating it would make the two differ.
      entries: shown,
      blocked,
    });
  }

  if (!shown.length) {
    process.stdout.write(
      renderEmpty({ key, all, askedOnly, label, inWindow: window.length, now, unreadable }),
    );
    return 0;
  }

  process.stdout.write(
    renderTrail(shown, {
      all,
      askedOnly,
      label,
      now,
      projectName: projectName(ctx?.root ?? ''),
      matchedTotal: matched.length,
      hidden: matched.length - shown.length,
      total: window.length,
      allowed,
      asked,
      blocked,
      unreadable,
    }),
  );
  return 0;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

interface TrailOpts {
  all: boolean;
  askedOnly: boolean;
  label: string;
  now: number;
  projectName: string;
  matchedTotal: number;
  hidden: number;
  total: number;
  allowed: number;
  asked: number;
  blocked: LedgerEntry[];
  unreadable: number;
}

function renderTrail(entries: LedgerEntry[], o: TrailOpts): string {
  const out: string[] = [''];
  const cols = columns(o.all);

  const where = o.all ? 'across every project' : `in ${c.bold(truncate(o.projectName, 28))}`;
  const scope = `${c.gray(`the last ${o.label}`)} ${where}`;
  // `--asked` keeps denials too, so calling it "what stopped to ask" would
  // undercount the row that matters most.
  const filter = o.askedOnly ? c.gray(`${sym.bullet} only what asked or was blocked`) : '';
  out.push(oneLineOrStacked(filter ? [scope, filter] : [scope], '  '));

  if (o.hidden > 0) {
    // `--limit` is capped, so past the cap the honest advice is a shorter
    // window rather than a number the command would quietly ignore.
    const seeRest =
      o.matchedTotal <= MAX_LIMIT
        ? `--limit ${o.matchedTotal} shows them all`
        : `--limit stops at ${fmt(MAX_LIMIT)}, so narrow the window with --since instead`;
    out.push(para(c.gray(`${plural(o.hidden, 'earlier action')} not shown ${sym.dash} ${seeRest}`), INDENT));
  }

  let lastHour = Number.NaN;

  for (const run of collapse(entries, o.all)) {
    const e = run.entry;
    const hour = startOfHour(e.at);
    if (hour !== lastHour) {
      out.push('');
      out.push(`  ${c.gray(hourLabel(e.at, o.now))}`);
      lastHour = hour;
    }
    out.push(row(e, run.count, e.at, cols, o.all));
  }

  // The footer: what all of that adds up to.
  out.push('');
  out.push(`  ${c.bold(plural(o.total, 'action'))} ${c.gray(`in the last ${o.label}`)}`);
  out.push(tally(o.allowed, o.asked, o.blocked.length));
  // `o.total` is the same number printed on the line above, and allowed + asked
  // + blocked adds up to it exactly, so this share has the denominator the
  // sentence claims. Size the bar to what is left after the sentence, so the
  // one line carrying the headline number is also the one that cannot wrap.
  const caption = `${percent(o.allowed, o.total)}% of those ran without interrupting you`;
  const room = term.cols - INDENT - 1 - width(caption);
  const cells = Math.max(4, Math.min(24, room));
  out.push(`  ${bar(o.allowed, o.total, cells, c.green)} ${c.gray(caption)}`);

  if (o.blocked.length) {
    const runs = collapseBySignature(o.blocked);
    out.push('');
    out.push(`  ${c.bold(c.red('blocked'))}`);
    // Same geometry as the timeline above, and the same `row`, so the blocked
    // list reads as a second pass over the same table rather than a new one.
    for (const run of runs.slice(0, BLOCKED_SHOWN)) {
      out.push(row(run.entry, run.count, run.lastAt, cols, o.all));
    }
    if (runs.length > BLOCKED_SHOWN) {
      out.push(`  ${c.gray(`…and ${plural(runs.length - BLOCKED_SHOWN, 'other kind')}`)}`);
    }
    out.push('');
    // Pushed whole rather than wrapped: `para` would happily break a command
    // across two lines, and a command you cannot double-click is not a hint.
    out.push(`  ${c.gray(`${sym.corner} why the most recent one stopped: leastgrant why`)}`);
  }

  if (o.unreadable > 0) {
    out.push('');
    out.push(unreadableNote(o.unreadable));
  }

  out.push('');
  return out.join('\n');
}

interface EmptyOpts {
  key: string;
  all: boolean;
  askedOnly: boolean;
  label: string;
  /** Readable entries inside the window. Zero unless `--asked` filtered them out. */
  inWindow: number;
  now: number;
  /** Damaged lines inside the window. */
  unreadable: number;
}

/**
 * The empty state does the most work of anything here: a brand-new user
 * running `trail` first has no way to tell "nothing happened" from "the hook
 * never fired", and only one of those is a problem they can fix.
 */
function renderEmpty(o: EmptyOpts): string {
  const out: string[] = [''];
  const whole = readLedger();
  const everything = whole.filter(readable);
  const damagedAnywhere = whole.length - everything.length;

  const close = (): string => {
    if (o.unreadable > 0) {
      out.push('');
      out.push(unreadableNote(o.unreadable));
    }
    out.push('');
    return out.join('\n');
  };

  if (!everything.length) {
    // A ledger full of lines we cannot parse is a different problem from an
    // empty one, and telling someone to install a hook they already installed
    // sends them off to fix the wrong thing.
    //
    // No count here on purpose: `readLedger` has already dropped the lines that
    // were not JSON at all, so any number this branch could quote would be the
    // damage it happened to see rather than the damage that is there.
    if (damagedAnywhere > 0) {
      out.push(`  ${c.bold('nothing in the ledger could be read.')}`);
      out.push('');
      out.push(
        para(
          c.gray(
            'there is a ledger on disk, but none of it is a decision LeastGrant recognises. It skips lines it cannot parse rather than guessing at them.',
          ),
          INDENT,
        ),
      );
      out.push('');
      out.push(...hints([['leastgrant doctor', 'check the setup']]));
      out.push('');
      return out.join('\n');
    }

    out.push(`  ${c.bold('nothing recorded yet.')}`);
    out.push('');
    out.push(
      para(
        c.gray(
          'LeastGrant writes a line here every time an agent asks to do something. None has arrived, which usually means the hook is not installed.',
        ),
        INDENT,
      ),
    );
    out.push('');
    out.push(
      ...hints([
        ['leastgrant install', 'connect it to your agent'],
        ['leastgrant init', 'read the history you already have'],
      ]),
    );
    return close();
  }

  const mine = o.all ? everything : everything.filter((e) => e.project === o.key);

  if (!mine.length) {
    const others = new Set(everything.map((e) => e.project)).size;
    out.push(`  ${c.bold('nothing recorded in this project yet.')}`);
    out.push('');
    out.push(
      para(
        c.gray(
          `LeastGrant is recording — ${plural(others, 'other project')} ${others === 1 ? 'has' : 'have'} activity. Nothing has happened in this one.`,
        ),
        INDENT,
      ),
    );
    out.push('');
    out.push(...hints([['leastgrant trail --all', 'every project']]));
    return close();
  }

  // Nothing asked, but plenty happened: that is the product working, not a gap.
  if (o.askedOnly && o.inWindow > 0) {
    out.push(`  ${c.green(sym.allow)} ${c.bold(`nothing asked in the last ${o.label}.`)}`);
    out.push('');
    out.push(para(c.gray(`all ${plural(o.inWindow, 'action')} went through without interrupting you.`), INDENT));
    return close();
  }

  const newest = mine[mine.length - 1];
  const scope = o.all ? 'anywhere' : 'in this project';

  out.push(`  ${c.bold(`nothing in the last ${o.label}.`)}`);
  out.push('');
  if (newest) {
    out.push(para(c.gray(`the most recent thing recorded ${scope} was ${ago(newest.at, o.now)}.`), INDENT));
    out.push('');
  }
  const rest: [string, string][] = [['leastgrant trail --since 7d', 'look further back']];
  if (!o.all) rest.push(['leastgrant trail --all', 'every project']);
  out.push(...hints(rest));
  return close();
}

// ---------------------------------------------------------------------------
// Row layout
// ---------------------------------------------------------------------------

interface Cols {
  body: number;
  kind: number;
}

/**
 * Split the line between the two elastic columns.
 *
 * Everything is derived from `term.cols`, and one column is left spare, so a
 * full-width row cannot land exactly on the wrap point of an 80-column
 * terminal — which is the width at which a row that is "exactly right" turns
 * into two ragged rows.
 */
function columns(showProject: boolean): Cols {
  const proj = showProject ? PROJ_W + 1 : 0;
  const usable = Math.max(BODY_MIN + GUTTER + KIND_MIN, term.cols - 1 - LEFT_W - proj);
  const kind = Math.max(KIND_MIN, Math.min(KIND_MAX, Math.floor((usable - GUTTER) * 0.35)));
  return { body: Math.max(BODY_MIN, usable - GUTTER - kind), kind };
}

/**
 * One timeline row, used by the main list and the blocked list both, so the
 * two can never drift out of alignment with each other.
 */
function row(e: LedgerEntry, count: number, at: number, cols: Cols, showProject: boolean): string {
  const mult = count > 1 ? ` x${fmt(count)}` : '';
  const said = oneLine(e.display) || c.gray('(nothing recorded)');
  const body = truncate(said, Math.max(1, cols.body - width(mult))) + (mult ? c.gray(mult) : '');
  const project = showProject
    ? `${c.gray(pad(truncate(oneLine(projectName(e.project)), PROJ_W), PROJ_W))} `
    : '';
  // The capability id (`fs.write.workspace`) is an internal label, not English.
  // `friendly` is the same map `status` prints, so the two commands agree.
  const kind = c.gray(truncate(friendly(e.capability), cols.kind));
  return `  ${c.gray(clock(at))} ${glyph(e.decision)} ${project}${pad(body, cols.body)}  ${kind}`.replace(
    /\s+$/,
    '',
  );
}

/**
 * The three-way count. Stacked rather than truncated when it will not fit,
 * because these are the numbers the command exists to deliver.
 */
function tally(allowed: number, asked: number, blocked: number): string {
  const parts = [
    `${c.green(sym.allow)} ${fmt(allowed)} ran without asking`,
    `${c.yellow(sym.ask)} ${fmt(asked)} asked you`,
    `${c.red(sym.deny)} ${fmt(blocked)} blocked`,
  ];
  return oneLineOrStacked(parts, c.gray(`   ${sym.vbar}   `));
}

/**
 * Join on one line when it fits the terminal, one per line when it does not.
 * Both the header and the tally want this, and two copies of it is exactly how
 * one of them ends up wrapping at 80 columns and the other does not.
 */
function oneLineOrStacked(parts: string[], separator: string, indent = INDENT): string {
  const lead = ' '.repeat(indent);
  const joined = lead + parts.join(separator);
  if (parts.length < 2 || width(joined) <= term.cols) return joined;
  return parts.map((p) => lead + p).join('\n');
}

/**
 * Commands and what they do, in two columns.
 *
 * The left column is measured from the commands actually being shown rather
 * than fixed, and the note drops to its own wrapped line when the pair will not
 * fit — the same "derive it, do not guess it" rule the row geometry follows.
 */
function hints(pairs: [command: string, note: string][]): string[] {
  const left = Math.max(0, ...pairs.map(([command]) => width(command)));
  const gap = 2;
  const out: string[] = [];
  for (const [command, note] of pairs) {
    if (INDENT + left + gap + width(note) <= term.cols) {
      out.push(`  ${c.cyan(pad(command, left))}${' '.repeat(gap)}${c.gray(note)}`);
    } else {
      out.push(`  ${c.cyan(command)}`);
      out.push(para(c.gray(note), INDENT + gap));
    }
  }
  return out;
}

function unreadableNote(n: number): string {
  return para(c.gray(`${sym.bullet} skipped ${plural(n, 'damaged line')} in the ledger.`), INDENT);
}

// ---------------------------------------------------------------------------
// Collapsing
// ---------------------------------------------------------------------------

interface Run {
  entry: LedgerEntry;
  count: number;
  lastAt: number;
}

/**
 * Fold consecutive repeats of the same signature into one line. A test loop
 * that ran forty times is one fact, not forty, and printing it forty times
 * pushes the one interesting line off the screen.
 */
function collapse(entries: LedgerEntry[], byProject: boolean): Run[] {
  const runs: Run[] = [];
  for (const e of entries) {
    const last = runs[runs.length - 1];
    if (
      last &&
      last.entry.signature === e.signature &&
      last.entry.decision === e.decision &&
      (!byProject || last.entry.project === e.project)
    ) {
      last.count += 1;
      last.lastAt = e.at;
      continue;
    }
    runs.push({ entry: e, count: 1, lastAt: e.at });
  }
  return runs;
}

/** Same idea for the blocked list, but non-consecutive: order there is by kind. */
function collapseBySignature(entries: LedgerEntry[]): Run[] {
  const byKey = new Map<string, Run>();
  for (const e of entries) {
    const existing = byKey.get(e.signature);
    if (existing) {
      existing.count += 1;
      existing.lastAt = Math.max(existing.lastAt, e.at);
    } else {
      byKey.set(e.signature, { entry: e, count: 1, lastAt: e.at });
    }
  }
  return [...byKey.values()].sort((a, b) => b.lastAt - a.lastAt);
}

// ---------------------------------------------------------------------------
// Reading the ledger defensively
// ---------------------------------------------------------------------------

const DECISIONS: readonly string[] = ['allow', 'ask', 'deny'];

/**
 * Is this line something we can put on the screen without lying or crashing?
 *
 * `readLedger` skips lines that are not JSON, but valid JSON that is not a
 * ledger entry gets through — a hand-edited file, a half-written line that
 * happened to close its brace, an entry from a future schema. Anything without
 * a usable timestamp or a decision we recognise is counted and set aside; the
 * rest has its string fields forced to strings so no renderer has to defend
 * itself again.
 *
 * "Usable timestamp" means a real instant, not merely a finite number: `Date`
 * gives up past ±8.64e15 and every getter on it returns NaN, which reaches the
 * screen as `NaN:NaN` under an `Invalid Date` heading.
 *
 * The repairs are deliberately empty strings rather than invented text: this
 * same object is what `--json` emits, and a placeholder written there would be
 * indistinguishable from something the agent actually did. The screen fills the
 * blank in; the machine-readable copy stays honest about what was missing.
 */
function readable(e: LedgerEntry | undefined): e is LedgerEntry {
  if (!e || typeof e !== 'object') return false;
  if (typeof e.at !== 'number' || !Number.isFinite(e.at)) return false;
  if (e.at < 0 || e.at > MAX_TIME) return false;
  if (typeof e.decision !== 'string' || !DECISIONS.includes(e.decision)) return false;
  if (typeof e.display !== 'string') e.display = '';
  // Signature is the folding key. Falling back to the display keeps unrelated
  // rows from collapsing into one another just because a field was missing.
  if (typeof e.signature !== 'string' || !e.signature) e.signature = e.display || String(e.at);
  if (typeof e.capability !== 'string') e.capability = 'exec.unknown';
  if (typeof e.project !== 'string') e.project = '';
  return true;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function glyph(d: Decision): string {
  if (d === 'allow') return c.green(sym.allow);
  if (d === 'deny') return c.red(sym.deny);
  return c.yellow(sym.ask);
}

function hh(at: number): string {
  return String(new Date(at).getHours()).padStart(2, '0');
}

function clock(at: number): string {
  const d = new Date(at);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function startOfHour(at: number): number {
  const d = new Date(at);
  d.setMinutes(0, 0, 0);
  return d.getTime();
}

function startOfDay(at: number): number {
  const d = new Date(at);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** e.g. `today 14:00`, `yesterday 23:00`, `Sat 30 Aug 09:00`, `Tue 4 Jun 2024 09:00`. */
function hourLabel(at: number, now: number): string {
  const days = Math.round((startOfDay(now) - startOfDay(at)) / DAY);
  if (days === 0) return `today ${hh(at)}:00`;
  if (days === 1) return `yesterday ${hh(at)}:00`;
  const then = new Date(at);
  // `--since 2w` and up can reach back past a year, where a bare "30 Aug" is
  // two different days and the reader has no way to tell which.
  const sameYear = then.getFullYear() === new Date(now).getFullYear();
  const day = then.toLocaleDateString('en-US', {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
  return `${day} ${hh(at)}:00`;
}

function projectName(key: string): string {
  return path.basename(key) || key || 'unknown';
}

/** Zero-width and bidi-override characters: invisible, and able to reorder what you read. */
const ZERO_WIDTH = /[\u200B-\u200F\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** C0 and C1 controls (ESC among them), DEL, and the Unicode line separators. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

/**
 * Flatten ledger text to one printable line.
 *
 * Two jobs, and the second is the important one. Whitespace is collapsed so a
 * multi-line command occupies one row. Then everything that steers a terminal
 * rather than showing up in it is removed: escape sequences and the rest of the
 * C0/C1 controls, plus the zero-width and bidi-override characters that can
 * make text read as something other than what it says.
 *
 * `display` is a string an agent chose. The redactor takes credentials out of
 * it before it is written down; it does not take out `\x1b[1A\x1b[2K`, which
 * would let a logged command erase and rewrite the line above it. In an audit
 * trail that is not a cosmetic bug, so nothing from the ledger reaches stdout
 * without passing through here.
 *
 * Known gap, stated rather than hidden: `width` in ../ui.js counts code units,
 * so a row whose text is mostly East Asian characters still measures narrower
 * than it draws. Fixing that belongs there, where every command benefits.
 */
function oneLine(s: string): string {
  return s
    .replace(ZERO_WIDTH, '')
    .replace(CONTROL, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * A whole-number percentage that never overstates itself.
 *
 * Plain rounding will print "100% ran without asking" directly above a line
 * saying one thing asked you, which is the kind of small lie that costs a
 * security tool the benefit of the doubt everywhere else.
 */
function percent(part: number, whole: number): number {
  if (!(whole > 0)) return 0;
  const rounded = Math.round((part / whole) * 100);
  if (rounded >= 100 && part < whole) return 99;
  if (rounded <= 0 && part > 0) return 1;
  return Math.max(0, Math.min(100, rounded));
}

/** `30m`, `6h`, `7d`, `2w`. A bare number means hours. */
function parseDuration(input: string): number | null {
  const m = /^(\d+(?:\.\d+)?)\s*(m|h|d|w)?$/i.exec(input.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = (m[2] ?? 'h').toLowerCase();
  const scale = unit === 'm' ? MINUTE : unit === 'd' ? DAY : unit === 'w' ? WEEK : HOUR;
  return Math.min(MAX_SINCE, n * scale);
}

/**
 * Turn a span back into words. Anything under two days stays in hours, because
 * the default window is 24h and "the last 1 day" reads like a rounding error.
 * Fractional spans keep their fraction rather than rounding, so the label and
 * the window it describes are the same span.
 */
function durationLabel(ms: number): string {
  if (ms >= 2 * WEEK && ms % WEEK === 0) return plural(ms / WEEK, 'week');
  if (ms < 2 * DAY) {
    if (ms % HOUR === 0) return plural(ms / HOUR, 'hour');
    return plural(Math.max(1, Math.round(ms / MINUTE)), 'minute');
  }
  return plural(Number((ms / DAY).toFixed(1)), 'day');
}

function parseCount(input: string): number | null {
  const n = Number(input.trim());
  if (!Number.isInteger(n) || n <= 0) return null;
  return Math.min(MAX_LIMIT, n);
}

const fmt = (n: number) => Math.round(n).toLocaleString('en-US');

function emit(data: unknown): number {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
  return 0;
}

/**
 * Bad input. Under --json this has to be JSON too, on stdout, or the flag is a
 * promise the command only keeps when nothing goes wrong.
 */
function fail(json: boolean, message: string, example: string): number {
  if (json) {
    process.stdout.write(JSON.stringify({ error: message, hint: example }, null, 2) + '\n');
    return 2;
  }
  process.stderr.write(`\n  ${c.red(message)}\n\n  ${c.gray('try:')} ${example}\n\n`);
  return 2;
}
