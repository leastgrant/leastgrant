/**
 * `leastgrant why [n]`
 *
 * "Why did you stop me?" — answered in full, for one decision.
 *
 * The ledger stores reason *codes*, not prose, so this command does not read an
 * explanation back off disk. It rebuilds the request and asks the engine again.
 * That costs a few milliseconds and buys a guarantee worth far more: the
 * explanation you read is the one your rules produce *now*, not a sentence
 * frozen at the moment it was written. When the two disagree, the disagreement
 * is the most interesting thing on the screen, so it gets printed rather than
 * quietly smoothed over.
 *
 * The honest caveat, stated in the output as well as here: the ledger keeps a
 * redacted display string, never the original tool input. Re-derivation is
 * therefore a good reconstruction, not a replay.
 *
 * Two rules this file has to keep, because it is usually the first command
 * someone runs after being surprised by a prompt:
 *
 *  - It must not crash. The ledger and the envelope are plain text that people
 *    are invited to read and therefore able to edit, and older versions of
 *    LeastGrant wrote fewer fields. A missing field has to produce a slightly
 *    vaguer sentence, never a stack trace. Everything off disk goes through
 *    `harden` on the way in.
 *
 *  - It must not overstate what it knows. Approval evidence decays, and a bulk
 *    grant made during setup is stored as the confirmation count it stands in
 *    for. Printing either of those as a literal "you approved this 11 times"
 *    would be a small lie, and a security tool does not get to tell those.
 */

import type {
  BlastRadius,
  Familiarity,
  LedgerEntry,
  Request,
  Rule,
  SignatureStat,
  Thresholds,
  Verdict,
} from '../../core/types.js';
import { blastTier, NIL_BLAST } from '../../core/types.js';
import { decide, matchRule } from '../../core/decide.js';
import { normalizeTool } from '../../core/classify.js';
import {
  applyTaint,
  approvalsNeededFor,
  canPromote,
  familiarity,
  newSession,
  CONFIDENCE_BY_TIER,
  type PromotionResult,
  type SessionState,
} from '../../core/envelope.js';
import { readLedger } from '../../store/index.js';
import { loadContext, type CliContext } from '../context.js';
import {
  ago,
  bar,
  blastStrip,
  c,
  hang,
  oneLine,
  pad,
  para,
  plural,
  sym,
  term,
  truncate,
  verdictBadge,
} from '../ui.js';
import { renderVerdict } from './check.js';
import type { Argv } from '../index.js';

/** Which entry we landed on, and why we landed there. */
type Picked = 'requested' | 'stopped-you' | 'nothing-but-allows';

export function whyCommand(argv: Argv): number {
  const ctx = loadContext();
  const jsonFlag = argv.flags['json'];
  // `--json=false` is the one spelling where the presence of the flag does not
  // mean yes, and reading it as yes would print JSON at someone who asked for
  // the opposite.
  const json = jsonFlag !== undefined && jsonFlag !== false && jsonFlag !== 'false';

  const entries = readLedger({ project: ctx.key });
  if (!entries.length) return renderEmpty(ctx, json);

  // `leastgrant why --json 3` parses as json="3" with no positional, because a
  // flag parser that does not know --json is boolean will eat the next word.
  // Give the number back rather than silently explaining the wrong decision.
  const swallowed = typeof jsonFlag === 'string' && /^\d+$/.test(jsonFlag) ? jsonFlag : undefined;
  const chosen = select(argv.positional[0] ?? swallowed, entries);

  if ('error' in chosen) {
    const detail = `this project has ${plural(entries.length, 'recorded decision')}`;
    if (json) {
      process.stdout.write(
        JSON.stringify({ error: chosen.error, detail, total: entries.length }, null, 2) + '\n',
      );
      return 2;
    }
    process.stderr.write(
      '\n' +
        para(c.red(chosen.error), 2) +
        '\n\n' +
        para(c.gray(detail + '. try:') + ' leastgrant why 1', 2) +
        '\n\n',
    );
    return 2;
  }

  const { index, picked } = chosen;
  const raw = entries[entries.length - index];
  // `select` has already bounds-checked, so this cannot fire. It costs one line
  // and removes the only non-null assertion on the hot path.
  if (!raw) return renderEmpty(ctx, json);
  const entry = harden(raw);
  const now = Date.now();

  const rebuilt = rebuildInput(entry);
  const req: Request = {
    agent: entry.agent,
    tool: entry.tool,
    input: rebuilt.input,
    cwd: ctx.root,
    sessionId: entry.sessionId,
    agentMode: entry.agentMode,
    branch: entry.branch,
    // Deliberately "now", not `entry.at`: the question is what your current
    // rules and current learning would say, not what they said then.
    at: now,
  };

  const verdict = decide(req, { ...ctx.decideCtx, session: replaySession(entries, entry) });
  const changed = verdict.decision !== entry.decision;

  // Learning is keyed on the normalized form of the command. If re-reading the
  // redacted line lands on a different one, the verdict above and the history
  // below are about two subtly different things, and saying so costs one line.
  if (entry.signature && verdict.action.signature && verdict.action.signature !== entry.signature) {
    rebuilt.caveats.push(
      `reading that line back does not produce quite the same command as the one recorded: ${quoted(verdict.action.signature)} rather than ${quoted(entry.signature)}. the answer above describes what was read back, and the history below describes what was recorded.`,
    );
  }

  const stat = ctx.envelope.signatures[entry.signature];
  const fam = familiarity(
    ctx.envelope,
    { signature: entry.signature, capability: entry.capability, blast: entry.blast, at: now },
    ctx.config.thresholds,
  );
  const promo = canPromote(fam, entry.blast, ctx.config.thresholds);
  const standing = matchRule(ctx.config.rules, entry.signature, ctx.key, now);
  // A hard "always ask" only speaks for the action it fired on. If re-reading
  // produced a different worst action, it says nothing about this one.
  const alwaysAsks = verdict.floor && verdict.action.signature === entry.signature;
  const advice = whatWouldChange(entry, fam, promo, standing, alwaysAsks, ctx);

  if (json) {
    process.stdout.write(
      JSON.stringify(
        {
          index,
          total: entries.length,
          picked,
          // The entry exactly as it sits on disk. Hardening and flattening are
          // for the terminal; a machine reader wants what was actually written.
          entry: raw,
          reDerived: { tool: req.tool, input: req.input, caveats: rebuilt.caveats, verdict },
          changed,
          was: entry.decision,
          now: verdict.decision,
          history: stat ?? null,
          familiarity: fam,
          // Taken straight from the engine rather than re-deriving the
          // precedence rules here, where the copy could drift out of step with
          // the original.
          runsWithoutAsking: verdict.decision === 'allow',
          alwaysAsks,
          promotion: promo,
          rule: standing ?? null,
          wouldChange: advice,
        },
        null,
        2,
      ) + '\n',
    );
    return 0;
  }

  const out: string[] = [''];
  out.push(...context(entry, index, entries.length, picked, rebuilt, verdict, changed));
  // No closing note from the verdict block: the one at the end of the history
  // below is better informed, and two of them disagreeing on the same screen is
  // how a reader stops believing either.
  out.push(...renderVerdict(verdict, subjectOf(entry), { closing: false }).split('\n'));
  out.push(...history(stat, fam, advice, ctx.config.thresholds));
  if (index < entries.length) {
    out.push(c.gray(`  the one before it: leastgrant why ${index + 1}`));
    out.push('');
  }

  const text = out.join('\n');
  process.stdout.write(text.endsWith('\n') ? text : text + '\n');
  return 0;
}

// ---------------------------------------------------------------------------
// Choosing an entry
// ---------------------------------------------------------------------------

function select(
  raw: string | undefined,
  entries: LedgerEntry[],
): { index: number; picked: Picked } | { error: string } {
  if (raw !== undefined) {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1) {
      return { error: `"${truncate(oneLine(raw), 24)}" is not a decision number` };
    }
    if (n > entries.length) return { error: `there is no decision #${n} here` };
    return { index: n, picked: 'requested' };
  }
  // People ask "why did you stop me" far more often than "why did you let me",
  // so the bare command lands on the most recent thing that was not waved
  // through, and says so. Tested positively against ask/deny rather than
  // negatively against allow, so a line with a missing or garbled decision does
  // not get presented as the thing that stopped you.
  for (let i = entries.length - 1; i >= 0; i--) {
    const decision = entries[i]?.decision;
    if (decision === 'ask' || decision === 'deny') {
      return { index: entries.length - i, picked: 'stopped-you' };
    }
  }
  return { index: 1, picked: 'nothing-but-allows' };
}

// ---------------------------------------------------------------------------
// Reading the ledger defensively
// ---------------------------------------------------------------------------

const REACHES = ['none', 'workspace', 'machine', 'network', 'external', 'production'] as const;
const REVERSIBILITIES = ['trivial', 'easy', 'hard', 'irreversible'] as const;
const EXPOSURES = ['none', 'reads-secrets', 'can-exfiltrate'] as const;
const SCALES = ['single', 'many', 'sweeping'] as const;
const DECISIONS = ['allow', 'ask', 'deny'] as const;

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value)
    ? (value as T)
    : fallback;
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** A non-negative whole number, or zero. Used wherever a count is displayed. */
function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

function hardenBlast(value: unknown): BlastRadius {
  const b = (value ?? {}) as Partial<BlastRadius>;
  return {
    reach: oneOf(b.reach, REACHES, NIL_BLAST.reach),
    reversibility: oneOf(b.reversibility, REVERSIBILITIES, NIL_BLAST.reversibility),
    exposure: oneOf(b.exposure, EXPOSURES, NIL_BLAST.exposure),
    scale: oneOf(b.scale, SCALES, NIL_BLAST.scale),
  };
}

/**
 * Fill in anything a ledger line is missing.
 *
 * `blastTier` and the classifier both index straight into lookup tables, so a
 * blast radius with a field from a future (or hand-typed) version of the format
 * turns into a `NaN` tier or a thrown property access several frames away from
 * the cause. Everything is pinned to a known value here instead, once, at the
 * boundary.
 */
function harden(e: LedgerEntry): LedgerEntry {
  return {
    ...e,
    at: typeof e.at === 'number' && Number.isFinite(e.at) && e.at > 0 ? e.at : 0,
    agent: str(e.agent),
    sessionId: str(e.sessionId),
    tool: str(e.tool),
    display: str(e.display),
    signature: str(e.signature),
    capability: e.capability ?? 'exec.unknown',
    decision: oneOf(e.decision, DECISIONS, 'ask'),
    blast: hardenBlast(e.blast),
  };
}

/** What the verdict block is about, flattened and never empty. */
function subjectOf(entry: LedgerEntry): string {
  return oneLine(entry.display) || oneLine(entry.tool) || 'this decision';
}

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

interface Rebuilt {
  input: Record<string, unknown>;
  /** Honest notes about what could not be recovered. Rendered dim. */
  caveats: string[];
}

const REDACTION_MARK = '«redacted:';

/**
 * Turn a ledger entry back into something the classifier can chew on.
 *
 * The display string is all we have, and it is lossy in two different ways
 * depending on the tool, so each family gets its own caveat rather than one
 * vague disclaimer that nobody reads.
 */
function rebuildInput(entry: LedgerEntry): Rebuilt {
  const caveats: string[] = [];
  const rest = entry.display.startsWith(entry.tool + ' ')
    ? entry.display.slice(entry.tool.length + 1)
    : entry.display;

  if (entry.display.includes(REDACTION_MARK)) {
    caveats.push(
      'anything that looked like a credential was swapped for a placeholder before this was written down, and the placeholder is what the answer below is worked out from.',
    );
  }

  switch (normalizeTool(entry.tool)) {
    case 'shell':
      caveats.unshift(
        'what was written down is a shortened, credential-stripped version of the part that drove the decision, never the exact command the agent sent. the answer below is worked out from the line shown above, so it can come out slightly differently.',
      );
      return { input: { command: entry.display }, caveats };
    case 'read':
    case 'write':
    case 'edit':
      return { input: { file_path: rest }, caveats };
    case 'search':
      return { input: { path: rest.replace(/^in /, '') }, caveats };
    case 'net':
      return { input: { url: rest }, caveats };
    default:
      // mcp, spawn and meta are judged on the tool name alone, so there is
      // nothing lost and nothing to apologise for.
      return { input: {}, caveats };
  }
}

/**
 * Rebuild the session as it stood at that moment.
 *
 * Some verdicts turn on sequence — "this session already read a credential file
 * and this call sends data off the machine". Re-deriving against a blank
 * session would drop that and then blame the difference on a rule change, which
 * would be a lie. Replaying the earlier entries of the same session is one pass
 * over a list already in memory.
 */
function replaySession(entries: LedgerEntry[], upto: LedgerEntry): SessionState {
  const prior = entries.filter((e) => e.sessionId === upto.sessionId && e.at < upto.at);
  const session = newSession(upto.sessionId, prior[0]?.at ?? upto.at);
  for (const e of prior) applyTaint(session, e.capability);
  return session;
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

// The labelled fields, the closing note and the "this changed" callout are all
// the same shape, and all three used to hard-code their own widths and run off
// the right-hand side of an 80-column terminal. They share `hang` from ../ui.js
// now, which takes its width from the terminal.

const FIELD_LABEL = 13;
const ROW_LABEL = 20;

/** A label/value line in the context block. */
const field = (label: string, value: string): string =>
  hang(c.gray(pad(label, FIELD_LABEL)), value, 2);

/** A label/value line in the history block, one level deeper. */
const row = (label: string, value: string): string => hang(c.gray(pad(label, ROW_LABEL)), value, 4);

/** The closing line, wrapped so it lines up under itself. */
const closing = (text: string): string => hang(c.gray(sym.corner), c.gray(text), 2);

/** Bars shrink rather than overflow when the terminal is narrow. */
const barCells = (): number => Math.max(6, Math.min(16, term.cols - 46));

// ---------------------------------------------------------------------------
// The context block
// ---------------------------------------------------------------------------

function context(
  entry: LedgerEntry,
  index: number,
  total: number,
  picked: Picked,
  rebuilt: Rebuilt,
  verdict: Verdict,
  changed: boolean,
): string[] {
  const counted = `(#${index} of ${total.toLocaleString('en-US')})`;
  const lead =
    picked === 'stopped-you'
      ? `the most recent thing LeastGrant did not simply wave through ${counted}`
      : picked === 'nothing-but-allows'
        ? `everything recent here was allowed, so this is the latest one ${counted}`
        : `the ${ordinal(index)} most recent decision here ${counted}`;

  const out = [para(c.gray(lead), 2), ''];

  out.push(field('ran', when(entry.at)));

  const agent = truncate(oneLine(entry.agent), 24) || c.gray('an unnamed agent');
  const branch = truncate(oneLine(str(entry.branch)), 24);
  const session = truncate(oneLine(entry.sessionId), 12);
  out.push(
    field(
      'agent',
      [agent, branch ? c.gray(`on ${branch}`) : '', session ? c.gray(`(session ${session})`) : '']
        .filter(Boolean)
        .join(' '),
    ),
  );
  out.push(field('mode', describeMode(entry.agentMode)));

  for (const note of rebuilt.caveats) {
    out.push('');
    out.push(c.dim(para(note, 2)));
  }

  if (changed) {
    out.push('');
    out.push(
      hang(
        c.brightYellow(sym.bullet),
        `${c.bold('this answer has changed.')} when it ran, LeastGrant said ${verdictBadge(entry.decision)}${c.gray(';')} today it would say ${verdictBadge(verdict.decision)}`,
        2,
      ),
    );
    out.push(
      para(
        c.gray(
          'your rules, or what LeastGrant has learned, have moved on since then. what follows is the answer you would get now.',
        ),
        4,
      ),
    );
  }

  return out;
}

/** Permission modes, in words, because "acceptEdits" is not an explanation. */
const MODES: Record<string, string> = {
  bypassPermissions: 'the agent was in bypass mode, so nobody was asked',
  dontAsk: 'the agent was told not to ask, so nobody was asked',
  auto: 'the agent was running unattended, so nobody was asked',
  acceptEdits: 'the agent was auto-accepting edits, so you were not asked about this',
  plan: 'the agent was in plan mode, where it is only meant to be thinking',
  default: 'the agent was asking before it acted, so this reached you',
  ask: 'the agent was asking before it acted, so this reached you',
};

function describeMode(mode?: string): string {
  if (!mode) return c.gray('the agent did not say what permission mode it was in');
  const known = MODES[mode];
  if (known) return known;
  return `the agent called its mode "${truncate(oneLine(mode), 32)}"`;
}

// ---------------------------------------------------------------------------
// The learning history
// ---------------------------------------------------------------------------

function history(
  stat: SignatureStat | undefined,
  fam: Familiarity,
  advice: string,
  th: Thresholds,
): string[] {
  const out = [`  ${c.gray('what it has learned about this')}`];

  if (!stat) {
    out.push(
      para(
        c.gray(
          'nothing yet. LeastGrant only counts an action once the call actually goes ahead, so this one was either blocked or never got that far.',
        ),
        4,
      ),
    );
  } else {
    // Floor, not round, and floor everywhere: the promotion gate compares
    // against `Math.floor(confirmed)`, so rounding up here would print "you
    // approved it 5 times" directly above "it needs 1 more yes".
    const yes = Math.floor(Math.max(0, fam.confirmed));
    const ran = Math.floor(Math.max(0, fam.observed));
    const no = Math.round(Math.max(0, fam.denied));
    const granted = fam.grantedAt;
    const cells = barCells();
    // The bars are relative to the largest of the three counts. The 1 is what
    // keeps a signature whose evidence has all decayed to nothing from dividing
    // by zero; `bar` guards it too, but not doing it twice is not a virtue.
    const max = Math.max(1, granted ? 0 : yes, ran, no);
    const total = count(stat.totalSeen);

    if (granted) {
      // A bulk grant is stored as the confirmation count it stands in for, so
      // that the maths downstream works out. Reading that number back as a
      // sentence would claim the person clicked yes eleven times when they made
      // one deliberate decision, which is exactly the sort of small lie that
      // costs a security tool the benefit of the doubt everywhere else.
      out.push(
        row('you approved it', `${c.green('once, during setup')} ${c.gray(`(${ago(granted)})`)}`),
      );
    } else {
      out.push(row('you approved it', `${bar(yes, max, cells, c.green)} ${times(yes)}`));
    }
    out.push(row('it ran, nobody asked', `${bar(ran, max, cells, c.cyan)} ${times(ran)}`));
    out.push(row('you turned it down', `${bar(no, max, cells, c.red)} ${times(no)}`));
    out.push(row('first seen', when(stat.firstSeen)));
    out.push(row('last seen', when(stat.lastSeen)));
    out.push(
      row(
        'seen in all',
        `${plural(total, 'time')} ${c.gray(
          `across ${plural(count(stat.days), 'day')} and ${plural(count(stat.sessions), 'session')}`,
        )}`,
      ),
    );
    out.push(row('worst it has been', blastStrip(hardenBlast(stat.worstBlast))));

    // The three counts above are weighted towards recent behaviour; "seen in
    // all" is a raw total. Left unsaid, the first is read as a count of events
    // and quietly contradicts the second.
    const faded = !granted && th.halfLifeDays > 0 && total > yes + ran + no;
    if (faded) {
      out.push('');
      out.push(
        para(
          c.gray(
            'the first three lines count recent behaviour for more than old behaviour, which is why they can add up to less than the total. a no is the exception: it never fades.',
          ),
          4,
        ),
      );
    }
  }

  out.push('');
  out.push(closing(advice));
  out.push('');
  return out;
}

const times = (n: number): string => (n === 0 ? c.gray('never') : plural(n, 'time'));

/**
 * Whether it runs on its own yet, and if not, exactly what closes the gap.
 *
 * "Not enough evidence" is a non-answer. Every branch here ends in something
 * the developer can actually do.
 */
function whatWouldChange(
  entry: LedgerEntry,
  fam: Familiarity,
  promo: PromotionResult,
  standing: Rule | undefined,
  alwaysAsks: boolean,
  ctx: CliContext,
): string {
  const th = ctx.config.thresholds;
  // Flattened: the signature is derived from a string the agent chose, and this
  // one is printed as a command the reader is invited to paste.
  const signature = oneLine(entry.signature);
  const sig = signature ? `leastgrant allow "${signature}"` : 'leastgrant allow "<the thing>"';

  if (standing?.effect === 'deny') {
    return `your own rule ${quoted(standing.match)} blocks this, and no amount of history will change that.${because(standing)} to drop the rule: leastgrant forget "${oneLine(standing.match)}"`;
  }
  if (standing?.effect === 'allow') {
    return `your rule ${quoted(standing.match)} already answers this, so it runs without asking.${because(standing)}`;
  }
  if (alwaysAsks) {
    return `this one always asks, however familiar it becomes — the whole point is that a person sees it go by. the only thing that stops the prompt is answering it in advance: ${sig}`;
  }
  if (promo.reason === 'blast-too-high') {
    return `this reaches too far for LeastGrant to approve on its own, no matter how often you say yes. a rule you write yourself is the only way: ${sig}`;
  }
  if (promo.reason === 'previously-denied') {
    return `you turned this down ${plural(Math.max(1, Math.round(fam.denied)), 'time')}, and a no does not expire. to change your mind: ${sig}`;
  }
  if (promo.eligible) {
    return fam.grantedAt
      ? 'you approved this during setup, so it goes through without asking.'
      : 'this is familiar enough now that it goes through without asking.';
  }

  const need = approvalsNeededFor(CONFIDENCE_BY_TIER[blastTier(entry.blast)] ?? th.minApproval);
  if (!Number.isFinite(need)) {
    // Reachable only from a hand-edited config asking for certainty of 1.0,
    // which no finite number of approvals reaches. Saying "∞ approvals" would
    // read like a bug; saying what to do about it does not.
    return `your settings ask for a level of certainty that no number of approvals can reach, so this will keep asking until you answer it outright: ${sig}`;
  }

  if (promo.reason === 'observed-only') {
    // Stated with the same test the engine uses, rather than a tier comparison
    // that looks equivalent and is not: a plain workspace read sits at tier 1
    // and would fail `tier <= observedMaxTier`, yet the engine promotes it
    // happily, so the old wording told people the opposite of the truth.
    const route = settlesUnattended(entry.blast)
      ? ` it can also settle without you after ${plural(th.minObserved, 'run')} spread over ${plural(th.minSessions, 'session')}, and it is at ${plural(Math.floor(Math.max(0, fam.observed + fam.confirmed)), 'run')} so far.`
      : ' running unattended will not settle it on its own — watching alone only decides things that stay inside the project and leave nothing to undo, and this is not one of those.';
    return `this has run here, but nothing you have done counts as approving it yet. ${plural(need, 'approval')} from you would settle it.${route} or answer it now: ${sig}`;
  }

  // Everything left is a straightforward shortfall. Say all of it at once —
  // being told about the approvals and then, five yeses later, about the days
  // is the kind of thing that makes people uninstall a tool.
  const gaps: string[] = [];
  // The engine already worked out the approval shortfall; using its number
  // keeps the sentence and the gate from ever disagreeing.
  const shortYes = promo.approvalsShort ?? Math.max(0, need - Math.floor(Math.max(0, fam.confirmed)));
  if (shortYes > 0) gaps.push(plural(shortYes, 'more yes', 'es'));
  const shortDays = th.minDays - count(fam.days);
  if (shortDays > 0) gaps.push(plural(shortDays, 'more day'));
  const shortSessions = th.minSessions - count(fam.sessions);
  if (shortSessions > 0) gaps.push(plural(shortSessions, 'more session'));
  return `still asking. it needs ${listOf(gaps) || 'a little more of the same'} before it stops asking. or skip the wait: ${sig}`;
}

/**
 * The engine's observation-only test, restated.
 *
 * Kept in terms of consequences rather than a tier number, because that is the
 * form a reader can check against the sentence it produces.
 */
function settlesUnattended(b: BlastRadius): boolean {
  return (
    (b.reach === 'workspace' || b.reach === 'none') &&
    b.reversibility === 'trivial' &&
    b.exposure === 'none' &&
    b.scale !== 'sweeping'
  );
}

function because(rule: Rule): string {
  const note = truncate(oneLine(str(rule.note)), 72);
  return note ? ` you noted: "${note}".` : '';
}

function quoted(s: string): string {
  return `"${truncate(oneLine(s), 44)}"`;
}

/** "a", "a and b", "a, b and c". */
function listOf(items: string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function renderEmpty(ctx: CliContext, json: boolean): number {
  const elsewhere = readLedger().filter((e) => e.project !== ctx.key).length;
  // Worth its own sentence: with recording off, "run it again and come back"
  // is advice that can never work.
  const recording = ctx.config.telemetry?.ledger !== false;

  if (json) {
    process.stdout.write(
      JSON.stringify(
        {
          index: 0,
          total: 0,
          picked: null,
          project: ctx.key,
          entry: null,
          entriesElsewhere: elsewhere,
          recording,
          hint: recording ? 'leastgrant init' : 'set telemetry.ledger to true in config.json',
        },
        null,
        2,
      ) + '\n',
    );
    return 0;
  }

  const out = ['', `  ${c.bold('Nothing to explain yet.')}`, ''];
  out.push(
    para('LeastGrant has not recorded a decision in this project, so there is no "why" to give you.', 2),
  );
  if (!recording) {
    out.push('');
    out.push(
      para(
        c.yellow(
          'recording is switched off in your config (telemetry.ledger), so nothing will be written down until you turn it back on.',
        ),
        2,
      ),
    );
  }
  if (elsewhere > 0) {
    out.push('');
    out.push(
      para(
        c.gray(
          `${plural(elsewhere, 'decision')} ${elsewhere === 1 ? 'is' : 'are'} recorded in other projects — why only looks at this one.`,
        ),
        2,
      ),
    );
  }
  out.push('');
  out.push(
    `  ${c.gray(sym.corner)} ${c.cyan('leastgrant init')}  ${c.gray('reads the history your agents already left behind')}`,
  );
  out.push(
    `  ${c.gray('  or')} ${c.cyan('leastgrant check "git push --force"')}  ${c.gray('to see how it thinks, right now')}`,
  );
  out.push('');
  process.stdout.write(out.join('\n') + '\n');
  return 0;
}

// ---------------------------------------------------------------------------

/** Absolute time and relative time together, or an honest shrug. */
function when(at: unknown): string {
  if (typeof at !== 'number' || !Number.isFinite(at) || at <= 0) return c.gray('not recorded');
  return `${stamp(at)} ${c.gray(`(${ago(at)})`)}`;
}

/** Absolute time, spelled out, because "3h ago" alone is not an audit trail. */
function stamp(at: number): string {
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return 'not recorded';
  const date = d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
  const time = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  return `${date}, ${time}`;
}

function ordinal(n: number): string {
  const rem100 = n % 100;
  if (rem100 >= 11 && rem100 <= 13) return `${n}th`;
  const suffix = ['th', 'st', 'nd', 'rd'][n % 10] ?? 'th';
  return `${n}${suffix}`;
}
