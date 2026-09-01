/**
 * `leastgrant doctor`
 *
 * Two questions in one command: is LeastGrant actually wired up, and how much
 * of this machine can your agents currently reach?
 *
 * The second half is the reason this exists. Setup checks are table stakes —
 * every tool has them — but nobody goes looking for the `.env` sitting
 * unignored next to their code, or the allow rule they wrote in March that now
 * covers something they would never approve today. Doctor goes looking, and
 * every finding comes with the command that fixes it.
 *
 * Three rules this file has to keep:
 *
 *   1. It runs on machines where nothing is set up yet. No state directory, no
 *      config, no ledger, no envelope — that is the *first* run, not an edge
 *      case, and doctor is also the command people reach for when something is
 *      already broken. It must not throw. Every denominator is checked before
 *      it is divided by, and every file on disk is treated as something a human
 *      may have hand-edited into a shape we did not expect.
 *
 *   2. Every count names the set it counted. "40% of the last 30 days" and
 *      "40% of the actions recorded in the last 30 days" are different claims
 *      and only one of them is true.
 *
 *   3. Exit code is 0 unless something is genuinely broken, so this can sit in
 *      CI — including under `--json`, which returns the same code the human
 *      output would and writes nothing decorative to stdout.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { BlastRadius, Config, LedgerEntry, Posture, Rule } from '../../core/types.js';
import { blastTier } from '../../core/types.js';
import { classifySecretPath, globMatch } from '../../core/secrets.js';
import { displayPath } from '../../core/paths.js';
import { listEnvelopes, readLedger, stateDir } from '../../store/index.js';
import { loadContext } from '../context.js';
import { claudeSettingsPath } from './install.js';
import { ago, c, para, plural, rule, sym, term, truncate, width } from '../ui.js';
import type { Argv } from '../index.js';

type Status = 'ok' | 'warn' | 'bad' | 'info';
type Group = 'setup' | 'exposure' | 'habits';

interface Check {
  id: string;
  group: Group;
  status: Status;
  /** One line, lowercase, addressed to the developer. Plain text. */
  title: string;
  /** Optional second line with the specifics. Plain text. */
  detail?: string;
  /** A command the user can run. Never executed for them unless it is purely local. */
  fix?: string;
  /** True when `--fix` actually did something. */
  fixed?: boolean;
}

const DAY_MS = 86_400_000;

/** The window the habit checks report on, named so the prose cannot drift. */
const WINDOW_DAYS = 30;

/**
 * Permission modes in which the human is not being consulted. Duplicated from
 * the hook rather than imported: the hook module runs before every tool call
 * and nothing should give the CLI a reason to load it.
 */
const UNATTENDED = new Set(['bypassPermissions', 'acceptEdits', 'dontAsk', 'auto']);

/**
 * Everything the checks need to know about where we are.
 *
 * Deliberately narrower than `CliContext`: doctor reads three things out of the
 * config and nothing out of the envelope or session, and taking only those
 * means a config that parsed into the wrong shapes cannot reach the checks.
 */
interface Site {
  root: string;
  key: string;
  posture: string;
  rules: Rule[];
  secretPatterns: string[];
  /** Set when we could not work out which project this is at all. */
  error?: string;
}

export function doctorCommand(argv: Argv): number {
  const json = flag(argv, 'json');
  const wantFix = flag(argv, 'fix');
  const now = Date.now();

  const site = loadSite();
  const ledger = safely(() => readLedger(), [] as LedgerEntry[]);

  const checks: Check[] = [
    ...setupChecks(site, wantFix),
    ...exposureChecks(site, ledger),
    ...habitChecks(site, ledger, now),
  ];

  const counts: Record<Status, number> = { ok: 0, warn: 0, bad: 0, info: 0 };
  for (const ch of checks) counts[ch.status]++;
  const exit = counts.bad > 0 ? 1 : 0;

  if (json) {
    // Nothing but JSON on stdout: no banner, no colour, no trailing summary.
    // The exit code matches the human run, so `doctor --json` works as a gate.
    process.stdout.write(
      JSON.stringify({ project: site.root, posture: site.posture, counts, exit, checks }, null, 2) + '\n',
    );
    return exit;
  }

  process.stdout.write(render(checks, counts, wantFix));
  return exit;
}

/**
 * `--json` and `--fix` take no value, but the argument parser cannot know that.
 * `--json=false` and `--fix false` both arrive here as the *string* `"false"`,
 * which is truthy, so a plain `Boolean()` turns an opt-out into an opt-in.
 */
function flag(argv: Argv, name: string): boolean {
  const v = argv.flags[name];
  return v !== undefined && v !== false && v !== 'false' && v !== '0';
}

/**
 * Load just enough context to run the checks, and survive not being able to.
 *
 * `loadContext` walks the filesystem for a project root; a deleted working
 * directory or an unreadable home makes it throw, and those are precisely the
 * machines someone runs doctor on.
 */
function loadSite(): Site {
  let root = safeCwd();
  let key = '';
  let config: Partial<Config> = {};
  let error: string | undefined;

  try {
    const ctx = loadContext();
    root = ctx.root || root;
    key = ctx.key || '';
    config = ctx.config ?? {};
  } catch (err) {
    error = (err as Error).message;
  }

  // `loadConfig` falls back to defaults for a missing or unparseable file, but
  // not for one that parses into the wrong shapes: a hand-edited `"rules": {}`
  // arrives as an object, and `.filter` is not a method on it.
  const site: Site = {
    root,
    key,
    posture: typeof config.posture === 'string' && config.posture ? config.posture : 'assist',
    rules: Array.isArray(config.rules) ? config.rules.filter(isRule) : [],
    secretPatterns: Array.isArray(config.secretPatterns)
      ? config.secretPatterns.filter((p): p is string => typeof p === 'string' && p !== '')
      : [],
  };
  if (error) site.error = error;
  return site;
}

function isRule(r: unknown): r is Rule {
  if (!r || typeof r !== 'object') return false;
  const v = r as Partial<Rule>;
  return typeof v.match === 'string' && v.match !== '';
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

function setupChecks(site: Site, wantFix: boolean): Check[] {
  const out: Check[] = [];

  if (site.error) {
    out.push({
      id: 'context',
      group: 'setup',
      status: 'bad',
      title: 'could not work out which project this is',
      detail: `${site.error}. Everything below is what LeastGrant can still see without it.`,
      fix: 'cd somewhere that still exists, then run doctor again',
    });
  }

  // --- state directory ---
  const dir = safely(() => stateDir(), '');

  if (!dir) {
    out.push({
      id: 'state-dir',
      group: 'setup',
      status: 'bad',
      title: 'cannot work out where to keep state',
      detail: 'there is no home directory to fall back on, so LeastGrant has nowhere to record anything',
      fix: 'set LEASTGRANT_HOME to a directory you can write to',
    });
  } else {
    let dirExists = safely(() => fs.statSync(dir).isDirectory(), false);

    if (!dirExists && wantFix) {
      // The only fix we perform without asking: making our own directory. It
      // touches nothing the user owns and cannot surprise anyone.
      try {
        fs.mkdirSync(dir, { recursive: true });
        dirExists = true;
        out.push({
          id: 'state-dir',
          group: 'setup',
          status: 'ok',
          title: 'created the state directory',
          detail: show(dir, site.root),
          fixed: true,
        });
      } catch (err) {
        out.push({
          id: 'state-dir',
          group: 'setup',
          status: 'bad',
          title: 'could not create the state directory',
          detail: `${show(dir, site.root)} — ${(err as Error).message}`,
        });
      }
    } else if (!dirExists) {
      out.push({
        id: 'state-dir',
        group: 'setup',
        status: 'warn',
        title: 'no state directory yet',
        detail: `${show(dir, site.root)} does not exist, so nothing has been recorded here`,
        fix: 'leastgrant init',
      });
    } else {
      const writable = safely(() => {
        fs.accessSync(dir, fs.constants.W_OK);
        return true;
      }, false);
      out.push(
        writable
          ? {
              id: 'state-dir',
              group: 'setup',
              status: 'ok',
              title: 'state directory is writable',
              detail: show(dir, site.root),
            }
          : {
              id: 'state-dir',
              group: 'setup',
              status: 'bad',
              title: 'state directory is not writable',
              detail: `${show(dir, site.root)} — LeastGrant cannot record decisions or learn anything while this is true`,
            },
      );
    }
  }

  // --- hooks ---
  const scopes = hookScopes(site.root);
  const pre = scopes.filter((s) => s.pre);
  const post = scopes.filter((s) => s.post);
  const anySettings = scopes.some((s) => s.exists);

  out.push(
    pre.length
      ? {
          id: 'hook-pre',
          group: 'setup',
          status: 'ok',
          title: 'the Claude Code hook is installed',
          detail: `LeastGrant sees tool calls before they run (${listScopes(pre)})`,
        }
      : {
          id: 'hook-pre',
          group: 'setup',
          status: 'bad',
          title: 'the Claude Code hook is not installed',
          detail: anySettings
            ? 'you have agent settings, but nothing in them runs leastgrant — no tool call is being checked'
            : 'nothing is asking LeastGrant about tool calls, so it has no effect at all right now',
          fix: 'leastgrant install',
        },
  );

  out.push(
    post.length
      ? {
          id: 'hook-post',
          group: 'setup',
          status: 'ok',
          title: 'LeastGrant also hears how each decision turned out',
          detail: `the answers you give feed back into what it knows (${listScopes(post)})`,
        }
      : {
          id: 'hook-post',
          group: 'setup',
          // With only the first hook we still decide correctly, we just never
          // find out that you said yes — so the asking never stops. That is a
          // slow failure, which is worse than a loud one.
          status: pre.length ? 'warn' : 'info',
          title: 'LeastGrant never hears how a decision turned out',
          detail:
            'the second Claude Code hook (PostToolUse) is missing, so approving something teaches it nothing and it will keep asking about the same work',
          fix: 'leastgrant install',
        },
  );

  // --- runtime ---
  const v = process.versions.node || '0.0.0';
  const segments = v.split('.');
  const major = Number.parseInt(segments[0] ?? '', 10) || 0;
  const minor = Number.parseInt(segments[1] ?? '', 10) || 0;
  const nodeOk = major > 20 || (major === 20 && minor >= 10);
  out.push({
    id: 'node',
    group: 'setup',
    status: nodeOk ? 'ok' : 'bad',
    title: nodeOk ? `node ${v}` : `node ${v} is too old`,
    detail: nodeOk ? undefined : 'LeastGrant needs node 20.10 or newer',
  });

  // --- posture ---
  const note = (POSTURE_NOTES as Record<string, string | undefined>)[site.posture];
  out.push({
    id: 'posture',
    group: 'setup',
    status: note ? 'info' : 'warn',
    title: `posture is ${site.posture}`,
    detail:
      note ??
      'LeastGrant does not recognise that setting, so it is behaving as it does under assist. The choices are observe, assist, autopilot and strict.',
  });

  return out;
}

/** Written out rather than inlined so adding a posture cannot skip the prose. */
const POSTURE_NOTES: Record<Posture, string> = {
  observe: 'LeastGrant is only watching — it records what happens and will not stop anything',
  strict: 'nothing is auto-approved; every decision comes back to you',
  autopilot: 'routine work goes through unattended, and anything that could do real damage still asks',
  assist: 'familiar low-risk work goes through, everything else asks',
};

interface ScopeHooks {
  label: string;
  file: string;
  exists: boolean;
  pre: boolean;
  post: boolean;
}

/**
 * Where a Claude Code hook can live. Project-local settings come in two files
 * (`settings.json` is committed, `settings.local.json` is not) and either one
 * counts, so they are folded into a single scope the user can act on.
 *
 * The paths come from `install`'s own helper rather than being rebuilt here.
 * That helper honours `CLAUDE_CONFIG_DIR`; a copy that did not would report
 * "not installed" about a hook `leastgrant install` had just written.
 */
function hookScopes(root: string): ScopeHooks[] {
  const user = safely(() => claudeSettingsPath('user'), '');
  const projectMain = root ? safely(() => claudeSettingsPath('project', root), '') : '';
  const scopes: { label: string; files: string[] }[] = [
    { label: 'your user settings', files: user ? [user] : [] },
    {
      label: 'this project',
      files: projectMain ? [projectMain, path.join(path.dirname(projectMain), 'settings.local.json')] : [],
    },
  ];

  return scopes.map((s) => {
    let exists = false;
    let pre = false;
    let post = false;
    for (const file of s.files) {
      const read = readSettings(file);
      if (!read.exists) continue;
      exists = true;
      pre ||= read.pre.some(mentionsUs);
      post ||= read.post.some(mentionsUs);
    }
    return { label: s.label, file: s.files[0] ?? '', exists, pre, post };
  });
}

/** A hook command counts as ours if it invokes the binary under either name. */
function mentionsUs(command: string): boolean {
  return /\bleastgrant\b/i.test(command) || /(^|[\s/\\"'])lg\s+hook\b/.test(command);
}

interface SettingsHooks {
  exists: boolean;
  pre: string[];
  post: string[];
}

function readSettings(file: string): SettingsHooks {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return { exists: false, pre: [], post: [] };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // A settings file we cannot parse is still a settings file; treat it as
    // present but hookless rather than pretending it is not there.
    return { exists: true, pre: [], post: [] };
  }
  const hooks = asRecord(asRecord(parsed)?.['hooks']);
  return {
    exists: true,
    pre: commandsFor(hooks?.['PreToolUse']),
    post: commandsFor(hooks?.['PostToolUse']),
  };
}

/** Pull every `command` string out of a hook event, whatever nesting it uses. */
function commandsFor(event: unknown): string[] {
  if (!Array.isArray(event)) return [];
  const out: string[] = [];
  for (const group of event) {
    const g = asRecord(group);
    if (!g) continue;
    if (typeof g['command'] === 'string') out.push(g['command']);
    const inner = g['hooks'];
    if (!Array.isArray(inner)) continue;
    for (const h of inner) {
      const cmd = asRecord(h)?.['command'];
      if (typeof cmd === 'string') out.push(cmd);
    }
  }
  return out;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function listScopes(scopes: ScopeHooks[]): string {
  return scopes.map((s) => s.label).join(' and ');
}

// ---------------------------------------------------------------------------
// Exposure — what is reachable from where the agent is standing
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'vendor', '.venv']);
/** Enough to cover a normal repo's top two levels; doctor must stay instant. */
const WALK_BUDGET = 400;

interface Found {
  abs: string;
  why: string;
}

function exposureChecks(site: Site, ledger: LedgerEntry[]): Check[] {
  const out: Check[] = [];
  const found = safely(() => scanForCredentials(site.root, site.secretPatterns), [] as Found[]);

  if (found.length) {
    const shown = found.slice(0, 6);
    const names = shown.map((f) => credentialLabel(f.abs, site.root));
    const one = found.length === 1;
    const first = found[0];
    out.push({
      id: 'credentials-in-tree',
      group: 'exposure',
      status: 'warn',
      // "top two levels" is what `scanForCredentials` actually looks at, and
      // saying so stops the clean result reading as "there are none anywhere".
      title: `${plural(found.length, 'credential file')} in the top two levels of this project`,
      detail:
        names.join(', ') +
        andMore(found.length, shown.length) +
        (one && first ? ` — ${first.why}` : '') +
        `. Any agent working here can read ${one ? 'it' : 'them'}, and LeastGrant will always stop to ask before it lets that happen.`,
    });
  } else {
    out.push({
      id: 'credentials-in-tree',
      group: 'exposure',
      status: 'ok',
      title: 'no credential files in the top two levels of this project',
    });
  }

  out.push(gitignoreCheck(site.root, found));

  // --- network footprint ---
  const hosts = hostCounts(ledger);
  if (!hosts.length) {
    out.push({
      id: 'hosts',
      group: 'exposure',
      status: 'info',
      title: 'no network calls recorded yet',
      detail: ledger.length
        ? 'nothing LeastGrant has recorded so far left this machine'
        : 'there is no history to read yet — run init and LeastGrant will pick up what your agents already did',
      fix: ledger.length ? undefined : 'leastgrant init',
    });
  } else {
    const shown = hosts.slice(0, 5);
    out.push({
      id: 'hosts',
      group: 'exposure',
      status: 'info',
      title: `your agents have reached ${plural(hosts.length, 'host')}`,
      // The ledger is machine-wide, so this is not a per-project number. Say so
      // rather than let it be read as one.
      detail:
        `by number of recorded calls: ${shown.map(([host, n]) => `${host} ${n}`).join(', ')}` +
        `${andMore(hosts.length, shown.length)}. That counts every project on this machine, not only this one.`,
    });
  }

  return out;
}

/** The project root can itself be a credential directory, where "." is no help. */
function credentialLabel(abs: string, root: string): string {
  const shown = show(abs, root);
  if (shown !== '.') return shown;
  return `${path.basename(root) || root} (the project directory itself)`;
}

/**
 * The root itself, its children, and one level below that. Deep scanning is
 * somebody else's job — the point is the credentials people leave lying in
 * plain sight, which are all near the top.
 */
function scanForCredentials(root: string, extra: string[]): Found[] {
  const found: Found[] = [];
  if (!root) return found;
  const seen = new Set<string>();
  let budget = WALK_BUDGET;

  const consider = (abs: string): void => {
    if (seen.has(abs)) return;
    seen.add(abs);
    const m = safely(() => classifySecretPath(abs, extra), null);
    if (m?.secret) found.push({ abs, why: m.why });
  };

  // Working *inside* a credential directory is the loudest case of all.
  consider(root);

  const level2: string[] = [];
  for (const entry of readDir(root)) {
    if (budget-- <= 0) break;
    const abs = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      level2.push(abs);
      consider(abs);
    } else {
      consider(abs);
    }
  }

  for (const dir of level2) {
    if (budget <= 0) break;
    for (const entry of readDir(dir)) {
      if (budget-- <= 0) break;
      if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
      consider(path.join(dir, entry.name));
    }
  }

  return found;
}

function readDir(dir: string): fs.Dirent[] {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

const DOTENV = /^\.env(\..*)?$/i;

/**
 * A `.env` that git can see is one `git add -A` away from being public, and
 * agents run `git add -A` constantly. Read as text on purpose: shelling out to
 * `git check-ignore` from a tool that is supposed to be watching what shells
 * out would be a poor look, and slower.
 */
function gitignoreCheck(root: string, found: Found[]): Check {
  const envFiles = root
    ? found.map((f) => f.abs).filter((abs) => path.dirname(abs) === root && DOTENV.test(path.basename(abs)))
    : [];

  if (!envFiles.length) {
    return { id: 'gitignore', group: 'exposure', status: 'ok', title: 'no .env file at the project root' };
  }

  const names = envFiles.map((f) => path.basename(f));
  const ignoreText = safely(() => fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), null);

  if (ignoreText === null) {
    const tracked = safely(() => fs.existsSync(path.join(root, '.git')), false);
    return {
      id: 'gitignore',
      group: 'exposure',
      status: tracked ? 'warn' : 'info',
      title: 'there is no .gitignore here',
      detail: `${names.join(', ')} ${isAre(names.length)} sitting in the project root with nothing stopping ${names.length === 1 ? 'it' : 'them'} being committed`,
    };
  }

  const patterns = ignoreText
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.replace(/^\/+/, '').replace(/\/+$/, ''));

  const exposed = names.filter((base) => !patterns.some((p) => covers(p, base)));

  if (!exposed.length) {
    return { id: 'gitignore', group: 'exposure', status: 'ok', title: 'your .env files are git-ignored' };
  }

  const firstExposed = exposed[0] ?? '.env';
  return {
    id: 'gitignore',
    group: 'exposure',
    status: 'bad',
    title: `${exposed.join(', ')} ${isAre(exposed.length)} not git-ignored`,
    detail:
      'you have a .gitignore and it does not cover this, so an agent running "git add -A" would commit your secrets',
    fix: `echo "${firstExposed}" >> .gitignore`,
  };
}

/**
 * Does one .gitignore line cover this filename?
 *
 * `**` is stripped as well as matched, because git treats a leading `**​/` as
 * "at any depth, including here" while the glob matcher requires a directory to
 * consume — without this, a repo that ignores `**​/.env` gets told its `.env` is
 * exposed when it is not.
 */
function covers(pattern: string, base: string): boolean {
  const bare = pattern.replace(/^\*\*\//, '');
  return pattern === base || bare === base || globMatch(pattern, base) || globMatch(bare, base);
}

/** Hosts appear in signatures as `<url:host>`; fall back to the display line. */
function hostCounts(ledger: LedgerEntry[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const e of ledger) {
    if (!e || typeof e.capability !== 'string' || !e.capability.startsWith('net.')) continue;
    const signature = typeof e.signature === 'string' ? e.signature : '';
    const display = typeof e.display === 'string' ? e.display : '';
    const host =
      /<url:([^>]+)>/.exec(signature)?.[1] ??
      /\bhttps?:\/\/(?:[^@/\s]*@)?([^/:?#\s]+)/i.exec(display)?.[1];
    if (!host) continue;
    const key = host.toLowerCase();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  // Tie-break by name so two runs over the same ledger print the same order.
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// ---------------------------------------------------------------------------
// Habits — what the history says about how you actually work
// ---------------------------------------------------------------------------

function habitChecks(site: Site, ledger: LedgerEntry[], now: number): Check[] {
  const out: Check[] = [];
  // A hand-edited or half-written ledger line can carry anything at all in
  // `at`, and every date calculation below would quietly become NaN.
  const dated = ledger.filter((e) => e && finite(e.at));
  const recent = dated.filter((e) => e.at >= now - WINDOW_DAYS * DAY_MS);

  out.push(unattendedCheck(dated, recent, now));

  // Over-broad first, so a rule that is both unused *and* over-broad is only
  // reported once, under the heading that actually matters.
  const reachy = reachyRuleChecks(site, now);
  out.push(...staleRuleChecks(site, ledger, now, reachy.flagged));
  out.push(...reachy.checks);

  return out;
}

function unattendedCheck(all: LedgerEntry[], recent: LedgerEntry[], now: number): Check {
  if (!recent.length) {
    const last = latest(all);
    return {
      id: 'unattended',
      group: 'habits',
      status: 'info',
      title: `nothing recorded in the last ${WINDOW_DAYS} days`,
      detail: last
        ? `the most recent thing LeastGrant saw was ${ago(last, now)}`
        : 'once the hook is in place this fills up on its own',
      fix: last ? undefined : 'leastgrant init',
    };
  }

  // Entries that never recorded a mode cannot be counted either way, so they
  // stay out of the denominator instead of being quietly counted as attended.
  const modes = recent
    .map((e) => e.agentMode)
    .filter((m): m is string => typeof m === 'string' && m !== '');

  if (!modes.length) {
    return {
      id: 'unattended',
      group: 'habits',
      status: 'info',
      title: 'cannot tell how much of this ran unattended',
      detail: `none of the ${plural(recent.length, 'action')} recorded in the last ${WINDOW_DAYS} days noted which permission mode ${recent.length === 1 ? 'it' : 'they'} ran in`,
    };
  }

  const unattended = modes.filter((m) => UNATTENDED.has(m)).length;
  const share = percent(unattended, modes.length);
  // Compare the counts, not the rounded share, so 49.6% is not "half or more".
  const high = unattended * 2 >= modes.length;
  const unknown = recent.length - modes.length;

  return {
    id: 'unattended',
    group: 'habits',
    status: high ? 'warn' : 'ok',
    // Say what the denominator is. This is a share of recorded actions, not of
    // the elapsed days, and the two are nowhere near the same number.
    title: `${share}% of the actions recorded in the last ${WINDOW_DAYS} days ran unattended`,
    detail:
      `${unattended} of ${plural(modes.length, 'action')} ran in a mode where you were never asked` +
      (unknown ? `; ${unknown} more did not record a mode and are left out of that share` : '') +
      (high
        ? '. LeastGrant treats those as things it saw rather than things you approved, so they never unlock anything on their own.'
        : '.'),
  };
}

const STALE_DAYS = 60;

function staleRuleChecks(site: Site, ledger: LedgerEntry[], now: number, skip: Set<string>): Check[] {
  const allow = activeRules(site, now).filter((r) => r.effect === 'allow' && !skip.has(r.match));
  if (!allow.length) {
    if (skip.size) return []; // every allow rule is already reported, louder
    return [{ id: 'stale-rules', group: 'habits', status: 'info', title: 'no allow rules yet' }];
  }

  const cutoff = now - STALE_DAYS * DAY_MS;

  // A rule written last week has not had time to be used; nagging about it
  // would just teach people to ignore doctor. It is also left out of the
  // headline count below, because a rule we did not examine cannot honestly be
  // described as "still in use".
  const judged = allow.filter((r) => finite(r.addedAt) && r.addedAt <= cutoff);
  const tooNew = allow.length - judged.length;

  if (!judged.length) {
    return [
      {
        id: 'stale-rules',
        group: 'habits',
        status: 'info',
        title: `${plural(allow.length, 'allow rule')}, none older than ${STALE_DAYS} days`,
        detail: 'too recent to say yet whether anything is using them',
      },
    ];
  }

  // One pass over the ledger, then match each rule against the distinct
  // signatures. Matching every rule against every entry compiles a fresh glob
  // per pair, and doctor has to stay instant on a ledger with tens of thousands
  // of lines.
  const lastUse = lastUseBySignature(ledger);

  const stale: { rule: Rule; lastUsed: number | null }[] = [];
  for (const r of judged) {
    let lastUsed: number | null = null;
    for (const [signature, at] of lastUse) {
      if (at > (lastUsed ?? 0) && globMatch(r.match, signature)) lastUsed = at;
    }
    if (lastUsed === null || lastUsed < cutoff) stale.push({ rule: r, lastUsed });
  }

  if (!stale.length) {
    return [
      {
        id: 'stale-rules',
        group: 'habits',
        status: 'ok',
        title: `${plural(judged.length, 'allow rule')} older than ${STALE_DAYS} days, all still in use`,
        detail: tooNew
          ? `${plural(tooNew, 'newer rule')} ${isAre(tooNew)} not counted here — too recent to judge`
          : undefined,
      },
    ];
  }

  return stale.map((s) => ({
    id: `stale-rule:${s.rule.match}`,
    group: 'habits' as const,
    status: 'warn' as const,
    title: `nothing has matched "${s.rule.match}" in ${STALE_DAYS} days`,
    detail:
      (s.lastUsed ? `last used ${ago(s.lastUsed, now)}` : 'it has never matched anything') +
      (finite(s.rule.addedAt) ? `, added ${ago(s.rule.addedAt, now)}` : '') +
      '. Dropping it costs little: if the work comes back, LeastGrant asks once and you can say yes again.',
    fix: `leastgrant forget "${s.rule.match}"`,
  }));
}

/**
 * The check worth the whole command: an allow rule written for something small
 * that has quietly grown to cover something that leaves the machine.
 */

/** The tier at which an action leaves this machine or cannot be undone. */
const REACHY_TIER = 3;

interface ReachyReport {
  checks: Check[];
  /** Rule patterns reported here, so the staleness check does not repeat them. */
  flagged: Set<string>;
}

function reachyRuleChecks(site: Site, now: number): ReachyReport {
  const flagged = new Set<string>();
  const allow = activeRules(site, now).filter((r) => r.effect === 'allow');
  if (!allow.length) return { checks: [], flagged };

  const reachy = reachySignatures();
  const checks: Check[] = [];

  for (const r of allow) {
    const hits: string[] = [];
    for (const [signature, keys] of reachy) {
      // A project-scoped rule only speaks for its own project.
      if (r.scope === 'project' && r.key && !keys.has(r.key)) continue;
      if (!globMatch(r.match, signature)) continue;
      hits.push(signature);
    }
    if (!hits.length) continue;

    flagged.add(r.match);
    const shown = hits.slice(0, 3);
    const one = hits.length === 1;
    checks.push({
      id: `broad-rule:${r.match}`,
      group: 'habits',
      status: 'bad',
      title: `"${r.match}" covers something LeastGrant would never approve on its own`,
      detail:
        `it matches ${shown.map((h) => `"${h}"`).join(', ')}${andMore(hits.length, shown.length)}, ` +
        `which ${one ? 'reaches' : 'reach'} past this machine or cannot be undone. ` +
        `The rule lets ${one ? 'it' : 'them'} through every time, without asking. Narrow the pattern if that is more than you meant to grant.`,
      fix: `leastgrant forget "${r.match}"`,
    });
  }

  if (!checks.length) {
    return {
      checks: [
        {
          id: 'broad-rules',
          group: 'habits',
          status: 'ok',
          title: 'none of your allow rules reach past the workspace',
        },
      ],
      flagged,
    };
  }
  return { checks, flagged };
}

/**
 * Every signature any project has seen whose worst recorded blast radius puts
 * it out of auto-approval range, mapped to the project keys it turned up in.
 *
 * Built once and shared across every rule. The alternative walks each envelope
 * for each rule and compiles a glob per signature per rule, which on a machine
 * with a dozen projects is the slowest thing doctor does.
 */
function reachySignatures(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const env of safely(() => listEnvelopes(), [])) {
    // Envelopes are parsed off disk, not validated: a truncated or hand-edited
    // file arrives as anything at all, `null` included.
    if (!env || typeof env !== 'object') continue;
    const signatures = env.signatures;
    if (!signatures || typeof signatures !== 'object') continue;
    const key = typeof env.key === 'string' ? env.key : '';

    for (const [name, stat] of Object.entries(signatures)) {
      if (!stat || typeof stat !== 'object') continue;
      if (safeTier(stat.worstBlast) < REACHY_TIER) continue;
      const signature = typeof stat.signature === 'string' && stat.signature ? stat.signature : name;
      const keys = out.get(signature) ?? new Set<string>();
      keys.add(key);
      out.set(signature, keys);
    }
  }
  return out;
}

/**
 * `blastTier` looks the four blast dimensions up in fixed tables. A partly
 * written envelope can hold a shape that is none of them, and the lookup then
 * yields NaN — where `NaN < REACHY_TIER` is false, so the unguarded version
 * reports unreadable data as a dangerous rule. Unreadable means unknown here,
 * not alarming: this is a report, and inventing a finding out of a corrupt file
 * is how people learn to stop reading the report.
 */
function safeTier(b: BlastRadius | undefined): number {
  if (!b || typeof b !== 'object') return 0;
  const tier = safely(() => blastTier(b), 0);
  return Number.isFinite(tier) ? tier : 0;
}

/**
 * Rules the engine would actually consult. `matchRule` skips expired ones, so
 * reporting an expired rule as over-broad is a finding about something that
 * already does nothing.
 */
function activeRules(site: Site, now: number): Rule[] {
  return site.rules.filter((r) => {
    const expires = r.expiresAt;
    return !(finite(expires) && expires < now);
  });
}

/** Latest use per distinct signature, in one pass over the ledger. */
function lastUseBySignature(ledger: LedgerEntry[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of ledger) {
    const signature = e?.signature;
    if (typeof signature !== 'string' || !signature || !finite(e.at)) continue;
    const prev = out.get(signature);
    if (prev === undefined || e.at > prev) out.set(signature, e.at);
  }
  return out;
}

/**
 * The newest timestamp in the ledger.
 *
 * Not `entries[entries.length - 1]`: entries are appended by several agent
 * sessions at once and are not strictly ordered. Not `Math.max(...entries)`
 * either — spreading a long ledger into a call throws RangeError, and a tool
 * that falls over once you have used it for a year is worse than no tool.
 */
function latest(entries: LedgerEntry[]): number | null {
  let best: number | null = null;
  for (const e of entries) {
    if (finite(e.at) && (best === null || e.at > best)) best = e.at;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const GROUPS: { id: Group; label: string }[] = [
  { id: 'setup', label: 'setup' },
  { id: 'exposure', label: 'what your agents can reach' },
  { id: 'habits', label: 'habits' },
];

/** Column where every line of a check's text begins, mark included. */
const BODY = 5;

/**
 * The usable width.
 *
 * One column narrower than the terminal: a line that fills the last column
 * wraps in some terminals and not others, and the difference shows up as a
 * stray blank line between every entry in an 80-column window.
 */
function usable(): number {
  return Math.max(40, term.cols - 1);
}

/**
 * The status mark. Shape carries the meaning as well as colour does, so this
 * still reads correctly under NO_COLOR: tick, question, cross, dot.
 */
function glyph(status: Status): string {
  if (status === 'ok') return c.green(sym.allow);
  if (status === 'bad') return c.red(sym.deny);
  if (status === 'warn') return c.yellow(sym.ask);
  return c.gray(sym.bullet);
}

/**
 * Wrap to the terminal, shortening any single word too long to fit.
 *
 * `para` never splits a word, so one long absolute path or signature would run
 * off the right edge of an 80-column window and take the alignment with it.
 * Returns bare lines so the caller can colour each one — a colour span left
 * open across a newline survives most terminals and not all of them.
 */
function wrapText(text: string, indent: number): string[] {
  const budget = Math.max(20, usable() - indent);
  const words = text
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => truncate(w, budget));
  if (!words.length) return [];
  return para(words.join(' '), 0, budget).split('\n');
}

function render(checks: Check[], counts: Record<Status, number>, wantFix: boolean): string {
  const out: string[] = [''];
  const gutter = ' '.repeat(BODY);

  for (const g of GROUPS) {
    const items = checks.filter((x) => x.group === g.id);
    if (!items.length) continue;
    out.push(rule(g.label));
    out.push('');

    for (const ch of items) {
      const style = ch.status === 'bad' ? c.bold : identity;
      const title = wrapText(ch.title, BODY);
      out.push(`  ${glyph(ch.status)}  ${style(title[0] ?? ch.title)}`);
      // Continuations hang under the title, clear of the status mark.
      for (const line of title.slice(1)) out.push(gutter + style(line));

      if (ch.detail) {
        for (const line of wrapText(ch.detail, BODY)) out.push(gutter + c.gray(line));
      }

      if (ch.fix) {
        // A fix is meant to be copied, so it is shortened rather than wrapped:
        // a command broken across two lines is a command that gets pasted wrong.
        const lead = `${gutter}fix  `;
        out.push(gutter + c.gray('fix') + '  ' + c.cyan(truncate(ch.fix, Math.max(20, usable() - lead.length))));
      }
    }
    out.push('');
  }

  const parts: string[] = [c.green(`${counts.ok} fine`)];
  if (counts.warn) parts.push(c.yellow(`${counts.warn} worth a look`));
  if (counts.bad) parts.push(c.red(`${counts.bad} to fix`));
  if (counts.info) parts.push(c.gray(`${counts.info} for information`));

  // Four counts and their separators do not fit in 80 columns. Stack them
  // rather than let the terminal fold the line wherever it happens to land.
  const summary = `  ${parts.join(c.gray(`  ${sym.vbar}  `))}`;
  if (width(summary) <= usable()) out.push(summary);
  else for (const p of parts) out.push(`  ${p}`);

  const firstFix =
    checks.find((x) => x.status === 'bad' && x.fix) ?? checks.find((x) => x.status === 'warn' && x.fix);
  if (firstFix?.fix) {
    const lead = `  ${sym.corner} start with: `;
    out.push(c.gray(lead) + c.cyan(truncate(firstFix.fix, Math.max(20, usable() - width(lead)))));
  } else if (!counts.bad && !counts.warn) {
    out.push(c.gray(`  ${sym.corner} nothing to do`));
  }

  if (wantFix && !checks.some((x) => x.fixed)) {
    // Be explicit that --fix did nothing, so nobody assumes it silently
    // rewrote their agent config. It never will.
    const note = "--fix only creates LeastGrant's own state directory; the commands above are yours to run";
    const lines = wrapText(note, BODY);
    out.push(c.gray(`  ${sym.corner} ${lines[0] ?? note}`));
    for (const line of lines.slice(1)) out.push(c.gray(gutter + line));
  }

  out.push('');
  return out.join('\n');
}

function identity(s: string): string {
  return s;
}

// ---------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------

/** A path as a human should see it: workspace-relative inside, else `~`-based. */
function show(abs: string, root = ''): string {
  return safely(() => displayPath(abs, root), abs);
}

/** ", and 4 more" — or nothing, when the list was shown in full. */
function andMore(total: number, shown: number): string {
  return total > shown ? `, and ${total - shown} more` : '';
}

function isAre(n: number): string {
  return n === 1 ? 'is' : 'are';
}

/**
 * A whole-number percent that does not lie at either end: something that
 * happened is never reported as 0%, and a share that is not everything is never
 * reported as 100%. Returns 0 for an empty set rather than dividing by it.
 */
function percent(part: number, whole: number): number {
  if (!(whole > 0)) return 0;
  const rounded = Math.round((part / whole) * 100);
  if (rounded >= 100 && part < whole) return 99;
  if (rounded <= 0 && part > 0) return 1;
  return Math.max(0, Math.min(100, rounded));
}

/** A usable timestamp: present, numeric, finite and after the epoch. */
function finite(n: unknown): n is number {
  return typeof n === 'number' && Number.isFinite(n) && n > 0;
}

/** Run something that touches the filesystem, and carry on if it cannot. */
function safely<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

function safeCwd(): string {
  try {
    return process.cwd();
  } catch {
    // The working directory was deleted out from under us. Rare, and exactly
    // the sort of morning that ends with someone running doctor.
    return safely(() => os.homedir(), '') || '.';
  }
}
