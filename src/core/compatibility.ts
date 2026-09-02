/**
 * Reading the compatibility data, and grading it.
 *
 * `compatibility/*.json` records what each agent's hook system can actually
 * enforce, and how each claim was established. This module turns that into the
 * one-line answer people actually want — "what am I getting with this agent" —
 * and it lives in core so that `leastgrant doctor` and the website reach the
 * same verdict from the same evidence. A grading rule duplicated in two places
 * would eventually let the CLI and the website disagree about the same agent,
 * which is precisely the drift the data directory exists to prevent.
 *
 * The grades are deliberately unflattering. There is no top grade that means
 * "perfect", because no agent surveyed so far deserves one: every agent except
 * Copilot fails open when the hook crashes, which means a LeastGrant that
 * cannot start enforces nothing and says nothing. A scale whose best value is
 * reachable by everyone is a marketing scale.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/** How a claim was established. Ordered weakest to strongest. */
export type Grade = 'unknown' | 'docs' | 'source' | 'probe';

export interface Fact<T = unknown> {
  value: T;
  evidence?: Grade;
  note?: string;
}

/**
 * A run that happened, recorded so a claim can point at it.
 *
 * `Grade` says how strong a piece of evidence is; this says WHAT WAS RUN, which
 * is a different question and the one that kept getting collapsed. `probe` was
 * doing three jobs at once: "we drove the real agent with our hook installed",
 * "we reproduced the agent's invocation and drove that", and "we ran the
 * product to learn how it behaves". Only the first is a live test, and reading
 * the second as one is how an untested integration gets a green badge.
 */
export interface Run {
  /** Did it happen. */
  done: boolean;
  /** What was run, in one line, specific enough to repeat. */
  what?: string;
  /** The agent version it ran against. */
  version?: string;
  /** Platforms it ran on. */
  os?: string[];
  /** When, ISO date. */
  date?: string;
  /** Why not, when `done` is false. This is the interesting field. */
  blockedBy?: string;
}

/**
 * What has actually been established about this integration, by kind.
 *
 * Deliberately four independent records rather than one level, because they are
 * not a ladder and an adapter can hold some and not others. Conformance says
 * our side is correct; it says nothing about whether the host ever calls us.
 * Contract says we read the host correctly; it says nothing about whether we
 * read it *completely*. Only `live` speaks to the whole path, and it is the one
 * that is hardest to get and easiest to imply.
 */
export interface Verification {
  /** The real agent ran, with LeastGrant installed, and enforcement was observed. */
  live: Run;
  /** The agent's real invocation was reproduced and LeastGrant driven through it. */
  transport: Run;
  /** The contract was read out of the shipped binary or official documentation. */
  contract: Run;
  /** The adapter passes the black-box conformance suite. Derived, never declared. */
  conformance: Run;
}

/**
 * A path on disk that decides what this agent is allowed to do later.
 *
 * Separate from `configPath`, which is prose for a human and names only where
 * LeastGrant installs itself. These are the files an attacker would rather have
 * than any single tool call, and there are more of them than the install path:
 * the host's own standing-grant store, its MCP wiring, the memory a later
 * session is handed as context.
 *
 * Recorded here because a list of them living only in `guards.ts` is a list
 * nobody updates when an adapter is added. `test/control-files.test.ts` walks
 * these and requires each to hit `guard.agent-config`, so adding an entry adds
 * the requirement, and adding an adapter without entries fails the docs guard.
 */
export interface ControlPath {
  /** `~`- or `<repo>`-rooted, matching how the runtime itself spells it. */
  path: string;
  /** What it decides. One clause, addressed to somebody deciding whether to care. */
  what: string;
  /** Why it is worth a person, as a category. */
  why: 'hook' | 'grant' | 'mcp' | 'instructions' | 'project' | 'settings';
}

export interface AgentCompatibility {
  id: string;
  name: string;
  /**
   * Whether an adapter ships, and if not, why not. Deliberately NOT a strength.
   *
   * It used to be, with `enforcing` and `partial` among its values, and every
   * shipped record declared a level stronger than its own evidence derived:
   * `enforcing` on Codex, which cannot ask anybody anything, and `enforcing` on
   * Antigravity, which nothing had ever run. Nobody wrote those in bad faith —
   * they were true intentions written before the data caught up, and a hand-set
   * strength field is a promise you have to remember to break.
   *
   * So the field no longer can be one. How strong an integration is comes from
   * `assess()`; what has been run to establish it comes from
   * `deriveVerification()`. This says only whether we shipped something.
   */
  supported: 'shipped' | 'evaluated-not-yet-shipped' | 'evaluated-and-deferred';
  adapter: string | null;
  configPath?: string;
  /** Everything on disk that decides what this agent may do later. See ControlPath. */
  controlPaths?: ControlPath[];
  /** What the user types to wire it up. */
  install?: string;
  /** One line on how the integration attaches — the mechanism, not the verdict. */
  mechanism?: string;
  versionTested: string;
  lastVerified: string;
  osTested: string[];
  osUntested?: string[];
  verification?: Verification;
  verdicts: Record<string, Fact<string>>;
  failure: Record<string, Fact<unknown>>;
  interception: Record<string, Fact<string>>;
  observation: Record<string, Fact<unknown>>;
  modes: Record<string, unknown>;
  upstreamLimitations: string[];
  leastgrantLimitations: string[];
  deferredBecause?: string;
}

/**
 * The public verification label, strongest first.
 *
 * Never written into a data file. `deriveVerification` computes it from the
 * runs that were recorded, so a label cannot be raised without recording the
 * run that justifies it, and recording a run without its version and OS is
 * itself an error — see `verificationProblems`.
 */
export type VerificationGrade =
  | 'LIVE VERIFIED'
  | 'REAL TRANSPORT PROBED'
  | 'CONTRACT / BINARY VERIFIED'
  | 'CONFORMANCE TESTED'
  | 'UNVERIFIED';

export const GRADE_MEANING: Record<VerificationGrade, string> = {
  'LIVE VERIFIED':
    'the real agent ran with LeastGrant installed and enforcement was observed happening',
  'REAL TRANSPORT PROBED':
    "the agent's own invocation was reproduced exactly and LeastGrant driven through it — stronger than reading the contract, and not the same as running the agent",
  'CONTRACT / BINARY VERIFIED':
    'the contract was read out of the shipped binary or official docs; nothing has exercised it',
  'CONFORMANCE TESTED':
    'the adapter passes the black-box contract every adapter must pass, which says our side is right and nothing about whether the host calls us',
  UNVERIFIED: 'no adapter ships, or nothing has been established about it',
};

/** The grade this agent's recorded evidence supports. Never declared. */
export function deriveVerification(agent: AgentCompatibility): VerificationGrade {
  const v = agent.verification;
  if (!agent.adapter) return 'UNVERIFIED';
  if (v?.live?.done) return 'LIVE VERIFIED';
  if (v?.transport?.done) return 'REAL TRANSPORT PROBED';
  if (v?.contract?.done) return 'CONTRACT / BINARY VERIFIED';
  if (v?.conformance?.done) return 'CONFORMANCE TESTED';
  return 'UNVERIFIED';
}

/**
 * Ways a record can claim more than it has established.
 *
 * Returned rather than thrown so the build can print all of them at once, and
 * so `doctor` can show the same list to a user who wants to know why an agent
 * is graded the way it is.
 */
export function verificationProblems(agent: AgentCompatibility): string[] {
  const out: string[] = [];
  const v = agent.verification;
  if (!agent.adapter) {
    if (v?.live?.done) out.push(`${agent.id}: claims a live test but ships no adapter`);
    return out;
  }
  if (!v) {
    out.push(`${agent.id}: ships an adapter with no verification record at all`);
    return out;
  }
  for (const [kind, run] of Object.entries(v) as [string, Run][]) {
    if (!run?.done) {
      // A run that did not happen must say why. "Nobody got round to it" is a
      // fine answer; silence is not, because silence reads as an oversight and
      // hides whether the thing is even possible.
      if (!run?.blockedBy) out.push(`${agent.id}: ${kind} is not done and does not say why`);
      continue;
    }
    if (!run.what) out.push(`${agent.id}: ${kind} is marked done without saying what was run`);
    if (!run.version) out.push(`${agent.id}: ${kind} is marked done with no agent version`);
    if (!run.os?.length) out.push(`${agent.id}: ${kind} is marked done with no OS`);
    if (!run.date) out.push(`${agent.id}: ${kind} is marked done with no date`);
  }

  // A live run and probe-grade facts have to corroborate each other. Somebody
  // who ran the real agent came back knowing something first-hand, so a record
  // claiming a live test while every fact in it is still marked `source` has
  // either not had the run written up or is claiming a run that did not happen.
  // Either way the grade is ahead of the evidence, which is the whole failure
  // this function exists to catch.
  if (v.live?.done) {
    const probed = Object.values({ ...agent.verdicts, ...agent.interception }).some(
      (f) => f?.evidence === 'probe',
    );
    if (!probed) {
      out.push(
        `${agent.id}: claims a live test but not one verdict or tool class is marked evidence: probe`,
      );
    }
    if (!agent.osTested?.length) {
      out.push(`${agent.id}: claims a live test but records no OS it was tested on`);
    }
  }
  return out;
}

/**
 * How much of LeastGrant survives the trip through this agent.
 *
 *   enforcing  every verdict lands, everything is intercepted, and somebody
 *              watched it happen.
 *   partial    it enforces, but there is a hole worth naming — a tool class it
 *              cannot see, or a verdict that degrades.
 *   degraded   the strongest thing it can do is refuse. An `ask` cannot reach a
 *              person here, so LeastGrant is a veto and not a prompt.
 *   unverified an adapter exists and nobody has run it against the real agent.
 *   none       no adapter ships.
 */
export type Enforcement = 'enforcing' | 'partial' | 'degraded' | 'unverified' | 'none';

export interface Assessment {
  agent: AgentCompatibility;
  level: Enforcement;
  /** Ordered, most important first. Each is a fact, not a slogan. */
  findings: { status: 'ok' | 'warn' | 'bad' | 'info'; text: string }[];
}

/**
 * Find the data directory.
 *
 * Walks up for package.json rather than assuming a depth, because this runs
 * from `dist/src/core/` in an installed package and from `src/core/` under a
 * loader, and an installed copy may sit anywhere at all.
 */
export function compatibilityDir(from = fileDir()): string {
  let dir = from;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, 'compatibility');
    if (fs.existsSync(path.join(dir, 'package.json')) && fs.existsSync(candidate)) return candidate;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return '';
}

function fileDir(): string {
  const u = new URL(import.meta.url);
  // On Windows a file URL path is `/D:/...`; strip the leading slash.
  return path.dirname(decodeURIComponent(u.pathname.replace(/^\/([A-Za-z]:)/, '$1')));
}

/**
 * Load every agent file.
 *
 * Never throws. Doctor runs on machines where something is already wrong, and
 * a diagnostic that dies because one data file is malformed is a diagnostic
 * that fails exactly when it is needed. A file that will not parse is skipped
 * and reported by its absence.
 */
export function loadCompatibility(dir = compatibilityDir()): AgentCompatibility[] {
  if (!dir || !fs.existsSync(dir)) return [];
  const out: AgentCompatibility[] = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')) as AgentCompatibility;
      if (parsed && typeof parsed.id === 'string') out.push(parsed);
    } catch {
      // Skipped on purpose. See above.
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

const val = (f: Fact<unknown> | undefined): string => String(f?.value ?? 'unknown');

/** The tool classes a user would expect to be covered, in the order they matter. */
const CLASSES: [string, string][] = [
  ['shell', 'shell commands'],
  ['fileWrite', 'file writes'],
  ['fileRead', 'file reads'],
  ['fileDelete', 'deletions'],
  ['mcp', 'MCP calls'],
];

export function assess(agent: AgentCompatibility): Assessment {
  const findings: Assessment['findings'] = [];

  if (!agent.adapter) {
    return {
      agent,
      level: 'none',
      findings: [
        {
          status: 'info',
          text:
            agent.supported === 'evaluated-and-deferred'
              ? `evaluated and deferred — ${firstSentence(agent.upstreamLimitations[0] ?? 'the hook surface is not sufficient')}`
              : 'evaluated, no adapter ships yet',
        },
      ],
    };
  }

  // 1. Can it refuse? Everything else is secondary: an agent where deny does
  //    not land is not a permission layer at all.
  const deny = val(agent.verdicts?.['deny']);
  findings.push(
    deny === 'honoured'
      ? { status: 'ok', text: 'deny is enforced, including in the most permissive mode' }
      : { status: 'bad', text: `deny is ${deny} — LeastGrant cannot refuse anything here` },
  );

  // 2. Can it ask? This is the difference between a prompt and a veto.
  const ask = val(agent.verdicts?.['ask']);
  if (ask === 'honoured') findings.push({ status: 'ok', text: 'an ask reaches a person' });
  else if (ask === 'partial') findings.push({ status: 'warn', text: `an ask reaches a person only on some channels — ${note(agent.verdicts?.['ask'])}` });
  else if (ask === 'degrades') findings.push({ status: 'warn', text: `an ask degrades — ${note(agent.verdicts?.['ask'])}` });
  else findings.push({ status: 'warn', text: 'no ask exists here, so LeastGrant is a veto rather than a prompt' });

  // 3. What happens when LeastGrant itself breaks.
  const crash = val(agent.failure?.['onCrash']);
  findings.push(
    crash === 'closed'
      ? { status: 'ok', text: 'if the hook errors, the call is refused rather than run' }
      : crash === 'open'
        ? { status: 'warn', text: 'if the hook errors or times out, the call runs anyway — a LeastGrant that cannot start enforces nothing' }
        : { status: 'warn', text: 'nobody has established what happens when the hook errors' },
  );

  // 4. Coverage gaps, named individually. A gap is the thing a support table is
  //    worst at admitting, so it gets a line each rather than a footnote.
  const gaps: string[] = [];
  const observedOnly: string[] = [];
  for (const [key, label] of CLASSES) {
    const v = val(agent.interception?.[key]);
    if (v === 'none') gaps.push(label);
    else if (v === 'observed') observedOnly.push(label);
  }
  if (gaps.length) findings.push({ status: 'bad', text: `not intercepted at all: ${gaps.join(', ')}` });
  if (observedOnly.length) {
    findings.push({
      status: 'warn',
      text: `seen only after the fact, not gated: ${observedOnly.join(', ')}`,
    });
  }

  // 5. Has anyone actually run it.
  //
  // Read off `deriveVerification` rather than re-derived from the evidence
  // marks. There were two definitions of "somebody ran this" in this file —
  // this one, and the verification record — and two definitions of one fact is
  // how a support table ends up disagreeing with the page explaining it.
  // `verificationProblems` holds them together from the other side: a record
  // claiming a live run with no probe-grade fact in it fails the build.
  const live = deriveVerification(agent) === 'LIVE VERIFIED';
  findings.push(
    live
      ? { status: 'ok', text: `verified against ${agent.name} ${agent.versionTested} on ${agent.osTested.join(', ')}` }
      : {
          status: 'warn',
          text: `never run inside a real ${agent.name} — ${
            agent.verification?.live?.blockedBy ??
            'the contract is read from what ships, the integration is untested'
          }`,
        },
  );

  for (const l of agent.upstreamLimitations.slice(0, 4)) findings.push({ status: 'info', text: l });

  // `degrades` and `unsupported` are not the same failure and must not collapse
  // into one grade. On Claude Code an ask reaches a person whenever a person is
  // there, and becomes a deny when nobody is — that is a prompt with a safe
  // fallback. On Codex there is no ask at any time, in any mode: LeastGrant can
  // only ever refuse. Calling both "degraded" would tell someone choosing
  // between them that it makes no difference, and it makes the largest
  // difference of anything in this file.
  const vetoOnly = ask === 'unsupported' || ask === 'ignored' || ask === 'unknown';

  const level: Enforcement =
    deny !== 'honoured' ? 'degraded'
    : vetoOnly ? 'degraded'
    : !live ? 'unverified'
    : gaps.length || observedOnly.length ? 'partial'
    : ask === 'honoured' && crash === 'closed' ? 'enforcing'
    : 'partial';

  return { agent, level, findings };
}

/** One line describing what a level means, for a reader who has not seen the scale. */
/**
 * The word every surface prints for an enforcement level.
 *
 * Here rather than in each renderer because the README, the website and doctor
 * all show this and two of them had drifted: the README said "Partial" while
 * the agents page said "partial", which is harmless until a test compares them
 * and someone weakens the test to make it pass.
 */
export const LEVEL_LABEL: Record<Enforcement, string> = {
  enforcing: 'Enforcing',
  partial: 'Partial',
  degraded: 'Veto only',
  // Not "Unverified". That word now belongs to the verification grade, and the
  // two axes are shown side by side — an agent reading "Unverified · REAL
  // TRANSPORT PROBED" invites the reader to decide which one is the real
  // answer. This axis says how much LeastGrant will claim; that one says what
  // was run.
  unverified: 'Unproven',
  none: 'Not yet',
};

export const LEVEL_MEANING: Record<Enforcement, string> = {
  enforcing: 'every verdict lands and every tool class is gated',
  partial: 'it enforces, with a named gap below',
  degraded: 'it can refuse, but it cannot ask a person',
  unverified:
    'an adapter ships and nothing has run it inside the real agent, so no enforcement claim is made',
  none: 'no adapter ships',
};

/**
 * The note, trimmed to one sentence and lowercased at the front.
 *
 * These are appended after an em dash mid-sentence, and a capital letter there
 * reads as the start of a new thought rather than the continuation it is. Only
 * the first character is touched, so "MCP calls" and "LeastGrant" keep their
 * capitals wherever they appear.
 */
function note(f: Fact<unknown> | undefined): string {
  const s = firstSentence(f?.note ?? 'no detail recorded');
  return /^[A-Z][a-z]/.test(s) ? s[0]!.toLowerCase() + s.slice(1) : s;
}

function firstSentence(s: string): string {
  const m = /^(.*?[.!?])(\s|$)/.exec(s.trim());
  const out = (m?.[1] ?? s).trim();
  return out.length > 160 ? out.slice(0, 157) + '…' : out;
}
