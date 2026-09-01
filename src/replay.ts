/**
 * Counterfactual replay: what would LeastGrant have done?
 *
 * This is the honesty engine. Anyone can claim their tool cuts prompts by 90%;
 * this replays your actual history and shows the number, including the times it
 * would have been wrong.
 *
 * The replay is **prequential**: events are processed in time order, and each
 * decision is made using only what was known *before* that event. It would be
 * much easier — and much more flattering — to build the model from all of
 * history and then ask it to grade the same history. That is called testing on
 * your training data, and it would turn "LeastGrant learns" into a number that
 * means nothing. So we do it the honest way, which also has the nice property
 * of showing the learning curve: the first week is noisy, the fourth is quiet.
 *
 * The metric that matters most is not the prompt reduction. It is `regrets` —
 * actions LeastGrant would have waved through that the human actually turned
 * down. A single one of those is worth more attention than any headline
 * percentage.
 */

import type { Capability, Config, Decision, Envelope, EvidenceKind, Request } from './core/types.js';
import { decide, type DecideCtx } from './core/decide.js';
import { newEnvelope, observe, newSession, applyTaint, type SessionState } from './core/envelope.js';
import { findProjectRoot, projectKey } from './core/paths.js';
import { stateDir } from './store/index.js';

export interface ReplayEvent {
  at: number;
  sessionId: string;
  cwd: string;
  tool: string;
  input: Record<string, unknown>;
  agentMode: string;
  /** True when the human turned this down at the time. */
  denied: boolean;
  /** Evidence class this event contributes once it has been decided. */
  evidence: EvidenceKind;
}

export interface ReplayOutcome {
  at: number;
  display: string;
  signature: string;
  capability: Capability;
  decision: Decision;
  reason: string;
  /** What the human actually did, where we know. */
  humanDenied: boolean;
}

export interface ReplayResult {
  total: number;
  allowed: number;
  asked: number;
  blocked: number;
  /** Actions the human turned down that we would have allowed. The number to watch. */
  regrets: ReplayOutcome[];
  /** Actions we would have blocked outright. */
  blockedItems: ReplayOutcome[];
  /** Actions we would have asked about, most notable first. */
  notable: ReplayOutcome[];
  /**
   * Prompts attributed to each reason code.
   *
   * The friction budget, itemised. A permission tool that asks about
   * everything is safe and useless, so "which rule is costing the most
   * prompts" has to be a number anyone can read off, not a thing you find out
   * by reading the source.
   */
  askReasons: Map<string, number>;
  /** Calls the classifier could not evaluate. Counted as prompts, as live. */
  crashed: number;
  /** Prompt volume over time, bucketed by day, for the learning curve. */
  timeline: { day: number; total: number; asked: number }[];
  /** How the ask rate changed from the first quarter of history to the last. */
  firstQuarterAskRate: number;
  lastQuarterAskRate: number;
  /** Envelope built during the replay; usable as a starting profile. */
  envelopes: Map<string, Envelope>;
  ms: number;
}

export interface ReplayOptions {
  config: Config;
  /** Only replay events in this project. */
  project?: string;
  /** Start from an existing set of envelopes rather than from nothing. */
  seed?: Map<string, Envelope>;
}

const DAY = 86_400_000;

export function replay(events: ReplayEvent[], opts: ReplayOptions): ReplayResult {
  const started = Date.now();
  const sorted = [...events].sort((a, b) => a.at - b.at);

  // The seed is cloned, not adopted. A replay folds every event it decides into
  // the envelope, so running one against a caller's live profile would silently
  // double its counts — which is exactly the bug that made a measurement of
  // this function's own output read half what it should have.
  const envelopes = new Map<string, Envelope>();
  for (const [key, env] of opts.seed ?? []) envelopes.set(key, structuredClone(env));
  const sessions = new Map<string, SessionState>();
  const byDay = new Map<number, { total: number; asked: number }>();
  // Per-project decision order, so the learning curve can be measured as
  // "how does LeastGrant behave as it gets to know a project" rather than
  // "what happened last Tuesday". Measured by calendar time, the curve is
  // dominated by whichever project happened to start most recently — a brand
  // new repository always asks about everything, which would make the tool look
  // like it learns nothing.
  const perProject = new Map<string, boolean[]>();

  const regrets: ReplayOutcome[] = [];
  const blockedItems: ReplayOutcome[] = [];
  const notable: ReplayOutcome[] = [];

  let allowed = 0;
  let asked = 0;
  let blocked = 0;
  let total = 0;
  let crashed = 0;
  /** How many prompts each reason code was responsible for. */
  const askReasons = new Map<string, number>();

  for (const ev of sorted) {
    if (!ev.cwd) continue;
    const root = findProjectRoot(ev.cwd);
    const key = projectKey(root);
    if (opts.project && key !== projectKey(opts.project)) continue;

    let env = envelopes.get(key);
    if (!env) {
      env = newEnvelope('project', key);
      envelopes.set(key, env);
    }

    let session = sessions.get(ev.sessionId);
    if (!session) {
      session = newSession(ev.sessionId, ev.at);
      sessions.set(ev.sessionId, session);
    }

    const req: Request = {
      agent: 'claude-code',
      tool: ev.tool,
      input: ev.input,
      cwd: ev.cwd,
      sessionId: ev.sessionId,
      agentMode: ev.agentMode,
      at: ev.at,
    };

    const ctx: DecideCtx = {
      roots: [root, ...opts.config.additionalRoots],
      secretPatterns: opts.config.secretPatterns,
      config: opts.config,
      envelope: env,
      session,
      stateDir: stateDir(),
      projectKey: key,
    };

    let verdict;
    try {
      verdict = decide(req, ctx);
    } catch {
      // A classifier crash must not abort a whole replay — but it must not
      // vanish from the count either. The live hook asks when it cannot
      // evaluate a call, so the simulation counts the same thing, and a
      // measured ask rate stays a measurement of what would really happen.
      total++;
      asked++;
      crashed++;
      const day = Math.floor(ev.at / DAY);
      const b = byDay.get(day) ?? { total: 0, asked: 0 };
      b.total++;
      b.asked++;
      byDay.set(day, b);
      continue;
    }

    total++;
    const day = Math.floor(ev.at / DAY);
    const bucket = byDay.get(day) ?? { total: 0, asked: 0 };
    bucket.total++;

    const outcome: ReplayOutcome = {
      at: ev.at,
      display: verdict.action.display,
      signature: verdict.action.signature,
      capability: verdict.action.capability,
      decision: verdict.decision,
      reason: verdict.headline,
      humanDenied: ev.denied,
    };

    if (verdict.decision === 'allow') {
      allowed++;
      // The one that counts: we would have let it through, and the human said no.
      if (ev.denied) regrets.push(outcome);
    } else if (verdict.decision === 'deny') {
      blocked++;
      bucket.asked++;
      blockedItems.push(outcome);
    } else {
      asked++;
      bucket.asked++;
      notable.push(outcome);
    }
    if (verdict.decision !== 'allow') {
      for (const r of verdict.reasons) askReasons.set(r.code, (askReasons.get(r.code) ?? 0) + 1);
    }
    byDay.set(day, bucket);
    const seq = perProject.get(key) ?? [];
    seq.push(verdict.decision !== 'allow');
    perProject.set(key, seq);

    // Learn from the event only after deciding on it.
    //
    // Denials need care. The human refused a *command*, not each of its parts.
    // `cd build && rm -rf /` is one refusal, and attributing it to `cd` would
    // blacklist `cd` forever — denials never decay, so a handful of refused
    // compound commands can poison the most ordinary verbs on the machine.
    // Attribute the refusal to the action that presumably caused it (the worst
    // one), and record nothing for the rest: they did not run, so they are not
    // observations either.
    const learnFrom = ev.denied ? [verdict.action] : verdict.actions;
    for (const action of learnFrom) {
      observe(
        env,
        {
          signature: action.signature,
          capability: action.capability,
          blast: action.blast,
          evidence: ev.evidence,
          at: ev.at,
          sessionId: ev.sessionId,
          display: action.display,
          ...(session.lastCapability ? { previousCapability: session.lastCapability } : {}),
        },
        opts.config.thresholds,
      );
      applyTaint(session, action.capability);
    }
  }

  const timeline = [...byDay.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([day, v]) => ({ day, total: v.total, asked: v.asked }));

  // Rank the things it would have asked about by how unusual they are, so the
  // sample shown to the user is the interesting tail rather than the first
  // forty `cd` calls.
  notable.sort((a, b) => rank(b) - rank(a));

  return {
    total,
    allowed,
    asked,
    blocked,
    regrets,
    blockedItems,
    notable,
    timeline,
    askReasons,
    crashed,
    firstQuarterAskRate: learningCurve(perProject, 'first'),
    lastQuarterAskRate: learningCurve(perProject, 'last'),
    envelopes,
    ms: Date.now() - started,
  };
}

const INTERESTING: Partial<Record<Capability, number>> = {
  'secret.read': 100,
  'net.send': 90,
  'exec.remote': 85,
  'exec.pkg.publish': 80,
  'exec.iac': 75,
  'exec.cloud': 70,
  'exec.vcs.publish': 65,
  'fs.write.outside': 60,
  'fs.delete': 55,
  'exec.privilege': 50,
  'exec.db': 45,
  'exec.container': 30,
  'exec.unknown': 20,
};

function rank(o: ReplayOutcome): number {
  return INTERESTING[o.capability] ?? 0;
}

/**
 * Ask rate over the first (or last) quarter of each project's history,
 * aggregated across projects that have enough events to say anything.
 *
 * Projects with fewer than 40 decisions are skipped: a repository someone
 * touched once cannot demonstrate a trend, and including it just adds noise in
 * whichever direction it happened to fall.
 */
function learningCurve(perProject: Map<string, boolean[]>, which: 'first' | 'last'): number {
  let asked = 0;
  let total = 0;
  for (const seq of perProject.values()) {
    if (seq.length < 40) continue;
    const n = Math.floor(seq.length / 4);
    const slice = which === 'first' ? seq.slice(0, n) : seq.slice(-n);
    for (const a of slice) {
      total++;
      if (a) asked++;
    }
  }
  return total ? asked / total : 0;
}
