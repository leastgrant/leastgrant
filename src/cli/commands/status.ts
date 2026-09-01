/**
 * `leastgrant status`
 *
 * What LeastGrant knows about this project.
 *
 * This is the command someone runs when they want to know whether the thing is
 * actually doing anything, so it has to be specific rather than reassuring.
 * Two numbers carry the whole answer: how many distinct kinds of action now run
 * without asking, and — the honest one — what share of the work that actually
 * covers. A tool can stop asking about 90% of the kinds of thing you do and
 * still interrupt you every other minute, because the interruptions are the
 * things you do most.
 *
 * The `still asking` table is the point of the command. Anyone can print what
 * has been learned; the useful part is telling you, before it happens, exactly
 * what will stop you and what would change that.
 *
 * Two rules this file must keep:
 *
 *  - Never claim something runs unattended when the engine would still stop it.
 *    Under-claiming is a mild annoyance; over-claiming is a broken promise.
 *  - Every count and percentage names its own denominator. "68%" of what is the
 *    only part of "68%" that carries information.
 */

import * as path from 'node:path';
import type {
  BlastRadius,
  Config,
  Envelope,
  Familiarity,
  SignatureStat,
  Thresholds,
} from '../../core/types.js';
import { blastTier } from '../../core/types.js';
import {
  canPromote,
  familiarity,
  CONFIDENCE_BY_TIER,
  approvalsNeededFor,
  type PromotionResult,
} from '../../core/envelope.js';
import { friendly, matchRule } from '../../core/decide.js';
import { listEnvelopes, loadConfig } from '../../store/index.js';
import { loadContext } from '../context.js';
import { ago, bar, c, heading, pad, para, plural, sym, table, term, truncate, width } from '../ui.js';
import type { Argv } from '../index.js';

const DAY_MS = 86_400_000;

/** Every block on the page is indented by this much, and every width budget knows it. */
const INDENT = 2;

export function statusCommand(argv: Argv): number {
  const json = flag(argv, 'json');
  if (flag(argv, 'all')) return allProjects(json);

  const ctx = loadContext();
  const now = Date.now();
  const name = path.basename(ctx.root) || ctx.root || 'this project';
  const view = assess(ctx.envelope, ctx.config, ctx.key, now);
  const events = count(ctx.envelope.events);

  if (json) {
    return emit({
      project: name,
      root: ctx.root,
      key: ctx.key,
      posture: ctx.config.posture,
      /**
       * True when the posture means these verdicts are a preview rather than
       * what will happen: in `observe` LeastGrant stays silent and the agent's
       * own permission flow decides.
       */
      advisory: view.advisory,
      events,
      firstSeen: view.firstSeen || null,
      lastSeen: view.lastSeen || null,
      /** Calendar span between the first and last thing seen, not active days. */
      days: view.days,
      sessions: view.sessions,
      signatures: {
        total: view.rows.length,
        autoApproved: view.auto.length,
        stillAsking: view.asking.length,
      },
      coverage: {
        occurrences: view.seenTotal,
        occurrencesAutoApproved: view.seenAuto,
        /** Fraction in 0..1 of occurrences, not of distinct signatures. */
        share: view.seenTotal > 0 ? view.seenAuto / view.seenTotal : 0,
      },
      autoApproved: view.auto.map((r) => ({
        signature: r.stat.signature,
        capability: r.stat.capability,
        totalSeen: r.stat.totalSeen,
        lastSeen: r.stat.lastSeen || null,
        byRule: r.ruled === 'allow',
      })),
      stillAsking: view.asking.map((r) => ({
        signature: r.stat.signature,
        capability: r.stat.capability,
        totalSeen: r.stat.totalSeen,
        lastSeen: r.stat.lastSeen || null,
        reason: askReason(r),
        approvalsShort: approvalsShort(r, ctx.config.thresholds),
        quietRunsShort: quietRunsShort(r, ctx.config.thresholds),
        sessionsShort: sessionsShort(r, ctx.config.thresholds),
      })),
      capabilities: capabilityRows(ctx.envelope).map(([id, n]) => ({
        capability: id,
        label: friendly(id),
        count: n,
      })),
      denied: view.denied.map((r) => ({
        signature: r.stat.signature,
        denied: Math.round(r.stat.denied),
      })),
    });
  }

  // No signatures means nothing to report, whatever the event counter claims —
  // saying "0 of 0 kinds of action" would be technically true and useless.
  if (!view.rows.length) {
    process.stdout.write(emptyProject(name, ctx.root, ctx.config.posture));
    return 0;
  }

  // A hand-edited envelope can lose its event counter while keeping the
  // per-signature totals. Those add up to the same thing, so prefer whichever
  // is larger rather than reporting a project as having watched nothing.
  const watched = Math.max(events, view.seenTotal);

  const out: string[] = [''];

  // --- header --------------------------------------------------------------
  out.push(titleLine(name, ctx.root));
  out.push('');
  out.push(field('posture', `${c.cyan(ctx.config.posture)} ${c.gray(`${sym.dash} ${describePosture(ctx.config.posture)}`)}`));
  const span = spanPhrase(view);
  out.push(field('watched', plural(watched, 'action') + (span ? ` ${c.gray(span)}` : '')));
  out.push(field('last one', c.gray(view.lastSeen ? ago(view.lastSeen, now) : 'not recorded')));

  // --- the headline number -------------------------------------------------
  out.push('');
  if (view.auto.length) {
    const verb = view.advisory ? 'would run without asking' : 'run without asking';
    out.push(`${sp()}${c.bold(`${fmt(view.auto.length)} of ${fmt(view.rows.length)} kinds of action ${verb}`)}`);
    // The two numbers above count distinct kinds; this one counts occurrences,
    // which is the number you actually feel. Say which is which.
    if (view.seenTotal > 0) {
      const cells = clamp(term.cols - 46, 10, 30);
      out.push(
        `${sp()}${bar(view.seenAuto, view.seenTotal, cells, c.green)}  ` +
          c.gray(`${percent(view.seenAuto, view.seenTotal)} of ${plural(view.seenTotal, 'action')} on record`),
      );
    }
  } else {
    out.push(`${sp()}${c.bold('nothing runs without asking yet')}`);
    // In strict mode this is not a matter of waiting — approvals never promote
    // anything — so the note below says the true thing instead.
    if (ctx.config.posture !== 'strict') {
      out.push(
        para(
          c.gray('LeastGrant waits for a few approvals, on separate days, before it stops asking about something.'),
          INDENT,
        ),
      );
    }
  }

  // Strict and observe both make the numbers above advisory rather than live,
  // which is exactly the sort of thing a status screen must not let you assume.
  const held = view.rows.filter((r) => r.strictHold).length;
  if (ctx.config.posture === 'strict') {
    out.push('');
    out.push(
      note(
        'strict mode: only the rules you wrote run without asking' +
          (held ? `, though ${kinds(held)} have already learned enough to qualify` : ''),
      ),
    );
  } else if (ctx.config.posture === 'observe') {
    out.push('');
    out.push(
      note(
        'observe mode: LeastGrant is watching and learning but never answers a prompt, so this is a preview of what it would do, not what happens today',
      ),
    );
  }

  // --- running without asking ----------------------------------------------
  if (view.auto.length) {
    const top = view.auto.slice(0, 12);
    const max = Math.max(1, top[0]?.stat.totalSeen ?? 0);
    const barCells = 16;
    out.push(heading(`${sp()}${view.advisory ? 'would run without asking' : 'running without asking'}`));
    out.push(
      block(
        table(
          [
            { header: 'what', width: fit([7, barCells], 20, 64) },
            { header: 'seen', width: 7, align: 'right' },
            { header: '', width: barCells },
          ],
          top.map((r) => [
            r.ruled === 'allow' ? `${r.stat.signature} ${c.gray('(your rule)')}` : r.stat.signature,
            fmt(r.stat.totalSeen),
            bar(r.stat.totalSeen, max, barCells, c.green),
          ]),
        ),
      ),
    );
    if (view.auto.length > top.length) {
      out.push(`${sp()}${c.gray(`…and ${fmt(view.auto.length - top.length)} more`)}`);
    }
  }

  // --- still asking --------------------------------------------------------
  if (view.asking.length) {
    const top = view.asking.slice(0, 8);
    const w = askWidths();
    out.push(heading(`${sp()}still asking`));
    out.push(
      block(
        table(
          [
            { header: 'what', width: w.sig },
            { header: 'seen', width: 7, align: 'right' },
            { header: 'why', width: w.why },
          ],
          top.map((r) => [r.stat.signature, fmt(r.stat.totalSeen), c.gray(whyItAsks(r, ctx.config.thresholds))]),
        ),
      ),
    );
    if (view.asking.length > top.length) {
      out.push(`${sp()}${c.gray(`…and ${fmt(view.asking.length - top.length)} more`)}`);
    }
    out.push('');
    out.push(note(`to stop being asked: leastgrant allow "${allowExample(top[0])}"`));
  }

  // --- what your agents do here --------------------------------------------
  const caps = capabilityRows(ctx.envelope).slice(0, 8);
  if (caps.length) {
    const max = Math.max(1, caps[0]?.[1] ?? 0);
    const barCells = 16;
    out.push(heading(`${sp()}what your agents do here`));
    out.push(
      block(
        table(
          [
            { header: 'kind', width: fit([7, barCells], 16, 36) },
            { header: 'times', width: 7, align: 'right' },
            { header: '', width: barCells },
          ],
          caps.map(([id, n]) => [friendly(id), fmt(n), bar(n, max, barCells)]),
        ),
      ),
    );
  }

  // --- refusals ------------------------------------------------------------
  const denied = view.denied.slice(0, 6);
  if (denied.length) {
    out.push(heading(`${sp()}you have turned these down`));
    out.push(
      block(
        table(
          [
            { header: 'what', width: fit([12], 20, 46) },
            { header: 'turned down', width: 12, align: 'right' },
          ],
          denied.map((r) => [
            `${c.red(sym.deny)} ${r.stat.signature}`,
            plural(Math.round(r.stat.denied), 'time'),
          ]),
        ),
      ),
    );
    out.push('');
    out.push(note('a no sticks — these keep asking until you allow them by hand'));
  }

  out.push('');
  process.stdout.write(out.join('\n'));
  return 0;
}

// ---------------------------------------------------------------------------
// --all: one row per project
// ---------------------------------------------------------------------------

function allProjects(json: boolean): number {
  const config = loadConfig();
  const now = Date.now();
  const envelopes = listEnvelopes()
    .map(normalizeEnvelope)
    // No key means the file did not survive parsing as an envelope. There is
    // nothing to name it and nowhere to send you, so listing it is just noise.
    .filter((e) => e.scope !== 'global' && Boolean(e.key))
    .map((env) => ({ env, view: assess(env, config, env.key, now) }))
    .sort((a, b) => b.view.lastSeen - a.view.lastSeen);

  if (json) {
    return emit({
      posture: config.posture,
      advisory: config.posture === 'observe',
      projects: envelopes.map(({ env, view }) => ({
        project: projectName(env.key),
        key: env.key,
        events: env.events,
        signatures: view.rows.length,
        autoApproved: view.auto.length,
        lastSeen: view.lastSeen || null,
      })),
    });
  }

  if (!envelopes.length) {
    process.stdout.write(
      '\n' +
        para(c.bold('LeastGrant has not learned anything anywhere yet.'), INDENT) +
        '\n\n' +
        para(c.gray('go into a project you work in and run:'), INDENT) +
        '\n\n' +
        `${sp(4)}${c.cyan('leastgrant init')}\n\n`,
    );
    return 0;
  }

  const totalEvents = envelopes.reduce((n, x) => n + x.env.events, 0);
  const out: string[] = [''];
  out.push(`${sp()}${c.bold(plural(envelopes.length, 'project'))}  ${c.gray(`${plural(totalEvents, 'action')} watched in total`)}`);
  out.push(
    block(
      table(
        [
          { header: 'project', width: fit([9, 14, 13], 12, 40) },
          { header: 'actions', width: 9, align: 'right' },
          { header: 'no longer asks', width: 14, align: 'right' },
          { header: 'last activity', width: 13 },
        ],
        envelopes.map(({ env, view }) => [
          projectName(env.key),
          fmt(env.events),
          view.auto.length ? c.green(fmt(view.auto.length)) : c.gray('0'),
          c.gray(view.lastSeen ? ago(view.lastSeen, now) : 'never'),
        ]),
      ),
      true,
    ),
  );
  out.push('');
  out.push(note('for the detail on one of them, run leastgrant status inside it'));
  out.push('');
  process.stdout.write(out.join('\n'));
  return 0;
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

interface SigView {
  stat: SignatureStat;
  /** Evidence decayed to *now*, which is what the engine would use. */
  fam: Familiarity;
  promo: PromotionResult;
  /** Set when an explicit rule, not learning, settles the answer. */
  ruled?: 'allow' | 'deny';
  /** Learned enough, but strict posture is holding it back. */
  strictHold?: boolean;
  /** The stored record was incomplete, so we could not read what this does. */
  malformed?: boolean;
}

interface EnvelopeView {
  rows: SigView[];
  auto: SigView[];
  asking: SigView[];
  denied: SigView[];
  /** Occurrence-weighted totals: the numbers that reflect lived experience. */
  seenTotal: number;
  seenAuto: number;
  firstSeen: number;
  lastSeen: number;
  /** Calendar span, in days, between the first and last thing seen. */
  days: number;
  sessions: number;
  /** True when the posture means these verdicts are a preview, not a promise. */
  advisory: boolean;
}

/**
 * Re-derive, for every signature, the answer the engine would give today.
 *
 * Evidence decays, so this is computed against the current clock rather than
 * read off the stored counts — otherwise status would promise auto-approval
 * for something that has gone quiet for six months and quietly demoted itself.
 *
 * Two things this cannot see, both of which make it under-claim rather than
 * over-claim: the guards in `decide.ts` run against a parsed action, not a
 * stored signature, so a signature that always trips `guard.not-understood`
 * will be listed here as auto-approved when it is not; and autopilot's
 * concession for unreadable in-project code likewise needs the parsed action.
 * Under-claiming is the safe direction, so neither is faked.
 */
function assess(env: Envelope, config: Config, key: string, now: number): EnvelopeView {
  const th = config.thresholds;
  const rows: SigView[] = [];
  let firstSeen = 0;
  let lastSeen = 0;
  let sessions = 0;

  for (const raw of Object.values(env.signatures ?? {})) {
    const { stat, malformed } = normalizeStat(raw);
    if (!stat) continue;

    const fam = familiarity(
      env,
      { signature: stat.signature, capability: stat.capability, blast: stat.worstBlast, at: now },
      th,
    );
    const promo = canPromote(sanitizeFam(fam), stat.worstBlast, th);
    const rule = matchRule(config.rules, stat.signature, key, now);
    const view: SigView = { stat, fam: sanitizeFam(fam), promo };
    if (malformed) view.malformed = true;
    if (rule?.effect === 'allow') view.ruled = 'allow';
    if (rule?.effect === 'deny') view.ruled = 'deny';
    if (!view.ruled && promo.eligible && config.posture === 'strict') view.strictHold = true;
    rows.push(view);

    if (stat.firstSeen && (!firstSeen || stat.firstSeen < firstSeen)) firstSeen = stat.firstSeen;
    if (stat.lastSeen > lastSeen) lastSeen = stat.lastSeen;
    if (stat.sessions > sessions) sessions = stat.sessions;
  }

  // Strict posture suspends learned promotion entirely, so status must not
  // claim things run unattended when the engine would still stop them. Observe
  // suspends every verdict, but there the split is still worth showing as a
  // preview — the caller labels it as one.
  const strict = config.posture === 'strict';
  const isAuto = (r: SigView) => {
    if (r.ruled === 'allow') return true;
    if (r.ruled === 'deny' || r.malformed || strict) return false;
    if (r.promo.eligible) return true;
    // Autopilot's second concession, mirrored from `decideOne`: observation
    // alone may promote recoverable work that stays inside the project. Reach
    // stands in for `containedInProject`, which needs the parsed action.
    return (
      config.posture === 'autopilot' &&
      r.promo.reason === 'observed-only' &&
      (r.stat.worstBlast.reach === 'workspace' || r.stat.worstBlast.reach === 'none') &&
      (r.stat.worstBlast.reversibility === 'trivial' || r.stat.worstBlast.reversibility === 'easy') &&
      r.fam.observed >= th.minObserved &&
      r.fam.sessions >= th.minSessions
    );
  };

  const bySeen = (a: SigView, b: SigView) => b.stat.totalSeen - a.stat.totalSeen;
  const auto = rows.filter(isAuto).sort(bySeen);
  const asking = rows.filter((r) => !isAuto(r)).sort(bySeen);

  return {
    rows,
    auto,
    asking,
    denied: rows.filter((r) => r.stat.denied > 0).sort((a, b) => b.stat.denied - a.stat.denied),
    seenTotal: rows.reduce((n, r) => n + r.stat.totalSeen, 0),
    seenAuto: auto.reduce((n, r) => n + r.stat.totalSeen, 0),
    firstSeen,
    lastSeen,
    days: firstSeen && lastSeen ? Math.max(1, Math.ceil((lastSeen - firstSeen) / DAY_MS)) : 0,
    sessions,
    advisory: config.posture === 'observe',
  };
}

// --- the gaps, all measured against the same evidence the engine uses -------

/**
 * The observation-only route, mirrored from `canPromote`.
 *
 * Stated in terms of consequences rather than a tier number, because that is
 * the version a reader can check against the engine. An earlier version of this
 * compared `blastTier` against `observedMaxTier`, which is a different and
 * stricter test — it said "approve this five more times" for ordinary workspace
 * reads that were in fact three quiet runs away from never asking again.
 */
function quietRunsPossible(b: BlastRadius): boolean {
  return (
    (b.reach === 'workspace' || b.reach === 'none') &&
    b.reversibility === 'trivial' &&
    b.exposure === 'none' &&
    b.scale !== 'sweeping'
  );
}

/** Is the gap one that more evidence could ever close? */
function evidenceGap(r: SigView): boolean {
  return !r.ruled && !r.malformed && (r.promo.reason === 'not-enough-evidence' || r.promo.reason === 'observed-only');
}

/** How many more human approvals stand between this and silence, if that is the gap. */
function approvalsShort(r: SigView, th: Thresholds): number | undefined {
  if (!evidenceGap(r)) return undefined;
  if (r.promo.approvalsShort !== undefined) return r.promo.approvalsShort;
  const required = CONFIDENCE_BY_TIER[blastTier(r.stat.worstBlast)] ?? th.minApproval;
  const needed = approvalsNeededFor(required);
  // A threshold of 1.0 asks for certainty, which no finite number of approvals
  // buys. Saying "approve it Infinity more times" would be worse than silence.
  if (!Number.isFinite(needed)) return undefined;
  return Math.max(1, needed - Math.floor(r.fam.confirmed));
}

/**
 * Progress along the unattended-run route, for the things that qualify for it.
 *
 * Both halves come off one rounded number so that "5 of 8" and "3 to go" can
 * never disagree — decayed evidence is fractional, and rounding it twice is how
 * a status screen ends up printing a sum that does not add up.
 */
function quietRuns(r: SigView, th: Thresholds): { seen: number; short: number } | undefined {
  if (!evidenceGap(r) || !quietRunsPossible(r.stat.worstBlast)) return undefined;
  const seen = Math.min(th.minObserved, Math.round(r.fam.observed + r.fam.confirmed));
  return { seen, short: Math.max(0, th.minObserved - seen) };
}

function quietRunsShort(r: SigView, th: Thresholds): number | undefined {
  return quietRuns(r, th)?.short;
}

/**
 * How many more distinct sessions are needed — but only where sessions are
 * actually the thing standing in the way. Reporting "1 more session" for an
 * action that can reach credentials would imply a session would unlock it.
 */
function sessionsShort(r: SigView, th: Thresholds): number | undefined {
  const unlockable =
    evidenceGap(r) || r.promo.reason === 'needs-more-days' || r.promo.reason === 'needs-more-sessions';
  if (!unlockable || r.promo.eligible) return undefined;
  return Math.max(0, th.minSessions - r.fam.sessions);
}

function askReason(r: SigView): string {
  if (r.ruled === 'deny') return 'rule-deny';
  if (r.strictHold) return 'strict-mode';
  if (r.malformed) return 'unreadable-record';
  return r.promo.reason;
}

/**
 * The most valuable sentence in the command: not "denied", but what to expect
 * and what would change it.
 *
 * These are written short on purpose. This is the narrowest column on the page
 * and it is also the one worth reading, so a sentence that only fits on a wide
 * terminal is a sentence nobody reads.
 */
function whyItAsks(r: SigView, th: Thresholds): string {
  if (r.ruled === 'deny') return 'your rule blocks this';
  if (r.strictHold) return 'learned, but strict mode holds it';
  if (r.malformed) return 'the stored record is incomplete';

  switch (r.promo.reason) {
    case 'blast-too-high': {
      // Name the dimension that put it over the line. "too risky" teaches
      // nothing; "reaches credentials" tells you why it will never change.
      const b = r.stat.worstBlast;
      if (b.exposure !== 'none') return 'reaches credentials — always asks';
      if (b.reversibility === 'irreversible') return 'cannot be undone — always asks';
      if (b.reach === 'production') return 'touches production — always asks';
      if (b.reach === 'external') return 'changes things off this machine';
      if (b.reversibility === 'hard') return 'hard to undo — always asks';
      if (b.scale === 'sweeping') return 'touches too much at once';
      return 'reaches too far — always asks';
    }
    case 'previously-denied':
      return 'you turned this down before';
    case 'needs-more-days':
      return `seen on ${plural(r.fam.days, 'day')}, needs ${th.minDays}`;
    case 'needs-more-sessions':
      return `seen in ${plural(r.fam.sessions, 'session')}, needs ${th.minSessions}`;
    case 'observed-only':
    case 'not-enough-evidence': {
      // Two clocks can be ticking, and which one matters depends on the action:
      // quiet runs only ever graduate contained, reversible work. Name the gate
      // that is still shut, and count against the same rounded number that is
      // printed, so "5 so far, 4 to go" can never add up to something other
      // than the target.
      const moreSessions = sessionsShort(r, th) ?? 0;
      const runs = quietRuns(r, th);
      const alsoSessions = moreSessions > 0 ? `, in ${plural(th.minSessions, 'session')}` : '';
      if (runs) {
        if (runs.short > 0) return `${runs.seen} of ${th.minObserved} quiet runs${alsoSessions}`;
        if (moreSessions > 0) return `run often enough${alsoSessions}`;
      }
      const approvals = approvalsShort(r, th);
      // A threshold of 1.0 asks for certainty; no finite number of approvals
      // buys that, and saying "approve it Infinity times" would be worse.
      if (approvals === undefined) return 'no number of approvals meets your threshold';
      return `approve it ${plural(approvals, 'more time')}, over ${plural(th.minDays, 'day')}`;
    }
    default:
      return 'still learning';
  }
}

function capabilityRows(env: Envelope): [string, number][] {
  return Object.entries(env.capabilities ?? {})
    .map(([id, n]) => [id, count(n)] as [string, number])
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
}

// ---------------------------------------------------------------------------
// Defensive reading
//
// Envelopes are plain JSON that a person is invited to read, and therefore to
// edit and to truncate. Nothing in here may throw on a file that is merely
// wrong, and nothing may treat "the file did not say" as "harmless".
// ---------------------------------------------------------------------------

const REACHES = new Set(['none', 'workspace', 'machine', 'network', 'external', 'production']);
const REVERSIBILITIES = new Set(['trivial', 'easy', 'hard', 'irreversible']);
const EXPOSURES = new Set(['none', 'reads-secrets', 'can-exfiltrate']);
const SCALES = new Set(['single', 'many', 'sweeping']);

/** A blast radius we could not read is treated as the worst case, never the best. */
const UNKNOWN_BLAST: BlastRadius = {
  reach: 'production',
  reversibility: 'irreversible',
  exposure: 'can-exfiltrate',
  scale: 'sweeping',
};

function normalizeBlast(b: unknown): { blast: BlastRadius; ok: boolean } {
  const raw = b as Partial<BlastRadius> | undefined;
  if (
    raw &&
    REACHES.has(String(raw.reach)) &&
    REVERSIBILITIES.has(String(raw.reversibility)) &&
    EXPOSURES.has(String(raw.exposure)) &&
    SCALES.has(String(raw.scale))
  ) {
    return { blast: raw as BlastRadius, ok: true };
  }
  return { blast: UNKNOWN_BLAST, ok: false };
}

function normalizeStat(raw: SignatureStat | undefined): { stat?: SignatureStat; malformed: boolean } {
  if (!raw || typeof raw !== 'object' || typeof raw.signature !== 'string' || !raw.signature) {
    return { malformed: true };
  }
  const { blast, ok } = normalizeBlast(raw.worstBlast);
  return {
    stat: {
      ...raw,
      capability: raw.capability ?? 'exec.unknown',
      confirmed: count(raw.confirmed),
      denied: count(raw.denied),
      observed: count(raw.observed),
      totalSeen: count(raw.totalSeen),
      firstSeen: count(raw.firstSeen),
      lastSeen: count(raw.lastSeen),
      sessions: count(raw.sessions),
      days: count(raw.days),
      worstBlast: blast,
      samples: Array.isArray(raw.samples) ? raw.samples : [],
    },
    malformed: !ok,
  };
}

/** `familiarity` reads the raw stored stat, so its output needs the same care. */
function sanitizeFam(f: Familiarity): Familiarity {
  return {
    ...f,
    confirmed: count(f.confirmed),
    denied: count(f.denied),
    observed: count(f.observed),
    sessions: count(f.sessions),
    days: count(f.days),
    approvalLowerBound: count(f.approvalLowerBound),
  };
}

/** `listEnvelopes` hands back whatever parsed, including `null` and half a file. */
function normalizeEnvelope(e: Envelope | null | undefined): Envelope {
  const raw = (e ?? {}) as Partial<Envelope>;
  return {
    scope: raw.scope ?? 'project',
    key: typeof raw.key === 'string' ? raw.key : '',
    updatedAt: count(raw.updatedAt),
    signatures: raw.signatures ?? {},
    transitions: raw.transitions ?? {},
    capabilities: raw.capabilities ?? {},
    events: count(raw.events),
  };
}

/** Any non-finite number on the way in becomes zero, so no NaN reaches the page. */
function count(n: unknown): number {
  return typeof n === 'number' && Number.isFinite(n) ? n : 0;
}

function projectName(key: string): string {
  if (!key) return 'unnamed project';
  try {
    return path.basename(key) || key;
  } catch {
    return key;
  }
}

// ---------------------------------------------------------------------------
// Rendering odds and ends
// ---------------------------------------------------------------------------

const POSTURE: Record<string, string> = {
  observe: 'watching quietly, deciding nothing, learning the whole time',
  assist: 'lets the routine through, stops to ask about the rest',
  autopilot: 'runs everything it safely can, keeps the hard floors',
  strict: 'only the things you allowed by hand run without asking',
};

function describePosture(posture: string): string {
  return POSTURE[posture] ?? 'deciding as configured';
}

/** The warm version of nothing: a new project has no data and needs a nudge. */
function emptyProject(name: string, root: string, posture: string): string {
  return (
    '\n' +
    `${sp()}${c.bold(truncate(name, 30))}  ${c.gray(truncate(root, term.cols - 36))}\n` +
    '\n' +
    para(c.bold('nothing learned here yet.'), INDENT) +
    '\n\n' +
    para(
      c.gray(
        `LeastGrant is set to ${posture}, but it has not watched anything happen in this project, so it has no opinions to show you. The quickest way to start is to let it read the agent history you already have:`,
      ),
      INDENT,
    ) +
    '\n\n' +
    `${sp(4)}${c.cyan('leastgrant init')}\n` +
    '\n' +
    para(c.gray('or see how it thinks, without running anything:'), INDENT) +
    '\n\n' +
    `${sp(4)}${c.cyan('leastgrant check "git push --force"')}\n` +
    '\n'
  );
}

const sp = (n = INDENT) => ' '.repeat(n);

const GUTTER = INDENT + 9 + 2;

/**
 * A labelled line, wrapped with a hanging indent so the value stays in its own
 * column on a narrow terminal instead of running off the end of it. `pad`
 * measures visible width, so a styled label still lines up.
 */
function field(label: string, value: string): string {
  // `para` indents every line by `GUTTER`; strip that off the first one so the
  // value starts beside its label, and the rest stay in the column.
  const wrapped = para(value, GUTTER, term.cols - 1).slice(GUTTER);
  return `${sp()}${c.gray(pad(label, 9))}  ${wrapped}`;
}

/** Project name and path, trimmed to one line rather than wrapped mid-path. */
function titleLine(name: string, root: string): string {
  const shown = truncate(name, Math.max(12, term.cols - 24));
  const room = term.cols - INDENT - width(shown) - 2 - 1;
  const tail = room >= 12 ? `  ${c.gray(truncate(root, room))}` : '';
  return `${sp()}${c.bold(shown)}${tail}`;
}

/** A trailing aside, wrapped, marked with the corner glyph. */
function note(text: string): string {
  return para(c.gray(`${sym.corner} ${text}`), INDENT);
}

/** Indent a rendered block; the header row is dimmed by `table` already. */
function block(rendered: string, leadingBlank = false): string {
  const body = rendered
    .split('\n')
    .map((l) => sp() + l)
    .join('\n');
  return leadingBlank ? '\n' + body : body;
}

/**
 * Width for the one flexible column in an indented table.
 *
 * `table` shrinks columns on its own, but it measures against the full terminal
 * and cannot know the block gets indented afterwards, so the sums are done here
 * and it is handed widths that already fit. One column of slack is left at the
 * right so an exactly-full line never wraps into a stray blank one.
 */
function fit(fixed: number[], min: number, max: number): number {
  const gaps = fixed.length * 2; // two spaces between each pair of columns
  const spare = term.cols - INDENT - 1 - fixed.reduce((a, b) => a + b, 0) - gaps;
  return clamp(spare, min, max);
}

/** The widest `why` we ever produce; anything past this is wasted column. */
const WHY_MAX = 44;

/**
 * Split the `still asking` row between what and why.
 *
 * The reason column is the reason the table exists, so it is served first and
 * the signature gets what is left, rather than the other way round. Signatures
 * are recoverable from `leastgrant why`; a truncated reason is just noise.
 */
function askWidths(): { sig: number; why: number } {
  const spare = term.cols - INDENT - 1 - 7 - 4; // seen column, two gaps, slack
  const sig = clamp(spare - WHY_MAX, 20, 44);
  return { sig, why: Math.max(20, spare - sig) };
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

/**
 * A percentage that never rounds away the thing it describes.
 *
 * A status screen that reads 100% while something still interrupts you is
 * lying, and so is one that reads 0% for a signature that fired this morning.
 */
function percent(part: number, total: number): string {
  if (total <= 0) return '0%';
  if (part >= total) return '100%';
  const raw = (part / total) * 100;
  if (raw <= 0) return '0%';
  if (raw < 1) return '<1%';
  return `${clamp(Math.round(raw), 1, 99)}%`;
}

/** "3 kinds of action", without `plural` pluralising the wrong word. */
function kinds(n: number): string {
  return `${plural(n, 'kind')} of action`;
}

function spanPhrase(view: EnvelopeView): string {
  const parts: string[] = [];
  if (view.days) parts.push(`over ${plural(view.days, 'day')}`);
  if (view.sessions) parts.push(`in at least ${plural(view.sessions, 'session')}`);
  return parts.join(', ');
}

/**
 * A copy-pasteable example, or a placeholder when the real signature will not
 * fit. Truncating it with an ellipsis would produce something that looks
 * pasteable and silently is not, which is worse than a placeholder.
 */
function allowExample(r: SigView | undefined): string {
  const sig = (r?.stat.signature ?? '').replace(/\s+/g, ' ').trim();
  const room = term.cols - INDENT - width('╰ to stop being asked: leastgrant allow ""');
  if (!sig || sig.includes('"') || width(sig) > room) return '<pattern>';
  return sig;
}

const fmt = (n: number) => Math.round(count(n)).toLocaleString('en-US');

/** `--json false` and `--json=0` mean what they say. */
function flag(argv: Argv, name: string): boolean {
  const v = argv.flags[name];
  if (typeof v === 'string') return !['false', '0', 'no', 'off', ''].includes(v.toLowerCase());
  return Boolean(v);
}

function emit(data: unknown): number {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
  return 0;
}
