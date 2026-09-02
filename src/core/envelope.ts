/**
 * The behaviour envelope: what is normal here, and how sure are we?
 *
 * Three deliberate constraints shape everything below.
 *
 * 1. **Learning may only reduce friction within a risk tier, never across one.**
 *    No amount of evidence promotes `git push --force` into the auto-approve
 *    set. Evidence decides whether we stop asking about things that were
 *    already in the "could be automatic" band; it never widens that band. This
 *    is what makes the boiling-frog attack structurally impossible instead of
 *    statistically unlikely.
 *
 * 2. **Only human-attested evidence promotes.** An action that merely happened
 *    while the agent was in bypass mode tells us what is *typical*, not what is
 *    *sanctioned*. Typicality is used for anomaly detection (where it is strong
 *    evidence of abnormality) and never for approval (where it would be weak
 *    evidence of safety). Asymmetric use is the honest use.
 *
 * 3. **Denials are permanent; approvals decay.** Saying no once means we keep
 *    asking. Only an explicit rule the human writes can undo that. This is
 *    simpler than a Bayesian demotion schedule, more predictable for the user,
 *    and immune to "wait for the denial to decay away" attacks.
 */

import type {
  BlastRadius,
  Capability,
  Envelope,
  EvidenceKind,
  Familiarity,
  Scope,
  SignatureStat,
  Thresholds,
} from './types.js';
import { blastTier, worseBlast, NIL_BLAST } from './types.js';

const DAY_MS = 86_400_000;

/**
 * One-sided 95% z. The gates are all of the form "the true approval rate is at
 * least X", which is a one-sided claim; using the two-sided 1.96 here would
 * silently make every threshold stricter than documented.
 */
export const Z = 1.645;

/**
 * Wilson score lower bound on a proportion.
 *
 * For the all-approved case this reduces to the pleasant closed form
 * `n / (n + z^2)`, which is worth knowing because it is the whole promotion
 * schedule in one expression: 5 approvals buys 0.65 confidence, 11 buys 0.80,
 * 25 buys 0.90. Anyone can check our thresholds with a calculator.
 */
export function wilsonLowerBound(successes: number, total: number, z = Z): number {
  if (total <= 0) return 0;
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const centre = p + z2 / (2 * total);
  const margin = z * Math.sqrt((p * (1 - p)) / total + z2 / (4 * total * total));
  return Math.max(0, (centre - margin) / denom);
}

/** Confidence produced by `n` clean approvals — the inverse of the above. */
export function confidenceFor(n: number, z = Z): number {
  return n / (n + z * z);
}

/** Approvals needed to reach a given confidence, from a clean record. */
export function approvalsNeededFor(confidence: number, z = Z): number {
  if (confidence >= 1) return Infinity;
  return Math.ceil((confidence * z * z) / (1 - confidence));
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  minSessions: 2,
  minDays: 2,
  minApproval: 0.6,
  minObserved: 8,
  maxTier: 2,
  halfLifeDays: 90,
};

/**
 * Confidence required, by blast tier.
 *
 * The rule a human can hold in their head: the more an action could break, the
 * more evidence we want before we stop asking. Tier 3+ is absent because it is
 * never auto-approvable at any level of evidence.
 */
export const CONFIDENCE_BY_TIER: Record<number, number> = {
  0: 0.6, // 5 clean approvals
  1: 0.6, // 5
  2: 0.8, // 11
};

/**
 * Confidence required to promote at `tier`, for every tier — including the ones
 * the table above does not name.
 *
 * The table stops at 2 because that is the default ceiling, and for a while the
 * code fell back to `thresholds.minApproval` above it. That is *lower* than the
 * tier-2 entry, so a user who raised `maxTier` to 3 — opting into promoting
 * irreversible, machine-wide actions — got a schedule that asked for **fewer**
 * approvals the more dangerous the action became. The ceiling check happened to
 * hide it at the default setting, which is the worst kind of correctness: right
 * by accident, wrong the moment someone changes a knob.
 *
 * So the schedule is monotone by construction. Past the table each tier keeps a
 * quarter of the remaining doubt: 0.8 → 0.95 (52 clean approvals) → 0.9875
 * (214). Raising the ceiling is allowed; getting a discount for it is not.
 */
export function requiredConfidence(tier: number, th: Thresholds = DEFAULT_THRESHOLDS): number {
  if (tier > th.maxTier) return Infinity;
  const named = CONFIDENCE_BY_TIER[tier];
  if (named !== undefined) return Math.max(th.minApproval, named);
  const tiers = Object.keys(CONFIDENCE_BY_TIER).map(Number);
  const last = Math.max(...tiers);
  const top = CONFIDENCE_BY_TIER[last]!;
  const steps = Math.max(1, tier - last);
  return Math.max(th.minApproval, 1 - (1 - top) / Math.pow(4, steps));
}

/**
 * Signatures are built from agent-controlled argv and then used as object keys.
 * `__proto__` reaches Object.prototype, `constructor` reaches the constructor,
 * and both make "have I seen this before" answer yes for something never seen.
 *
 * The maps are created with `Object.create(null)` so this cannot happen — but
 * an envelope can also arrive from a caller that built one with a plain literal,
 * and the guard belongs with the function that accepts the untrusted key rather
 * than with every possible constructor of the thing it writes into.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function safeSignatureKey(signature: string): string {
  return DANGEROUS_KEYS.has(signature) ? `sig:${signature}` : signature;
}

/**
 * Read a property only if the object actually owns it.
 *
 * Two different attacks land here. An agent-chosen key like `__proto__` reaches
 * `Object.prototype` through a plain-object map, so "have I seen this?" answers
 * yes for something never seen. And a *polluted* `Object.prototype` — from
 * anywhere in the process, not necessarily from us — makes every record look
 * like it carries fields it does not, of which `grantedAt` is the lethal one:
 * `canPromote` reads it as a standing human attestation and skips the
 * confidence, days and sessions gates entirely.
 *
 * Null-prototype maps fix the first. This fixes the second, and it has to be
 * used at the point of *use*, because a stat can be an ordinary literal built
 * by any caller.
 */
function own<T extends object, K extends keyof T>(o: T | undefined, k: K): T[K] | undefined {
  if (!o) return undefined;
  return Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined;
}

/** A map that agent-controlled strings can be used as keys of, safely. */
function bareMap<V>(): Record<string, V> {
  return Object.create(null) as Record<string, V>;
}

export function newEnvelope(scope: Scope, key: string): Envelope {
  return {
    scope,
    key,
    updatedAt: 0,
    signatures: bareMap(),
    transitions: bareMap(),
    capabilities: bareMap(),
    events: 0,
  };
}

/** Multiplicative decay factor for evidence `ageMs` old. */
function decayFactor(ageMs: number, halfLifeDays: number): number {
  if (halfLifeDays <= 0) return 1;
  // Clamped at both ends. A negative age — a stored lastSeen in the future,
  // from clock skew or a hand-edited file — yields a factor greater than one,
  // and evidence would *grow* as it aged. A non-finite age yields NaN, which
  // poisons every comparison downstream into false.
  if (!Number.isFinite(ageMs) || ageMs <= 0) return 1;
  const f = Math.pow(0.5, ageMs / (halfLifeDays * DAY_MS));
  return Number.isFinite(f) ? Math.min(1, Math.max(0, f)) : 0;
}

export interface ObserveInput {
  signature: string;
  capability: Capability;
  blast: BlastRadius;
  evidence: EvidenceKind;
  at: number;
  sessionId: string;
  /** Redacted display string, kept as a sample for the UI. */
  display: string;
  /** Capability of the previous action in this session, for transitions. */
  previousCapability?: Capability;
}

/**
 * Fold one observation into an envelope, in place.
 *
 * History does not always arrive in order. The live hook folds events as they
 * happen, and `leastgrant simulate` sorts before replaying, but `leastgrant
 * init` walks transcript files newest-first — so a project's evidence reaches
 * this function backwards. Everything below is therefore written to give the
 * same answer whatever order the same set of events arrives in. Getting that
 * wrong is not a rounding error: an out-of-order fold used to drag `lastSeen`
 * backwards to the *oldest* event, after which every mined approval was decayed
 * as though it were as old as the project itself.
 */
export function observe(env: Envelope, input: ObserveInput, th: Thresholds = DEFAULT_THRESHOLDS): void {
  // A timestamp that is not a real time cannot contribute a calendar day, and
  // must not be used for decay arithmetic either.
  const usableTime = Number.isFinite(input.at) && input.at > 0;
  const day = usableTime ? Math.floor(input.at / DAY_MS) : Number.NaN;
  const key = safeSignatureKey(input.signature);
  let s = Object.prototype.hasOwnProperty.call(env.signatures, key)
    ? env.signatures[key]
    : undefined;

  if (!s) {
    s = {
      signature: input.signature,
      capability: input.capability,
      confirmed: 0,
      denied: 0,
      observed: 0,
      totalSeen: 0,
      firstSeen: input.at,
      lastSeen: input.at,
      sessions: 0,
      days: 0,
      worstBlast: NIL_BLAST,
      samples: [],
    };
    env.signatures[key] = s;
    // Internal bookkeeping fields, not part of the public shape.
    (s as MutableStat)._recentDays = [];
    (s as MutableStat)._recentSessions = [];
  }

  const m = s as MutableStat;

  // Decayed counts are held at a common anchor: `lastSeen`, the newest thing we
  // know about. A newer event moves the anchor forward and decays the running
  // total to meet it; an older one leaves the anchor where it is and is added
  // at its own decayed weight. Both give the same total for the same events.
  //
  // Denials are deliberately excluded: a "no" does not expire, so it is never
  // decayed and always counts as one.
  let weight = 1;
  if (input.at > s.lastSeen) {
    const f = decayFactor(input.at - s.lastSeen, th.halfLifeDays);
    s.confirmed *= f;
    s.observed *= f;
    // The per-tier buckets are the numbers familiarity() actually reads, so
    // they have to move with the flat totals. Decaying only the totals left the
    // buckets growing forever, and evidence never aged.
    const b = own(s as MutableStat, '_byTier');
    if (b) for (const k of Object.keys(b)) { const e = b[Number(k)]!; e.confirmed *= f; e.observed *= f; }
  } else if (input.at < s.lastSeen) {
    weight = decayFactor(s.lastSeen - input.at, th.halfLifeDays);
  }

  // Bucketed by the tier this occurrence actually reached, so a promotion can
  // only ever spend evidence gathered at or above the tier it is deciding.
  const tierNow = blastTier(input.blast);
  // A human said yes, either at a prompt or deliberately during setup.
  const isApproval = input.evidence === 'confirmed' || input.evidence === 'granted';
  const m2 = s as MutableStat;
  m2._byTier ??= {};
  const bucket = (m2._byTier[tierNow] ??= { confirmed: 0, observed: 0 });

  switch (input.evidence) {
    case 'confirmed':
      s.confirmed += weight;
      bucket.confirmed += weight;
      break;
    case 'denied':
      s.denied += 1;
      break;
    case 'observed':
      s.observed += weight;
      bucket.observed += weight;
      break;
    case 'granted':
      // A bulk grant made during setup, with the blast radius on screen. That
      // is a real human attestation, so it counts — but it is one decision, not
      // many, so we record the fact of the grant rather than inflating a count
      // the user never produced. Explanations read it from `grantedAt` and say
      // "you approved this during setup".
      s.grantedAt = input.at;
      bucket.confirmed = Math.max(bucket.confirmed, approvalsNeededFor(0.8));
      s.confirmed = Math.max(s.confirmed, approvalsNeededFor(0.8));
      break;
  }

  s.totalSeen += 1;
  s.firstSeen = Math.min(s.firstSeen, input.at);
  s.lastSeen = Math.max(s.lastSeen, input.at);
  s.worstBlast = worseBlast(s.worstBlast, input.blast);

  // Distinct days, not day *changes*. Remembering only the last day stamp
  // counted the same afternoon twice whenever two transcripts interleaved, and
  // `minDays` is a promotion gate — the one that stops a single hard day's work
  // from teaching a habit. The list is bounded, evicting the oldest day: past
  // 32 distinct days the gate is long since satisfied, so the imprecision that
  // buys the size limit cannot change an outcome.
  const seenDays = m._recentDays ?? (m._recentDays = m._lastDay !== undefined && m._lastDay >= 0 ? [m._lastDay] : []);
  // A timestamp that is not a real time contributes no day. An unparseable
  // transcript date used to arrive as 0 — which is 1970, a perfectly distinct
  // calendar day as far as the multi-day gate was concerned, and a free one
  // toward promotion.
  if (usableTime && !seenDays.includes(day)) {
    s.days += 1;
    seenDays.push(day);
    if (seenDays.length > 32) {
      seenDays.sort((a, b) => a - b);
      seenDays.shift();
    }
  }
  const recent = m._recentSessions ?? (m._recentSessions = []);
  if (!recent.includes(input.sessionId)) {
    s.sessions += 1;
    recent.push(input.sessionId);
    if (recent.length > 16) recent.shift();
  }

  // The same two counts, over APPROVALS only.
  //
  // `days` and `sessions` above count sightings of any kind, and the promotion
  // gate they feed exists to stop a burst of prompt-clicks inside one session
  // from teaching a habit. Sightings do not carry that meaning: the agent
  // generates them itself, unattended, just by running the command. So running
  // something twice on two days in bypass mode satisfied "two days, two
  // sessions" before a human had approved anything, and eleven clicks in one
  // eleven-second burst then promoted it.
  //
  // Counted separately rather than by changing the meaning of the fields above,
  // because autopilot's observation-only route legitimately wants the sighting
  // count — there, observations are the evidence, and requiring approvals would
  // be requiring the thing that route exists to do without.
  if (isApproval) {
    const okDays = m._approvedDays ?? (m._approvedDays = []);
    if (usableTime && !okDays.includes(day)) {
      s.approvedDays = (s.approvedDays ?? 0) + 1;
      okDays.push(day);
      if (okDays.length > 32) {
        okDays.sort((a, b) => a - b);
        okDays.shift();
      }
    }
    const okSessions = m._approvedSessions ?? (m._approvedSessions = []);
    if (!okSessions.includes(input.sessionId)) {
      s.approvedSessions = (s.approvedSessions ?? 0) + 1;
      okSessions.push(input.sessionId);
      if (okSessions.length > 16) okSessions.shift();
    }
  }

  if (s.samples.length < 3 && !s.samples.includes(input.display)) {
    s.samples.push(input.display);
  }

  env.capabilities[input.capability] = (env.capabilities[input.capability] ?? 0) + 1;
  if (input.previousCapability) {
    const key = `${input.previousCapability}>${input.capability}`;
    env.transitions[key] = (env.transitions[key] ?? 0) + 1;
  }
  env.events += 1;
  env.updatedAt = input.at;
}

interface MutableStat extends SignatureStat {
  /** Approvals and observations, split by the blast tier they happened at. */
  _byTier?: Record<number, { confirmed: number; observed: number }>;
  /** Written by older versions; read once to seed `_recentDays`, then dropped. */
  _lastDay?: number;
  _recentDays?: number[];
  _recentSessions?: string[];
  _approvedDays?: number[];
  _approvedSessions?: string[];
}

/**
 * The share of observations that were first-of-their-kind.
 *
 * This is the Good-Turing estimate of "probability the next thing is new", and
 * it is what turns "I have never seen this before" from an alarm into a
 * calibrated statement. In a fresh repository almost everything is new, and a
 * tool that alarms on all of it gets uninstalled by lunchtime.
 */
export function noveltyRate(env: Envelope): number {
  const sigs = Object.values(env.signatures);
  if (!sigs.length || !env.events) return 1;
  const hapax = sigs.filter((s) => s.totalSeen === 1).length;
  return hapax / env.events;
}

export interface FamiliarityQuery {
  signature: string;
  capability: Capability;
  blast: BlastRadius;
  previousCapability?: Capability;
  at: number;
}

/** Look up what we know about a signature, decayed to `at`. */
export function familiarity(
  env: Envelope,
  q: FamiliarityQuery,
  th: Thresholds = DEFAULT_THRESHOLDS,
): Familiarity {
  // `hasOwnProperty`, not a truthiness test: an envelope that arrived as a
  // plain object (from JSON, or from a caller that built one with a literal)
  // resolves `__proto__` and `constructor` through the prototype chain, and a
  // signature we have never seen would come back as an object.
  const key = safeSignatureKey(q.signature);
  const s = Object.prototype.hasOwnProperty.call(env.signatures, key)
    ? env.signatures[key]
    : undefined;
  if (!s) {
    return {
      signature: q.signature,
      confirmed: 0,
      denied: 0,
      observed: 0,
      sessions: 0,
      days: 0,
      approvedSessions: 0,
      approvedDays: 0,
      approvalLowerBound: 0,
      novel: true,
      novelTransition: q.previousCapability
        ? !own(env.transitions, `${q.previousCapability}>${q.capability}`)
        : false,
    };
  }

  // A `lastSeen` in the future is not a reason to stop ageing evidence.
  //
  // Clamping the factor at one stopped evidence *growing*, but left it frozen:
  // a single bogus timestamp — clock skew, a timezone mistake, a hand edit —
  // made every approval on that signature immortal. When the anchor is not
  // believable, fall back to the first time we saw the thing, which is.
  const anchor = s.lastSeen > q.at ? Math.min(s.firstSeen || q.at, q.at) : s.lastSeen;
  const f = q.at > anchor ? decayFactor(q.at - anchor, th.halfLifeDays) : 1;

  // Only evidence gathered at this tier or a worse one may be spent here.
  // Without this, a signature approved twenty times while it was harmless could
  // be promoted at a tier it had never actually been seen at.
  const wantTier = blastTier(q.blast);
  const byTier = own(s as MutableStat, '_byTier');
  let confirmed: number;
  let observed: number;
  if (byTier) {
    let c = 0;
    let o = 0;
    for (const [tierStr, counts] of Object.entries(byTier)) {
      if (Number(tierStr) < wantTier) continue;
      c += counts.confirmed;
      o += counts.observed;
    }
    confirmed = c * f;
    observed = o * f;
  } else {
    // An envelope written before buckets existed. Its flat totals are all we
    // have; they are used as-is rather than discarded, since throwing away a
    // user's history on upgrade is its own kind of failure.
    confirmed = s.confirmed * f;
    observed = s.observed * f;
  }
  const denied = s.denied; // never decays

  const out: Familiarity = {
    signature: q.signature,
    confirmed,
    denied,
    observed,
    sessions: s.sessions,
    days: s.days,
    approvedSessions: s.approvedSessions ?? 0,
    approvedDays: s.approvedDays ?? 0,
    approvalLowerBound: wilsonLowerBound(confirmed, confirmed + denied),
    novel: false,
    novelTransition: q.previousCapability
      ? !own(env.transitions, `${q.previousCapability}>${q.capability}`)
      : false,
  };
  const grantedAt = own(s, 'grantedAt');
  if (grantedAt) out.grantedAt = grantedAt;
  return out;
}

export interface PromotionResult {
  /** May this signature be auto-approved on the strength of what we know? */
  eligible: boolean;
  /** Machine-readable reason, used to build the explanation. */
  reason:
    | 'promoted'
    | 'blast-too-high'
    | 'previously-denied'
    | 'not-enough-evidence'
    | 'needs-more-days'
    | 'needs-more-sessions'
    | 'observed-only';
  /** How many more clean human approvals would be needed, if that is the gap. */
  approvalsShort?: number;
  /** Confidence required at this blast tier. */
  required?: number;
  /** Confidence we actually have. */
  have?: number;
}

/**
 * The promotion gate.
 *
 * Reading order matters: the blast ceiling is checked before any statistics, so
 * that no accumulation of evidence can ever be *examined*, let alone accepted,
 * for an action above the ceiling. Denials are checked next, before evidence,
 * for the same reason.
 */
export function canPromote(
  fam: Familiarity,
  blast: BlastRadius,
  th: Thresholds = DEFAULT_THRESHOLDS,
): PromotionResult {
  const tier = blastTier(blast);

  if (tier > th.maxTier) {
    return { eligible: false, reason: 'blast-too-high' };
  }
  if (fam.denied > 0) {
    return { eligible: false, reason: 'previously-denied' };
  }

  const required = requiredConfidence(tier, th);

  // Human-attested route.
  //
  // Failing this route falls through to the observation route below rather than
  // returning. A signature with one approval and four hundred observations is
  // strictly better evidenced than one with four hundred observations alone,
  // and it would be perverse for that first approval to make LeastGrant *more*
  // cautious than it was the moment before.
  // A grant made during setup is immediate. The day and session spread exists
  // to stop a burst of prompt-clicks inside one compromised session from
  // teaching a habit; a reviewed, deliberate, one-off decision is not that.
  // `own`, not a plain read: this is the single field that skips every other
  // gate, so it is the field a polluted `Object.prototype` would most want to
  // supply. A `Familiarity` is an ordinary object literal built here and passed
  // across module boundaries, so the check belongs where it is trusted.
  if (own(fam, 'grantedAt')) {
    return { eligible: true, reason: 'promoted' };
  }

  let humanGap: PromotionResult | null = null;
  if (fam.confirmed >= 1) {
    const have = wilsonLowerBound(fam.confirmed, fam.confirmed + fam.denied);
    if (have >= required && fam.approvedDays >= th.minDays && fam.approvedSessions >= th.minSessions) {
      return { eligible: true, reason: 'promoted', required, have };
    }
    humanGap =
      have < required
        ? {
            eligible: false,
            reason: 'not-enough-evidence',
            // Round, do not floor. `confirmed` is decayed on read, so two
            // approvals a second old arrive here as 1.9999998 — and flooring
            // that told the user "approve this 4 more times" when the answer
            // was 3. Rounding is also the number the UI prints, so the
            // countdown and the count agree.
            approvalsShort: Math.max(1, approvalsNeededFor(required) - Math.round(fam.confirmed)),
            required,
            have,
          }
        : fam.approvedDays < th.minDays
          ? { eligible: false, reason: 'needs-more-days', required, have }
          : { eligible: false, reason: 'needs-more-sessions', required, have };
  }

  // Observation-only route.
  //
  // Someone who has been running their agent in bypass mode has generated
  // thousands of actions and zero approvals. Refusing to learn anything from
  // that would make LeastGrant ask about `ls` on day one, and it would be
  // uninstalled by lunchtime. But observation is weak evidence — nobody agreed
  // to any of it — so it may only ever promote actions that cannot do harm
  // even if the observation was of an agent misbehaving.
  //
  // The predicate is stated in terms of consequences, not a tier number,
  // because that is the part a reader needs to be able to check: it must stay
  // inside the project, leave nothing to undo, and touch no credentials. Reads
  // and inspections qualify. Writes, deletes, and anything networked do not —
  // those need either a human approval or an explicit rule, which
  // `leastgrant init` offers to collect in bulk.
  const harmless =
    (blast.reach === 'workspace' || blast.reach === 'none') &&
    blast.reversibility === 'trivial' &&
    blast.exposure === 'none' &&
    blast.scale !== 'sweeping';

  // The gate here is *distinct sessions*, not distinct days.
  //
  // The human-attested route above requires both, because a burst of approvals
  // inside one session is exactly what a compromised session would produce. But
  // applying the same day requirement to observation makes LeastGrant useless
  // on the first day of any project — and a project worked on hard for one
  // afternoon never promotes anything at all, which measured out at four fifths
  // of ordinary file edits still being asked about.
  //
  // Requiring more than one session still defeats the case that matters (a
  // single runaway session cannot bootstrap its own trust), and the actions
  // eligible by this route are contained and reversible by construction, so the
  // downside of being wrong is small and recoverable.
  // Approvals are also observations — a human watching it run is at least as
  // good evidence that it ran without incident.
  const seen = fam.observed + fam.confirmed;
  if (harmless && seen >= th.minObserved && fam.sessions >= th.minSessions) {
    return { eligible: true, reason: 'promoted' };
  }

  if (humanGap) return humanGap;
  return { eligible: false, reason: fam.observed > 0 ? 'observed-only' : 'not-enough-evidence' };
}

// ---------------------------------------------------------------------------
// Session taint: the shape of an exfiltration, not the signature of one
// ---------------------------------------------------------------------------

/**
 * Capability classes worth remembering for the rest of a session.
 *
 * The point is not that any of these is bad. It is that some *sequences* are
 * meaningful even when every step is individually unremarkable: reading a
 * credential file is fine, and making a network request is fine, and doing the
 * second right after the first is the exact shape of an exfiltration.
 */
export type Taint = 'read-secrets' | 'read-outside' | 'fetched-code' | 'network-egress';

export const TAINT_BY_CAPABILITY: Partial<Record<Capability, Taint>> = {
  'secret.read': 'read-secrets',
  'fs.read.outside': 'read-outside',
  'net.fetch': 'network-egress',
  'net.send': 'network-egress',
  'exec.pkg': 'fetched-code',
};

export interface SessionState {
  sessionId: string;
  taints: Set<Taint>;
  /** Capability of the most recent action, for transition novelty. */
  lastCapability?: Capability;
  /** Number of actions seen this session. */
  count: number;
  startedAt: number;
}

export function newSession(sessionId: string, at: number): SessionState {
  return { sessionId, taints: new Set(), count: 0, startedAt: at };
}

export function applyTaint(session: SessionState, capability: Capability): void {
  const t = TAINT_BY_CAPABILITY[capability];
  if (t) session.taints.add(t);
  session.lastCapability = capability;
  session.count += 1;
}

/**
 * Does this action complete a sequence worth mentioning?
 * Returns a plain-English clause, or null.
 */
export function taintConcern(session: SessionState, capability: Capability, blast: BlastRadius): string | null {
  // Any outbound call counts, not only one already marked as exfiltrating. A
  // plain GET carries whatever the agent chose to put in the URL, and the
  // sequence — read a credential, then reach the network — is the shape that
  // matters, not the verb.
  if (session.taints.has('read-secrets') && (capability === 'net.send' || capability === 'net.fetch')) {
    return 'this session already read a credential file, and this call sends data off the machine';
  }
  if (session.taints.has('read-secrets') && capability === 'exec.vcs.publish') {
    return 'this session already read a credential file, and this call pushes to a remote';
  }
  // An MCP call is a call to a server. Whether that server is on this machine
  // or across the internet is not something LeastGrant can see, and the
  // arguments are arbitrary JSON the agent composed — which is exactly the
  // shape of a credential leaving. This was missing while `curl` was covered,
  // so the same exfiltration performed through an MCP tool raised nothing.
  if (session.taints.has('read-secrets') && capability === 'mcp.call') {
    return 'this session already read a credential file, and this call hands data to an MCP server';
  }
  if (session.taints.has('fetched-code') && capability === 'exec.unknown') {
    return 'this session downloaded packages, and this call runs code we cannot inspect';
  }
  return null;
}
