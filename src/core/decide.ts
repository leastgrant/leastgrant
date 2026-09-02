/**
 * The decision pipeline.
 *
 * Precedence, highest first. This order is the product; everything else is
 * plumbing.
 *
 *   1. Integrity floors        — deny. Not overridable, by anyone.
 *   2. Explicit deny rules     — deny. The human said never.
 *   3. Explicit allow rules    — allow. The human already answered this question.
 *   4. Ask floors              — ask.  Learning cannot unlock these.
 *   5. Learned promotion       — allow, if the evidence clears the bar for this
 *                                blast tier.
 *   6. Otherwise               — ask.
 *
 * Note where (3) sits: an explicit allow rule satisfies an ask-floor, because a
 * floor's whole purpose is to get a human answer, and a rule *is* a human
 * answer given in advance. Integrity floors are the exception — nothing lets an
 * agent quietly edit the thing that is watching it.
 */

import type {
  Action,
  Config,
  Decision,
  Envelope,
  Familiarity,
  Reason,
  Request,
  Rule,
  Verdict,
} from './types.js';
import { blastTier } from './types.js';
import { analyze, type AnalyzeCtx } from './classify.js';
import { checkGuards, type GuardCtx, type GuardHit } from './guards.js';
import { canPromote, familiarity, noveltyRate, taintConcern, type SessionState } from './envelope.js';
import { globMatch } from './secrets.js';
import { DEFAULT_THRESHOLDS } from './envelope.js';

export interface DecideCtx extends AnalyzeCtx {
  config: Config;
  /** Merged learned envelope for this project. */
  envelope: Envelope;
  /** Global envelope, consulted when the project has little history. */
  globalEnvelope?: Envelope;
  /** Live session state, for sequence and taint reasoning. */
  session: SessionState;
  /** Where LeastGrant keeps its own files. */
  stateDir: string;
  /** Project key, for scoping rules. */
  projectKey: string;
}

export function decide(req: Request, ctx: DecideCtx): Verdict {
  const analysis = analyze(req, ctx);
  const th = ctx.config.thresholds ?? DEFAULT_THRESHOLDS;

  const guardCtx: GuardCtx = {
    roots: ctx.roots,
    stateDir: ctx.stateDir,
    understood: analysis.understood,
    wrapperTags: analysis.wrapperTags,
    pipedFromNetwork: analysis.pipedFromNetwork,
  };

  interface Judged {
    action: Action;
    /** Every guard that fired. Reporting. */
    hits: GuardHit[];
    /**
     * The guards that actually constrained this action's decision.
     *
     * Not the same set as `hits`, and the difference is load-bearing. A guard
     * the human's own allow rule already answered, or one autopilot waives,
     * fired but decided nothing. Folding `floor` from `hits` reported those as
     * floors, and `floor` is not decoration: the Codex adapter reads it to tell
     * "merely unfamiliar" from "a rule LeastGrant enforces itself". A standing
     * allow rule on `cat <path:secret>` therefore made Codex *hard-deny* an
     * unrelated unreadable script in the same command — adding a rule to remove
     * friction created it somewhere else, in another agent.
     */
    floored: GuardHit[];
    fam: Familiarity;
    decision: Decision;
    reasons: Reason[];
    /** taintConcern for THIS action, against the session as it stands. */
    concern: string | null;
  }

  const judged: Judged[] = analysis.actions.map((action, index) => {
    const hits = checkGuards(action, guardCtx);
    const fam = familiarity(
      ctx.envelope,
      {
        signature: action.signature,
        capability: action.capability,
        blast: action.blast,
        previousCapability: ctx.session.lastCapability,
        at: req.at,
      },
      th,
    );
    const { decision, reasons, floored } = decideOne(action, hits, fam, ctx, req);
    return {
      action,
      hits,
      floored,
      fam,
      decision,
      reasons,
      // Per action, not once for the elected one. `cat ~/.ssh/id_rsa` earlier in
      // the session then `rm -rf ./build && curl https://x` used to come back
      // ALLOW, because the delete outranks the fetch on blast tier and wins the
      // election, and `fs.delete` has no taint rule. The curl alone asked. So
      // appending a delete to an exfiltration-shaped call removed the prompt.
      concern: taintConcern(ctx.session, action.capability, action.blast),
      index,
    } as Judged & { index: number };
  });

  // Election picks which action the *sentences* are about. It does not decide
  // anything: every security-relevant field below is folded across all of them,
  // so a fact cannot be lost by losing this sort.
  //
  // Deny beats ask beats allow, then the larger blast radius, and — new — then
  // the signature, so the order is total. It was previously decided by input
  // order among equals, which handed the choice of representative to the agent
  // whose request is being judged: emitting the same two actions the other way
  // round changed which one the human was shown.
  const rank = (d: Decision) => (d === 'deny' ? 2 : d === 'ask' ? 1 : 0);
  judged.sort((a, b) => {
    const r = rank(b.decision) - rank(a.decision);
    if (r !== 0) return r;
    const t = blastTier(b.action.blast) - blastTier(a.action.blast);
    if (t !== 0) return t;
    return a.action.signature < b.action.signature ? -1 : a.action.signature > b.action.signature ? 1 : 0;
  });

  const worst = judged[0]!;
  const reasons = [...worst.reasons];

  // Every guard that fired, not just the ones on the winning action.
  //
  // `worst` is chosen by decision rank and then by blast tier, which is right
  // for picking *a verdict* and wrong for reporting *why*. In
  // `rm -rf ./build && cat ~/.ssh/id_rsa` the delete has the larger blast tier
  // and fires no guard at all, so it wins the sort — and the credential read's
  // `guard.secret-read` was dropped from the reasons and from `floor`.
  //
  // That was invisible while `floor` only drove a sentence in the CLI. It stops
  // being invisible the moment an adapter uses it to decide, which is what the
  // Codex adapter now does: floor false means "merely unfamiliar", so it stood
  // aside and let the credential read run.
  //
  // Deduped by code: the same guard firing on three actions is one reason to a
  // human.
  const seen = new Set(reasons.map((r) => r.code));
  for (const other of judged.slice(1)) {
    for (const hit of other.hits) {
      if (seen.has(hit.id)) continue;
      seen.add(hit.id);
      // `blocks` only if it actually blocked. A sibling's guard that the human's
      // own rule already satisfied is reported, because they should still see
      // that their command reads a credential — but as information, with the
      // same wording decideOne uses, not as a reason the request was held up.
      const waived = !other.floored.some((f) => f.id === hit.id);
      reasons.push(
        waived
          ? { code: hit.id, text: `${hit.text} (allowed by your rule)`, weight: 'info' }
          : { code: hit.id, text: hit.text, weight: 'blocks' },
      );
    }
  }

  // When several actions are bundled, say so — it changes what the human is
  // actually agreeing to.
  if (judged.length > 1) {
    reasons.push({
      code: 'multi.actions',
      text: `this command runs ${judged.length} separate things; the verdict reflects the most far-reaching one`,
      weight: 'info',
    });
  }

  // --- the fold ------------------------------------------------------------
  //
  // Every field below is derived from ALL judged actions. The rule this file
  // now keeps: a security fact may only come from a fold, never from `worst`.
  // Three separate bugs were one violation of it — the floor, the taint, and
  // the reasons were each read off whichever action happened to win a sort on
  // two unrelated keys.

  // Deny beats ask beats allow, over every action.
  const folded: Decision = judged.reduce<Decision>(
    (acc, j) => (rank(j.decision) > rank(acc) ? j.decision : acc),
    'allow',
  );

  // Any action whose guard actually held. Waived guards are reported, not
  // gated on — see Judged.floored.
  const flooredGuards = [...new Set(judged.flatMap((j) => j.floored.map((h) => h.id)))];
  const floor = flooredGuards.length > 0;

  // The first concern any action raises, in the order the human will read them.
  const concern = judged.find((j) => j.concern)?.concern ?? null;

  // A taint concern raises an allow to an ask; it never lowers a deny.
  const decision: Decision = concern && folded === 'allow' ? 'ask' : folded;

  if (concern && decision !== 'deny') {
    reasons.unshift({ code: 'session.taint', text: concern, weight: 'raises' });
  }

  return {
    decision,
    action: worst.action,
    actions: analysis.actions,
    reasons,
    headline: headlineFor(decision, worst.action, reasons),
    floor,
    flooredGuards,
    familiarity: worst.fam,
  };
}

function decideOne(
  action: Action,
  hits: GuardHit[],
  fam: Familiarity,
  ctx: DecideCtx,
  req: Request,
): { decision: Decision; reasons: Reason[]; floored: GuardHit[] } {
  const reasons: Reason[] = [];
  const th = ctx.config.thresholds ?? DEFAULT_THRESHOLDS;

  // 1. Integrity floors — never overridable.
  const integrity = hits.find((h) => h.decision === 'deny');
  if (integrity) {
    reasons.push({ code: integrity.id, text: integrity.text, weight: 'blocks' });
    return { decision: 'deny', reasons, floored: [integrity] };
  }

  // 2 & 3. Explicit rules.
  const rule = matchRule(ctx.config.rules, action.signature, ctx.projectKey, req.at);
  if (rule?.effect === 'deny') {
    reasons.push({
      code: 'rule.deny',
      text: rule.note ? `you set a rule to always block this: ${rule.note}` : 'you set a rule to always block this',
      weight: 'blocks',
    });
    return { decision: 'deny', reasons, floored: [] };
  }
  if (rule?.effect === 'allow') {
    reasons.push({
      code: 'rule.allow',
      text: rule.note ? `you allowed this: ${rule.note}` : 'you have allowed this before, as a standing rule',
      weight: 'lowers',
    });
    for (const h of hits) {
      reasons.push({ code: h.id, text: `${h.text} (allowed by your rule)`, weight: 'info' });
    }
    // Every guard here fired and none of them held: the human answered this
    // question in advance, which is what an allow rule is. Reporting them as
    // floors is the bug described on Judged.floored.
    return { decision: 'allow', reasons, floored: [] };
  }

  // 4. Ask floors.
  //
  // Autopilot makes exactly one concession, and it is worth being precise about
  // what it is. Running a script means running code LeastGrant cannot read, so
  // in assist mode it always asks. But someone who would otherwise be running
  // their agent with permissions switched off entirely has already accepted
  // that; refusing to meet them there just means they use nothing at all. So in
  // autopilot, unreadable code that stays inside the project is allowed to be
  // learned — and every other floor still applies, which is strictly more
  // protection than the bypass mode they were using instead.
  const effective =
    ctx.config.posture === 'autopilot'
      ? hits.filter((h) => !(h.id === 'guard.not-understood' && containedInProject(action)))
      : hits;

  if (effective.length) {
    for (const h of effective) reasons.push({ code: h.id, text: h.text, weight: 'blocks' });
    reasons.push({
      code: 'floor.explain',
      text: 'LeastGrant never auto-approves this kind of action, however often it happens',
      weight: 'info',
    });
    return { decision: 'ask', reasons, floored: effective };
  }
  if (hits.length && effective.length === 0) {
    reasons.push({
      code: 'posture.autopilot',
      text: 'you are in autopilot, so code that stays inside the project runs without being read first',
      weight: 'info',
    });
  }

  // 5. Learned promotion.
  if (ctx.config.posture === 'strict') {
    reasons.push({
      code: 'posture.strict',
      text: 'you are in strict mode, so only actions you have explicitly allowed run without asking',
      weight: 'raises',
    });
    return { decision: 'ask', reasons, floored: [] };
  }

  let promo = canPromote(fam, action.blast, th);

  // Autopilot's second concession: observation may promote reversible work
  // inside the project, not just read-only work. Editing a file in the repo you
  // are working on is the thing the agent is *for*, it is recoverable from
  // version control, and the persistence and outside-the-project floors still
  // stand above it. Everything that leaves the machine still needs a human.
  if (
    !promo.eligible &&
    promo.reason === 'observed-only' &&
    ctx.config.posture === 'autopilot' &&
    containedInProject(action) &&
    (action.blast.reversibility === 'trivial' || action.blast.reversibility === 'easy') &&
    fam.observed >= th.minObserved &&
    fam.sessions >= th.minSessions
  ) {
    promo = { eligible: true, reason: 'promoted' };
  }

  if (promo.eligible) {
    if (fam.grantedAt) {
      // A bulk grant is stored as the confirmation count it stands in for, so
      // the arithmetic downstream works out. Reading that number back as a
      // sentence would claim the human clicked yes eleven times when they made
      // one deliberate decision with the blast radius in front of them —
      // `SignatureStat.grantedAt` says in as many words that the UI must not do
      // that.
      reasons.push({
        code: 'familiar.granted',
        text: 'you approved this during setup, with its blast radius in front of you',
        weight: 'lowers',
      });
    } else if (fam.confirmed >= 1) {
      reasons.push({
        code: 'familiar.confirmed',
        text: `you have approved this ${count(fam.confirmed)} across ${plural(fam.days, 'day')} and ${plural(fam.sessions, 'session')}`,
        weight: 'lowers',
      });
    } else {
      reasons.push({
        code: 'familiar.observed',
        text: `this has run ${count(fam.observed)} here without incident, and it cannot reach outside the project`,
        weight: 'lowers',
      });
    }
    reasons.push({
      code: 'blast.small',
      text: describeBlast(action),
      weight: 'info',
    });
    return { decision: 'allow', reasons, floored: [] };
  }

  // 6. Ask, with a reason that says what would change our mind.
  reasons.push(promotionGap(promo, fam, action, ctx));
  if (fam.novel) {
    // Novelty means very different things depending on how much we have seen.
    // In a repository LeastGrant has never watched, everything is new and
    // saying so on every line would be noise. Once there is a real baseline,
    // "first time" starts to carry weight — but only in proportion to how rare
    // first-timers actually are here.
    const seen = ctx.envelope.events;
    if (seen < 25) {
      reasons.push({
        code: 'novel.no-baseline',
        text: 'LeastGrant has barely seen this project yet, so it is asking about most things',
        weight: 'info',
      });
    } else {
      const rate = noveltyRate(ctx.envelope);
      reasons.push({
        code: 'novel.first-time',
        text:
          rate > 0.15
            ? `this is the first time, though about ${pct(rate)} of what runs here is a first-timer`
            : 'this is the first time this has run here',
        weight: rate > 0.15 ? 'info' : 'raises',
      });
    }
  }
  if (fam.novelTransition && ctx.session.count > 3) {
    reasons.push({
      code: 'novel.transition',
      text: `this session has not gone from ${friendly(ctx.session.lastCapability)} to ${friendly(action.capability)} before`,
      weight: 'raises',
    });
  }
  return { decision: 'ask', reasons, floored: [] };
}

function promotionGap(
  promo: ReturnType<typeof canPromote>,
  fam: Familiarity,
  action: Action,
  ctx: DecideCtx,
): Reason {
  switch (promo.reason) {
    case 'blast-too-high':
      return {
        code: 'gap.blast',
        text: `${describeBlast(action)}, which is more than LeastGrant will ever approve on its own`,
        weight: 'blocks',
      };
    case 'previously-denied':
      return {
        code: 'gap.denied',
        text: `you turned this down ${plural(fam.denied, 'time')} before, so it keeps asking`,
        weight: 'raises',
      };
    case 'needs-more-days':
      return {
        code: 'gap.days',
        text: 'you have only approved this today; LeastGrant waits for a second day before it stops asking',
        weight: 'info',
      };
    case 'needs-more-sessions':
      return {
        code: 'gap.sessions',
        text: 'you have only approved this in one session so far',
        weight: 'info',
      };
    case 'observed-only':
      return {
        code: 'gap.observed',
        text: `this has run ${count(fam.observed)} here, but never with you actually approving it`,
        weight: 'info',
      };
    case 'not-enough-evidence':
    default: {
      const short = promo.approvalsShort;
      void ctx;
      return {
        code: 'gap.evidence',
        text: short
          ? `approve this ${plural(short, 'more time')} and LeastGrant will stop asking`
          : 'LeastGrant has not seen enough of this yet to stop asking',
        weight: 'info',
      };
    }
  }
}

/** Find the most specific matching rule. Deny wins ties. */
export function matchRule(
  rules: Rule[],
  signature: string,
  projectKey: string,
  now: number,
): Rule | undefined {
  const applicable = rules.filter((r) => {
    if (r.expiresAt && r.expiresAt < now) return false;
    if (r.scope === 'project' && r.key && r.key !== projectKey) return false;
    return globMatch(r.match, signature);
  });
  if (!applicable.length) return undefined;
  const deny = applicable.find((r) => r.effect === 'deny');
  if (deny) return deny;
  // Prefer the most specific pattern: fewer wildcards, then longer.
  applicable.sort((a, b) => {
    const wa = (a.match.match(/\*/g) ?? []).length;
    const wb = (b.match.match(/\*/g) ?? []).length;
    if (wa !== wb) return wa - wb;
    return b.match.length - a.match.length;
  });
  return applicable[0];
}

// --- phrasing ---------------------------------------------------------------

function headlineFor(decision: Decision, action: Action, reasons: Reason[]): string {
  const primary = reasons.find((r) => r.weight === 'blocks') ?? reasons.find((r) => r.weight === 'raises') ?? reasons[0];
  const why = primary?.text ?? describeBlast(action);
  if (decision === 'deny') return `LeastGrant blocked this: ${why}.`;
  if (decision === 'allow') return `LeastGrant allowed this: ${why}.`;
  return `${capitalize(why)}.`;
}

/**
 * Does this action's effect stay inside the project directory?
 * Used only by autopilot, where it is the boundary of the one concession made.
 */
function containedInProject(action: Action): boolean {
  return (
    (action.blast.reach === 'workspace' || action.blast.reach === 'none') &&
    action.blast.exposure === 'none' &&
    !action.targets.some((t) => t.secret || (t.type === 'path' && t.inWorkspace === false))
  );
}

/** A plain-English blast radius, with no numbers in it. */
export function describeBlast(action: Action): string {
  const b = action.blast;
  const where =
    b.reach === 'workspace' ? 'stays inside the project'
    : b.reach === 'machine' ? 'touches this machine outside the project'
    : b.reach === 'network' ? 'reaches the network'
    : b.reach === 'external' ? 'changes something outside this machine'
    : b.reach === 'production' ? 'targets production'
    : 'has no effect';
  const undo =
    b.reversibility === 'irreversible' ? ' and cannot be undone'
    : b.reversibility === 'hard' ? ' and would be hard to undo'
    : '';
  const scale = b.scale === 'sweeping' ? ', possibly many times over' : '';
  return `it ${where}${undo}${scale}`;
}

const FRIENDLY: Record<string, string> = {
  'fs.read.workspace': 'reading project files',
  'fs.read.outside': 'reading files outside the project',
  'fs.write.workspace': 'editing project files',
  'fs.write.outside': 'writing outside the project',
  'fs.delete': 'deleting files',
  'secret.read': 'reading credentials',
  'exec.inspect': 'looking around',
  'exec.build': 'building',
  'exec.test': 'running tests',
  'exec.pkg': 'installing packages',
  'exec.pkg.publish': 'publishing a package',
  'exec.vcs.read': 'reading git state',
  'exec.vcs.write': 'changing local git history',
  'exec.vcs.publish': 'pushing to a remote',
  'exec.container': 'running containers',
  'exec.cloud': 'changing cloud resources',
  'exec.iac': 'changing infrastructure',
  'exec.db': 'talking to a database',
  'exec.process': 'managing processes',
  'exec.privilege': 'running as root',
  'exec.remote': 'running commands on another machine',
  'exec.unknown': 'running something unrecognised',
  'net.fetch': 'fetching from the network',
  'net.send': 'sending data out',
  'mcp.call': 'calling an MCP server',
  'agent.spawn': 'starting a subagent',
  meta: 'housekeeping',
};

export function friendly(capability?: string): string {
  return (capability && FRIENDLY[capability]) || 'something';
}

const count = (n: number) => plural(Math.round(n), 'time');
const plural = (n: number, word: string) => `${Math.round(n)} ${word}${Math.round(n) === 1 ? '' : 's'}`;
const pct = (x: number) => `${Math.round(x * 100)}%`;
const capitalize = (s: string) => (s ? s[0]!.toUpperCase() + s.slice(1) : s);
