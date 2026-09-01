/**
 * LeastGrant core domain model.
 *
 * Everything in LeastGrant flows through one shape: an agent wants to do
 * something (a `Request`), we decompose it into one or more `Action`s, and the
 * engine returns a `Verdict` that a human can read out loud.
 *
 * Design rules that this file encodes, and that the rest of the codebase must
 * not quietly break:
 *
 *  1. An `Action` is never auto-approved unless `understood === true`.
 *     If the parser could not fully account for a command, that is itself the
 *     signal. Obfuscation must not be a way to look boring.
 *
 *  2. Blast radius is a set of independent dimensions, not a single opaque
 *     score. "0.7314" is not an explanation. `reach: 'network'` is.
 *
 *  3. Evidence is typed by *how it was obtained*. An action that merely
 *     happened while the human was not looking (bypass mode) is weaker
 *     evidence than one the human explicitly approved. Learning that ignores
 *     this distinction can be trained by the thing it is supposed to watch.
 */

// ---------------------------------------------------------------------------
// Requests: what an adapter hands us
// ---------------------------------------------------------------------------

/** Which agent produced this request. Free-form so new adapters need no core change. */
export type AgentId = string;

/**
 * A single tool invocation as reported by an agent adapter, normalized just
 * enough to be agent-agnostic. Adapters translate their native event shape
 * into this.
 */
export interface Request {
  /** Adapter-assigned agent identity, e.g. `claude-code`, `cursor`, `codex`. */
  agent: AgentId;
  /** Agent-native tool name, e.g. `Bash`, `Edit`, `mcp__github__create_issue`. */
  tool: string;
  /** Raw tool input, agent-native. */
  input: Record<string, unknown>;
  /** Absolute working directory the agent is operating in. */
  cwd: string;
  /** Stable id for the conversation/session, used for sequence + scoping. */
  sessionId: string;
  /** The agent's own permission mode at the time, if it exposes one. */
  agentMode?: string;
  /** Milliseconds since epoch. Injected so replay is deterministic. */
  at: number;
  /** Optional: git branch, used for branch-scoped rules and drift reporting. */
  branch?: string;
}

// ---------------------------------------------------------------------------
// Actions: what the request actually *does*
// ---------------------------------------------------------------------------

/**
 * Coarse capability classes. These are the vocabulary for the behaviour
 * envelope and for sequence novelty ("this session went editing -> secret-read,
 * which it has never done"). Deliberately small: a human should be able to hold
 * the whole list in their head.
 */
export type Capability =
  | 'fs.read.workspace'
  | 'fs.read.outside'
  | 'fs.write.workspace'
  | 'fs.write.outside'
  | 'fs.delete'
  | 'secret.read'
  | 'exec.inspect' // ls, cat, grep, ps — read-only shell
  | 'exec.build'
  | 'exec.test'
  | 'exec.pkg' // package managers
  | 'exec.pkg.publish'
  | 'exec.vcs.read'
  | 'exec.vcs.write' // commit, branch, stash — local history
  | 'exec.vcs.publish' // push, tag push — leaves the machine
  | 'exec.container'
  | 'exec.cloud'
  | 'exec.iac' // terraform/pulumi/helm
  | 'exec.db'
  | 'exec.process' // kill, systemctl, service
  | 'exec.privilege' // sudo, doas, runas
  | 'exec.remote' // ssh, scp, rsync to a host
  | 'exec.unknown'
  | 'net.fetch'
  | 'net.send' // outbound with a payload — exfil-shaped
  | 'mcp.call'
  | 'agent.spawn'
  | 'meta'; // todo lists, thinking, plan mode — no side effects

/** What kind of thing the action is, used for display grouping. */
export type ActionKind =
  | 'exec'
  | 'file.read'
  | 'file.write'
  | 'file.edit'
  | 'file.delete'
  | 'net'
  | 'mcp'
  | 'search'
  | 'meta';

/** How far the effect can travel if the action is wrong. */
export type Reach =
  | 'none'
  | 'workspace' // inside the project directory
  | 'machine' // this computer, outside the project
  | 'network' // reaches out, read-only-ish
  | 'external' // changes state in someone else's system
  | 'production'; // changes state in something users depend on

/** How hard it is to undo. */
export type Reversibility = 'trivial' | 'easy' | 'hard' | 'irreversible';

/** Whether the action can see or move secrets. */
export type Exposure = 'none' | 'reads-secrets' | 'can-exfiltrate';

/** How much it touches. */
export type Scale = 'single' | 'many' | 'sweeping';

export interface BlastRadius {
  reach: Reach;
  reversibility: Reversibility;
  exposure: Exposure;
  scale: Scale;
}

/** A concrete thing an action touches, used for explanations and for globbing. */
export interface Target {
  type: 'path' | 'host' | 'service' | 'remote' | 'package';
  value: string;
  /** For paths: is it inside the workspace? */
  inWorkspace?: boolean;
  /** For paths: does it match a known-secret pattern? */
  secret?: boolean;
}

/**
 * The atomic unit LeastGrant reasons about. One `Request` may yield several
 * (`npm test && git push` is two actions, judged separately, worst wins).
 */
export interface Action {
  kind: ActionKind;
  capability: Capability;
  /**
   * Stable normalized identity used for learning. Volatile parts (paths,
   * hashes, numbers, message strings) are templated out so that
   * `git commit -m "fix a"` and `git commit -m "fix b"` are the same thing.
   */
  signature: string;
  /** One-line human rendering, e.g. `git push --force origin main`. */
  display: string;
  blast: BlastRadius;
  targets: Target[];
  /**
   * True only if LeastGrant fully accounted for this action's structure.
   * False for unparseable shell, dynamic evaluation, or opaque wrappers.
   * A false here makes auto-approval impossible, by construction.
   */
  understood: boolean;
  /** Parser/classifier observations surfaced in explanations. */
  notes: string[];
}

// ---------------------------------------------------------------------------
// Evidence + the learned envelope
// ---------------------------------------------------------------------------

/**
 * How we learned that an action is "normal". The distinction is load-bearing:
 * `confirmed` means a human said yes. `observed` means it merely happened,
 * possibly while the human was asleep and the agent was in bypass mode.
 */
export type EvidenceKind =
  | 'confirmed' // human explicitly approved (or approved via agent's own prompt)
  | 'denied' // human explicitly refused
  | 'observed' // ran without a human decision (bypass/accept-edits/auto)
  | 'granted'; // an explicit rule the human wrote

/** Per-signature learned statistics. */
export interface SignatureStat {
  signature: string;
  capability: Capability;
  /** Decayed counts, by evidence kind. */
  confirmed: number;
  denied: number;
  observed: number;
  /** Undecayed lifetime totals, for honest reporting. */
  totalSeen: number;
  firstSeen: number;
  lastSeen: number;
  /** Distinct session ids and UTC day-stamps observed, capped for size. */
  sessions: number;
  days: number;
  /** Worst blast radius ever seen for this signature. */
  worstBlast: BlastRadius;
  /** Sample display strings, redacted, for the UI. Capped. */
  samples: string[];
  /**
   * Set when the human approved this as part of a reviewed set during setup,
   * rather than by answering a prompt. It counts as attestation — they saw the
   * blast radius and said yes — but the UI must not claim they "approved it 11
   * times", because they did not. They approved it once, deliberately, in bulk.
   */
  grantedAt?: number;
}

/** Scope at which a piece of learning applies. */
export type Scope = 'global' | 'project' | 'session';

/** The learned behaviour envelope for one scope. */
export interface Envelope {
  scope: Scope;
  /** Project key (canonical path hash) when scope === 'project'. */
  key: string;
  /** Last time the envelope was updated. */
  updatedAt: number;
  /** Signature statistics. */
  signatures: Record<string, SignatureStat>;
  /** Observed capability transitions, for sequence novelty. */
  transitions: Record<string, number>;
  /** Capability-level totals. */
  capabilities: Record<string, number>;
  /** Number of events folded in. */
  events: number;
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

export type Decision = 'allow' | 'ask' | 'deny';

/**
 * A single reason contributing to a verdict. Verdicts are built out of these
 * so the UI can render a bulleted "why", and so tests can assert on structure
 * rather than on prose.
 */
export interface Reason {
  /** Stable machine code, e.g. `guard.secret-read`, `familiar.confirmed`. */
  code: string;
  /** Plain-English sentence. No jargon, no scores. */
  text: string;
  /** Which way this reason pushed. */
  weight: 'blocks' | 'raises' | 'lowers' | 'info';
}

export interface Verdict {
  decision: Decision;
  /** The action that drove the verdict (the worst one, if several). */
  action: Action;
  /** All actions considered. */
  actions: Action[];
  /** Ordered, most important first. */
  reasons: Reason[];
  /**
   * Short single sentence for the agent's own permission prompt.
   * This is what the developer actually reads at 2am.
   */
  headline: string;
  /**
   * True when the verdict came from a hard guard that learning can never
   * unlock. Surfaced so the UI can say "this will always ask".
   */
  floor: boolean;
  /** Familiarity summary used, for `leastgrant why`. */
  familiarity?: Familiarity;
}

export interface Familiarity {
  signature: string;
  /** Decayed evidence counts at decision time. */
  confirmed: number;
  denied: number;
  observed: number;
  sessions: number;
  days: number;
  /** Lower bound of a Wilson interval on the approval rate. */
  approvalLowerBound: number;
  /** True if this signature has never been seen in this scope before. */
  novel: boolean;
  /** True if the capability transition into this action is unprecedented. */
  novelTransition: boolean;
  /** Set when this was approved as part of a reviewed set during setup. */
  grantedAt?: number;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/**
 * One append-only record. The ledger is simultaneously the audit trail, the
 * training data, and the replay input for `leastgrant simulate`. It is plain
 * JSONL on purpose: a security tool whose data you cannot read is a worse
 * security tool.
 *
 * Everything written here passes through the redactor first.
 */
export interface LedgerEntry {
  v: 1;
  at: number;
  agent: AgentId;
  sessionId: string;
  project: string;
  branch?: string;
  tool: string;
  /** Redacted display string. */
  display: string;
  signature: string;
  capability: Capability;
  blast: BlastRadius;
  understood: boolean;
  decision: Decision;
  /** Reason codes only; prose is regenerated at read time. */
  reasons: string[];
  /** Agent's own mode, so we can tell confirmed from observed. */
  agentMode?: string;
  /** Filled in later by the outcome watcher, if we learn what happened. */
  outcome?: 'ok' | 'error' | 'rejected';
  /** Decision latency in ms, for the perf budget. */
  ms?: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** How aggressive LeastGrant is allowed to be about auto-approving. */
export type Posture = 'observe' | 'assist' | 'autopilot' | 'strict';

export interface Thresholds {
  /** Minimum distinct sessions. */
  minSessions: number;
  /** Minimum distinct days. Stops a single long session from teaching a habit. */
  minDays: number;
  /** Minimum Wilson lower bound on approval rate. */
  minApproval: number;
  /**
   * Minimum decayed *observations* that may substitute for confirmations,
   * but only for actions at or below `observedMaxTier`.
   */
  minObserved: number;
  /** Highest blast tier promotable at all, from any evidence. */
  maxTier: number;
  /** Half-life for evidence decay, in days. */
  halfLifeDays: number;
}

export interface Config {
  version: 1;
  posture: Posture;
  thresholds: Thresholds;
  /** Explicit user rules, always win over learning. */
  rules: Rule[];
  /** Directories treated as additional workspace roots. */
  additionalRoots: string[];
  /** Extra glob patterns to treat as secrets. */
  secretPatterns: string[];
  /** Disable the ledger entirely (LeastGrant then cannot learn). */
  telemetry: { ledger: boolean };
}

export interface Rule {
  /** Signature glob, e.g. `npm run test*` or `git push *`. */
  match: string;
  effect: Decision;
  /** Where the rule applies. */
  scope: Scope;
  /** Project key when scope === 'project'. */
  key?: string;
  /** Why the human added it — shown in `leastgrant why`. */
  note?: string;
  /** When it was added, and optionally when it lapses. */
  addedAt: number;
  expiresAt?: number;
}

// ---------------------------------------------------------------------------
// Blast tier: a derived ordinal used only for thresholds, never for display
// ---------------------------------------------------------------------------

const REACH_TIER: Record<Reach, number> = {
  none: 0,
  workspace: 1,
  machine: 2,
  network: 2,
  external: 3,
  production: 4,
};

const REVERSIBILITY_TIER: Record<Reversibility, number> = {
  trivial: 0,
  easy: 1,
  hard: 3,
  irreversible: 4,
};

const EXPOSURE_TIER: Record<Exposure, number> = {
  none: 0,
  'reads-secrets': 3,
  'can-exfiltrate': 4,
};

const SCALE_BUMP: Record<Scale, number> = {
  single: 0,
  many: 1,
  sweeping: 2,
};

/**
 * Collapse a blast radius into 0..4 for threshold comparisons.
 *
 * Deliberately a max, not an average: an action that is trivially reversible
 * but reads your SSH key is not "medium risk", it is a secret read. Averaging
 * is how security tools end up approving the one thing that mattered.
 */
export function blastTier(b: BlastRadius): number {
  const base = Math.max(
    REACH_TIER[b.reach],
    REVERSIBILITY_TIER[b.reversibility],
    EXPOSURE_TIER[b.exposure],
  );
  // Scale multiplies harm; it does not create it. Doing a recoverable,
  // project-local thing a thousand times is still recoverable — an `echo` in a
  // loop is not a bigger deal than an `echo`, and a test run that writes a
  // hundred build artifacts is not a bigger deal than one that writes ten.
  //
  // So scale only amplifies where there is something to amplify: the action
  // reaches past the project, or it cannot easily be undone, or it touches
  // credentials. Without this, ordinary work like `npm test` was landing a tier
  // above where it belongs and asking for eleven approvals instead of five.
  const amplifiable =
    REACH_TIER[b.reach] >= 2 ||
    b.reversibility === 'hard' ||
    b.reversibility === 'irreversible' ||
    b.exposure !== 'none';
  return Math.min(4, base + (base > 0 && amplifiable ? SCALE_BUMP[b.scale] : 0));
}

/** Order two blast radii; returns the worse one. */
export function worseBlast(a: BlastRadius, b: BlastRadius): BlastRadius {
  return blastTier(b) > blastTier(a) ? b : a;
}

/** The benign default: a no-op with no reach. */
export const NIL_BLAST: BlastRadius = {
  reach: 'none',
  reversibility: 'trivial',
  exposure: 'none',
  scale: 'single',
};
