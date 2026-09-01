/**
 * The programmatic API.
 *
 * LeastGrant is primarily a CLI and a hook, but the decision engine is useful
 * on its own — that is how you write an adapter for an agent nobody has
 * supported yet, or embed the same judgement in your own tooling. Everything
 * exported here is deliberate and covered by tests; nothing else is public.
 *
 * The engine is pure: `decide()` reads no files and writes none. Path
 * resolution touches the filesystem (it has to, to follow a symlink), but
 * nothing here mutates state. Persisting what you learn is a separate,
 * explicit step.
 *
 *     import { decide, analyze, newEnvelope, newSession } from 'leastgrant';
 *
 *     const verdict = decide(
 *       { agent: 'my-agent', tool: 'Bash', input: { command: 'rm -rf /' },
 *         cwd: process.cwd(), sessionId: 'abc', at: Date.now() },
 *       { roots: [process.cwd()], secretPatterns: [], config, envelope,
 *         session, stateDir, projectKey },
 *     );
 *     verdict.decision;  // 'allow' | 'ask' | 'deny'
 *     verdict.headline;  // a sentence you can show a human
 */

// --- the decision ----------------------------------------------------------
export { decide, describeBlast, friendly, matchRule, type DecideCtx } from './core/decide.js';
export { analyze, normalizeTool, registerKnowledge, type AnalyzeCtx, type Analysis, type ToolKind } from './core/classify.js';
export { checkGuards, guardDecision, type GuardCtx, type GuardHit } from './core/guards.js';

// --- the domain model ------------------------------------------------------
export type {
  Action,
  ActionKind,
  AgentId,
  BlastRadius,
  Capability,
  Config,
  Decision,
  Envelope,
  EvidenceKind,
  Exposure,
  Familiarity,
  LedgerEntry,
  Posture,
  Reach,
  Reason,
  Request,
  Reversibility,
  Rule,
  Scale,
  Scope,
  SignatureStat,
  Target,
  Thresholds,
  Verdict,
} from './core/types.js';
export { blastTier, worseBlast, NIL_BLAST } from './core/types.js';

// --- learning --------------------------------------------------------------
export {
  applyTaint,
  approvalsNeededFor,
  canPromote,
  confidenceFor,
  familiarity,
  newEnvelope,
  newSession,
  noveltyRate,
  observe,
  taintConcern,
  wilsonLowerBound,
  CONFIDENCE_BY_TIER,
  DEFAULT_THRESHOLDS,
  type SessionState,
  type Taint,
} from './core/envelope.js';

// --- writing an adapter or a knowledge module ------------------------------
export { parseShell, type ParsedCommand, type ParsedShell } from './core/shell/parse.js';
export { effectiveCommands, unwrap, baseName, type EffectiveCommand } from './core/shell/unwrap.js';
export { tokenize, scanSubstitutions, findSubstitutions, type Token } from './core/shell/tokenize.js';
export {
  CAPABILITY_DEFAULTS,
  toBlast,
  firstNonFlag,
  flagValue,
  hasFlag,
  hostOf,
  nonFlags,
  type Classifier,
  type Judgement,
  type KnowledgeCtx,
  type ProgramKnowledge,
} from './core/knowledge/types.js';

// --- paths, secrets, identity ----------------------------------------------
export {
  candidatesOf,
  canonicalize,
  canonicalDir,
  canonicalRoots,
  displayPath,
  findProjectRoot,
  inWorkspace,
  isInside,
  looksLikePath,
  projectKey,
  resolvePhysical,
  samePath,
  type CanonicalPath,
  type PathIO,
} from './core/paths.js';
export { classifySecretPath, containsSecretLike, globMatch, redact, type SecretMatch } from './core/secrets.js';
export { commandSignature, familyOf, normalizeArg, toolSignature, type SignatureCtx } from './core/signature.js';

// --- state -----------------------------------------------------------------
export {
  DEFAULT_CONFIG,
  addRule,
  appendLedger,
  loadConfig,
  loadEnvelope,
  readLedger,
  removeRule,
  saveConfig,
  saveEnvelope,
  stateDir,
} from './store/index.js';

// --- replay ----------------------------------------------------------------
export { replay, type ReplayEvent, type ReplayOptions, type ReplayResult } from './replay.js';
export { proposeBundles, coverageOf, type Bundle } from './core/bundles.js';
