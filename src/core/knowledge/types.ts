/**
 * The knowledge layer: what does this program actually *do*?
 *
 * This is the part of LeastGrant that is opinion rather than mechanism, and
 * therefore the part most worth contributing to. A knowledge module answers one
 * question for a family of programs: given this argv, what capability is being
 * used and how far can it reach?
 *
 * Modules are deliberately small and declarative so that a reviewer can check
 * them by reading, and so that being wrong about `terraform` cannot break
 * `git`.
 */

import type {
  BlastRadius,
  Capability,
  Exposure,
  Reach,
  Reversibility,
  Scale,
  Target,
} from '../types.js';

// Re-exported so knowledge modules have a single import site for everything
// they need. Adding a family should never require reaching into core/types.
export type { BlastRadius, Capability, Exposure, Reach, Reversibility, Scale, Target };

export interface KnowledgeCtx {
  /** Absolute cwd of the agent. */
  cwd: string;
  /** Workspace roots; paths outside these are "outside". */
  roots: string[];
  /** Resolve an argument to a canonical absolute path. */
  resolve(arg: string): string;
  /** True if the canonical path is inside a workspace root. */
  inWorkspace(abs: string): boolean;
  /** True if the canonical path looks like a credential store. */
  isSecret(abs: string): boolean;
  /**
   * True if a *recursive* walk from this path is certain to descend into a
   * credential store — `~`, `/home`, `/etc`, a drive root. See
   * `credentialTreeRoot` in `../secrets.ts`. A classifier only consults this
   * when the invocation actually recurses.
   */
  isCredentialTree(abs: string): boolean;
}

/**
 * A classifier's answer. Only state what differs from the capability's
 * default blast radius — the engine fills in the rest. Keeping these sparse is
 * what stops the knowledge base from turning into thousands of copy-pasted
 * risk tuples that nobody can audit.
 */
export interface Judgement {
  capability: Capability;
  reach?: Reach;
  reversibility?: Reversibility;
  exposure?: Exposure;
  scale?: Scale;
  /** Plain-English clause appended to the explanation, e.g. `rewrites history`. */
  note?: string;
  /**
   * Which argv indices name filesystem paths.
   * `'auto'` (default) treats every non-flag argument that looks like a path
   * as one. `'none'` disables path extraction, for programs whose arguments
   * are not paths (e.g. `kubectl get pods`).
   */
  pathArgs?: number[] | 'auto' | 'none';
  /** Extra non-path targets: hosts, remotes, services, packages. */
  targets?: Target[];
  /**
   * Set when the program's real effect is not knowable from argv alone
   * (a script name, a Makefile target, an interpreter's `-c` payload).
   */
  opaque?: boolean;
}

/**
 * Returns a judgement, or `null` to decline (the next module, then the
 * fallback, gets a turn).
 */
export type Classifier = (argv: string[], ctx: KnowledgeCtx) => Judgement | null;

export interface ProgramKnowledge {
  /** Base program names handled, lowercased, no extension. */
  names: string[];
  /** One-line description, surfaced by `leastgrant knowledge`. */
  describe: string;
  classify: Classifier;
}

/**
 * Default blast radius per capability. Knowledge modules override only what
 * the specific invocation changes.
 *
 * These defaults are the project's actual risk opinions, so they live in one
 * readable table rather than scattered across the codebase.
 */
export const CAPABILITY_DEFAULTS: Record<Capability, BlastRadius> = {
  'fs.read.workspace': { reach: 'workspace', reversibility: 'trivial', exposure: 'none', scale: 'single' },
  'fs.read.outside': { reach: 'machine', reversibility: 'trivial', exposure: 'none', scale: 'single' },
  'fs.write.workspace': { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'single' },
  'fs.write.outside': { reach: 'machine', reversibility: 'hard', exposure: 'none', scale: 'single' },
  'fs.delete': { reach: 'workspace', reversibility: 'hard', exposure: 'none', scale: 'single' },
  'secret.read': { reach: 'machine', reversibility: 'trivial', exposure: 'reads-secrets', scale: 'single' },
  'exec.inspect': { reach: 'workspace', reversibility: 'trivial', exposure: 'none', scale: 'single' },
  'exec.build': { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'many' },
  'exec.test': { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'many' },
  'exec.pkg': { reach: 'machine', reversibility: 'easy', exposure: 'none', scale: 'many' },
  'exec.pkg.publish': { reach: 'external', reversibility: 'irreversible', exposure: 'none', scale: 'single' },
  'exec.vcs.read': { reach: 'workspace', reversibility: 'trivial', exposure: 'none', scale: 'single' },
  'exec.vcs.write': { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'many' },
  'exec.vcs.publish': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'many' },
  'exec.container': { reach: 'machine', reversibility: 'easy', exposure: 'none', scale: 'many' },
  'exec.cloud': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'many' },
  'exec.iac': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'sweeping' },
  'exec.db': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'many' },
  'exec.process': { reach: 'machine', reversibility: 'easy', exposure: 'none', scale: 'single' },
  'exec.privilege': { reach: 'machine', reversibility: 'hard', exposure: 'none', scale: 'many' },
  'exec.remote': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'many' },
  'exec.unknown': { reach: 'machine', reversibility: 'hard', exposure: 'none', scale: 'single' },
  'net.fetch': { reach: 'network', reversibility: 'trivial', exposure: 'none', scale: 'single' },
  'net.send': { reach: 'network', reversibility: 'irreversible', exposure: 'can-exfiltrate', scale: 'single' },
  'mcp.call': { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'single' },
  'agent.spawn': { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'many' },
  meta: { reach: 'none', reversibility: 'trivial', exposure: 'none', scale: 'single' },
};

/** Fill a sparse judgement into a complete blast radius. */
export function toBlast(j: Judgement): BlastRadius {
  const base = CAPABILITY_DEFAULTS[j.capability];
  return {
    reach: j.reach ?? base.reach,
    reversibility: j.reversibility ?? base.reversibility,
    exposure: j.exposure ?? base.exposure,
    scale: j.scale ?? base.scale,
  };
}

// --- small helpers shared by knowledge modules -----------------------------

/** First argument that is not an option flag, from index `from`. */
export function firstNonFlag(argv: string[], from = 1): string | undefined {
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return argv[i + 1];
    if (!a.startsWith('-')) return a;
  }
  return undefined;
}

/** All non-flag arguments from index `from`. */
export function nonFlags(argv: string[], from = 1): string[] {
  const out: string[] = [];
  let sawDashDash = false;
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--' && !sawDashDash) {
      sawDashDash = true;
      continue;
    }
    if (!sawDashDash && a.startsWith('-') && a !== '-') continue;
    out.push(a);
  }
  return out;
}

/** True if any of `flags` appears in argv (exact match or `--flag=value`). */
export function hasFlag(argv: string[], ...flags: string[]): boolean {
  return argv.some((a, i) => i > 0 && flags.some((f) => a === f || a.startsWith(f + '=')));
}

/** Value of `--flag value` or `--flag=value`. */
export function flagValue(argv: string[], ...flags: string[]): string | undefined {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    for (const f of flags) {
      if (a === f) return argv[i + 1];
      if (a.startsWith(f + '=')) return a.slice(f.length + 1);
    }
  }
  return undefined;
}

/** Extract a hostname from a URL-ish argument, if there is one. */
export function hostOf(arg: string): string | undefined {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/:?#\s]+)/i.exec(arg);
  if (m) return m[1]!.toLowerCase();
  // bare host:port/path or host/path
  const b = /^([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?(?:\/|$)/i.exec(arg);
  return b ? b[1]!.toLowerCase() : undefined;
}
