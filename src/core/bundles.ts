/**
 * Turning observed history into a proposal a human can actually read.
 *
 * A developer who has been running their agent unsupervised has thousands of
 * observed actions and zero approvals. LeastGrant will not treat observation as
 * consent — that is the whole point of the design — so on day one it would ask
 * about almost everything, which is useless.
 *
 * The way out is not to weaken the rule. It is to *ask once, properly*: group
 * what the agent has actually been doing into a handful of plain-English
 * bundles, show what each one covers and what it pointedly does not, and let
 * the human approve the set in one deliberate act.
 *
 * That approval is real attestation — they saw the blast radius and said yes —
 * so it flows through the ordinary pipeline as `granted` evidence. Every floor
 * still applies on top of it. Approving "edit files in this project" does not
 * approve editing `.bashrc`, because the persistence floor is not something a
 * grant can reach.
 */

import type { Capability, Envelope } from './types.js';
import { blastTier } from './types.js';

export interface Bundle {
  id: string;
  /** Imperative, plain English. What the user is being asked to allow. */
  title: string;
  /** One line of detail. */
  detail: string;
  /** What this pointedly does NOT cover — the reason it is safe to say yes. */
  excludes: string;
  capabilities: Capability[];
  /** Signatures in the observed history that this bundle would cover. */
  signatures: string[];
  /** How many times those signatures have been seen. */
  occurrences: number;
  /** Whether to pre-select it. */
  recommended: boolean;
}

interface BundleSpec {
  id: string;
  title: string;
  detail: string;
  excludes: string;
  capabilities: Capability[];
  recommended: boolean;
}

/**
 * Ordered least- to most-consequential. The first three are pre-selected
 * because they are the ordinary substance of using a coding agent and are all
 * either read-only or recoverable from version control. The rest are offered
 * but not pre-selected — installing packages runs third-party install scripts,
 * and an MCP server is a black box, so those deserve a deliberate yes.
 */
const SPECS: BundleSpec[] = [
  {
    id: 'read',
    title: 'Read and search files in your projects',
    detail: 'opening, listing and grepping files inside a project directory',
    excludes: 'not files outside the project, and not anything that looks like a credential',
    capabilities: ['fs.read.workspace', 'exec.inspect'],
    recommended: true,
  },
  {
    id: 'git-read',
    title: 'Look at git state',
    detail: 'status, diff, log, branch listings — reading, never changing',
    excludes: 'not commits, not pushes, not anything that rewrites history',
    capabilities: ['exec.vcs.read'],
    recommended: true,
  },
  {
    id: 'edit',
    title: 'Edit and create files inside your projects',
    detail: 'the ordinary work of a coding agent, all of it recoverable from version control',
    excludes:
      'not files outside the project, not shell profiles or git hooks, not anything credential-shaped',
    capabilities: ['fs.write.workspace'],
    recommended: true,
  },
  {
    id: 'build',
    title: 'Run your build and test commands',
    detail: 'the specific build and test commands already seen in this history',
    excludes: 'not arbitrary scripts, and not commands that have not run here before',
    capabilities: ['exec.build', 'exec.test'],
    recommended: true,
  },
  {
    id: 'git-write',
    title: 'Make local git commits and branches',
    detail: 'staging, committing, branching, stashing — all of it still on your machine',
    excludes: 'not push, not force-push, not tag deletion, nothing that leaves the machine',
    capabilities: ['exec.vcs.write'],
    recommended: false,
  },
  {
    id: 'packages',
    title: 'Install dependencies',
    detail: 'package manager installs, which run third-party install scripts on this machine',
    excludes: 'not publishing, not global installs, not registry credential changes',
    capabilities: ['exec.pkg'],
    recommended: false,
  },
  {
    id: 'mcp',
    title: 'Call the MCP servers you already use',
    detail: 'read-shaped calls to MCP servers seen in this history',
    excludes: 'not MCP calls whose names suggest they change or run something',
    capabilities: ['mcp.call'],
    recommended: false,
  },
];

export interface ProposeOptions {
  /** Minimum times a signature must have been seen to be worth including. */
  minOccurrences?: number;
  /** Highest blast tier a bundle may include. */
  maxTier?: number;
}

/**
 * Build the proposal from one or more learned envelopes.
 *
 * A signature is eligible only if it has never been denied, its worst observed
 * blast radius is within the ceiling, and it is not credential-adjacent. Those
 * checks are belt-and-braces — the floors would catch such an action anyway at
 * decision time — but a proposal that *listed* something alarming would
 * undermine the point of asking.
 */
export function proposeBundles(envelopes: Envelope[], opts: ProposeOptions = {}): Bundle[] {
  const minOccurrences = opts.minOccurrences ?? 3;
  const maxTier = opts.maxTier ?? 2;

  const out: Bundle[] = [];

  for (const spec of SPECS) {
    const caps = new Set<Capability>(spec.capabilities);
    const signatures = new Set<string>();
    let occurrences = 0;

    for (const env of envelopes) {
      for (const s of Object.values(env.signatures)) {
        if (!caps.has(s.capability)) continue;
        if (s.denied > 0) continue;
        if (s.totalSeen < minOccurrences) continue;
        if (blastTier(s.worstBlast) > maxTier) continue;
        if (s.worstBlast.exposure !== 'none') continue;
        if (spec.id === 'mcp' && !isReadShapedMcp(s.signature)) continue;
        signatures.add(s.signature);
        occurrences += s.totalSeen;
      }
    }

    if (!signatures.size) continue;
    out.push({
      id: spec.id,
      title: spec.title,
      detail: spec.detail,
      excludes: spec.excludes,
      capabilities: spec.capabilities,
      signatures: [...signatures],
      occurrences,
      recommended: spec.recommended,
    });
  }

  return out.sort((a, b) => b.occurrences - a.occurrences);
}

/**
 * An MCP tool name that reads rather than changes.
 *
 * Mirrors the verb heuristic in classify.ts. Kept as its own small check here
 * because a proposal is a stronger statement than a per-call judgement, and it
 * should err further toward caution: anything not clearly a read is left out.
 */
function isReadShapedMcp(signature: string): boolean {
  const tool = signature.split('__')[2] ?? '';
  const verb = tool.toLowerCase().split(/[_-]/)[0] ?? '';
  return [
    'get', 'list', 'read', 'search', 'find', 'fetch', 'query', 'describe',
    'show', 'view', 'preview', 'inspect', 'check', 'count', 'lookup', 'logs',
    'screenshot', 'snapshot', 'status',
  ].includes(verb);
}

/** Total actions a set of bundles would stop asking about. */
export function coverageOf(bundles: Bundle[]): number {
  return bundles.reduce((n, b) => n + b.occurrences, 0);
}
