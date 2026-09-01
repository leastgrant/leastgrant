/**
 * Shared setup for CLI commands: work out which project we are in, load what
 * has been learned about it, and hand back a context the decision engine can
 * use. Same code path the hook uses, so `leastgrant check` and the live hook
 * cannot disagree.
 */

import type { Config, Envelope } from '../core/types.js';
import { findProjectRoot, projectKey } from '../core/paths.js';
import { newSession, type SessionState } from '../core/envelope.js';
import type { DecideCtx } from '../core/decide.js';
import { loadConfig, loadEnvelope, stateDir } from '../store/index.js';

export interface CliContext {
  cwd: string;
  root: string;
  key: string;
  config: Config;
  envelope: Envelope;
  session: SessionState;
  decideCtx: DecideCtx;
}

export function loadContext(cwd = process.cwd(), sessionId = 'cli'): CliContext {
  const root = findProjectRoot(cwd);
  const key = projectKey(root);
  const config = loadConfig();
  const envelope = loadEnvelope('project', key);
  const session = newSession(sessionId, Date.now());

  const decideCtx: DecideCtx = {
    roots: [root, ...config.additionalRoots],
    secretPatterns: config.secretPatterns,
    config,
    envelope,
    session,
    stateDir: stateDir(),
    projectKey: key,
  };

  return { cwd, root, key, config, envelope, session, decideCtx };
}
