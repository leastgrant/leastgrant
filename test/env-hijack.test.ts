/**
 * Learned trust must not transfer between environment variables.
 *
 * The corpus in `corpus/bypasses.json` asserts that each of these commands is
 * not auto-approved. This file asserts the thing underneath, which is stronger
 * and is what actually broke: that the *identity* LeastGrant learns for an
 * assignment includes the variable name.
 *
 * The bug it exists for. `export CACHE_DIR=/tmp/build` and
 * `export LD_PRELOAD=/tmp/evil.so` both normalized to `export <path>`, because
 * `commandSignature` templated the whole `NAME=value` token as an argument that
 * happened to look like a path. Forty sessions of the first — an ordinary build
 * step — auto-approved the second, along with BASH_ENV, NODE_OPTIONS and
 * PYTHONSTARTUP. The inline spelling `LD_PRELOAD=x git status` was never
 * affected: it goes through `assignmentSignature`, whose comment has said "the
 * names are what matter" since it was written.
 *
 * So the corpus case alone would not have been enough. A future refactor could
 * make these ask for some incidental reason — unfamiliarity, a tier change —
 * while quietly restoring the shared signature, and the corpus would stay
 * green while the hole reopened. These tests name the mechanism.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import { analyze } from '../src/core/classify.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';

const WS = path.join(os.tmpdir(), 'leastgrant-envhijack-ws');
const DAY = 86_400_000;
const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

const sigOf = (command: string): string => {
  const a = analyze(
    { agent: 't', tool: 'Bash', input: { command }, cwd: WS, sessionId: 's', at: Date.now() },
    { roots: [WS], secretPatterns: [] },
  );
  return a.actions[0]?.signature ?? '(none)';
};

/** An envelope saturated with approvals for one benign assignment. */
function trainedOnBenignExport(at = Date.now()) {
  const envelope = newEnvelope('project', WS);
  for (let i = 0; i < 40; i++) {
    const a = analyze(
      {
        agent: 't',
        tool: 'Bash',
        input: { command: 'export CACHE_DIR=/tmp/build' },
        cwd: WS,
        sessionId: `s${i}`,
        at: at - (40 - i) * DAY,
      },
      { roots: [WS], secretPatterns: [] },
    );
    for (const action of a.actions) {
      observe(envelope, {
        signature: action.signature,
        capability: action.capability,
        blast: action.blast,
        evidence: 'confirmed',
        at: at - (40 - i) * DAY,
        sessionId: `s${i}`,
        display: action.display,
      });
    }
  }
  return {
    roots: [WS],
    secretPatterns: [],
    config,
    envelope,
    session: newSession('attack', at),
    stateDir: path.join(os.tmpdir(), 'leastgrant-envhijack-state'),
    projectKey: WS,
  };
}

const HIJACKS = [
  'export LD_PRELOAD=/tmp/evil.so',
  'export BASH_ENV=/tmp/evil.sh',
  'export NODE_OPTIONS=--require=/tmp/evil.js',
  'export PYTHONSTARTUP=/tmp/evil.py',
  'export GIT_SSH_COMMAND=/tmp/evil.sh',
  'export PATH=/tmp/evil:$PATH',
];

describe('an assignment is learned under the variable name, not just its shape', () => {
  test('the benign training command is genuinely learnable', () => {
    // Without this the suite could pass by making everything ask, which would
    // fix the hole by breaking the product.
    const ctx = trainedOnBenignExport();
    const v = decide(
      { agent: 't', tool: 'Bash', input: { command: 'export CACHE_DIR=/tmp/build' }, cwd: WS, sessionId: 'attack', at: Date.now() },
      ctx,
    );
    assert.equal(v.decision, 'allow', `the benign export should settle, got ${v.decision}: ${v.headline}`);
  });

  for (const cmd of HIJACKS) {
    test(`${cmd} does not share a signature with the benign export`, () => {
      assert.notEqual(
        sigOf(cmd),
        sigOf('export CACHE_DIR=/tmp/build'),
        'the variable name was templated away, so trust in one assignment covers the other',
      );
    });

    test(`${cmd} is not auto-approved by trust in the benign export`, () => {
      const ctx = trainedOnBenignExport();
      const v = decide(
        { agent: 't', tool: 'Bash', input: { command: cmd }, cwd: WS, sessionId: 'attack', at: Date.now() },
        ctx,
      );
      assert.notEqual(v.decision, 'allow', `AUTO-APPROVED ${cmd}: ${v.headline}`);
    });

    test(`${cmd} reports a floor, so an adapter denies rather than standing aside`, () => {
      // Load-bearing beyond the verdict. The Codex adapter abstains when floor
      // is false, on the reasoning that "merely unfamiliar" is for the agent's
      // own prompt to handle — and in an unattended mode nothing prompts, so
      // the call runs. An environment hijack must be floor=true or it is
      // ungated there regardless of what `decision` says.
      const ctx = trainedOnBenignExport();
      const v = decide(
        { agent: 't', tool: 'Bash', input: { command: cmd }, cwd: WS, sessionId: 'attack', at: Date.now() },
        ctx,
      );
      assert.equal(v.floor, true, `${cmd} has no floor, so Codex would stand aside: ${v.headline}`);
    });
  }

  test('alias is covered too, because it redefines a program by name', () => {
    assert.notEqual(sigOf('alias git=/tmp/evil.sh'), sigOf('alias ll=/tmp/other.sh'));
    const ctx = trainedOnBenignExport();
    const v = decide(
      { agent: 't', tool: 'Bash', input: { command: 'alias git=/tmp/evil.sh' }, cwd: WS, sessionId: 'attack', at: Date.now() },
      ctx,
    );
    assert.notEqual(v.decision, 'allow', `AUTO-APPROVED an alias redefinition: ${v.headline}`);
    assert.equal(v.floor, true);
  });

  test('an ordinary variable is still ordinary', () => {
    // The fix must not turn every assignment into a floor. `export NODE_ENV=test`
    // is the single most common thing in this family and making it prompt would
    // be exactly the approval fatigue the product exists to remove.
    const a = analyze(
      { agent: 't', tool: 'Bash', input: { command: 'export NODE_ENV=test' }, cwd: WS, sessionId: 's', at: Date.now() },
      { roots: [WS], secretPatterns: [] },
    );
    assert.equal(a.actions[0]?.capability, 'meta', 'a harmless assignment should stay housekeeping');
    assert.equal(a.actions[0]?.understood, true);
  });
});
