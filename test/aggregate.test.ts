/**
 * A security fact may only come from a fold across every action, never from
 * whichever action won the election.
 *
 * One request becomes N actions. The engine judges each, sorts them, and lets
 * the first stand for the set in the sentences it writes. That is fine for
 * prose and wrong for anything a consumer branches on, and the same mistake has
 * now been made three times in three fields:
 *
 *   floor    read off `worst` — fixed earlier, `rm -rf ./build && cat ~/.ssh/id_rsa`
 *            reported no floor because the delete outranked the credential read.
 *   taint    read off `worst` — fixed here. Appending a delete to an
 *            exfiltration-shaped call removed the prompt entirely.
 *   floor    folded from `hits` rather than from the guards that actually held —
 *            fixed here. A standing allow rule made an unrelated sibling look
 *            floored, which pushed Codex into a hard deny.
 *
 * Three instances of one rule being broken is a sign the rule needs a test that
 * names it, so these assert the mechanism — flooredGuards, the per-action taint
 * evaluation, the totality of the election order — rather than only the verdict
 * a particular payload happens to produce.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config, Rule } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, applyTaint, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';

const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'leastgrant-aggregate-'));
fs.mkdirSync(path.join(WS, '.git'), { recursive: true });
fs.writeFileSync(path.join(WS, '.env'), 'TOKEN=x');
fs.writeFileSync(path.join(WS, 'script.sh'), '#!/bin/sh\n');
const STATE = path.join(os.tmpdir(), 'leastgrant-aggregate-state');
const AT = 1_760_000_000_000;

const rule = (match: string, effect: 'allow' | 'deny'): Rule => ({
  match,
  effect,
  scope: 'global',
  addedAt: 0,
});

function ctxFor(opts: { rules?: Rule[]; taint?: 'secret.read' | 'exec.pkg' } = {}) {
  const session = newSession('s', AT);
  if (opts.taint) applyTaint(session, opts.taint);
  const config: Config = {
    ...DEFAULT_CONFIG,
    thresholds: { ...DEFAULT_THRESHOLDS },
    rules: opts.rules ?? [],
  };
  return {
    roots: [WS],
    secretPatterns: [],
    config,
    envelope: newEnvelope('project', WS),
    session,
    stateDir: STATE,
    projectKey: WS,
  };
}

const run = (command: string, opts?: Parameters<typeof ctxFor>[0]) =>
  decide(
    { agent: 't', tool: 'Bash', input: { command }, cwd: WS, sessionId: 's', at: AT },
    ctxFor(opts),
  );

describe('taint is evaluated for every action, not just the elected one', () => {
  // The session has already read a credential, and both commands are covered by
  // standing allow rules — so nothing except the taint stands between the agent
  // and an unprompted outbound call.
  const RULES = [rule('rm <path> -rf', 'allow'), rule('curl <url:example.com>', 'allow')];

  test('the outbound call alone asks, because the session is tainted', () => {
    const v = run('curl https://example.com', { rules: RULES, taint: 'secret.read' });
    assert.equal(v.decision, 'ask');
    assert.ok(v.reasons.some((r) => r.code === 'session.taint'));
  });

  test('appending a delete does not remove the prompt', () => {
    // The delete has the larger blast tier, so it wins the election, and
    // `fs.delete` has no taint rule. Reading the concern off the winner
    // therefore returned null and the whole compound came back ALLOW: adding a
    // second, unrelated action to a request made it *less* gated than the
    // request without it.
    const v = run('rm -rf ./build && curl https://example.com', {
      rules: RULES,
      taint: 'secret.read',
    });
    assert.equal(v.decision, 'ask', `masked by the delete: ${v.headline}`);
    assert.ok(v.reasons.some((r) => r.code === 'session.taint'));
  });

  test('the order the agent lists them in does not matter', () => {
    const a = run('rm -rf ./build && curl https://example.com', { rules: RULES, taint: 'secret.read' });
    const b = run('curl https://example.com && rm -rf ./build', { rules: RULES, taint: 'secret.read' });
    assert.equal(a.decision, b.decision);
    assert.equal(a.floor, b.floor);
  });

  test('an untainted session is not made to ask by the same command', () => {
    // Guards the other direction: if this asked regardless of taint the tests
    // above would pass while proving nothing about taint at all.
    const v = run('rm -rf ./build && curl https://example.com', { rules: RULES });
    assert.equal(v.decision, 'allow', `no taint, both rules allow, so this should not ask: ${v.headline}`);
  });
});

describe('floor counts the guards that held, not the guards that fired', () => {
  test('a credential read on its own is a floor', () => {
    const v = run('cat .env');
    assert.equal(v.floor, true);
    assert.deepEqual(v.flooredGuards, ['guard.secret-read']);
  });

  test('a standing allow rule waives it, and the verdict stops claiming a floor', () => {
    const v = run('cat .env', { rules: [rule('cat <path:secret>', 'allow')] });
    assert.equal(v.decision, 'allow');
    assert.equal(v.floor, false, 'floor means "this will always ask", and it just allowed');
    assert.deepEqual(v.flooredGuards, []);
    // Still reported, because the developer should see what their rule covered.
    assert.ok(v.reasons.some((r) => r.code === 'guard.secret-read'));
  });

  test('a waived guard on one action does not floor its sibling', () => {
    // The reported failure: with a rule on the credential read, Codex hard-denied
    // `cat .env && ./script.sh` under bypassPermissions, while `./script.sh`
    // alone abstained — because the compound's reason list gained a
    // `guard.secret-read` the rule had already answered. Adding a rule to remove
    // friction created it in a different agent, on an unrelated command.
    const rules = [rule('cat <path:secret>', 'allow')];
    const alone = run('./script.sh', { rules });
    const compound = run('cat .env && ./script.sh', { rules });

    assert.deepEqual(
      compound.flooredGuards.slice().sort(),
      alone.flooredGuards.slice().sort(),
      'the rule-covered read added a constraint that was not constraining anything',
    );
  });

  test('an unwaived sibling guard still floors — the earlier fix stays fixed', () => {
    const v = run('rm -rf ./build && cat .env');
    assert.equal(v.floor, true);
    assert.ok(
      v.flooredGuards.includes('guard.secret-read'),
      'the credential read loses the election on blast tier; its guard must survive anyway',
    );
  });
});

describe('the election is a total order', () => {
  test('reordering equally-ranked actions does not change the outcome', () => {
    // Before, ties fell back to input order, which handed the choice of
    // representative to the agent whose request is being judged.
    const a = run('cat .env && ./script.sh');
    const b = run('./script.sh && cat .env');
    assert.equal(a.decision, b.decision);
    assert.equal(a.floor, b.floor);
    assert.deepEqual(a.flooredGuards.slice().sort(), b.flooredGuards.slice().sort());
    assert.equal(a.action.signature, b.action.signature, 'the elected action should not depend on ordering');
  });
});

describe('adding an action never makes a request more permissive', () => {
  // The general law the three bugs each broke. Not exhaustive — a property test
  // over generated compounds belongs here eventually — but these are the shapes
  // that actually failed.
  const RANK = { allow: 0, ask: 1, deny: 2 } as const;
  const CASES: Array<[string, string]> = [
    ['curl https://example.com', 'rm -rf ./build && curl https://example.com'],
    ['cat .env', 'echo hi && cat .env'],
    ['./script.sh', 'echo hi && ./script.sh'],
    ['cat .env', 'rm -rf ./build && cat .env'],
  ];

  for (const [part, whole] of CASES) {
    test(`"${whole}" is at least as gated as "${part}"`, () => {
      const p = run(part, { taint: 'secret.read' });
      const w = run(whole, { taint: 'secret.read' });
      assert.ok(
        RANK[w.decision] >= RANK[p.decision],
        `adding an action relaxed the verdict: ${p.decision} -> ${w.decision}`,
      );
      assert.ok(!p.floor || w.floor, 'adding an action removed a floor');
    });
  }
});
