/**
 * A list argument is judged by everything in it, not by its first element.
 *
 * `shapeValue` templated an array as `<list of ${shape(v[0])}>`, for a reason
 * that is still valid — a five-hundred-item batch must not produce a
 * five-hundred-fragment signature. The implementation of that reason threw away
 * everything after index zero, so
 *
 *     read_multiple_files({ paths: ['src/a.ts', '~/.ssh/id_rsa'] })
 *
 * signed byte-identically to a read of two project files, and approvals of the
 * ordinary batch promoted the one with the key in it. The tell that this was a
 * bug rather than a policy: a credential in position *zero* did change the
 * signature. The distinction was always meant to survive templating; it just
 * stopped after the first element.
 *
 * Second half of the same hole: an MCP call produced exactly one target — the
 * server — and `exposure: 'none'` unconditionally, so `guard.secret-read`,
 * which is gated on exposure or capability, could not fire for an MCP call at
 * all. There was no backstop. A filesystem MCP server reading a private key was
 * an `mcp.call` to `filesystem` and nothing else.
 *
 * These assert the mechanism — the signature, the capability, the exposure —
 * rather than only the verdict, because a verdict can come out right for the
 * wrong reason (an unfamiliar action asks too) and would keep passing if the
 * collapse came back.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config } from '../src/core/types.js';
import { analyze } from '../src/core/classify.js';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, observe, applyTaint, taintConcern, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';

const WS = path.join(os.tmpdir(), 'leastgrant-mcp-batch-ws');
const KEY = path.join(os.homedir(), '.ssh', 'id_rsa');
const BATCH = 'mcp__filesystem__read_multiple_files';
const DAY = 86_400_000;
const AT = 1_760_000_000_000;

const act = (tool: string, input: Record<string, unknown>) => {
  const a = analyze(
    { agent: 't', tool, input, cwd: WS, sessionId: 's', at: AT },
    { roots: [WS], secretPatterns: [] },
  );
  return a.actions[0]!;
};

describe('an MCP list argument is judged by all of it', () => {
  test('a credential after the first element changes the identity', () => {
    const benign = act(BATCH, { paths: ['src/a.ts', 'src/b.ts'] });
    const attack = act(BATCH, { paths: ['src/a.ts', KEY] });
    assert.notEqual(
      attack.signature,
      benign.signature,
      'a batch containing a private key learned the same identity as an ordinary one',
    );
  });

  test('and it is recognised as a credential read, not merely a different call', () => {
    // Without this the signature fix alone would only mean "unfamiliar", which
    // wears off after enough approvals. The floor is what makes it permanent.
    const attack = act(BATCH, { paths: ['src/a.ts', KEY] });
    assert.equal(attack.capability, 'secret.read');
    assert.equal(attack.blast.exposure, 'reads-secrets');
    assert.ok(
      attack.targets.some((t) => t.type === 'path' && t.secret),
      'no credential target, so guard.secret-read has nothing to fire on',
    );
  });

  test('position does not matter, and neither does order', () => {
    const first = act(BATCH, { paths: [KEY, 'src/a.ts'] });
    const second = act(BATCH, { paths: ['src/a.ts', KEY] });
    assert.equal(first.capability, 'secret.read');
    assert.equal(second.capability, 'secret.read');
    // Sorted, so shuffling the same set cannot mint a second identity that
    // would have to be learned — or approved — separately.
    assert.equal(first.signature, second.signature);
  });

  test('a uniform batch of any size is still one fragment', () => {
    // The property the original `v[0]` was protecting. It has to survive the
    // fix or the signature grows with the payload, which is both unreadable and
    // a memory concern on a hot path.
    const many = act(BATCH, { paths: Array.from({ length: 500 }, (_, i) => `src/f${i}.ts`) });
    const two = act(BATCH, { paths: ['src/a.ts', 'src/b.ts'] });
    assert.equal(many.signature, two.signature);
  });

  test('a deliberately heterogeneous list cannot grow the signature without bound', () => {
    const wild = act(BATCH, {
      paths: ['src/a.ts', 42, true, null, { a: 1 }, ['x'], 'other.txt', 3.5, false],
    } as unknown as Record<string, unknown>);
    assert.ok(wild.signature.length < 200, `signature grew to ${wild.signature.length} chars`);
  });

  test('it is not filesystem-specific', () => {
    // The collapse was in the templater, so every batch-shaped MCP tool had it.
    const one = act('mcp__db__query', { statements: ['select 1'] });
    const two = act('mcp__db__query', { statements: ['select 1', 'drop table users'] });
    assert.notEqual(one.signature, two.signature);
  });

  test('an ordinary batch is untouched', () => {
    // The cost check. Reading project files in bulk is what these servers are
    // for, and it must stay learnable.
    const benign = act(BATCH, { paths: ['src/a.ts', 'src/b.ts'] });
    assert.equal(benign.capability, 'mcp.call');
    assert.equal(benign.blast.exposure, 'none');
  });
});

describe('learning an ordinary batch does not buy the one with a key in it', () => {
  const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

  function trained() {
    const envelope = newEnvelope('project', WS);
    for (let i = 0; i < 40; i++) {
      const a = analyze(
        { agent: 't', tool: BATCH, input: { paths: ['src/a.ts', 'src/b.ts'] }, cwd: WS, sessionId: `s${i}`, at: AT - (40 - i) * DAY },
        { roots: [WS], secretPatterns: [] },
      );
      for (const x of a.actions)
        observe(envelope, {
          signature: x.signature, capability: x.capability, blast: x.blast,
          evidence: 'confirmed', at: AT - (40 - i) * DAY, sessionId: `s${i}`, display: x.display,
        });
    }
    return {
      roots: [WS], secretPatterns: [], config, envelope,
      session: newSession('attack', AT),
      stateDir: path.join(os.tmpdir(), 'leastgrant-mcp-batch-state'),
      projectKey: WS,
    };
  }

  const verdict = (input: Record<string, unknown>) =>
    decide({ agent: 't', tool: BATCH, input, cwd: WS, sessionId: 'attack', at: AT }, trained());

  test('the ordinary batch settles, or this proves nothing', () => {
    const v = verdict({ paths: ['src/a.ts', 'src/b.ts'] });
    assert.equal(v.decision, 'allow', `the benign batch never settled: ${v.headline}`);
  });

  test('the same call with a private key in it does not', () => {
    const v = verdict({ paths: ['src/a.ts', KEY] });
    assert.notEqual(v.decision, 'allow', `AUTO-APPROVED a credential read: ${v.headline}`);
    assert.equal(v.floor, true, 'no floor, so an adapter that cannot ask would stand aside');
  });
});

describe('an MCP call is a call to a server', () => {
  test('a credential read through MCP taints the session', () => {
    // Without this the sequence guard is blind to the whole MCP surface: the
    // credential is read, nothing is recorded, and the outbound call that
    // follows sees a clean session.
    const a = act('mcp__filesystem__read_file', { path: KEY });
    const s = newSession('x', AT);
    applyTaint(s, a.capability);
    assert.ok(s.taints.has('read-secrets'), `capability was ${a.capability}, which taints nothing`);
  });

  test('and a later MCP call is treated as somewhere data can go', () => {
    // `curl` was covered and `mcp__slack__post_message` was not, so the same
    // exfiltration performed through a tool raised nothing. Whether the server
    // is local or across the internet is not visible from here, and the
    // arguments are arbitrary JSON the agent composed.
    const s = newSession('y', AT);
    applyTaint(s, 'secret.read');
    const call = act('mcp__slack__post_message', { text: 'hi' });
    assert.ok(
      taintConcern(s, call.capability, call.blast),
      'reading a key then handing data to an MCP server raised nothing',
    );
  });

  test('an untainted session is not made to worry by the same call', () => {
    const s = newSession('z', AT);
    const call = act('mcp__slack__post_message', { text: 'hi' });
    assert.equal(taintConcern(s, call.capability, call.blast), null);
  });
});

describe('a SQL statement that carries more statements is not its first verb', () => {
  test('stacking a drop onto a select changes the identity', () => {
    const read = act('mcp__db__query', { statements: ['select 1'] });
    const stacked = act('mcp__db__query', { statements: ['select 1; drop table users'] });
    assert.notEqual(
      stacked.signature,
      read.signature,
      'approvals of an ordinary read would cover a table drop appended to it',
    );
  });

  test('a semicolon inside a string is punctuation, not a second statement', () => {
    // The cost check. Over-splitting would give every query containing a
    // semicolon in its data a separate identity, which is friction with no
    // safety behind it.
    const plain = act('mcp__db__query', { statements: ['select 1'] });
    const quoted = act('mcp__db__query', { statements: ["select 'a; b'"] });
    assert.equal(quoted.signature, plain.signature);
  });

  test('a trailing semicolon is punctuation too', () => {
    const plain = act('mcp__db__query', { statements: ['select 1'] });
    const trailing = act('mcp__db__query', { statements: ['select 1;'] });
    assert.equal(trailing.signature, plain.signature);
  });
});
