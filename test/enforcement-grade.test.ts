/**
 * Grading what each agent actually enforces.
 *
 * `assess()` turns the compatibility data into the one-line answer shown by
 * `leastgrant doctor` and by the website. Both call it, so it is the single
 * place where "what does this agent give me" is decided — and a grading rule is
 * exactly the kind of thing that reads as reasonable and is quietly wrong, so
 * the interesting tests here are about the distinctions it must NOT collapse.
 *
 * The one that matters most: an ask that degrades is not an ask that does not
 * exist. On Claude Code a prompt reaches a person whenever a person is there,
 * and becomes a deny when nobody is. On Codex there is no ask at any time in
 * any mode. The first version of this grader called both "degraded", which
 * would have told someone choosing between the two agents that it made no
 * difference — and it is the largest difference in the data.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { assess, loadCompatibility, LEVEL_MEANING, type AgentCompatibility } from '../src/core/compatibility.js';

const base = (over: Partial<AgentCompatibility> = {}): AgentCompatibility => ({
  id: 'test',
  name: 'Test Agent',
  supported: 'enforcing',
  adapter: 'src/adapters/claude-code/hook.ts',
  versionTested: '1.0.0',
  lastVerified: '2026-09-02',
  osTested: ['win32'],
  verdicts: {
    allow: { value: 'honoured', evidence: 'probe' },
    deny: { value: 'honoured', evidence: 'probe' },
    ask: { value: 'honoured', evidence: 'probe' },
  },
  failure: {
    onCrash: { value: 'closed', evidence: 'probe' },
    onTimeout: { value: 'closed', evidence: 'probe' },
  },
  interception: {
    shell: { value: 'gated', evidence: 'probe' },
    fileRead: { value: 'gated', evidence: 'probe' },
    fileWrite: { value: 'gated', evidence: 'probe' },
    fileDelete: { value: 'gated', evidence: 'probe' },
    mcp: { value: 'gated', evidence: 'probe' },
    subagentSpawn: { value: 'gated', evidence: 'probe' },
    network: { value: 'gated', evidence: 'probe' },
  },
  observation: { postToolUse: { value: true, evidence: 'probe' } },
  modes: {},
  upstreamLimitations: [],
  leastgrantLimitations: [],
  ...over,
});

describe('enforcement grading', () => {
  test('the ideal agent grades as enforcing', () => {
    // If this ever becomes unreachable the scale has become decorative.
    assert.equal(assess(base()).level, 'enforcing');
  });

  test('an ask that degrades is not the same as an ask that does not exist', () => {
    const degrades = assess(
      base({ verdicts: { ...base().verdicts, ask: { value: 'degrades', evidence: 'probe' } } }),
    );
    const missing = assess(
      base({ verdicts: { ...base().verdicts, ask: { value: 'unsupported', evidence: 'source' } } }),
    );
    assert.equal(degrades.level, 'partial', 'an ask that works when a human is present still asks');
    assert.equal(missing.level, 'degraded', 'no ask at all means veto-only');
    assert.notEqual(degrades.level, missing.level);
  });

  test('an agent that cannot deny is degraded whatever else it does', () => {
    const v = assess(base({ verdicts: { ...base().verdicts, deny: { value: 'ignored', evidence: 'source' } } }));
    assert.equal(v.level, 'degraded');
    assert.ok(
      v.findings.some((f) => f.status === 'bad' && /cannot refuse/.test(f.text)),
      'not being able to refuse must be reported as bad, not as a note',
    );
  });

  test('a tool class that is not intercepted is named, not omitted', () => {
    const v = assess(
      base({ interception: { ...base().interception, fileWrite: { value: 'none', evidence: 'source' } } }),
    );
    assert.equal(v.level, 'partial');
    assert.ok(
      v.findings.some((f) => f.status === 'bad' && /not intercepted at all: file writes/.test(f.text)),
      'a gap must appear as its own finding',
    );
  });

  test('observed-after-the-fact is distinguished from gated', () => {
    // Cursor reads a file, then tells the hook. Denying suppresses the content
    // reaching the model; it does not prevent the read. Reporting that as
    // "gated" would be the single most misleading thing this file could say.
    const v = assess(
      base({ interception: { ...base().interception, fileRead: { value: 'observed', evidence: 'source' } } }),
    );
    assert.ok(v.findings.some((f) => /not gated: file reads/.test(f.text)));
    assert.notEqual(v.level, 'enforcing');
  });

  test('contract evidence alone never grades as verified', () => {
    const v = assess(
      base({
        osTested: [],
        verdicts: {
          allow: { value: 'honoured', evidence: 'source' },
          deny: { value: 'honoured', evidence: 'source' },
          ask: { value: 'honoured', evidence: 'source' },
        },
        interception: Object.fromEntries(
          Object.keys(base().interception).map((k) => [k, { value: 'gated', evidence: 'source' }]),
        ),
      }),
    );
    assert.equal(v.level, 'unverified');
  });

  test('an agent with no adapter is reported as none, not as broken', () => {
    const v = assess(base({ adapter: null, supported: 'evaluated-and-deferred', upstreamLimitations: ['The hook never fires.'] }));
    assert.equal(v.level, 'none');
    assert.ok(v.findings.every((f) => f.status === 'info'), 'not shipping an adapter is not a fault to report');
  });

  test('every level has a meaning a reader can act on', () => {
    for (const [level, text] of Object.entries(LEVEL_MEANING)) {
      assert.ok(text.length > 10, `${level} has no explanation`);
      assert.ok(!/^good|^bad|^fine/i.test(text), `${level} reads as a rating rather than a fact`);
    }
  });
});

describe('the real data grades sensibly', () => {
  const agents = loadCompatibility();

  test('the data is found from the built code', () => {
    // Guards the packaging: compatibility/ must be resolvable from dist/.
    assert.ok(agents.length >= 5, `loaded only ${agents.length} agents`);
  });

  test('nothing claims to be fully enforcing yet', () => {
    // Not a rule of the design — a fact about today that should fail loudly if
    // it ever stops being true, so the claim gets re-read rather than drifting
    // in unnoticed. Every agent surveyed except Copilot fails open on a hook
    // crash, and Copilot's ask degrades.
    const perfect = agents.filter((a) => assess(a).level === 'enforcing').map((a) => a.id);
    assert.deepEqual(perfect, [], `now grading as fully enforcing: ${perfect.join(', ')} — re-read the claim`);
  });

  test('every shipped adapter can at least deny', () => {
    for (const a of agents.filter((x) => x.adapter)) {
      assert.equal(
        String(a.verdicts['deny']?.value),
        'honoured',
        `${a.id} ships an adapter but cannot refuse anything`,
      );
    }
  });
});
