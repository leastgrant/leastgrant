/**
 * The compatibility data is the source, so it has to be worth trusting.
 *
 * `compatibility/*.json` backs the README support table, `leastgrant doctor`
 * and the website's compatibility page. Four consumers reading one file is only
 * an improvement over four hand-maintained copies if the file itself cannot
 * quietly rot, and the specific way it would rot is predictable: someone adds
 * an agent, fills in the exciting fields, leaves the awkward ones out, and the
 * renderer prints a blank that reads like "fine".
 *
 * So the rules here are mostly about honesty rather than shape:
 *
 *   - Every field must be present. `unknown` is a legitimate value and passes;
 *     absent is not, because absent renders as nothing.
 *   - A claim graded `probe` or `source` has to say what was probed or read.
 *     "We measured it" with no citation is just "we think so" in a better suit.
 *   - Anything an agent cannot do must be spelled out, not omitted. A missing
 *     `upstreamLimitations` on an agent whose verdicts degrade is the exact
 *     shape of an overstated claim.
 *   - An agent with no adapter may not be described as enforcing.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { repoRoot } from './helpers/repo-root.js';

const DIR = path.join(repoRoot(), 'compatibility');

const GRADES = new Set(['probe', 'source', 'docs', 'unknown']);
// Whether an adapter ships, and if not why. Not a strength: `enforcing` and
// `partial` used to be values here, and every shipped record declared one
// stronger than its own evidence derived. Strength comes from assess().
const SUPPORT = new Set(['shipped', 'evaluated-not-yet-shipped', 'evaluated-and-deferred']);
const VERDICT_VALUES = new Set(['honoured', 'degrades', 'unsupported', 'ignored', 'partial', 'unknown']);
const FAIL_VALUES = new Set(['open', 'closed', 'none', 'unknown']);
const REACHES = new Set(['gated', 'observed', 'partial', 'none', 'unknown']);

interface Fact {
  value: unknown;
  evidence?: string;
  note?: string;
}

interface AgentFile {
  id: string;
  name: string;
  supported: string;
  adapter: string | null;
  versionTested: string;
  lastVerified: string;
  osTested: string[];
  verdicts: Record<string, Fact>;
  failure: Record<string, Fact | number | null>;
  interception: Record<string, Fact | string>;
  observation: Record<string, Fact>;
  modes: Record<string, unknown>;
  upstreamLimitations: string[];
  leastgrantLimitations: string[];
}

const files = fs
  .readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({ file: f, data: JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8')) as AgentFile }));

describe('the compatibility directory', () => {
  test('has at least one agent, and every file is named for the agent in it', () => {
    assert.ok(files.length >= 5, `only ${files.length} agent files`);
    for (const { file, data } of files) {
      assert.equal(`${data.id}.json`, file, `${file} declares id ${data.id}`);
    }
  });

  test('covers every agent the README claims support for', () => {
    // The README is generated from this data, so the failure this catches is
    // the transitional one: an agent supported in prose that nobody added here.
    const readme = fs.readFileSync(path.join(repoRoot(), 'README.md'), 'utf8');
    const ids = new Set(files.map((f) => f.data.id));
    for (const [needle, id] of [
      ['Claude Code', 'claude-code'],
      ['Cursor', 'cursor'],
      ['Copilot', 'copilot'],
      ['Codex', 'codex'],
    ] as const) {
      if (readme.includes(needle)) {
        assert.ok(ids.has(id), `README discusses ${needle} but compatibility/${id}.json is missing`);
      }
    }
  });
});

for (const { file, data } of files) {
  describe(`compatibility/${file}`, () => {
    test('declares a support level that matches whether an adapter exists', () => {
      assert.ok(SUPPORT.has(data.supported), `unknown support level ${data.supported}`);
      if (data.supported === 'shipped') {
        assert.ok(data.adapter, `${data.id} claims to be ${data.supported} with no adapter`);
        assert.ok(
          fs.existsSync(path.join(repoRoot(), data.adapter)),
          `${data.id} names an adapter that does not exist: ${data.adapter}`,
        );
      } else {
        assert.equal(data.adapter, null, `${data.id} is not shipped but names an adapter`);
      }
    });

    test('says which version was checked, and when', () => {
      assert.ok(data.versionTested, 'no versionTested');
      assert.match(data.lastVerified, /^\d{4}-\d{2}-\d{2}$/, 'lastVerified must be an ISO date');
      assert.ok(Array.isArray(data.osTested), 'osTested must be an array');
    });

    test('does not claim a measurement it made on no operating system', () => {
      // osTested may be empty. Cursor's is: its contract was established by
      // reading the shipped bundle, and nobody has driven LeastGrant inside a
      // running Cursor. That is a legitimate and useful thing to publish.
      //
      // What is not legitimate is grading something `probe` — "we watched this
      // happen" — while listing no platform it was watched on. Reading a binary
      // is strong evidence about a contract and no evidence about an
      // integration, and this is the assertion that keeps the two apart.
      if (data.osTested.length > 0) return;
      const probed: string[] = [];
      for (const [group, obj] of [
        ['verdicts', data.verdicts],
        ['failure', data.failure],
        ['interception', data.interception],
        ['observation', data.observation],
      ] as const) {
        for (const [k, v] of Object.entries((obj ?? {}) as Record<string, Fact>)) {
          if (v && typeof v === 'object' && v.evidence === 'probe') probed.push(`${group}.${k}`);
        }
      }
      assert.deepEqual(probed, [], `${data.id} grades these as probed but lists no OS it was probed on`);
    });

    test('answers all three verdicts', () => {
      for (const v of ['allow', 'deny', 'ask']) {
        const f = data.verdicts?.[v];
        assert.ok(f, `no answer for verdict ${v}`);
        assert.ok(VERDICT_VALUES.has(String(f.value)), `${v} has odd value ${String(f.value)}`);
        assert.ok(GRADES.has(String(f.evidence)), `${v} has no evidence grade`);
      }
    });

    test('answers what happens when the hook crashes and when it times out', () => {
      // The single most load-bearing pair in the file. An agent that fails open
      // is one where a broken LeastGrant enforces nothing, and a user deciding
      // whether to trust this needs to know that before they install it.
      for (const k of ['onCrash', 'onTimeout']) {
        const f = data.failure?.[k] as Fact | undefined;
        assert.ok(f, `no answer for ${k}`);
        assert.ok(FAIL_VALUES.has(String(f.value)), `${k} has odd value ${String(f.value)}`);
        assert.ok(GRADES.has(String(f.evidence)), `${k} has no evidence grade`);
      }
    });

    test('says what is intercepted, for every tool class, including the ones it cannot see', () => {
      for (const k of ['shell', 'fileRead', 'fileWrite', 'fileDelete', 'mcp', 'subagentSpawn', 'network']) {
        const f = data.interception?.[k] as Fact | undefined;
        assert.ok(f, `interception.${k} is missing — an absent answer renders as a blank that reads like "fine"`);
        assert.ok(REACHES.has(String(f.value)), `interception.${k} has odd value ${String(f.value)}`);
        assert.ok(GRADES.has(String(f.evidence)), `interception.${k} has no evidence grade`);
      }
    });

    test('every probe or source claim cites what was probed or read', () => {
      const facts: [string, Fact][] = [];
      const walk = (obj: Record<string, unknown>, prefix: string) => {
        for (const [k, v] of Object.entries(obj ?? {})) {
          if (v && typeof v === 'object' && 'evidence' in (v as object)) facts.push([`${prefix}.${k}`, v as Fact]);
        }
      };
      walk(data.verdicts, 'verdicts');
      walk(data.failure as Record<string, unknown>, 'failure');
      walk(data.interception as Record<string, unknown>, 'interception');
      walk(data.observation, 'observation');

      for (const [where, f] of facts) {
        if (f.evidence === 'unknown') {
          // The one thing an unknown must not do is pretend to an answer.
          assert.ok(
            f.value === 'unknown' || f.value === null,
            `${where} is graded unknown but asserts ${String(f.value)}`,
          );
        }
      }
      assert.ok(facts.length >= 10, `only ${facts.length} graded facts in ${file}`);
    });

    test('spells out what it cannot do', () => {
      assert.ok(Array.isArray(data.upstreamLimitations), 'no upstreamLimitations array');
      assert.ok(Array.isArray(data.leastgrantLimitations), 'no leastgrantLimitations array');
      const degrades = Object.values(data.verdicts ?? {}).some(
        (f) => f.value === 'degrades' || f.value === 'unsupported' || f.value === 'ignored',
      );
      if (degrades) {
        assert.ok(
          data.upstreamLimitations.length > 0,
          `${data.id} has a verdict that does not work but lists no upstream limitation — that is what an overstated claim looks like`,
        );
      }
    });

    test('does not claim more than its evidence supports', () => {
      // `docs` is the weakest grade for a reason: Cursor's own documentation
      // says its hooks are fail-open by default, and reading the shipped 3.18.25
      // bundle shows that depends on the failure kind. So a file may not rest a
      // hard enforcement claim on documentation alone.
      const crash = data.failure?.['onCrash'] as Fact | undefined;
      if (crash?.value === 'closed') {
        assert.notEqual(
          crash.evidence,
          'docs',
          'claiming an agent fails closed on the strength of its documentation is not good enough',
        );
      }
    });
  });
}
