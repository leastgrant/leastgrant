/**
 * The benchmark command.
 *
 * These assertions are about SHAPE, not speed. A test that fails when a shared
 * CI runner is busy teaches people to rerun until it passes, and a suite people
 * rerun until it passes is not a suite. The latency budgets live in the command
 * itself, where a human reads the number in context and can see the machine it
 * came from; the regression guard is comparing `--json` between releases on the
 * same hardware, not an assertion here.
 *
 * What is worth testing is that the measurement is not lying: that percentiles
 * are ordered, that the environment is recorded, and that every sample actually
 * ran the number of iterations it claims.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { repoRoot } from './helpers/repo-root.js';

interface Sample {
  name: string;
  unit: string;
  runs: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  budget?: number;
}

interface Report {
  version: number;
  environment: Record<string, unknown>;
  samples: Sample[];
}

const ROOT = repoRoot();

/** One run, small, shared by every assertion below — it is the slow part. */
const report: Report = JSON.parse(
  execFileSync(process.execPath, [path.join(ROOT, 'bin', 'leastgrant.js'), 'benchmark', '--runs', '60', '--json'], {
    encoding: 'utf8',
    timeout: 120_000,
  }),
);

describe('leastgrant benchmark', () => {
  test('reports every stage of the hot path', () => {
    const names = report.samples.map((s) => s.name);
    for (const required of ['core decision', 'shell analysis']) {
      assert.ok(names.includes(required), `no sample named ${required}; got ${names.join(', ')}`);
    }
    assert.ok(names.length >= 5, `only ${names.length} samples`);
  });

  test('percentiles are ordered', () => {
    for (const s of report.samples) {
      assert.ok(s.p50 <= s.p95, `${s.name}: p50 ${s.p50} > p95 ${s.p95}`);
      assert.ok(s.p95 <= s.p99, `${s.name}: p95 ${s.p95} > p99 ${s.p99}`);
      assert.ok(s.p99 <= s.max, `${s.name}: p99 ${s.p99} > max ${s.max}`);
    }
  });

  test('every sample actually ran, and took a measurable amount of time', () => {
    for (const s of report.samples) {
      assert.equal(s.runs, 60, `${s.name} claims ${s.runs} runs`);
      // Zero would mean the timer never fired or the work was optimised away
      // entirely — either way the number would be meaningless rather than fast.
      assert.ok(s.p50 > 0, `${s.name} reports a p50 of zero`);
    }
  });

  test('records the machine, because a number without one is an anecdote', () => {
    for (const key of ['node', 'platform', 'cpu', 'cores', 'leastgrant']) {
      assert.ok(report.environment[key], `environment is missing ${key}`);
    }
    assert.notEqual(report.environment['leastgrant'], 'unknown', 'could not resolve its own version');
  });

  test('the version it reports is the version in package.json', () => {
    // The same trap the website had: a benchmark filed under the wrong version
    // is worse than no benchmark, because it will be compared against the wrong
    // baseline and the difference read as a regression.
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as {
      version: string;
    };
    assert.equal(report.environment['leastgrant'], pkg.version);
  });
});
