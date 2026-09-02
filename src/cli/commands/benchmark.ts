/**
 * `leastgrant benchmark`
 *
 * How long the permission hot path takes, measured rather than asserted.
 *
 * This exists for one reason, and it is not to produce a number for the README.
 * LeastGrant runs before every tool call an agent makes. If it gets slow, it
 * gets uninstalled, and a security control nobody runs protects nothing. The
 * job of this command is to make a regression visible on the commit that causes
 * it, while it is still one commit.
 *
 * Two decisions worth explaining.
 *
 * It reports percentiles, not a mean. The mean of a latency distribution is the
 * number least likely to describe anyone's experience of it: a p50 of 2ms with
 * a p99 of 400ms is a tool that feels broken one call in a hundred, and the
 * mean hides that completely.
 *
 * It records the environment alongside the numbers. A benchmark without the
 * machine it ran on is not a measurement, it is an anecdote, and comparing one
 * laptop's p95 against a CI runner's would produce confident nonsense. `--json`
 * emits both so a CI job can compare like with like and fail on drift.
 */

import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Config, Request } from '../../core/types.js';
import { decide } from '../../core/decide.js';
import { analyze } from '../../core/classify.js';
import { canonicalize, inWorkspace } from '../../core/paths.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../../core/envelope.js';
import { DEFAULT_CONFIG } from '../../store/index.js';
import { c, heading, para, rule, table } from '../ui.js';
import type { Argv } from '../index.js';

/**
 * Budgets, in milliseconds.
 *
 * These are the numbers the project is willing to defend, not aspirations. They
 * are deliberately loose: a budget tight enough to trip on ordinary variance
 * gets muted, and a muted budget is worse than none. What catches real
 * regressions is the release-to-release comparison in `--json` mode, not these.
 */
const BUDGET: Record<string, number> = {
  'core decision': 10,
  'shell analysis': 5,
  'path resolution (cached)': 1,
  // No budget on cold path resolution deliberately. It calls realpath, so what
  // it measures is the filesystem: it came in at 883 µs on an idle machine and
  // 2.48 ms on the same machine under load, and neither number says anything
  // about LeastGrant's code. Reported because it is worth knowing that a fresh
  // path costs a hundred times a cached one; not budgeted, because a budget
  // that fails on someone else's disk teaches people to ignore budgets.
};

interface Sample {
  name: string;
  unit: 'ms';
  runs: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  budget?: number;
}

export function benchmarkCommand(argv: Argv): number {
  const runs = Math.max(50, Number(argv.flags['runs'] ?? 2000) || 2000);
  const asJson = Boolean(argv.flags['json']);

  const samples: Sample[] = [];
  for (const b of benches(runs)) {
    samples.push(measure(b.name, b.runs, b.fn));
  }

  const report = {
    version: 1 as const,
    environment: environment(),
    samples,
  };

  if (asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return over(samples).length ? 1 : 0;
  }

  process.stdout.write(render(report));
  return over(samples).length ? 1 : 0;
}

const over = (s: Sample[]) => s.filter((x) => x.budget !== undefined && x.p95 > x.budget);

// --- the benchmarks ---------------------------------------------------------

interface Bench {
  name: string;
  runs: number;
  fn: () => void;
}

function benches(runs: number): Bench[] {
  const WS = path.join(os.tmpdir(), 'leastgrant-bench-ws');
  const STATE = path.join(os.tmpdir(), 'leastgrant-bench-state');
  const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };
  const at = Date.now();

  // A realistically-populated envelope. Measuring against an empty one would
  // flatter the result: familiarity lookup and decay are the parts that grow
  // with history, and history is the normal state of a working install.
  const envelope = newEnvelope('project', WS);
  const warm = ['git status', 'npm test', 'ls -la', 'git log --oneline', 'cat README.md'];
  for (let i = 0; i < 60; i++) {
    for (const cmd of warm) {
      const a = analyze(
        { agent: 'b', tool: 'Bash', input: { command: cmd }, cwd: WS, sessionId: `s${i}`, at },
        { roots: [WS], secretPatterns: [] },
      );
      for (const action of a.actions) {
        observe(envelope, {
          signature: action.signature,
          capability: action.capability,
          blast: action.blast,
          evidence: 'confirmed',
          at: at - i * 3_600_000,
          sessionId: `s${i}`,
          display: action.display,
        });
      }
    }
  }

  const ctx = {
    roots: [WS],
    secretPatterns: [],
    config,
    envelope,
    session: newSession('bench', at),
    stateDir: STATE,
    projectKey: WS,
  };

  const req = (command: string): Request => ({
    agent: 'bench',
    tool: 'Bash',
    input: { command },
    cwd: WS,
    sessionId: 'bench',
    at,
  });

  // Three shapes, because they exercise different amounts of the pipeline and
  // an average over only the cheap one would be a comfortable lie.
  const FAMILIAR = req('git status');
  const NOVEL = req('terraform apply -auto-approve');
  const COMPOUND = req('npm test && git push origin main && rm -rf ./dist');

  return [
    { name: 'core decision', runs, fn: () => void decide(FAMILIAR, ctx) },
    { name: 'core decision (novel)', runs, fn: () => void decide(NOVEL, ctx) },
    { name: 'core decision (compound)', runs, fn: () => void decide(COMPOUND, ctx) },
    {
      name: 'shell analysis',
      runs,
      fn: () =>
        void analyze(
          { agent: 'b', tool: 'Bash', input: { command: 'npm test && git push' }, cwd: WS, sessionId: 's', at },
          { roots: [WS], secretPatterns: [] },
        ),
    },
    // Canonicalize then answer the containment question, which is the pair the
    // guards run per target. Split warm from cold deliberately: canonicalize()
    // is LRU-cached, so hammering one input would measure the cache and report
    // a number no real workload ever sees. Both are honest, and they answer
    // different questions — the warm one is what a repeated path in a loop
    // costs, the cold one is what a fresh path costs.
    {
      name: 'path resolution (cached)',
      runs,
      fn: () => {
        const p = canonicalize('src/../lib/index.ts', WS);
        void inWorkspace(p.abs, [WS]);
      },
    },
    {
      name: 'path resolution (cold)',
      runs,
      fn: (() => {
        let n = 0;
        return () => {
          const p = canonicalize(`src/../lib/mod${n++}/index.ts`, WS);
          void inWorkspace(p.abs, [WS]);
        };
      })(),
    },
  ];
}

// --- measurement ------------------------------------------------------------

function measure(name: string, runs: number, fn: () => void): Sample {
  // Warm up before recording. The first few hundred calls measure the JIT
  // deciding what to optimise, which is real but is not what anyone is asking
  // about when they ask how long a decision takes.
  const warmup = Math.min(200, Math.floor(runs / 4));
  for (let i = 0; i < warmup; i++) fn();

  const times = new Float64Array(runs);
  for (let i = 0; i < runs; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    times[i] = Number(process.hrtime.bigint() - t0) / 1e6;
  }

  const sorted = Array.from(times).sort((a, b) => a - b);
  return {
    name,
    unit: 'ms',
    runs,
    p50: pct(sorted, 0.5),
    p95: pct(sorted, 0.95),
    p99: pct(sorted, 0.99),
    max: round(sorted[sorted.length - 1] ?? 0),
    ...(BUDGET[name] !== undefined ? { budget: BUDGET[name] } : {}),
  };
}

/**
 * Nearest-rank percentile.
 *
 * Not interpolated: for latency the honest answer to "what is the p95" is a
 * value that actually occurred, not one synthesised between two that did.
 */
function pct(sorted: number[], q: number): number {
  if (!sorted.length) return 0;
  const rank = Math.max(1, Math.ceil(q * sorted.length));
  return round(sorted[rank - 1] ?? sorted[sorted.length - 1] ?? 0);
}

const round = (n: number) => Math.round(n * 1000) / 1000;

function environment() {
  const cpus = os.cpus();
  return {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    os: `${os.type()} ${os.release()}`,
    cpu: cpus[0]?.model?.trim() ?? 'unknown',
    cores: cpus.length,
    memoryGB: Math.round(os.totalmem() / 1024 ** 3),
    leastgrant: packageVersion(),
  };
}

function packageVersion(): string {
  // Walk up for package.json rather than guessing a depth: this file runs from
  // dist/cli/commands/ after a build and from src/ under a loader.
  let dir = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  for (let i = 0; i < 8; i++) {
    const p = path.join(dir, 'package.json');
    try {
      if (fs.existsSync(p)) return String(JSON.parse(fs.readFileSync(p, 'utf8')).version ?? 'unknown');
    } catch {
      // A package.json we cannot parse is not worth failing a benchmark over.
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return 'unknown';
}

// --- rendering --------------------------------------------------------------

function render(report: { environment: ReturnType<typeof environment>; samples: Sample[] }): string {
  const e = report.environment;
  const out: string[] = [''];

  out.push(heading('  How long a decision takes'));
  out.push('');
  out.push(
    para(
      'LeastGrant runs before every tool call, so this is latency the person using the agent actually feels. Percentiles, not an average: the average of a latency distribution is the number least likely to describe anybody.',
    ),
  );
  out.push('');

  out.push(
    indent(table(
      [
        { header: '', width: 26 },
        { header: 'p50', width: 9, align: 'right' },
        { header: 'p95', width: 9, align: 'right' },
        { header: 'p99', width: 9, align: 'right' },
        { header: 'max', width: 9, align: 'right' },
        { header: 'budget', width: 10, align: 'right' },
      ],
      report.samples.map((s) => [
        s.name,
        ms(s.p50),
        s.budget !== undefined && s.p95 > s.budget ? c.red(ms(s.p95)) : ms(s.p95),
        ms(s.p99),
        c.gray(ms(s.max)),
        s.budget === undefined ? c.gray('—') : c.gray(`${s.budget} ms`),
      ]),
    )),
  );

  out.push('');
  out.push(rule());
  out.push(
    para(
      c.gray(
        `${e.leastgrant} · node ${e.node} · ${e.cpu} · ${e.cores} cores · ${e.platform}`,
      ),
    ),
  );
  out.push(
    para(
      c.gray(
        'A benchmark without the machine it ran on is an anecdote. Compare runs from the same hardware; `--json` emits the environment for CI to check.',
      ),
    ),
  );
  out.push(
    para(
      c.gray(
        'Run it on an otherwise idle machine. Under load these numbers roughly triple and the max goes up by two orders of magnitude, which is contention rather than anything about the code.',
      ),
    ),
  );

  const bad = over(report.samples);
  if (bad.length) {
    out.push('');
    for (const s of bad) {
      out.push(`  ${c.red('over budget')}  ${s.name}: p95 ${ms(s.p95)} against ${s.budget} ms`);
    }
  }
  out.push('');
  return out.join('\n');
}

const ms = (n: number) => (n >= 1 ? `${n.toFixed(2)} ms` : `${(n * 1000).toFixed(0)} µs`);

/** Line up a rendered block with the two-space body indent the CLI uses. */
const indent = (s: string) =>
  s
    .split('\n')
    .map((l) => '  ' + l)
    .join('\n');
