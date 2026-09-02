/**
 * How much of what an agent actually runs does LeastGrant claim to understand?
 *
 * The README quotes 44.5%, measured once against 6,057 commands from one
 * machine. That number is the single most consequential figure in the project:
 * a not-understood command can never be auto-approved, so the unknown rate *is*
 * the prompt rate, and the prompt rate is what decides whether anybody keeps
 * the tool installed.
 *
 * It is also the number most likely to be quietly wrong after a change, because
 * every fix that makes something opaque — correctly — pushes it up. This script
 * re-measures it, and, more usefully, says WHY each command is unknown, grouped
 * into families. "44.5% unknown" is not actionable; "31% of the unknowns are a
 * package-manager script whose body we could hash" is.
 *
 * Local only. It reads the transcripts already on this machine through the same
 * mine() the product uses for `leastgrant init`, sends nothing anywhere, and
 * prints no command text unless asked with --samples.
 *
 *   node scripts/measure-unknowns.mjs [--samples N] [--json]
 */

import * as path from 'node:path';
import { transcriptFiles, readTranscript } from '../dist/src/adapters/claude-code/mine.js';
import { analyze } from '../dist/src/core/classify.js';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const sampleN = Number(args[args.indexOf('--samples') + 1]) || 0;

/**
 * Why a command could not be accounted for.
 *
 * Ordered: the first matching rule wins, so put the specific ones first. These
 * are families a fix could plausibly address, not a taxonomy for its own sake —
 * each one is a question of the form "could we know what this does without
 * running it, and at what cost".
 */
const FAMILIES = [
  ['inline code', /\b(python3?|node|ruby|perl|php|deno|bun)\b[^|;&]*\s-(c|e|-eval)\b/],
  ['npm/yarn/pnpm script', /\b(npm|yarn|pnpm|bun)\s+(run|run-script)\b/],
  ['package runner', /\b(npx|pnpm\s+dlx|yarn\s+dlx|bunx|uvx|pipx\s+run)\b/],
  ['make / task runner', /\b(make|just|task|mise|rake|invoke)\b/],
  ['build tool', /\b(cargo|go|gradle|mvn|dotnet|swift|zig|bazel)\b/],
  ['test runner', /\b(pytest|jest|vitest|mocha|tox|nox|phpunit)\b/],
  ['script file', /(^|[\s|;&])\.?\.?\/[\w.\-/]+\.(sh|bash|zsh|ps1|py|rb|js|mjs|ts)\b/],
  ['shell -c payload', /\b(sh|bash|zsh|dash|ksh|pwsh|powershell)\b[^|;&]*\s-(c|Command)\b/],
  ['docker / compose', /\b(docker|docker-compose|podman|nerdctl)\b/],
  ['unparseable', /^$/],
];

/**
 * Which family the command falls into, attributed to the part that is actually
 * unaccounted for.
 *
 * The subtlety that made the first run of this useless: attribute on the whole
 * command string and `cd /d D:\repo && python -c "..."` gets filed under `cd`,
 * because `cd` is the first token. That produced "cd" as 29% of all unknowns —
 * a number which is not merely imprecise but points at the wrong fix entirely,
 * since `cd` is understood perfectly well and is not why that command asked.
 *
 * So when the analyzer has told us which action it could not account for, the
 * family is decided from THAT action's rendering, and only from the raw command
 * when the whole parse failed.
 */
function familyOf(command, unaccounted) {
  const subject = unaccounted?.display || command;
  for (const [name, re] of FAMILIES) {
    if (name === 'unparseable') continue;
    if (re.test(subject)) return name;
  }
  if (!unaccounted) return 'unparseable';
  // Nothing matched a known shape, so the program itself is simply not in the
  // knowledge base. That is the interesting residue: it is where new coverage
  // would come from, and it is also where guessing would be most dangerous.
  const first = /^[\s(]*([\w.\-/\\]+)/.exec(subject)?.[1] ?? '?';
  return `unknown program: ${path.basename(first)}`;
}

const commands = [];
let filesRead = 0;
for (const file of transcriptFiles()) {
  let events;
  try {
    events = readTranscript(file);
  } catch {
    continue;
  }
  filesRead++;
  for (const ev of events) {
    if (ev.tool !== 'Bash') continue;
    const cmd = String(ev.input?.command ?? '').trim();
    if (cmd) commands.push({ cmd, cwd: ev.cwd || process.cwd() });
  }
}

if (!commands.length) {
  process.stderr.write(
    'No Bash commands found in local history. This measurement needs transcripts from real\n' +
      'agent sessions; there is nothing to measure on a fresh machine.\n',
  );
  process.exit(2);
}

let understood = 0;
let crashed = 0;
const families = new Map();
const samples = new Map();
let totalMs = 0;

for (const { cmd, cwd } of commands) {
  let a;
  const t0 = process.hrtime.bigint();
  try {
    a = analyze(
      { agent: 'measure', tool: 'Bash', input: { command: cmd }, cwd, sessionId: 'm', at: Date.now() },
      { roots: [cwd], secretPatterns: [] },
    );
  } catch {
    crashed++;
    continue;
  }
  totalMs += Number(process.hrtime.bigint() - t0) / 1e6;

  const ok = a.understood && a.actions.every((x) => x.understood);
  if (ok) {
    understood++;
    continue;
  }
  const fam = familyOf(cmd, a.actions.find((x) => !x.understood));
  families.set(fam, (families.get(fam) ?? 0) + 1);
  if (!samples.has(fam)) samples.set(fam, []);
  if (samples.get(fam).length < sampleN) samples.get(fam).push(cmd);
}

const total = commands.length;
const unknown = total - understood - crashed;
const ranked = [...families.entries()].sort((a, b) => b[1] - a[1]);

if (asJson) {
  process.stdout.write(
    JSON.stringify(
      {
        total,
        understood,
        unknown,
        crashed,
        understoodPct: +((understood / total) * 100).toFixed(1),
        avgParseMs: +(totalMs / total).toFixed(3),
        families: ranked.map(([name, n]) => ({
          name,
          count: n,
          shareOfUnknown: +((n / unknown) * 100).toFixed(1),
          shareOfAll: +((n / total) * 100).toFixed(1),
        })),
      },
      null,
      2,
    ) + '\n',
  );
  process.exit(0);
}

const pct = (n) => `${((n / total) * 100).toFixed(1)}%`;
console.log('');
console.log(`  ${total} Bash commands from ${filesRead} local transcripts`);
console.log('');
console.log(`  understood       ${String(understood).padStart(6)}   ${pct(understood).padStart(6)}`);
console.log(`  not understood   ${String(unknown).padStart(6)}   ${pct(unknown).padStart(6)}`);
if (crashed) console.log(`  parser crashed   ${String(crashed).padStart(6)}   ${pct(crashed).padStart(6)}`);
console.log(`  parse time       ${(totalMs / total).toFixed(3)} ms average`);
console.log('');
console.log('  why the rest are not understood, largest first');
console.log('');
for (const [name, n] of ranked.slice(0, 18)) {
  const bar = '#'.repeat(Math.max(1, Math.round((n / ranked[0][1]) * 28)));
  console.log(`  ${name.padEnd(30)} ${String(n).padStart(5)}  ${((n / unknown) * 100).toFixed(1).padStart(5)}%  ${bar}`);
  for (const s of samples.get(name) ?? []) console.log(`      ${s.slice(0, 100)}`);
}
if (ranked.length > 18) console.log(`  ${`…and ${ranked.length - 18} more families`.padEnd(30)}`);
console.log('');
console.log('  Every one of these always asks, by design: an action that was not fully');
console.log('  accounted for can never be auto-approved. So this table is the prompt');
console.log('  budget. A family worth attacking is one that is large AND where the');
console.log('  answer is knowable without running the code.');
console.log('');
