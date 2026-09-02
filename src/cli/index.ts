/**
 * The `leastgrant` command line.
 *
 * Hand-rolled argument parsing, for the same reason as the renderer: a tool
 * that asks to sit between you and your agent should be auditable in an
 * afternoon, and every dependency is a thing you would have to audit too.
 */

import { c, logo, para, rule, sym } from './ui.js';

export interface Argv {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgv(args: string[]): Argv {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let command = '';

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = args[i + 1];
        if (next && !next.startsWith('-')) {
          flags[a.slice(2)] = next;
          i++;
        } else {
          flags[a.slice(2)] = true;
        }
      }
    } else if (a.startsWith('-') && a.length > 1) {
      for (const ch of a.slice(1)) flags[ch] = true;
    } else if (!command) {
      command = a;
    } else {
      positional.push(a);
    }
  }
  return { command, positional, flags };
}

const COMMANDS: { name: string; args?: string; blurb: string }[] = [
  { name: 'init', blurb: 'look at what your agents already did, then set LeastGrant up' },
  { name: 'status', blurb: 'what LeastGrant knows about this project' },
  { name: 'check', args: '<command>', blurb: 'ask what it would decide, without running anything' },
  { name: 'why', args: '[n]', blurb: 'explain a recent decision in full' },
  { name: 'trail', blurb: 'what your agents have been doing' },
  { name: 'simulate', blurb: 'replay history against the current settings' },
  { name: 'allow', args: '<pattern>', blurb: 'stop asking about something' },
  { name: 'deny', args: '<pattern>', blurb: 'always block something' },
  { name: 'forget', args: '<pattern>', blurb: 'remove a rule or unlearn a signature' },
  { name: 'rules', blurb: 'list the rules you have set' },
  { name: 'doctor', blurb: 'check the setup and look for over-broad access' },
  { name: 'benchmark', blurb: 'measure how long a decision takes on this machine' },
  { name: 'install', args: '[agent]', blurb: 'install the hook for an agent' },
  { name: 'uninstall', args: '[agent]', blurb: 'remove the hook' },
  { name: 'hook', blurb: c.gray('(internal) run as an agent hook') },
];

export function help(): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(logo());
  lines.push('');
  lines.push(c.gray('  Coding agents are useful right up until you spend the day clicking Allow.'));
  lines.push(c.gray('  LeastGrant learns what yours normally do, lets the routine through, and'));
  lines.push(c.gray('  stops to ask about the rest.'));
  lines.push('');
  lines.push(c.bold('  Usage'));
  lines.push(`    leastgrant <command> [options]   ${c.gray('(also available as `lg`)')}`);
  lines.push('');
  lines.push(c.bold('  Commands'));
  for (const cmd of COMMANDS) {
    if (cmd.name === 'hook') continue;
    const left = `    ${cmd.name}${cmd.args ? ' ' + c.gray(cmd.args) : ''}`;
    const padLen = 26 + (left.length - stripLen(left));
    lines.push(left.padEnd(padLen) + c.gray(cmd.blurb));
  }
  lines.push('');
  lines.push(c.bold('  Getting started'));
  lines.push(`    ${c.cyan('leastgrant init')}                ${c.gray('start here — it reads history you already have')}`);
  lines.push(`    ${c.cyan('leastgrant check "git push --force"')}  ${c.gray('see how it thinks')}`);
  lines.push('');
  lines.push(c.bold('  Options'));
  lines.push(`    --json                     ${c.gray('machine-readable output')}`);
  lines.push(`    --no-color                 ${c.gray('plain text')}`);
  lines.push(`    --help, --version`);
  lines.push('');
  lines.push(
    c.gray(`  ${sym.bullet} LeastGrant is a decision layer, not a sandbox. See THREAT-MODEL.md.`),
  );
  lines.push('');
  return lines.join('\n');
}

function stripLen(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '').length;
}

export function unknownCommand(name: string): string {
  const known = COMMANDS.map((x) => x.name);
  const near = known
    .map((k) => ({ k, d: distance(k, name) }))
    .sort((a, b) => a.d - b.d)
    .filter((x) => x.d <= 3)[0];
  const lines = [`${c.red('Unknown command')} ${c.bold(name)}`];
  if (near) lines.push(`Did you mean ${c.cyan(near.k)}?`);
  lines.push(c.gray('Run `leastgrant --help` for the list.'));
  // Wrapped line by line. `para` reflows on whitespace, so joining with two
  // spaces (or with a newline) collapsed the sentences into one run-on:
  // "Unknown command bogus Run `leastgrant --help` for the list."
  return '\n' + lines.map((l) => para(l, 2)).join('\n') + '\n';
}

/** Levenshtein, for the "did you mean" line. */
function distance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(
        (prev[j] ?? 0) + 1,
        (cur[j - 1] ?? 0) + 1,
        (prev[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = cur;
  }
  return prev[n] ?? 0;
}

export { rule };
