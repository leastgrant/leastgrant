/**
 * `leastgrant simulate`
 *
 * "If I changed this setting, what would actually happen?"
 *
 * Security tools ask people to accept a trade-off between friction and safety
 * without ever showing them the exchange rate. This command shows it: pick a
 * posture, and see — against your own history — how many prompts you would get
 * and what would slip through.
 *
 * It replays your real history through the same engine the hook uses, starting
 * from the profile LeastGrant has today — because the question is what changes
 * for you tomorrow, and tomorrow starts from what it already knows. (`init`
 * replays from an empty profile instead: its question is the historical one,
 * and seeding that would be marking its own homework. See replay.ts.)
 */

import type { Config, Posture } from '../../core/types.js';
import { evidenceFor, readTranscript, transcriptFiles } from '../../adapters/claude-code/mine.js';
import { replay, type ReplayEvent, type ReplayResult } from '../../replay.js';
import { loadConfig } from '../../store/index.js';
import { loadContext } from '../context.js';
import { c, pad, padStart, para, plural, sym, truncate } from '../ui.js';
import type { Argv } from '../index.js';

/**
 * `observe` is deliberately absent from the comparison.
 *
 * In observe posture LeastGrant reaches no verdict at all — the hook stays
 * silent and the agent's own permission flow decides. Putting it in a table
 * headed "asks you" would imply it prompts, which it never does. It is
 * described in the legend instead.
 */
const POSTURES: Posture[] = ['assist', 'autopilot', 'strict'];

const POSTURE_BLURB: Record<Posture, string> = {
  observe: 'watches, never intervenes',
  assist: 'asks about anything unusual (the default)',
  autopilot: 'trusts the routine sooner',
  strict: 'only what you have explicitly allowed',
};

export function simulateCommand(argv: Argv): number {
  const json = Boolean(argv.flags['json']);
  const days = Number(argv.flags['days'] ?? 30);
  const onlyThisProject = !argv.flags['all'];
  const ctx = loadContext();

  const since = Date.now() - days * 86_400_000;
  const events: ReplayEvent[] = [];
  for (const f of transcriptFiles()) {
    for (const ev of readTranscript(f)) {
      if (!ev.cwd || ev.at < since) continue;
      events.push({
        at: ev.at,
        sessionId: ev.sessionId,
        cwd: ev.cwd,
        tool: ev.tool,
        input: ev.input,
        agentMode: ev.permissionMode,
        denied: ev.denied,
        evidence: evidenceFor(ev),
      });
    }
  }

  if (!events.length) {
    process.stdout.write(
      '\n' +
        para(
          c.gray(
            `No agent history in the last ${plural(days, 'day')} to replay. Try a longer window with --days 90, or run \`leastgrant init\` first.`,
          ),
          2,
        ) +
        '\n\n',
    );
    return 0;
  }

  const base = loadConfig();
  const which: Posture[] = argv.flags['posture']
    ? [String(argv.flags['posture']) as Posture]
    : POSTURES;

  const runs = new Map<Posture, ReplayResult>();
  for (const posture of which) {
    if (!POSTURES.includes(posture)) {
      process.stderr.write(`\n  ${c.red('Unknown posture')} ${posture}\n  ${c.gray('One of: ' + POSTURES.join(', '))}\n\n`);
      return 2;
    }
    const config: Config = { ...base, posture };
    // Seeded with what LeastGrant already knows, because the question this
    // command answers is "if I change this setting, what changes for me
    // tomorrow" — and tomorrow starts from today's profile, not from nothing.
    // (`init` replays from an empty profile instead, since its question is the
    // historical one and seeding it would be marking its own homework.)
    runs.set(
      posture,
      replay(events, {
        config,
        seed: new Map([[ctx.key, structuredClone(ctx.envelope)]]),
        ...(onlyThisProject ? { project: ctx.root } : {}),
      }),
    );
  }

  if (json) {
    const out: Record<string, unknown> = {};
    for (const [posture, r] of runs) {
      out[posture] = {
        total: r.total,
        allowed: r.allowed,
        asked: r.asked,
        blocked: r.blocked,
        regrets: r.regrets.length,
      };
    }
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return 0;
  }

  const first = [...runs.values()][0]!;
  process.stdout.write('\n');
  process.stdout.write(
    `  ${c.bold('Replaying')} ${plural(first.total, 'action')} ${c.gray(`from the last ${plural(days, 'day')}`)}` +
      (onlyThisProject ? c.gray(` in ${ctx.root}`) : c.gray(' across every project')) +
      '\n\n',
  );

  process.stdout.write(
    '  ' +
      c.gray(pad('mode', 12) + padStart('runs freely', 14) + padStart('asks you', 12) + padStart('blocks', 9) + '   ') +
      c.gray('missed') +
      '\n',
  );

  for (const [posture, r] of runs) {
    const pct = r.total ? Math.round((r.allowed / r.total) * 100) : 0;
    const isCurrent = posture === base.posture;
    const name = isCurrent ? c.bold(posture) + c.gray(' *') : posture;
    const missed =
      r.regrets.length === 0
        ? c.green('none')
        : c.yellow(plural(r.regrets.length, 'action'));
    process.stdout.write(
      '  ' +
        pad(name, 12) +
        padStart(`${r.allowed.toLocaleString('en-US')} (${pct}%)`, 14) +
        padStart(r.asked.toLocaleString('en-US'), 12) +
        padStart(r.blocked ? c.red(String(r.blocked)) : '0', 9) +
        '   ' +
        missed +
        '\n',
    );
  }
  process.stdout.write('\n');
  process.stdout.write(
    '  ' + c.gray('* current setting') + '\n',
  );
  for (const p of which) {
    process.stdout.write(`  ${c.gray(pad(p, 12) + POSTURE_BLURB[p])}\n`);
  }
  process.stdout.write('\n');

  // "Missed" is the column that should decide the choice, so explain it where
  // the eye lands rather than in a footnote.
  const worst = [...runs.entries()].find(([, r]) => r.regrets.length > 0);
  if (worst) {
    const [posture, r] = worst;
    process.stdout.write(
      para(
        c.gray('"missed" means an action you actually turned down that this mode would have let through. In ') +
          c.bold(posture) +
          c.gray(':'),
        2,
      ) + '\n',
    );
    for (const g of r.regrets.slice(0, 3)) {
      process.stdout.write(`    ${c.yellow(sym.bullet)} ${truncate(g.display, 70)}\n`);
    }
    process.stdout.write('\n');
  } else {
    process.stdout.write(
      para(c.gray('No mode would have auto-approved anything you turned down.'), 2) + '\n\n',
    );
  }

  const current = runs.get(base.posture);
  if (current && which.length > 1) {
    const better = [...runs.entries()]
      .filter(([p, r]) => p !== base.posture && r.regrets.length <= current.regrets.length && r.allowed > current.allowed)
      .sort((a, b) => b[1].allowed - a[1].allowed)[0];
    if (better) {
      const saved = better[1].allowed - current.allowed;
      process.stdout.write(
        para(
          `${c.gray('Switching to')} ${c.bold(better[0])} ${c.gray(`would have avoided ${plural(saved, 'more prompt')} without missing anything extra:`)} ${c.cyan(`leastgrant config posture ${better[0]}`)}`,
          2,
        ) + '\n\n',
      );
    }
  }

  return 0;
}
