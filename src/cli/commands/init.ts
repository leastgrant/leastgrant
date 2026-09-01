/**
 * `leastgrant init`
 *
 * The first thirty seconds.
 *
 * Most tools in this space start by asking you to write a policy. LeastGrant
 * starts by reading the thousands of decisions already sitting in your agent's
 * session logs, replaying them, and telling you what it would have done. By the
 * time it asks to install anything, you have already seen it be right — and,
 * where applicable, seen it be wrong, because the replay reports its own
 * mistakes.
 *
 * Nothing here is written to disk until the summary has been shown.
 */

import * as readline from 'node:readline/promises';
import * as path from 'node:path';
import type { Capability } from '../../core/types.js';
import { mine, evidenceFor, transcriptFiles, readTranscript } from '../../adapters/claude-code/mine.js';
import { replay, type ReplayEvent } from '../../replay.js';
import { coverageOf, proposeBundles, type Bundle } from '../../core/bundles.js';
import { friendly } from '../../core/decide.js';
import { observe } from '../../core/envelope.js';
import { loadConfig, saveConfig, saveEnvelope } from '../../store/index.js';
import { bar, c, logo, pad, para, plural, sym, term, truncate } from '../ui.js';
import type { Argv } from '../index.js';
import { installCommand, isClaudeInstalled } from './install.js';

export async function initCommand(argv: Argv): Promise<number> {
  const json = Boolean(argv.flags['json']);
  const dryRun = Boolean(argv.flags['dry-run']);
  const assumeYes = Boolean(argv.flags['yes'] || argv.flags['y']);

  if (!json) {
    process.stdout.write('\n' + logo() + '\n\n');
    process.stdout.write(c.gray('  Reading what your agents have already done…\n'));
  }

  const files = transcriptFiles();
  if (!files.length) {
    return firstRunWithNoHistory(json, assumeYes, dryRun);
  }

  // --- gather -------------------------------------------------------------
  const events: ReplayEvent[] = [];
  for (const f of files) {
    for (const ev of readTranscript(f)) {
      if (!ev.cwd) continue;
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

  const summary = mine();
  const config = loadConfig();
  const result = replay(events, { config });

  if (json) {
    process.stdout.write(
      JSON.stringify(
        {
          sessions: summary.sessions,
          projects: summary.byProject.size,
          actions: result.total,
          allowed: result.allowed,
          asked: result.asked,
          blocked: result.blocked,
          regrets: result.regrets.length,
          // Named for what they measure. Mining does not produce human
          // attestation any more (see `evidenceFor` in mine.ts), so calling
          // these `confirmed`/`observed` would report an approval count that
          // does not exist.
          attended: summary.confirmed,
          unattended: summary.observed,
          denied: summary.denied,
          firstQuarterAskRate: result.firstQuarterAskRate,
          lastQuarterAskRate: result.lastQuarterAskRate,
        },
        null,
        2,
      ) + '\n',
    );
    return 0;
  }

  // --- what we found ------------------------------------------------------
  const days = Math.max(1, Math.round((summary.latest - summary.earliest) / 86_400_000));
  process.stdout.write(
    `  ${c.green(sym.allow)} ${plural(summary.sessions, 'session')} across ${plural(summary.byProject.size, 'project')}  ` +
      c.gray(`${plural(result.total, 'action')}, about ${plural(days, 'day')} of history`) +
      '\n\n',
  );

  // What the agents actually did, by capability.
  const caps = new Map<string, number>();
  for (const p of summary.byProject.values()) {
    for (const [k, v] of Object.entries(p.envelope.capabilities)) {
      caps.set(k, (caps.get(k) ?? 0) + v);
    }
  }
  const topCaps = [...caps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const capMax = topCaps[0]?.[1] ?? 1;
  process.stdout.write(c.bold('  What they have been doing\n'));
  for (const [cap, n] of topCaps) {
    process.stdout.write(
      `    ${pad(friendly(cap as Capability), 34)} ${bar(n, capMax, 18)} ${c.gray(n.toLocaleString('en-US'))}\n`,
    );
  }
  process.stdout.write('\n');

  // --- how much of it was actually supervised -----------------------------
  const unsupervised = summary.observed / Math.max(1, summary.events);
  if (unsupervised > 0.5) {
    process.stdout.write(
      para(
        c.yellow(`${Math.round(unsupervised * 100)}% of that ran in a mode where nobody was asked.`) +
          c.gray(
            ' LeastGrant counts those as things it has seen, not things you approved — so they teach it what is normal here without granting anything.',
          ),
        2,
      ) + '\n\n',
    );
  }

  // --- the counterfactual -------------------------------------------------
  process.stdout.write(c.bold('  What LeastGrant would have done\n'));
  const pctOf = (n: number) => (result.total ? Math.round((n / result.total) * 100) : 0);
  process.stdout.write(
    `    ${c.green(sym.allow)} ${pad(plural(result.allowed, 'action'), 22)} ${c.gray('would have run without asking')}  ${c.bold(pctOf(result.allowed) + '%')}\n`,
  );
  process.stdout.write(
    `    ${c.yellow(sym.ask)} ${pad(plural(result.asked, 'action'), 22)} ${c.gray('would have paused for you')}  ${c.gray(pctOf(result.asked) + '%')}\n`,
  );
  if (result.blocked) {
    process.stdout.write(
      `    ${c.red(sym.deny)} ${pad(plural(result.blocked, 'action'), 22)} ${c.gray('would have been stopped')}\n`,
    );
  }
  process.stdout.write('\n');

  // The learning curve. This is the claim that distinguishes learning from a
  // static ruleset, so it is worth stating precisely or not at all.
  if (result.timeline.length >= 8) {
    const a = Math.round(result.firstQuarterAskRate * 100);
    const b = Math.round(result.lastQuarterAskRate * 100);
    if (a > b) {
      process.stdout.write(
        para(
          `${c.gray('It gets quieter as it goes:')} early on it would have interrupted ${c.bold(a + '%')} of the time, by the end ${c.bold(b + '%')}${c.gray('.')}`,
          2,
        ) + '\n\n',
      );
    }
  }

  // --- the interesting tail ----------------------------------------------
  const interesting = [...result.blockedItems, ...result.notable].slice(0, 6);
  if (interesting.length) {
    process.stdout.write(c.bold('  The kind of thing it would have stopped to ask about\n'));
    const w = Math.min(term.cols - 12, 74);
    for (const o of interesting) {
      const glyph = o.decision === 'deny' ? c.red(sym.deny) : c.yellow(sym.ask);
      process.stdout.write(`    ${glyph} ${truncate(o.display.replace(/\s+/g, ' '), w)}\n`);
      process.stdout.write(`      ${c.gray(truncate(stripPrefix(o.reason), w))}\n`);
    }
    process.stdout.write('\n');
  }

  // --- the honesty section ------------------------------------------------
  process.stdout.write(c.bold('  Checking itself\n'));
  if (summary.denied === 0) {
    process.stdout.write(
      para(c.gray('You never turned an action down in this history, so there is nothing to check its judgement against yet. It will keep score from here.'), 4) + '\n',
    );
  } else if (result.regrets.length === 0) {
    process.stdout.write(
      `    ${c.green(sym.allow)} ${c.gray(`of the ${plural(summary.denied, 'action')} you turned down, LeastGrant would have waved through`)} ${c.bold('none')}${c.gray('.')}\n`,
    );
  } else {
    process.stdout.write(
      `    ${c.yellow('!')} ${c.gray(`of the ${plural(summary.denied, 'action')} you turned down, LeastGrant would have allowed`)} ${c.bold(String(result.regrets.length))}${c.gray(':')}\n`,
    );
    for (const r of result.regrets.slice(0, 3)) {
      process.stdout.write(`      ${c.gray(sym.bullet)} ${truncate(r.display, 68)}\n`);
    }
    process.stdout.write(
      para(
        c.gray('That is a real miss, shown here rather than hidden. You can close each one with `leastgrant deny "<signature>"`.'),
        6,
      ) + '\n',
    );
  }
  process.stdout.write('\n');

  // --- the proposal -------------------------------------------------------
  //
  // Everything above was observation, which LeastGrant will not treat as
  // consent. This is where it asks for consent, once, with the consequences on
  // screen — and it is what makes the tool useful on day one instead of after a
  // fortnight of clicking.
  const envelopeList = [...result.envelopes.values()];
  const bundles = proposeBundles(envelopeList);
  // The denominator has to be actions, not events: one `npm test && git push`
  // is a single event but two actions, and a bundle's occurrence count is in
  // actions. Mixing the two produced a coverage figure over 100%.
  const totalActions = envelopeList.reduce(
    (n, env) => n + Object.values(env.signatures).reduce((m, s) => m + s.totalSeen, 0),
    0,
  );
  // A dry run still prints the proposal — seeing what it would offer is most of
  // the point of asking for a preview — it just never prompts and never writes.
  const chosen = await offerBundles(bundles, totalActions, assumeYes, dryRun);
  if (dryRun) {
    process.stdout.write(para(c.gray('Dry run: nothing written, nothing installed.'), 2) + '\n\n');
    return 0;
  }

  const grantedAt = Date.now();
  let grantedSignatures = 0;
  for (const b of chosen) {
    for (const env of envelopeList) {
      for (const sig of b.signatures) {
        const stat = env.signatures[sig];
        if (!stat) continue;
        observe(
          env,
          {
            signature: sig,
            capability: stat.capability,
            blast: stat.worstBlast,
            evidence: 'granted',
            at: grantedAt,
            sessionId: 'setup',
            display: stat.samples[0] ?? sig,
          },
          config.thresholds,
        );
        grantedSignatures++;
      }
    }
  }

  // Persist what the replay learned so the hook starts warm rather than blank.
  for (const env of result.envelopes.values()) saveEnvelope(env);
  saveConfig(config);
  process.stdout.write(
    `\n  ${c.green(sym.allow)} ${c.gray(`Saved a starting profile for ${plural(result.envelopes.size, 'project')}`)}` +
      (grantedSignatures
        ? c.gray(`, with ${plural(chosen.length, 'bundle')} approved.`)
        : c.gray('. Nothing pre-approved — it will ask and learn as you go.')) +
      '\n\n',
  );

  const already = isClaudeInstalled('user');
  if (already) {
    process.stdout.write(`  ${c.gray(sym.bullet)} The Claude Code hook is already installed.\n\n`);
    process.stdout.write(nextSteps());
    return 0;
  }

  const wants = assumeYes || (await confirm('  Install the Claude Code hook now?'));
  if (!wants) {
    process.stdout.write(
      '\n' + para(c.gray('Left alone. When you want it: `leastgrant install`.'), 2) + '\n\n',
    );
    return 0;
  }

  await installCommand({ command: 'install', positional: ['claude-code'], flags: {} });
  process.stdout.write(nextSteps());
  return 0;
}

function nextSteps(): string {
  return (
    c.bold('  Next\n') +
    `    ${c.cyan('leastgrant check "git push --force"')}   ${c.gray('see how it reasons')}\n` +
    `    ${c.cyan('leastgrant status')}                     ${c.gray('what it knows about this project')}\n` +
    `    ${c.cyan('leastgrant trail')}                      ${c.gray('what your agents did today')}\n\n` +
    para(
      c.gray(
        'It starts in assist mode: it stops for anything unusual, and gets quieter as it sees you approve the routine. `leastgrant status` always shows what it will and will not ask about.',
      ),
      2,
    ) +
    '\n\n'
  );
}

/** A machine with no agent history yet: explain and offer to install. */
async function firstRunWithNoHistory(json: boolean, assumeYes: boolean, dryRun: boolean): Promise<number> {
  if (json) {
    process.stdout.write(JSON.stringify({ sessions: 0, actions: 0, installed: false }, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(
    '\n' +
      para(
        c.gray(
          "No Claude Code session history found, so there is nothing to learn from yet. That is fine — LeastGrant will start watching from now and get quieter as it goes.",
        ),
        2,
      ) +
      '\n\n',
  );
  if (dryRun) return 0;
  const wants = assumeYes || (await confirm('  Install the Claude Code hook now?'));
  if (!wants) {
    process.stdout.write('\n' + para(c.gray('When you want it: `leastgrant install`.'), 2) + '\n\n');
    return 0;
  }
  await installCommand({ command: 'install', positional: ['claude-code'], flags: {} });
  process.stdout.write(nextSteps());
  return 0;
}

/**
 * Present the bundles and collect one deliberate answer.
 *
 * The design constraint is that this must be readable in five seconds and
 * impossible to say yes to by accident. So: a short list, the recommended ones
 * marked, the exclusions printed next to each one, and a default that only
 * covers work that stays inside the project.
 */
async function offerBundles(
  bundles: Bundle[],
  totalActions: number,
  assumeYes: boolean,
  previewOnly = false,
): Promise<Bundle[]> {
  if (!bundles.length) return [];

  const recommended = bundles.filter((b) => b.recommended);
  const covered = coverageOf(recommended);
  const share = totalActions ? Math.min(100, Math.round((covered / totalActions) * 100)) : 0;

  process.stdout.write(c.bold('  What it could stop asking about\n'));
  process.stdout.write(
    para(
      c.gray(
        'None of the above counts as your approval — it ran while nobody was asked. Here is what LeastGrant can see you doing routinely. Approving a bundle is you saying yes once, in advance.',
      ),
      2,
    ) + '\n\n',
  );

  bundles.forEach((b, i) => {
    const mark = b.recommended ? c.green(sym.allow) : c.gray(sym.bullet);
    process.stdout.write(
      `   ${c.gray(String(i + 1) + '.')} ${mark} ${c.bold(b.title)}  ${c.gray(plural(b.occurrences, 'time') + ' so far')}\n`,
    );
    process.stdout.write(`        ${c.gray(b.detail)}\n`);
    process.stdout.write(`        ${c.gray(b.excludes)}\n`);
  });
  process.stdout.write('\n');
  process.stdout.write(
    para(
      c.gray(`The ${plural(recommended.length, 'marked bundle')} cover about `) +
        c.bold(share + '%') +
        c.gray(' of everything your agents did. Floors still apply on top: credentials, anything outside a project, shell profiles and git hooks keep asking regardless.'),
      2,
    ) + '\n\n',
  );

  if (previewOnly) return [];
  if (assumeYes) return recommended;
  if (!process.stdin.isTTY) return [];

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (
      await rl.question(
        `  Approve the marked bundles? ${c.gray('[Y]es / [a]ll / [n]one / numbers like 1,3')} `,
      )
    )
      .trim()
      .toLowerCase();

    if (answer === 'n' || answer === 'no') return [];
    if (answer === 'a' || answer === 'all') return bundles;
    if (/^[\d,\s]+$/.test(answer) && answer !== '') {
      const picked = new Set(
        answer
          .split(/[,\s]+/)
          .filter(Boolean)
          .map((x) => Number(x) - 1),
      );
      return bundles.filter((_b, i) => picked.has(i));
    }
    return recommended;
  } finally {
    rl.close();
  }
}

async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} ${c.gray('[Y/n]')} `)).trim().toLowerCase();
    return answer === '' || answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

/** Headlines are written for the agent prompt; here the prefix is noise. */
function stripPrefix(s: string): string {
  return s.replace(/^LeastGrant (blocked|allowed) this: /, '');
}

export { path };
