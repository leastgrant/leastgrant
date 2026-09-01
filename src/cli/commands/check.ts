/**
 * `leastgrant check "<command>"`
 *
 * Ask what LeastGrant would decide, without running anything.
 *
 * This is the command that makes the tool legible. Every claim the README makes
 * is something you can put in here and watch happen, and every bug report can
 * start with its output. It is also the fastest way to understand the model:
 * run it on something boring, then on something frightening, and the difference
 * explains the product better than any diagram.
 */

import type { Request, Verdict } from '../../core/types.js';
import { decide, friendly } from '../../core/decide.js';
import { blastTier } from '../../core/types.js';
import { approvalsNeededFor, CONFIDENCE_BY_TIER } from '../../core/envelope.js';
import { loadContext } from '../context.js';
import { blastStrip, c, hang, oneLine, pad, para, sym, term, verdictBadge, width } from '../ui.js';
import type { Argv } from '../index.js';

export function checkCommand(argv: Argv): number {
  const command = argv.positional.join(' ') || String(argv.flags['command'] ?? '');
  const tool = String(argv.flags['tool'] ?? 'Bash');

  if (!command && tool === 'Bash') {
    process.stderr.write(
      `\n  ${c.red('Nothing to check.')}\n\n  ${c.gray('Try:')} leastgrant check "git push --force"\n\n`,
    );
    return 2;
  }

  const ctx = loadContext();
  const input: Record<string, unknown> =
    tool === 'Bash' ? { command } : { file_path: command, command };

  const req: Request = {
    agent: 'cli',
    tool,
    input,
    cwd: ctx.cwd,
    sessionId: 'check',
    at: Date.now(),
  };

  const verdict = decide(req, ctx.decideCtx);

  if (argv.flags['json']) {
    process.stdout.write(JSON.stringify(verdict, null, 2) + '\n');
    return 0;
  }

  // Show the tool for anything that is not a shell command. `check --tool Write
  // ~/.claude/settings.json` used to print only the path, so the one example in
  // the demo that is about *write* access read as though it were about a file.
  const subject = tool === 'Bash' ? command : command ? `${tool} ${command}` : tool;
  process.stdout.write(renderVerdict(verdict, subject));
  return 0;
}

/**
 * The explanation layout.
 *
 * Shape: what it is, what it would do, why, and what would change the answer.
 * No scores anywhere — a developer at 2am needs a sentence, not a number.
 */
export interface VerdictLayout {
  /**
   * Print the closing "what would change it" line. `leastgrant why` sets this
   * false and prints its own, which knows about your rules and what has been
   * learned; two corner notes giving slightly different advice about the same
   * decision is worse than one.
   */
  closing?: boolean;
}

/** Label column for the field rows, wide enough for "blast radius". */
const LABEL = 14;

export function renderVerdict(verdict: Verdict, subject: string, layout: VerdictLayout = {}): string {
  const out: string[] = [''];
  const a = verdict.action;

  out.push(`  ${verdictBadge(verdict.decision)}  ${c.bold(truncateMid(subject, Math.min(68, term.cols - 12)))}`);
  out.push('');

  // What it is. These wrap: a capability description or a full blast strip runs
  // well past 80 columns, and this block is also embedded in `leastgrant why`.
  const field = (label: string, value: string) => hang(c.gray(pad(label, LABEL)), value, 2);
  out.push(field('what it does', describeAction(a)));
  out.push(field('blast radius', blastStrip(a.blast)));

  const targets = a.targets.filter((t) => t.value).slice(0, 4);
  if (targets.length) {
    const rendered = targets.map((t) => {
      const label = shorten(t.value);
      if (t.secret) return c.red(label) + c.gray(' (credentials)');
      if (t.type === 'host') return c.cyan(label);
      if (t.inWorkspace === false) return c.yellow(label) + c.gray(' (outside)');
      return label;
    });
    out.push(field('touches', rendered.join(c.gray(', '))));
  }

  if (verdict.actions.length > 1) {
    out.push('');
    out.push(`  ${c.gray('this command runs ' + verdict.actions.length + ' things:')}`);
    for (const act of verdict.actions.slice(0, 6)) {
      const t = blastTier(act.blast);
      const dot = t >= 3 ? c.red(sym.bullet) : t >= 2 ? c.yellow(sym.bullet) : c.green(sym.bullet);
      out.push(`    ${dot} ${truncateMid(act.display, 62)}  ${c.gray(act.capability)}`);
    }
    if (verdict.actions.length > 6) {
      out.push(c.gray(`    …and ${verdict.actions.length - 6} more`));
    }
  }

  // Why
  out.push('');
  out.push(`  ${c.gray('why')}`);
  for (const r of verdict.reasons.slice(0, 6)) {
    const mark =
      r.weight === 'blocks' ? c.red(sym.bullet)
      : r.weight === 'raises' ? c.yellow(sym.bullet)
      : r.weight === 'lowers' ? c.green(sym.bullet)
      : c.gray(sym.bullet);
    out.push(indentWrap(`${mark} ${oneLine(r.text)}`, 4, 6));
  }

  // What would change it
  const next = layout.closing === false ? null : whatWouldChange(verdict);
  if (next) {
    out.push('');
    out.push(indentWrap(`${c.gray(sym.corner + ' ' + next)}`, 2, 4));
  }

  out.push('');
  return out.join('\n');
}

function describeAction(a: Verdict['action']): string {
  const notes = a.notes.filter(Boolean);
  if (notes.length) return oneLine(notes[0]!);
  return friendly(a.capability);
}

/**
 * The single most useful line in the output: what the user can do about it.
 * A permission prompt that does not tell you how to stop seeing it is just a
 * nag.
 */
function whatWouldChange(verdict: Verdict): string | null {
  if (verdict.decision === 'allow') return null;

  if (verdict.reasons.some((r) => r.code === 'guard.self-write')) {
    return 'nothing changes this — LeastGrant will not let an agent edit its own records';
  }

  // Do not hand out advice that is worse than the problem. When the reason we
  // stopped is that the payload is unknowable, the signature is something like
  // `sh` or `python <path>`, and telling someone to allow *that* would grant far
  // more than the command in front of them. `leastgrant allow` would refuse the
  // pattern anyway; better not to suggest it in the first place.
  const unknowable = verdict.reasons.some(
    (r) =>
      r.code === 'guard.not-understood' ||
      r.code === 'guard.pipe-to-shell' ||
      r.code === 'guard.fetch-run',
  );
  if (unknowable) {
    return 'there is no safe way to pre-approve this one: LeastGrant cannot see what the code does, so it asks every time';
  }

  if (verdict.floor) {
    // `--force` when this signature is new here.
    //
    // `leastgrant allow` refuses a pattern that matches nothing it has seen,
    // on the grounds that a rule matching nothing is worse than no rule. That
    // is a good rule, but it made `check` print a command that `allow` then
    // turned down — the tool contradicting itself in the space of two lines.
    const known = (verdict.familiarity?.confirmed ?? 0) + (verdict.familiarity?.observed ?? 0) > 0;
    const force = known ? '' : ' --force';
    return `this always asks. To pre-answer it, run: leastgrant allow ${quote(verdict.action.signature)}${force}`;
  }
  if (verdict.reasons.some((r) => r.code === 'gap.denied')) {
    return `you turned this down before. To change your mind: leastgrant allow ${quote(verdict.action.signature)}`;
  }

  const tier = blastTier(verdict.action.blast);
  const need = CONFIDENCE_BY_TIER[tier];
  if (need !== undefined) {
    const n = approvalsNeededFor(need);
    const have = Math.floor(verdict.familiarity?.confirmed ?? 0);
    const left = Math.max(1, n - have);
    return `approve this ${left} more time${left === 1 ? '' : 's'} (on ${plural2(2, 'separate day')}) and it stops asking — or run: leastgrant allow ${quote(verdict.action.signature)}`;
  }
  return `to pre-answer this: leastgrant allow ${quote(verdict.action.signature)}`;
}

const plural2 = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

function quote(s: string): string {
  return c.cyan(`"${s}"`);
}

function shorten(p: string): string {
  const n = oneLine(p).replace(/\\/g, '/');
  const parts = n.split('/');
  return parts.length > 3 ? '…/' + parts.slice(-2).join('/') : n;
}

/**
 * `oneLine` first, not just a whitespace squeeze: `leastgrant why` feeds this
 * renderer display strings an agent chose and the ledger stored verbatim, and a
 * row that can move the cursor can rewrite the rows above it.
 */
function truncateMid(s: string, max: number): string {
  const flat = oneLine(s);
  if (flat.length <= max) return flat;
  const head = Math.ceil((max - 1) * 0.65);
  const tail = max - 1 - head;
  return flat.slice(0, head) + '…' + flat.slice(flat.length - tail);
}

/** Wrap text at the terminal width with a hanging indent. */
function indentWrap(text: string, indent: number, hang: number): string {
  // 96 reads well on a wide terminal; on a narrow one it is just overflow, and
  // `leastgrant why` renders this same block inside its own output.
  const max = Math.min(96, term.cols);
  const words = text.split(' ');
  const lines: string[] = [];
  let line = ' '.repeat(indent);
  let first = true;
  for (const w of words) {
    const prospective = line === ' '.repeat(first ? indent : hang) ? line + w : line + ' ' + w;
    if (width(prospective) > max && width(line) > (first ? indent : hang)) {
      lines.push(line);
      line = ' '.repeat(hang) + w;
      first = false;
    } else {
      line = prospective;
    }
  }
  lines.push(line);
  return lines.join('\n');
}

export { para };
