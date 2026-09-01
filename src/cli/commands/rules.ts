/**
 * `leastgrant allow | deny | forget | rules`
 *
 * The four commands that let you answer a question before it gets asked.
 *
 * They live in one file because they are one data structure seen from four
 * angles: a rule is a signature glob plus an effect, and the whole list is
 * usually shorter than this comment. They also share one hazard, which is why
 * `allow` is so much longer than the other three.
 *
 * Rules sit above the ask floors in the decision order (see decide.ts). That is
 * intentional — a rule *is* a human answer, given in advance — but it means a
 * careless `allow "*"` quietly switches off the part of the tool that stops to
 * ask. So before writing an allow rule down we look at what it would actually
 * cover in this project, and refuse the ones that cover too much. Once. With a
 * narrower pattern to copy.
 */

import type { Envelope, Rule, SignatureStat } from '../../core/types.js';
import { blastTier } from '../../core/types.js';
import { globMatch } from '../../core/secrets.js';
import { addRule, saveConfig, saveEnvelope } from '../../store/index.js';
import { loadContext, type CliContext } from '../context.js';
import { ago, blastStrip, c, pad, para, plural, sym, table, truncate, verdictBadge } from '../ui.js';
import type { Argv } from '../index.js';

export function rulesCommand(argv: Argv): number {
  const ctx = loadContext();
  const json = Boolean(flag(argv, 'json'));

  switch (argv.command) {
    case 'allow':
      return add(argv, ctx, 'allow', json);
    case 'deny':
      return add(argv, ctx, 'deny', json);
    case 'forget':
      return forget(argv, ctx, json);
    default:
      return list(ctx, json);
  }
}

// ---------------------------------------------------------------------------
// allow / deny
// ---------------------------------------------------------------------------

function add(argv: Argv, ctx: CliContext, effect: 'allow' | 'deny', json: boolean): number {
  const pattern = patternOf(argv);
  if (!pattern) return missingPattern(effect, json);

  const global = Boolean(flag(argv, 'global'));
  const force = Boolean(flag(argv, 'force'));
  const note = typeof argv.flags['note'] === 'string' ? argv.flags['note'].trim() : '';
  const now = Date.now();

  let expiresAt: number | undefined;
  const expires = argv.flags['expires'];
  if (expires !== undefined && expires !== false) {
    const ms = typeof expires === 'string' ? parseDuration(expires) : null;
    if (ms === null) {
      if (json) {
        process.stdout.write(json2({ command: effect, ok: false, error: 'bad-duration', expires }));
        return 2;
      }
      process.stderr.write(
        `\n  ${c.red("I don't understand that duration.")}\n\n` +
          para(`--expires takes things like ${c.cyan('30d')}, ${c.cyan('2w')}, ${c.cyan('24h')}, ${c.cyan('6mo')}.`) +
          '\n\n',
      );
      return 2;
    }
    expiresAt = now + ms;
  }

  const matched = matchingSignatures(ctx.envelope, pattern);

  // An allow rule can pre-answer a hard floor, so it gets checked before it is
  // written. A deny rule can only ever add friction, so it does not.
  if (effect === 'allow' && !force) {
    const refusal = wouldCoverTooMuch(pattern, matched, ctx.envelope);
    if (refusal) {
      if (json) {
        process.stdout.write(
          json2({
            command: 'allow',
            pattern,
            added: null,
            refused: refusal.reason,
            covers: matched.map(describeSig),
            suggestion: refusal.suggestion,
            override: `leastgrant allow ${JSON.stringify(pattern)} --force`,
          }),
        );
        return 0;
      }
      process.stdout.write(renderRefusal(pattern, matched, refusal));
      return 2;
    }
  }

  const rule: Rule = {
    match: pattern,
    effect,
    scope: global ? 'global' : 'project',
    addedAt: now,
  };
  if (!global) rule.key = ctx.key;
  if (note) rule.note = note;
  if (expiresAt) rule.expiresAt = expiresAt;

  const replaced = ctx.config.rules.some(
    (r) => r.match === rule.match && r.scope === rule.scope && r.key === rule.key,
  );
  const config = addRule(ctx.config, rule);

  // A deny rule anywhere beats an allow rule everywhere. Saying so now is much
  // cheaper than the user discovering it during a demo.
  const shadowedBy =
    effect === 'allow'
      ? config.rules.find(
          (r) =>
            r.effect === 'deny' &&
            appliesHere(r, ctx.key, now) &&
            (r.match === pattern || matched.some((s) => globMatch(r.match, s.signature))),
        )
      : undefined;

  if (json) {
    process.stdout.write(
      json2({
        command: effect,
        pattern,
        added: rule,
        replaced,
        scope: rule.scope,
        covers: matched.map(describeSig),
        shadowedBy: shadowedBy ? shadowedBy.match : null,
      }),
    );
    return 0;
  }

  process.stdout.write(renderAdded(rule, matched, { replaced, shadowedBy, ctx, force }));
  return 0;
}

interface Refusal {
  reason: 'matches-nothing' | 'too-broad' | 'reaches-too-far';
  /** The sentence that explains it. One paragraph, no lecture. */
  text: string;
  suggestion: string | null;
}

/**
 * The gate on `allow`.
 *
 * Two failure shapes, and they fail for opposite reasons. A pattern that
 * matches nothing is dangerous because the user walks away believing they are
 * covered; a pattern that matches something frightening is dangerous because
 * they are. Both are recoverable with `--force`, so this is a speed bump, not a
 * policy.
 */
function wouldCoverTooMuch(
  pattern: string,
  matched: SignatureStat[],
  env: Envelope,
): Refusal | null {
  if (!matched.length) {
    const near = nearestSignature(pattern, env);
    return {
      reason: 'matches-nothing',
      text:
        `nothing LeastGrant has seen in this project matches ${quote(pattern)}. a rule that matches ` +
        `nothing is worse than no rule at all, because you will remember writing it and stop watching.`,
      suggestion: near,
    };
  }

  const risky = matched.filter((s) => blastTier(s.worstBlast) >= 3);
  const broad = pattern.startsWith('*') || pattern.trim().length < 4;

  if (risky.length) {
    const it = risky.length === 1 ? 'one of them reaches' : `${risky.length} of them reach`;
    return {
      reason: 'reaches-too-far',
      text:
        `${quote(pattern)} covers ${plural(matched.length, 'thing')} you already run here, and ${it} ` +
        `past this project — the kind of thing LeastGrant is built to stop and ask about. an allow rule ` +
        `answers that question in advance, permanently, for everything the pattern matches.`,
      suggestion: narrower(matched),
    };
  }

  if (broad) {
    return {
      reason: 'too-broad',
      text:
        `${quote(pattern)} is wider than it looks. it covers ${plural(matched.length, 'thing')} today, ` +
        `and it will silently cover whatever matches it next month too — including things LeastGrant ` +
        `would otherwise always stop for.`,
      suggestion: narrower(matched),
    };
  }

  return null;
}

function renderRefusal(pattern: string, matched: SignatureStat[], r: Refusal): string {
  const out: string[] = [''];
  out.push(`  ${c.red(sym.deny + ' not adding that rule')}`);
  out.push('');
  out.push(para(r.text, 2));

  if (matched.length) {
    out.push('');
    out.push(`  ${c.gray('it would cover')}`);
    out.push(...coverage(matched));
  }

  out.push('');
  if (r.suggestion) {
    const verb = r.reason === 'matches-nothing' ? 'closest thing it knows' : 'narrower';
    out.push(`  ${c.gray(sym.corner)} ${c.gray(verb + ':')} leastgrant allow ${c.cyan(`"${r.suggestion}"`)}`);
  }
  out.push(
    `  ${c.gray(sym.corner)} ${c.gray('if you meant it:')} leastgrant allow ${c.cyan(`"${pattern}"`)} ${c.cyan('--force')}`,
  );
  out.push('');
  return out.join('\n');
}

function renderAdded(
  rule: Rule,
  matched: SignatureStat[],
  extra: { replaced: boolean; shadowedBy: Rule | undefined; ctx: CliContext; force: boolean },
): string {
  const out: string[] = [''];
  out.push(`  ${verdictBadge(rule.effect === 'deny' ? 'deny' : 'allow')}  ${c.bold(rule.match)}`);
  out.push('');

  // Scope goes first and is spelled out. "global" in a table cell is how people
  // end up allowing something across every repo they own without noticing.
  if (rule.scope === 'global') {
    out.push(field('scope', c.yellow('every project on this machine')));
    out.push(field('', c.gray('including repositories you have not opened yet')));
  } else {
    out.push(field('scope', `this project only ${c.gray(short(extra.ctx.root))}`));
  }

  if (matched.length) {
    out.push(field('covers', `${plural(matched.length, 'thing')} you already run here`));
    out.push(...coverage(matched, 4));
  } else if (rule.effect === 'deny') {
    out.push(field('covers', c.gray('nothing yet — it will apply the first time something matches')));
  } else {
    out.push(field('covers', c.gray('nothing it has seen here yet')));
  }

  if (rule.expiresAt) {
    out.push(field('expires', `${inWords(rule.expiresAt - rule.addedAt)} from now`));
  }

  if (rule.note) {
    out.push(field('note', rule.note));
  } else {
    out.push(
      field('note', c.gray(`none — ${c.cyan('--note "why"')} shows up whenever this rule decides something`)),
    );
  }

  out.push('');
  if (extra.replaced) {
    out.push(`  ${c.gray(sym.corner)} ${c.gray('this replaced an earlier rule with the same pattern')}`);
  }
  if (extra.shadowedBy) {
    out.push(
      `  ${c.gray(sym.corner)} ${c.yellow('heads up:')} ${c.gray(
        `your deny rule ${quote(extra.shadowedBy.match)} still wins — deny beats allow`,
      )}`,
    );
  }
  out.push(`  ${c.gray(sym.corner)} ${c.gray('undo:')} leastgrant forget ${c.cyan(`"${rule.match}"`)}`);
  out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// forget
// ---------------------------------------------------------------------------

function forget(argv: Argv, ctx: CliContext, json: boolean): number {
  const pattern = patternOf(argv);
  if (!pattern) return missingPattern('forget', json);

  const now = Date.now();
  const global = Boolean(flag(argv, 'global'));
  const learned = Boolean(flag(argv, 'learned'));

  const doomed = ctx.config.rules.filter((r) => {
    if (global && r.scope !== 'global') return false;
    if (!global && !appliesHere(r, ctx.key, now)) return false;
    return r.match === pattern || globMatch(pattern, r.match);
  });

  const signatures = matchingSignatures(ctx.envelope, pattern);

  if (doomed.length) {
    // Not `removeRule`: it keys on match+scope only, so forgetting a project
    // rule here would also delete an identically-worded rule belonging to a
    // different project. Rules are the one thing that must never disappear by
    // accident.
    saveConfig({ ...ctx.config, rules: ctx.config.rules.filter((r) => !doomed.includes(r)) });
  }

  let forgotten = 0;
  if (learned && signatures.length) {
    const env = ctx.envelope;
    for (const s of signatures) {
      delete env.signatures[s.signature];
      // Keep the capability and event totals honest — `status` counts them, and
      // an envelope that still claims 40 events for evidence we just deleted is
      // lying. Transitions are capability-level and cannot be attributed back to
      // a single signature, so they stay.
      const seen = env.capabilities[s.capability] ?? 0;
      env.capabilities[s.capability] = Math.max(0, seen - s.totalSeen);
      env.events = Math.max(0, env.events - s.totalSeen);
      forgotten++;
    }
    env.updatedAt = now;
    saveEnvelope(env);
  }

  if (json) {
    process.stdout.write(
      json2({
        command: 'forget',
        pattern,
        rulesRemoved: doomed.map((r) => ({ match: r.match, effect: r.effect, scope: r.scope })),
        signaturesForgotten: learned ? signatures.map((s) => s.signature) : [],
        signaturesMatched: signatures.map((s) => s.signature),
        learned,
      }),
    );
    return 0;
  }

  const out: string[] = [''];

  if (!doomed.length && !forgotten) {
    out.push(`  ${c.gray('nothing matches')} ${c.bold(pattern)}`);
    out.push('');
    if (signatures.length) {
      out.push(
        para(
          `no rule uses that pattern, but ${plural(signatures.length, 'signature')} LeastGrant learned ` +
            `here match it. add ${c.cyan('--learned')} to unlearn those as well.`,
        ),
      );
    } else {
      out.push(
        para(
          `no rule and nothing learned in this project matches it. ` +
            `${c.cyan('leastgrant rules')} lists what you have set.`,
        ),
      );
    }
    out.push('');
    process.stdout.write(out.join('\n'));
    return 0;
  }

  const parts: string[] = [];
  if (doomed.length) parts.push(plural(doomed.length, 'rule'));
  if (forgotten) parts.push(`${plural(forgotten, 'learned signature')}`);
  out.push(`  ${c.green(sym.allow)} forgot ${parts.join(' and ')}`);

  if (doomed.length) {
    out.push('');
    for (const r of doomed) {
      out.push(
        `    ${effectLabel(r)}  ${pad(truncate(r.match, 44), 44)}  ${c.gray(scopeLabel(r, ctx.key))}`,
      );
    }
  }

  out.push('');
  if (forgotten) {
    out.push(
      para(
        c.gray(
          `LeastGrant will ask about ${forgotten === 1 ? 'that' : 'those'} again until it has watched ` +
            `you approve ${forgotten === 1 ? 'it' : 'them'} a few more times.`,
        ),
      ),
    );
  } else if (signatures.length) {
    out.push(
      `  ${c.gray(sym.corner)} ${c.gray(
        `${plural(signatures.length, 'learned signature')} still match — ${c.cyan('--learned')} removes those too`,
      )}`,
    );
  }
  out.push('');
  process.stdout.write(out.join('\n'));
  return 0;
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

function list(ctx: CliContext, json: boolean): number {
  const now = Date.now();
  const rules = ctx.config.rules;

  if (json) {
    process.stdout.write(
      json2({
        command: 'rules',
        project: ctx.root,
        rules: rules.map((r) => ({
          ...r,
          expired: isExpired(r, now),
          appliesHere: appliesHere(r, ctx.key, now),
        })),
      }),
    );
    return 0;
  }

  if (!rules.length) {
    process.stdout.write(emptyState());
    return 0;
  }

  const rank: Record<string, number> = { deny: 0, allow: 1, ask: 2 };
  const ordered = [...rules].sort((a, b) => {
    const ea = isExpired(a, now) ? 1 : 0;
    const eb = isExpired(b, now) ? 1 : 0;
    if (ea !== eb) return ea - eb;
    const ra = rank[a.effect] ?? 3;
    const rb = rank[b.effect] ?? 3;
    if (ra !== rb) return ra - rb;
    return b.addedAt - a.addedAt;
  });

  const rows = ordered.map((r) => {
    const dead = isExpired(r, now);
    const cells = [
      r.match,
      effectLabel(r),
      scopeCell(r, ctx.key),
      whenCell(r, now),
      r.note ?? c.gray('—'),
    ];
    // An expired rule decides nothing, so it should not look like it does.
    return dead ? cells.map((x) => c.gray(stripStyle(x))) : cells;
  });

  const out: string[] = [''];
  out.push(
    indent(
      table(
        [
          { header: 'pattern' },
          { header: 'effect' },
          { header: 'scope' },
          { header: 'age / expiry' },
          { header: 'note' },
        ],
        rows,
      ),
    ),
  );

  const active = rules.filter((r) => !isExpired(r, now)).length;
  const here = rules.filter((r) => appliesHere(r, ctx.key, now)).length;
  out.push('');
  out.push(
    `  ${c.gray(
      `${plural(rules.length, 'rule')}, ${active} active, ${here} applying in this project`,
    )}`,
  );
  out.push(
    `  ${c.gray(sym.corner)} ${c.gray('rules win over anything LeastGrant has learned. remove one with')} ` +
      `leastgrant forget ${c.cyan('"<pattern>"')}`,
  );
  out.push('');
  process.stdout.write(out.join('\n'));
  return 0;
}

function emptyState(): string {
  const out: string[] = [''];
  out.push(`  ${c.bold('no rules')} ${c.gray('— which is the normal state')}`);
  out.push('');
  out.push(
    para(
      'LeastGrant works without them. It watches what your agents actually do and stops asking about ' +
        'the things you keep approving, so most of what a rule would do happens on its own.',
    ),
  );
  out.push('');
  out.push(
    para(
      'Rules are for the rest: pre-answering something it would otherwise stop for every single time, ' +
        'or blocking something outright so it never comes up.',
    ),
  );
  out.push('');
  out.push(`    leastgrant allow ${c.cyan('"npm run <script>"')}     ${c.gray('stop being asked')}`);
  out.push(`    leastgrant deny  ${c.cyan('"git push --force *"')}   ${c.gray('never, not here')}`);
  out.push(`    leastgrant check ${c.cyan('"git push"')}             ${c.gray('see what it decides today')}`);
  out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// shared bits
// ---------------------------------------------------------------------------

function missingPattern(command: string, json: boolean): number {
  const example = command === 'deny' ? 'git push --force *' : 'npm run <script>';
  if (json) {
    // The one case that keeps a non-zero exit under --json: nothing ran, so
    // there is no result to report, and a script should notice.
    process.stdout.write(json2({ command, ok: false, error: 'missing-pattern' }));
    return 2;
  }
  process.stderr.write(
    `\n  ${c.red('That needs a pattern.')}\n\n` +
      para(`Try: leastgrant ${command} ${c.cyan(`"${example}"`)}`) +
      '\n\n' +
      para(
        c.gray(
          'A pattern matches a signature — the tidied-up form of a command, with paths and messages ' +
            'taken out. `leastgrant check "npm test"` prints the one it would use.',
        ),
      ) +
      '\n\n',
  );
  return 2;
}

function matchingSignatures(env: Envelope, pattern: string): SignatureStat[] {
  return Object.values(env.signatures)
    .filter((s) => globMatch(pattern, s.signature))
    .sort((a, b) => blastTier(b.worstBlast) - blastTier(a.worstBlast) || b.totalSeen - a.totalSeen);
}

function coverage(matched: SignatureStat[], limit = 6): string[] {
  const out: string[] = [];
  for (const s of matched.slice(0, limit)) {
    const tier = blastTier(s.worstBlast);
    const dot = tier >= 3 ? c.red(sym.bullet) : tier >= 2 ? c.yellow(sym.bullet) : c.green(sym.bullet);
    out.push(`    ${dot} ${pad(truncate(s.signature, 42), 42)}  ${blastStrip(s.worstBlast)}`);
  }
  if (matched.length > limit) {
    out.push(c.gray(`    …and ${matched.length - limit} more`));
  }
  return out;
}

/**
 * A pattern that covers the harmless part of what the user asked for. Better
 * than telling someone their pattern is wrong and leaving them to guess.
 */
function narrower(matched: SignatureStat[]): string | null {
  const safe = matched.filter((s) => blastTier(s.worstBlast) < 3).map((s) => s.signature);
  if (!safe.length) return null;
  if (safe.length === 1) return safe[0] ?? null;
  const prefix = commonPrefix(safe).replace(/\s+$/, '');
  return prefix.length >= 4 ? `${prefix}*` : (safe[0] ?? null);
}

/** The known signature that looks most like what they typed, for typo recovery. */
function nearestSignature(pattern: string, env: Envelope): string | null {
  const bare = pattern.replace(/[*?]/g, '').trim();
  if (!bare) return null;
  let best: string | null = null;
  let bestScore = 0;
  for (const s of Object.keys(env.signatures)) {
    const score = commonPrefix([bare, s]).length;
    if (score > bestScore) {
      bestScore = score;
      best = s;
    }
  }
  return bestScore >= 3 ? best : null;
}

function commonPrefix(xs: string[]): string {
  if (!xs.length) return '';
  let prefix = xs[0] ?? '';
  for (const s of xs.slice(1)) {
    let i = 0;
    while (i < prefix.length && i < s.length && prefix[i] === s[i]) i++;
    prefix = prefix.slice(0, i);
    if (!prefix) break;
  }
  return prefix;
}

function describeSig(s: SignatureStat): Record<string, unknown> {
  return {
    signature: s.signature,
    capability: s.capability,
    blast: s.worstBlast,
    timesSeen: s.totalSeen,
    lastSeen: s.lastSeen,
  };
}

function isExpired(r: Rule, now: number): boolean {
  return Boolean(r.expiresAt && r.expiresAt < now);
}

/** Same test decide.ts uses, minus the signature match. */
function appliesHere(r: Rule, key: string, now: number): boolean {
  if (isExpired(r, now)) return false;
  if (r.scope === 'project' && r.key && r.key !== key) return false;
  return true;
}

function scopeLabel(r: Rule, key: string): string {
  if (r.scope === 'global') return 'global';
  if (r.scope === 'session') return 'session';
  return !r.key || r.key === key ? 'this project' : 'other project';
}

function scopeCell(r: Rule, key: string): string {
  const label = scopeLabel(r, key);
  if (label === 'global') return c.yellow(label);
  if (label === 'other project') return c.gray(label);
  return label;
}

function effectLabel(r: Rule): string {
  if (r.effect === 'deny') return c.red('deny');
  if (r.effect === 'allow') return c.green('allow');
  return c.yellow('ask');
}

function whenCell(r: Rule, now: number): string {
  if (isExpired(r, now)) return 'expired';
  if (r.expiresAt) return `${inWords(r.expiresAt - now)} left`;
  return ago(r.addedAt, now);
}

function field(label: string, value: string): string {
  return `  ${c.gray(pad(label, 10))}  ${value}`;
}

function indent(block: string, n = 2): string {
  return block
    .split('\n')
    .map((l) => ' '.repeat(n) + l)
    .join('\n');
}

function quote(s: string): string {
  return c.cyan(`"${s}"`);
}

function short(p: string): string {
  const n = p.replace(/\\/g, '/');
  const parts = n.split('/');
  return parts.length > 3 ? '…/' + parts.slice(-2).join('/') : n;
}

function stripStyle(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function json2(data: unknown): string {
  return JSON.stringify(data, null, 2) + '\n';
}

/**
 * Flags that take no value. The argument parser cannot know that, so
 * `allow --global "npm test"` swallows the pattern into the flag; recovering it
 * here is better than telling someone their pattern matched nothing.
 */
const BARE_FLAGS = ['global', 'force', 'learned', 'json'] as const;

function flag(argv: Argv, name: string): boolean {
  const v = argv.flags[name];
  return v !== undefined && v !== false && v !== 'false';
}

function patternOf(argv: Argv): string {
  const parts = [...argv.positional];
  for (const f of BARE_FLAGS) {
    const v = argv.flags[f];
    if (typeof v === 'string' && v !== 'true' && v !== 'false') parts.unshift(v);
  }
  return parts.join(' ').trim();
}

// --- durations -------------------------------------------------------------

const HOUR = 3_600_000;
const DAY = 86_400_000;

const UNITS: { rx: RegExp; ms: number }[] = [
  { rx: /^h(ours?)?$/i, ms: HOUR },
  { rx: /^d(ays?)?$/i, ms: DAY },
  { rx: /^w(eeks?)?$/i, ms: 7 * DAY },
  { rx: /^mo(nths?)?$/i, ms: 30 * DAY },
  { rx: /^y(ears?)?$/i, ms: 365 * DAY },
];

/** `30d`, `2w`, `24h`, `6mo` → milliseconds. Null if it is not one of those. */
function parseDuration(s: string): number | null {
  const m = /^(\d+(?:\.\d+)?)\s*([a-z]+)$/i.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2] ?? '';
  if (!Number.isFinite(n) || n <= 0) return null;
  for (const u of UNITS) {
    if (u.rx.test(unit)) return Math.round(n * u.ms);
  }
  return null;
}

function inWords(ms: number): string {
  const h = Math.round(ms / HOUR);
  if (h < 48) return plural(Math.max(1, h), 'hour');
  const d = Math.round(ms / DAY);
  if (d < 14) return plural(d, 'day');
  if (d < 60) return plural(Math.round(d / 7), 'week');
  return plural(Math.round(d / 30), 'month');
}
