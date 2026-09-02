/**
 * On-disk state.
 *
 * Three files, all plain text, all readable with `cat`:
 *
 *   config.json            what you told LeastGrant to do
 *   ledger.jsonl           every decision, append-only
 *   envelopes/<key>.json   what it has learned, per project
 *
 * The ledger is deliberately not a database. It is the audit trail, the
 * training data, and the input to `leastgrant simulate` all at once, and a
 * security tool whose data you cannot read is a worse security tool. Every
 * line is written through the redactor first.
 *
 * Concurrency: several agent sessions can be running at once. Each ledger entry
 * is written as a single `appendFileSync` of one line, which is atomic enough
 * for this purpose on both POSIX (O_APPEND) and Windows. We deliberately do not
 * hash-chain the log — that would require a single writer, and a lock that can
 * wedge an agent mid-session is a worse failure than a log you cannot prove is
 * complete. The threat model says so out loud rather than implying tamper-
 * evidence we do not have.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import type { Config, Envelope, LedgerEntry, Rule, Scope, SignatureStat } from '../core/types.js';
import { NIL_BLAST } from '../core/types.js';
import { newEnvelope, safeSignatureKey } from '../core/envelope.js';
import { DEFAULT_THRESHOLDS } from '../core/envelope.js';
import { redact } from '../core/secrets.js';

export function stateDir(): string {
  const override = process.env['LEASTGRANT_HOME'];
  if (override) return path.resolve(override);
  return path.join(os.homedir(), '.leastgrant');
}

export const paths = {
  root: stateDir,
  config: () => path.join(stateDir(), 'config.json'),
  ledger: () => path.join(stateDir(), 'ledger.jsonl'),
  envelopes: () => path.join(stateDir(), 'envelopes'),
  envelope: (key: string) => path.join(stateDir(), 'envelopes', `${hashKey(key)}.json`),
  log: () => path.join(stateDir(), 'leastgrant.log'),
  denials: () => path.join(stateDir(), 'denials.jsonl'),
};

export function hashKey(key: string): string {
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export const DEFAULT_CONFIG: Config = {
  version: 1,
  posture: 'assist',
  thresholds: DEFAULT_THRESHOLDS,
  rules: [],
  additionalRoots: [],
  secretPatterns: [],
  telemetry: { ledger: true },
};

export function loadConfig(): Config {
  try {
    const raw = fs.readFileSync(paths.config(), 'utf8');
    const parsed = JSON.parse(raw) as Partial<Config>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      thresholds: { ...DEFAULT_THRESHOLDS, ...(parsed.thresholds ?? {}) },
      rules: parsed.rules ?? [],
      additionalRoots: parsed.additionalRoots ?? [],
      secretPatterns: parsed.secretPatterns ?? [],
      telemetry: { ...DEFAULT_CONFIG.telemetry, ...(parsed.telemetry ?? {}) },
    };
  } catch (err) {
    // "There is no config yet" and "your config is unreadable" are not the same
    // situation and used to get the same answer.
    //
    // A first run has no file, and the defaults are exactly right for it. A file
    // that exists and will not parse is a different thing entirely: whatever
    // deny rules and whatever posture the human chose are still on disk, and we
    // cannot read them. Returning the defaults there silently discarded their
    // rules and landed on `assist`, which auto-approves familiar work — quite
    // possibly *more* permissive than what they had configured, arrived at by
    // an error nobody was told about.
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };
    }

    // Fail towards asking. `strict` approves only what an explicit rule allows,
    // and we have no rules, so everything asks. That is disruptive on purpose:
    // it cannot be quieter than the configuration it is standing in for, and it
    // is impossible not to notice, which a corrupt config file deserves.
    process.stderr.write(
      `LeastGrant: ${paths.config()} could not be read (${(err as Error)?.message ?? 'unknown error'}).\n` +
        `  Your rules and posture are not being applied. Asking about everything until it is fixed.\n`,
    );
    logLine(`config-unreadable ${paths.config()}: ${String((err as Error)?.message ?? err)}`);
    return { ...DEFAULT_CONFIG, posture: 'strict', thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };
  }
}

export function saveConfig(config: Config): void {
  ensureDir(stateDir());
  writeAtomic(paths.config(), JSON.stringify(config, null, 2) + '\n');
}

export function addRule(config: Config, rule: Rule): Config {
  // A rule pattern is matched against a signature, and signatures are scrubbed
  // of credential shapes on their way out of `analyze()`. So a rule containing
  // a raw password could never match anything — it would sit in a plain-text
  // config file leaking the secret and doing nothing. Scrubbing it here makes
  // it both harmless and, for the first time, capable of matching.
  const scrubbed: Rule = { ...rule, match: redact(rule.match) };
  // Replace an existing rule with the same match+scope rather than stacking.
  const rules = config.rules.filter(
    (r) => !(r.match === scrubbed.match && r.scope === scrubbed.scope && r.key === scrubbed.key),
  );
  rules.push(scrubbed);
  const next = { ...config, rules };
  saveConfig(next);
  return next;
}

export function removeRule(config: Config, match: string, scope?: Scope): Config {
  const rules = config.rules.filter((r) => !(r.match === match && (!scope || r.scope === scope)));
  const next = { ...config, rules };
  saveConfig(next);
  return next;
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/**
 * Append a refusal to the durable journal.
 *
 * The envelope is a cache of what has been learned and can be rebuilt. This
 * file is the record of what was refused, and it is the one thing that must
 * survive a corrupt envelope, a lost race, or a hand edit — because "a no does
 * not expire" is a promise the product makes in plain words.
 */
function recordDenial(scope: Scope, key: string, signature: string, at: number): void {
  try {
    ensureDir(stateDir());
    fs.appendFileSync(
      paths.denials(),
      JSON.stringify({ v: 1, scope, key, signature, at }) + '\n',
      'utf8',
    );
  } catch {
    /* the envelope still carries it; this is the belt to that pair of braces */
  }
}

/** Replay the journal over an envelope, so refusals outlive the envelope. */
function applyDenials(env: Envelope): Envelope {
  let raw: string;
  try {
    raw = fs.readFileSync(paths.denials(), 'utf8');
  } catch {
    return env;
  }
  for (const line of raw.split('\n')) {
    if (!line) continue;
    let rec: { scope?: Scope; key?: string; signature?: string; at?: number };
    try {
      rec = JSON.parse(line) as typeof rec;
    } catch {
      continue;
    }
    if (rec.scope !== env.scope || rec.key !== env.key || !rec.signature) continue;
    const sig = safeSignatureKey(rec.signature);
    const existing = env.signatures[sig];
    if (existing) {
      if (existing.denied < 1) existing.denied = 1;
      continue;
    }
    // The envelope no longer remembers the action at all, but the refusal
    // stands. A minimal record is enough: canPromote() checks `denied` before
    // it looks at anything else.
    env.signatures[sig] = {
      signature: rec.signature,
      capability: 'exec.unknown',
      confirmed: 0,
      denied: 1,
      observed: 0,
      totalSeen: 1,
      firstSeen: rec.at ?? 0,
      lastSeen: rec.at ?? 0,
      sessions: 0,
      days: 0,
      worstBlast: NIL_BLAST,
      samples: [],
    };
  }
  return env;
}

export function loadEnvelope(scope: Scope, key: string): Envelope {
  const file = scope === 'global' ? path.join(stateDir(), 'global.json') : paths.envelope(key);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Envelope;
    // Defend against a truncated or hand-edited file rather than crashing the
    // hook — a broken envelope must degrade to "I know nothing", never to
    // "everything is allowed".
    if (!parsed || typeof parsed !== 'object' || !parsed.signatures) return applyDenials(newEnvelope(scope, key));
    // Rebuild the maps without a prototype. JSON.parse produces ordinary
    // objects, so a stored key of `__proto__` is reachable through the
    // prototype chain — and this file is plain text the docs invite people to
    // read and edit. Values are shape-checked on the way in for the same reason.
    const clean = newEnvelope(scope, key);
    clean.updatedAt = Number.isFinite(parsed.updatedAt) ? parsed.updatedAt : 0;
    clean.events = Number.isFinite(parsed.events) ? parsed.events : 0;
    for (const [k, v] of Object.entries(parsed.signatures ?? {})) {
      if (v && typeof v === 'object') clean.signatures[k] = v;
    }
    for (const [k, v] of Object.entries(parsed.transitions ?? {})) {
      if (typeof v === 'number' && Number.isFinite(v)) clean.transitions[k] = v;
    }
    for (const [k, v] of Object.entries(parsed.capabilities ?? {})) {
      if (typeof v === 'number' && Number.isFinite(v)) clean.capabilities[k] = v;
    }
    return applyDenials(clean);
  } catch {
    return applyDenials(newEnvelope(scope, key));
  }
}

/**
 * Merge an envelope with whatever is already on disk.
 *
 * Several agent sessions run at once, each loading, mutating and saving. A
 * plain overwrite means the last writer silently discards the others' evidence.
 * For approvals that is a lost count; for a DENIAL it is a security regression,
 * because denials are permanent by design and are the one signal a user cannot
 * cheaply re-assert.
 *
 * So the merge is monotone in the direction of caution: denials take the
 * maximum of both sides, grants survive from either, and counts take the
 * larger. Two concurrent writers can lose an approval; neither can lose a no.
 */
function mergeEnvelopes(disk: Envelope, mine: Envelope): Envelope {
  const out: Envelope = {
    ...mine,
    signatures: { ...disk.signatures },
    transitions: { ...disk.transitions },
    capabilities: { ...disk.capabilities },
    events: Math.max(disk.events ?? 0, mine.events ?? 0),
  };
  for (const [sig, m] of Object.entries(mine.signatures)) {
    const d = disk.signatures[sig];
    if (!d) {
      out.signatures[sig] = m;
      continue;
    }
    out.signatures[sig] = {
      ...m,
      denied: Math.max(d.denied ?? 0, m.denied ?? 0),
      confirmed: Math.max(d.confirmed ?? 0, m.confirmed ?? 0),
      observed: Math.max(d.observed ?? 0, m.observed ?? 0),
      totalSeen: Math.max(d.totalSeen ?? 0, m.totalSeen ?? 0),
      days: Math.max(d.days ?? 0, m.days ?? 0),
      sessions: Math.max(d.sessions ?? 0, m.sessions ?? 0),
      firstSeen: Math.min(d.firstSeen || m.firstSeen, m.firstSeen || d.firstSeen),
      lastSeen: Math.max(d.lastSeen ?? 0, m.lastSeen ?? 0),
      ...(d.grantedAt || m.grantedAt ? { grantedAt: d.grantedAt ?? m.grantedAt } : {}),
    };
  }
  for (const [k, v] of Object.entries(mine.transitions)) {
    out.transitions[k] = Math.max(disk.transitions[k] ?? 0, v);
  }
  for (const [k, v] of Object.entries(mine.capabilities)) {
    out.capabilities[k] = Math.max(disk.capabilities[k] ?? 0, v);
  }
  return out;
}

export interface SaveEnvelopeOptions {
  /**
   * Signatures the caller has deliberately removed, which the merge must not
   * bring back.
   *
   * The merge starts from what is on disk and only ever adds, which is right
   * for two hook processes racing — neither can lose the other's denial — and
   * exactly wrong for a person typing `leastgrant forget --learned`. That
   * deleted the signature from the in-memory envelope, and the merge restored
   * it from disk on the way out, so the command reported success and forgot
   * nothing. A tool that says it deleted your data and did not is worse than
   * one that refuses.
   *
   * Naming them, rather than adding a "do not merge" flag, keeps the
   * concurrency guarantee for everything else in the same write: a hook that
   * records a denial while `forget` is running still cannot be clobbered,
   * unless it is a denial of one of these exact signatures.
   *
   * A refusal still outlives this. Denials are journaled separately and
   * replayed over the envelope on load, because "a no does not expire" is a
   * promise the product makes in plain words — `forget --learned` unlearns
   * approvals, and to drop a refusal you have to write a rule.
   */
  forget?: readonly string[];
}

export function saveEnvelope(env: Envelope, opts: SaveEnvelopeOptions = {}): void {
  const file = env.scope === 'global' ? path.join(stateDir(), 'global.json') : paths.envelope(env.key);
  ensureDir(path.dirname(file));
  // Re-read immediately before writing and merge, so a concurrent session's
  // evidence — in particular its denials — is not overwritten.
  const disk = loadEnvelope(env.scope, env.key);

  // Journal a refusal only when this save carries one the file does not have.
  //
  // This used to append a record for every signature with `denied > 0`, on
  // every save — and a save happens on every completed tool call. A project
  // with ten refusals wrote ten more lines per tool call, forever, re-recording
  // refusals that were already there thousands of times over. Nothing prunes
  // the file, deliberately, because "a no does not expire".
  //
  // The failure at the end of that is not a large file. `applyDenials` reads it
  // into a single string with `readFileSync`, and past Node's maximum string
  // length that throws — into a `catch` that returns the envelope unchanged. So
  // the journal grows until the moment it silently stops being applied, and the
  // promise it exists to keep fails open.
  //
  // `disk` is loaded here anyway, so the comparison costs nothing: more
  // refusals than the file already knows about means new information.
  for (const [sig, stat] of Object.entries(env.signatures)) {
    const mine = stat?.denied ?? 0;
    if (mine <= 0) continue;
    if (mine <= (disk.signatures[sig]?.denied ?? 0)) continue;
    recordDenial(env.scope, env.key, stat.signature || sig, stat.lastSeen ?? 0);
  }
  let merged = disk.events || Object.keys(disk.signatures).length ? mergeEnvelopes(disk, env) : env;
  if (opts.forget?.length) {
    const gone = new Set(opts.forget.map(safeSignatureKey));
    const kept: Record<string, SignatureStat> = Object.create(null) as Record<string, SignatureStat>;
    for (const [sig, stat] of Object.entries(merged.signatures)) {
      if (!gone.has(sig)) kept[sig] = stat;
    }
    merged = { ...merged, signatures: kept };
  }
  writeAtomic(file, JSON.stringify(merged));
}

/** Every project envelope on disk, for `leastgrant status --all`. */
export function listEnvelopes(): Envelope[] {
  const dir = paths.envelopes();
  let names: string[] = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith('.json'));
  } catch {
    return [];
  }
  const out: Envelope[] = [];
  for (const n of names) {
    try {
      out.push(JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8')) as Envelope);
    } catch {
      /* skip unreadable */
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/** Append one decision. Never throws: logging must not break the agent. */
export function appendLedger(entry: LedgerEntry): void {
  try {
    ensureDir(stateDir());
    const safe: LedgerEntry = { ...entry, display: redact(entry.display) };
    fs.appendFileSync(paths.ledger(), JSON.stringify(safe) + '\n', 'utf8');
  } catch {
    /* a full disk must not stop the agent working */
  }
}

export interface ReadLedgerOptions {
  /** Only entries at or after this time. */
  since?: number;
  /** Only this project. */
  project?: string;
  /** Cap the number returned, taking the most recent. */
  limit?: number;
}

export function readLedger(opts: ReadLedgerOptions = {}): LedgerEntry[] {
  let raw: string;
  try {
    raw = fs.readFileSync(paths.ledger(), 'utf8');
  } catch {
    return [];
  }
  const out: LedgerEntry[] = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    let e: LedgerEntry;
    try {
      e = JSON.parse(line) as LedgerEntry;
    } catch {
      continue; // a partially-written final line is expected, not an error
    }
    if (opts.since && e.at < opts.since) continue;
    if (opts.project && e.project !== opts.project) continue;
    out.push(e);
  }
  if (opts.limit && out.length > opts.limit) return out.slice(-opts.limit);
  return out;
}

/**
 * Trim the ledger to a maximum age, keeping the file from growing without
 * bound. Called opportunistically by the CLI, never by the hook.
 */
export function pruneLedger(maxAgeDays: number): number {
  const cutoff = Date.now() - maxAgeDays * 86_400_000;
  const kept = readLedger().filter((e) => e.at >= cutoff);
  const all = readLedger();
  if (kept.length === all.length) return 0;
  writeAtomic(paths.ledger(), kept.map((e) => JSON.stringify(e)).join('\n') + (kept.length ? '\n' : ''));
  return all.length - kept.length;
}

// ---------------------------------------------------------------------------

/**
 * Write via a temp file and rename, so a crash mid-write cannot leave a
 * half-parsed config or envelope behind.
 */
function writeAtomic(file: string, contents: string): void {
  ensureDir(path.dirname(file));
  // The pid alone is not unique enough: one process can be part-way through
  // two writes to the same file, and a temp name that collides is a corrupt
  // write rather than a lost one.
  const tmp = `${file}.${process.pid}.${(tmpSeq++).toString(36)}.tmp`;
  fs.writeFileSync(tmp, contents, 'utf8');
  try {
    renameOver(tmp, file);
  } catch (err) {
    // Do not leave the scratch file behind. Before this, a burst of concurrent
    // envelope saves littered `envelopes/` with one `.tmp` per failure, and
    // they were never cleaned up because nothing knew they existed.
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw err;
  }
}

let tmpSeq = 0;

/** Codes Windows raises when the destination is momentarily held open. */
const CONTENDED = new Set(['EPERM', 'EACCES', 'EBUSY']);

/**
 * Replace a file, retrying while the destination is busy.
 *
 * POSIX `rename(2)` replaces the destination even if another process has it
 * open. Windows does not: `MoveFileEx` refuses with `EPERM` or `EACCES` while
 * any other handle is on the target, and every hook process opens the envelope
 * to read it before saving. Measured on twenty-four concurrent PostToolUse
 * processes: sixteen renames failed outright, and the evidence from those
 * sixteen completed calls was silently dropped — the exception was swallowed by
 * the hook's fail-open handler, so all anybody saw was a permission layer that
 * learned far more slowly than the number of approvals it had been given.
 *
 * The contention is momentary — a `readFileSync` and nothing more — so a short
 * bounded backoff turns it into a few milliseconds of waiting. Bounded, because
 * the alternative to giving up is wedging a hook, and a lost envelope write is
 * recoverable in a way a hung agent is not: refusals are journalled separately
 * to `denials.jsonl`, which is append-only precisely so that no failed write
 * here can lose a no.
 */
function renameOver(tmp: string, file: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(tmp, file);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? '';
      if (attempt >= 12 || !CONTENDED.has(code)) throw err;
      sleepMs(1 + attempt); // 1..12ms, 78ms of waiting before giving up
    }
  }
}

/**
 * Sleep without an event loop.
 *
 * Everything on this path is synchronous by design — the hook is a short-lived
 * process that must not return before its state is durable — so the wait has to
 * be too.
 */
function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Diagnostic log, used when the hook cannot speak to the user any other way. */
export function logLine(msg: string): void {
  try {
    ensureDir(stateDir());
    fs.appendFileSync(paths.log(), `${new Date().toISOString()} ${redact(msg)}\n`, 'utf8');
  } catch {
    /* ignore */
  }
}
