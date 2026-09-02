/**
 * Per-session scratch state, written so that concurrent hook processes cannot
 * lose it.
 *
 * Every tool call is a separate hook *process*, and agents issue tool calls in
 * parallel. The previous shape of this was one JSON file per session that each
 * process read, merged and rewrote. That is a read–modify–write with no lock,
 * and it loses updates by construction: a process whose read lands before
 * another's write but whose write lands after it silently reverts the other's
 * change. Measured at only five concurrent hook processes, the session taint
 * set came back empty in one trial in twenty-five, and at thirty concurrent it
 * was four in twenty-five. A torn read of the same file was worse still — the
 * blanket `catch` turned it into a brand-new empty session, which was then
 * written back as the truth for the rest of the conversation.
 *
 * `taints` is the only thing carrying "a credential was read earlier in this
 * conversation" to the outbound call that would exfiltrate it, so losing it is
 * not a lost lesson, it is a lost guard, and it fails *open*.
 *
 * The fix is representational rather than a lock. A lock on this path would
 * have to be taken before every single tool call, on Windows as well as POSIX,
 * and a holder that dies mid-write would wedge the agent — a worse failure than
 * the one being fixed. Instead every piece of session state is stored in a form
 * that has no read–modify–write in it at all:
 *
 *   taints   append-only. Each record is one taint token. The set is monotone
 *            by definition and there are exactly four possible tokens, so the
 *            file converges and then stops growing. Nothing ever rewrites it,
 *            so no reader — torn, slow or unlucky — can erase a taint.
 *
 *   log      append-only. One record per decision: `+` for a PreToolUse, `-`
 *            for the PostToolUse that completed one. Everything derived from it
 *            (how many calls, when the session started, which capability came
 *            last) is a fold over records that only ever get appended.
 *
 *   p/<id>   one file per `tool_use_id`. The Pre that created that id is its
 *            only writer and the matching Post is its only reader and deleter,
 *            so there is no contention to lose: the previous shape dropped
 *            roughly a fifth of these under a burst, and with them a fifth of
 *            everything LeastGrant would have learned.
 *
 * Appends are single small `O_APPEND` writes, which the kernel serialises
 * against other appenders on POSIX and Windows alike — the same property the
 * ledger already relies on. Records are framed with a newline on *both* sides
 * anyway, so that if one were ever cut short its remains cannot swallow the
 * start of the next record; a damaged record is dropped, never merged.
 *
 * Cost: the log grows by about thirty bytes per tool call and is never
 * compacted, so a very long session reads a slightly larger file. Reading it is
 * one `readFileSync` plus a single scan that allocates nothing per record —
 * about a third of a millisecond at five thousand calls, against a hook process
 * that costs eighty. Compaction is deliberately absent: it would reintroduce
 * exactly the rewrite this file exists to remove.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Capability, Decision, LedgerEntry } from '../../core/types.js';
import { newSession, type SessionState, type Taint } from '../../core/envelope.js';
import { hashKey, logLine, stateDir } from '../../store/index.js';

/** A decision waiting for its PostToolUse. */
export interface PendingCall {
  signature: string;
  capability: Capability;
  blast: LedgerEntry['blast'];
  decision: Decision;
  display: string;
  toolUseId: string;
  at: number;
  attended: boolean;
  project: string;
  previousCapability?: Capability;
}

export type LiveSession = SessionState & {
  /** Capability of the last call that *completed*, for transition novelty. */
  previousCapability?: Capability;
};

export const SESSION_TTL_MS = 24 * 3600 * 1000;

/**
 * Ceiling on `p/`, the in-flight directory.
 *
 * A Pre with no matching Post leaves a file behind — an interrupted call, a
 * crash, or an agent that simply never finishes one. Without a bound the
 * directory grows for as long as the session lives.
 */
export const MAX_PENDING = 64;

/** How often the in-flight directory is swept, in calls. */
const PRUNE_EVERY = 16;

/** The four tokens `applyTaint` can produce. Anything else on disk is noise. */
const KNOWN_TAINTS: ReadonlySet<string> = new Set<Taint>([
  'read-secrets',
  'read-outside',
  'fetched-code',
  'network-egress',
]);

/**
 * What a session looks like when its taint file exists but cannot be read.
 *
 * Not the empty set. "I cannot tell you whether this conversation read a
 * credential" is not the same statement as "it did not", and the whole point of
 * this file is that the second one must never be manufactured out of an I/O
 * error. These are the two tokens `taintConcern()` actually acts on, so the
 * effect is that outbound calls and uninspectable execs get asked about instead
 * of waved through.
 */
const UNREADABLE_TAINTS: readonly Taint[] = ['read-secrets', 'fetched-code'];

function safeId(id: string): string {
  return id.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
}

export function sessionsRoot(): string {
  return path.join(stateDir(), 'sessions');
}

export function sessionDir(id: string): string {
  return path.join(sessionsRoot(), safeId(id));
}

/**
 * The pre-0.2.1 single-file layout.
 *
 * Read as a base layer and never written: a conversation that was already
 * running when LeastGrant was upgraded keeps its taints, its count and its
 * capability history. Its in-flight entries are *not* carried over — a Post for
 * a call that started under the old layout finds nothing and records nothing,
 * which is the same thing that already happens for a hook installed mid-session.
 * The file is deleted by the ordinary 24-hour sweep.
 */
function legacyFile(id: string): string {
  return path.join(sessionsRoot(), `${safeId(id)}.json`);
}

function taintFile(id: string): string {
  return path.join(sessionDir(id), 'taints');
}

function logFile(id: string): string {
  return path.join(sessionDir(id), 'log');
}

function pendingDir(id: string): string {
  return path.join(sessionDir(id), 'p');
}

function pendingFile(id: string, toolUseId: string): string {
  // Hashed rather than sanitised: two different `tool_use_id`s must not be able
  // to collapse onto one filename, or one call's Post would consume another
  // call's evidence.
  return path.join(pendingDir(id), `${hashKey(toolUseId)}.json`);
}

// ---------------------------------------------------------------------------
// Append-only primitives
// ---------------------------------------------------------------------------

/**
 * Append one record.
 *
 * The newline before the record is the interesting one. A record cut short
 * mid-write would otherwise leave a fragment that the next record's opening
 * bytes join onto, producing one plausible-looking line out of two real ones.
 * With a leading newline the fragment is stranded on its own line, fails
 * validation and is dropped, and the next record survives intact.
 */
function appendRecord(file: string, record: string): void {
  fs.appendFileSync(file, `\n${record}\n`, 'utf8');
}

type ReadResult = { text: string; missing: boolean; failed: boolean };

function readFile(file: string): ReadResult {
  try {
    return { text: fs.readFileSync(file, 'utf8'), missing: false, failed: false };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { text: '', missing: true, failed: false };
    }
    // One retry, no sleep: on Windows a concurrent append can momentarily
    // refuse a share, and that clears immediately.
    try {
      return { text: fs.readFileSync(file, 'utf8'), missing: false, failed: false };
    } catch {
      return { text: '', missing: false, failed: true };
    }
  }
}

// ---------------------------------------------------------------------------
// Taints
// ---------------------------------------------------------------------------

function readTaints(id: string): Set<Taint> {
  const r = readFile(taintFile(id));
  if (r.failed) {
    logLine(`session ${safeId(id)}: taint file unreadable, assuming the worst`);
    return new Set(UNREADABLE_TAINTS);
  }
  const out = new Set<Taint>();
  if (!r.text) return out;
  for (const line of r.text.split('\n')) {
    const t = line.trim();
    if (KNOWN_TAINTS.has(t)) out.add(t as Taint);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The decision log
// ---------------------------------------------------------------------------

interface LogFold {
  /** Number of `+` records: calls judged in this session. */
  count: number;
  /** `at` of the first well-formed record, 0 if there is none. */
  startedAt: number;
  /** Capability of the last call judged. */
  last?: Capability;
  /** Capability of the last call that completed. */
  previous?: Capability;
}

const CAPABILITY_RE = /^[a-z][a-z0-9]*(\.[a-z0-9]+)*$/;

/** `<kind> <at> <capability>` -> its parts, or null if the record is damaged. */
function parseRecord(line: string): { at: number; capability: Capability } | null {
  const first = line.indexOf(' ');
  if (first < 0) return null;
  const second = line.indexOf(' ', first + 1);
  if (second < 0) return null;
  if (line.indexOf(' ', second + 1) >= 0) return null;
  const at = Number(line.slice(first + 1, second));
  if (!Number.isSafeInteger(at) || at < 0) return null;
  const capability = line.slice(second + 1);
  if (!CAPABILITY_RE.test(capability)) return null;
  return { at, capability: capability as Capability };
}

/**
 * Fold the log.
 *
 * One pass, one native `indexOf` per line, and no string allocated for any line
 * except the two or three that are actually parsed. This runs before every tool
 * call, and a session that has been going all day has thousands of records.
 */
export function foldLog(text: string): LogFold {
  const fold: LogFold = { count: 0, startedAt: 0 };
  let firstAt = -1;
  let lastPlus = -1;
  let lastPlusEnd = -1;
  let lastMinus = -1;
  let lastMinusEnd = -1;

  let i = 0;
  while (i < text.length) {
    const end = text.indexOf('\n', i);
    // No terminator: a record still being written, or one cut short by a crash.
    // Either way it is not yet a fact.
    if (end < 0) break;
    if (end > i) {
      const kind = text.charCodeAt(i);
      if (kind === 43 /* + */) {
        fold.count++;
        lastPlus = i;
        lastPlusEnd = end;
        if (firstAt < 0) firstAt = i;
      } else if (kind === 45 /* - */) {
        lastMinus = i;
        lastMinusEnd = end;
        if (firstAt < 0) firstAt = i;
      }
    }
    i = end + 1;
  }

  if (lastPlus >= 0) {
    const rec = parseRecord(text.slice(lastPlus + 1, lastPlusEnd));
    if (rec) fold.last = rec.capability;
    else fold.count--; // a damaged trailing record is not a call we saw
  }
  if (lastMinus >= 0) {
    const rec = parseRecord(text.slice(lastMinus + 1, lastMinusEnd));
    if (rec) fold.previous = rec.capability;
  }
  if (firstAt >= 0) {
    const end = text.indexOf('\n', firstAt);
    const rec = parseRecord(text.slice(firstAt + 1, end));
    if (rec) fold.startedAt = rec.at;
  }
  return fold;
}

// ---------------------------------------------------------------------------
// The pre-0.2.1 single file, read-only
// ---------------------------------------------------------------------------

interface LegacyBase {
  taints: Taint[];
  count: number;
  startedAt: number;
  lastCapability?: Capability;
  previousCapability?: Capability;
}

function readLegacy(id: string): LegacyBase | null {
  const r = readFile(legacyFile(id));
  if (r.missing || r.failed || !r.text) return null;
  try {
    const p = JSON.parse(r.text) as Partial<LegacyBase>;
    return {
      taints: (p.taints ?? []).filter((t) => KNOWN_TAINTS.has(t)),
      count: typeof p.count === 'number' ? p.count : 0,
      startedAt: typeof p.startedAt === 'number' ? p.startedAt : 0,
      ...(p.lastCapability ? { lastCapability: p.lastCapability } : {}),
      ...(p.previousCapability ? { previousCapability: p.previousCapability } : {}),
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Everything a PreToolUse needs to judge the call.
 *
 * Deliberately does not read the in-flight directory: a Pre has no use for
 * other calls' pending entries, and not reading them keeps the hot path to two
 * small files.
 */
export function loadSession(id: string, now: number): LiveSession {
  const s = newSession(id, now) as LiveSession;
  try {
    const taints = readTaints(id);
    const fold = foldLog(readFile(logFile(id)).text);
    const legacy = readLegacy(id);

    for (const t of taints) s.taints.add(t);
    if (legacy) for (const t of legacy.taints) s.taints.add(t);

    s.count = fold.count + (legacy?.count ?? 0);
    const started = fold.startedAt || legacy?.startedAt || 0;
    s.startedAt = started || now;

    const last = fold.last ?? legacy?.lastCapability;
    if (last) s.lastCapability = last;
    const previous = fold.previous ?? legacy?.previousCapability;
    if (previous) s.previousCapability = previous;
  } catch {
    /* session memory is an optimisation, not a requirement */
  }
  return s;
}

/**
 * Persist what a PreToolUse decided.
 *
 * Three appends and one file this process alone owns. Nothing here reads a
 * value and writes it back, so nothing here can lose another process's work.
 */
export function commitPre(session: LiveSession, toolUseId: string, pending: PendingCall): void {
  try {
    const dir = sessionDir(session.sessionId);
    fs.mkdirSync(path.join(dir, 'p'), { recursive: true });

    // Only the tokens this process just learned, and only if the disk does not
    // already have them. Four possible tokens means the file converges to at
    // most four records plus whatever a concurrent burst duplicated, and then
    // never grows again.
    const known = readTaints(session.sessionId);
    for (const t of session.taints) {
      if (!known.has(t)) appendRecord(taintFile(session.sessionId), t);
    }

    appendRecord(logFile(session.sessionId), `+ ${pending.at} ${pending.capability}`);

    fs.writeFileSync(
      pendingFile(session.sessionId, toolUseId),
      JSON.stringify(pending),
      'utf8',
    );

    if (session.count % PRUNE_EVERY === 0) prunePending(session.sessionId);
    pruneSessions();
  } catch {
    /* session memory is an optimisation, not a requirement */
  }
}

/**
 * Read and consume the record a PreToolUse left for this `tool_use_id`.
 *
 * Consumption is an `unlink` of a file only this pair of calls ever touches, so
 * a concurrent Pre cannot resurrect it and a concurrent Post cannot double-count
 * it.
 */
export function takePending(sessionId: string, toolUseId: string): PendingCall | undefined {
  const file = pendingFile(sessionId, toolUseId);
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
  try {
    fs.unlinkSync(file);
  } catch {
    /* already gone: the entry below is still the honest answer */
  }
  try {
    const parsed = JSON.parse(raw) as PendingCall;
    return parsed && typeof parsed.signature === 'string' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** Persist what a PostToolUse completed, so the next call knows what preceded it. */
export function commitPost(sessionId: string, capability: Capability, at: number): void {
  try {
    fs.mkdirSync(sessionDir(sessionId), { recursive: true });
    appendRecord(logFile(sessionId), `- ${at} ${capability}`);
  } catch {
    /* session memory is an optimisation, not a requirement */
  }
}

/**
 * Sweep the in-flight directory back under its ceiling.
 *
 * Opportunistic and racy on purpose: two processes sweeping at once might
 * remove one entry each, and the answer to "which of the oldest abandoned
 * entries got dropped" does not matter. Only entries past the ceiling are ever
 * touched, so a session running normally never loses one.
 */
export function prunePending(sessionId: string): void {
  const dir = pendingDir(sessionId);
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }
  if (names.length <= MAX_PENDING) return;
  const aged: Array<{ file: string; at: number }> = [];
  for (const n of names) {
    const file = path.join(dir, n);
    try {
      aged.push({ file, at: fs.statSync(file).mtimeMs });
    } catch {
      /* vanished under us: someone else's Post got there first */
    }
  }
  aged.sort((a, b) => b.at - a.at);
  for (const e of aged.slice(MAX_PENDING)) {
    try {
      fs.unlinkSync(e.file);
    } catch {
      /* ignore */
    }
  }
}

let sweptSessions = false;

/** Drop whole sessions nobody has touched for a day. Once per process. */
export function pruneSessions(): void {
  if (sweptSessions) return;
  sweptSessions = true;
  try {
    const root = sessionsRoot();
    const now = Date.now();
    for (const name of fs.readdirSync(root)) {
      const full = path.join(root, name);
      if (now - lastTouched(full) > SESSION_TTL_MS) fs.rmSync(full, { recursive: true, force: true });
    }
  } catch {
    /* ignore */
  }
}

/**
 * When this session last did anything.
 *
 * A directory's own mtime moves when an in-flight entry is added or removed,
 * which covers ordinary activity, but the log is the file every single call
 * appends to — so take the later of the two rather than deleting a busy session
 * that happens to have a stable set of in-flight calls. A session we cannot
 * stat at all reads as "just now": refusing to delete is the safe direction.
 */
function lastTouched(full: string): number {
  try {
    const st = fs.statSync(full);
    if (!st.isDirectory()) return st.mtimeMs;
    let m = st.mtimeMs;
    try {
      m = Math.max(m, fs.statSync(path.join(full, 'log')).mtimeMs);
    } catch {
      /* a session directory with no log yet */
    }
    return m;
  } catch {
    return Date.now();
  }
}

/** Test seam: `pruneSessions` runs once per process, and a test is one process. */
export function resetSweepForTests(): void {
  sweptSessions = false;
}
