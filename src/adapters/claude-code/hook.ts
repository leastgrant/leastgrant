/**
 * The Claude Code hook entry point.
 *
 * This runs as a fresh process before every single tool call, so two properties
 * matter more than features:
 *
 *   **It must be fast.** Budget is a few milliseconds on top of Node's ~20ms
 *   start. Everything on this path is a file read and some hash lookups; the
 *   CLI, the renderer and the miner are deliberately not imported here.
 *
 *   **It must never break the agent.** Claude Code treats a hook that crashes,
 *   times out, or exits non-zero (other than 2) as a non-blocking error and
 *   *proceeds with the tool call*. So LeastGrant fails open. That is stated
 *   plainly in THREAT-MODEL.md rather than papered over: we are a decision
 *   layer, not a sandbox. Everything here is wrapped so that the worst case is
 *   "no opinion", never "agent wedged".
 *
 * Contract (verified against Claude Code v2.1.240):
 *   stdin   { session_id, transcript_path, cwd, permission_mode, hook_event_name,
 *             tool_name, tool_input, tool_use_id }
 *   stdout  { "hookSpecificOutput": { "hookEventName": "PreToolUse",
 *             "permissionDecision": "allow"|"deny"|"ask",
 *             "permissionDecisionReason": "..." } }
 *   exit 0 + no output  => no decision, normal permission flow continues
 *   exit 2              => blocks unconditionally, even over an allow rule
 *
 * A hook `allow` is *not* absolute — the user's own deny and ask rules still
 * override it. A hook `deny` is. We are a reliable veto and a best-effort
 * grant, and the product is designed around that asymmetry.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Decision, LedgerEntry, Request, Verdict } from '../../core/types.js';
import { decide } from '../../core/decide.js';
import { observe, applyTaint, newSession, type SessionState } from '../../core/envelope.js';
import { findProjectRoot, projectKey } from '../../core/paths.js';
import {
  appendLedger,
  loadConfig,
  loadEnvelope,
  logLine,
  saveEnvelope,
  stateDir,
} from '../../store/index.js';

interface HookInput {
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  permission_mode?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
}

/** Permission modes in which the human is not being consulted at all. */
/**
 * The modes in which a prompt actually reaches a person.
 *
 * Deliberately an allowlist. The previous blocklist —
 * `['bypassPermissions', 'acceptEdits', 'dontAsk', 'auto']` — was correct about
 * every mode it named and wrong about every mode it did not, and "every mode it
 * did not" included "no mode was sent".
 */
const ATTENDED = new Set(['default', 'plan', 'ask']);

/**
 * Was a human actually in the loop when this call was decided?
 *
 * Exported because it is the hinge of the whole learning story — the difference
 * between "someone approved this" and "this happened" — and a rule that
 * important should be tested against the code that runs, not against a copy of
 * it in a test file that can drift.
 */
export function wasAttended(posture: string, permissionMode: string | undefined): boolean {
  if (posture === 'observe') return false;
  // An allowlist of modes in which a human is genuinely consulted, not a
  // blocklist of the ones where they are not.
  //
  // This used to default an absent or unrecognised mode to `default`, i.e. to
  // "a human approved it" — the most generous reading available. Copilot sends
  // no mode at all, so every Copilot call that completed was banked as a human
  // approval, and any future agent that omits the field, or names a mode this
  // build has never heard of, would do the same. Manufactured `confirmed`
  // evidence is the one input that can promote a signature, so getting this
  // wrong lets an agent train the thing that is supposed to be watching it.
  //
  // Unknown now means observed. The cost is that such agents learn more slowly;
  // the alternative cost is that they learn things nobody agreed to.
  return ATTENDED.has(String(permissionMode ?? '').toLowerCase());
}

/** The evidence a completed call earns. See the note in `postToolUse`. */
export function evidenceFor(decision: string, attended: boolean): 'confirmed' | 'observed' {
  return decision === 'ask' && attended ? 'confirmed' : 'observed';
}

export async function runHook(): Promise<void> {
  let input: HookInput;
  try {
    input = JSON.parse(await readStdin()) as HookInput;
  } catch {
    // Nothing we can say about a call we cannot read.
    process.exit(0);
  }

  try {
    // Codex before Claude Code, because their event names collide.
    //
    // Codex sends `PreToolUse` and `PostToolUse` with the same field names,
    // but it rejects `permissionDecision: "ask"` — and then runs the call
    // anyway. Falling through to the Claude Code renderer would therefore turn
    // every `ask` into a silent allow on Codex, which is the one failure this
    // project cannot have. The installer writes `--agent codex`; the payload
    // check behind it is for a hand-edited config that lost the flag.
    const { isCodexEvent, looksLikeCodex, runCodexHook } = await import('../codex/hook.js');
    const flaggedCodex = agentFlag() === 'codex';
    if (isCodexEvent(String(input.hook_event_name ?? '')) && (flaggedCodex || looksLikeCodex(input))) {
      if (!flaggedCodex) {
        logLine('codex: routed by payload shape, not by --agent codex; re-run `leastgrant install codex`');
      }
      runCodexHook(input);
      process.exit(0);
    }

    // Matched case-insensitively. The event name is chosen by the agent, not
    // by an attacker, so this is not a security boundary — but a client that
    // spelled it `pretooluse` would silently turn LeastGrant off, and going
    // quiet is the failure this project can least afford to have happen
    // without anyone noticing.
    switch ((input.hook_event_name ?? '').toLowerCase()) {
      case 'pretooluse':
        return preToolUse(input);
      case 'posttooluse':
        return postToolUse(input);
      case 'sessionstart':
      case 'sessionend':
        process.exit(0);
      // eslint-disable-next-line no-fallthrough
      default: {
        // Cursor uses its own event names and its own response shape. Routing
        // on the event rather than on the `--agent` flag the installer writes
        // means a hand-edited `hooks.json` that lost the flag still works —
        // and a Cursor event arriving at a Claude-shaped handler would
        // otherwise fall through to silence, which is the failure mode this
        // project can least afford to have happen unnoticed.
        const { isCursorEvent, runCursorHook } = await import('../cursor/hook.js');
        if (isCursorEvent(String(input.hook_event_name ?? ''))) {
          runCursorHook(input);
          process.exit(0);
        }
        if (input.hook_event_name) logLine(`unknown hook event: ${String(input.hook_event_name)}`);
        process.exit(0);
      }
    }
  } catch (err) {
    // Fail open, loudly in the log and silently to the agent.
    logLine(`hook error: ${(err as Error)?.stack ?? String(err)}`);
    process.exit(0);
  }
}

/** What a Pre decision came to, for an adapter to render however its agent expects. */
export interface PreOutcome {
  decision: Decision;
  headline: string;
  /** True in `observe` posture: LeastGrant watched and must say nothing. */
  silent: boolean;
  /** Reason codes behind the decision, for adapters that must map it down. */
  reasons: string[];
  /**
   * True when a floor produced this verdict, rather than a shortage of
   * evidence.
   *
   * The distinction only matters to an adapter whose agent cannot express
   * `ask` — Codex is the case — because the two kinds of `ask` deserve
   * opposite fallbacks. An `ask` from a floor is one of the things the design
   * says learning must never unlock, so letting it through silently is the
   * exact harm the floor exists to prevent. An `ask` from "I have not seen
   * this enough times yet" is ordinary unfamiliarity, and blocking all of it
   * would make a fresh install unusable.
   *
   * Inferring this from the presence of a `floor.explain` reason code worked,
   * but tied a security decision to a string meant for humans. It is a field.
   */
  floor: boolean;
}

/**
 * Judge one tool call and record it as pending.
 *
 * Exported so that every adapter shares one decision path. The alternative —
 * a copy per agent — is how a fix lands in one place and not the other, which
 * this codebase has already been bitten by once: two copies of an expansion
 * reader, and the patched one was not the reachable one.
 *
 * The caller is responsible only for translating its agent's request shape into
 * these arguments, and for rendering `PreOutcome` in whatever form that agent
 * reads. Nothing about the judgement itself lives in an adapter.
 */
export function judgePre(p: {
  agent: string;
  cwd: string;
  tool: string;
  input: Record<string, unknown>;
  sessionId: string;
  toolUseId: string;
  permissionMode?: string;
}): PreOutcome {
  const started = Date.now();
  const cwd = p.cwd || process.cwd();
  const root = findProjectRoot(cwd);
  const key = projectKey(root);
  const config = loadConfig();

  const input: HookInput = {
    tool_name: p.tool,
    tool_input: p.input,
    session_id: p.sessionId,
    tool_use_id: p.toolUseId,
    permission_mode: p.permissionMode,
    cwd,
  };

  const req: Request = {
    agent: p.agent,
    tool: p.tool || 'unknown',
    input: p.input ?? {},
    cwd,
    sessionId: p.sessionId || 'unknown',
    agentMode: p.permissionMode,
    at: started,
  };

  const envelope = loadEnvelope('project', key);
  const session = loadSession(req.sessionId, started);

  let verdict: Verdict;
  try {
    verdict = decide(req, {
      roots: [root, ...config.additionalRoots],
      secretPatterns: config.secretPatterns,
      config,
      envelope,
      session,
      stateDir: stateDir(),
      projectKey: key,
    });
  } catch (err) {
    // A crash while *judging* is not the same as a crash while loading config
    // or writing state, and it must not be handled the same way.
    //
    // The outer handler fails open, which is right for infrastructure: a bad
    // disk should not stop the agent working. But failing open here means a
    // tool call went through with LeastGrant unable to say anything about it —
    // and in `bypassPermissions` mode nothing else is checking either, so the
    // call simply runs. An input that reliably crashes the classifier would
    // therefore be a complete bypass, which is the one outcome this project
    // exists to prevent.
    //
    // Asking is the honest answer: we do not know what this is. It is also
    // recoverable in a way silence is not — the user sees the prompt and the
    // reason, rather than never learning we were absent.
    logLine(`decide error: ${(err as Error)?.stack ?? String(err)}`);
    return {
      decision: 'ask',
      headline: 'LeastGrant could not evaluate this tool call, so it is asking rather than guessing',
      silent: config.posture === 'observe',
      reasons: ['engine.error'],
      // Counted as a floor, deliberately.
      //
      // `floor` tells an adapter whose agent cannot express `ask` which way to
      // fall. "I could not evaluate this" must fall the same way a credential
      // read does: an input that reliably crashes the classifier would
      // otherwise be a complete bypass on Codex in an unattended mode, which
      // is the outcome the paragraph above exists to prevent.
      floor: true,
    };
  }

  const ms = Date.now() - started;

  // Record the decision before emitting it, so the ledger is complete even if
  // the agent dies immediately after.
  const entry: LedgerEntry = {
    v: 1,
    at: started,
    agent: p.agent,
    sessionId: req.sessionId,
    project: key,
    tool: req.tool,
    display: verdict.action.display,
    signature: verdict.action.signature,
    capability: verdict.action.capability,
    blast: verdict.action.blast,
    understood: verdict.action.understood,
    decision: verdict.decision,
    reasons: verdict.reasons.map((r) => r.code),
    agentMode: input.permission_mode,
    ms,
  };
  if (config.telemetry.ledger) appendLedger(entry);

  // Update session taint and remember what we decided, so PostToolUse can tell
  // "the human approved it" from "we approved it".
  applyTaint(session, verdict.action.capability);
  // Keyed by tool_use_id: several calls can be in flight in one session, and a
  // subagent shares the session id. A single slot credited whichever call
  // finished next.
  session.pendingById ??= {};
  session.pendingById[input.tool_use_id || 'anonymous'] = {
    signature: verdict.action.signature,
    capability: verdict.action.capability,
    blast: verdict.action.blast,
    decision: verdict.decision,
    display: verdict.action.display,
    toolUseId: input.tool_use_id ?? '',
    at: started,
    // Captured here, not at Post: this is the mode in force at the moment the
    // human was, or was not, consulted.
    //
    // In observe posture LeastGrant emits nothing at all, so no prompt of ours
    // ever reached anybody — recording the result as `confirmed` would be the
    // tool manufacturing its own evidence.
    attended: wasAttended(config.posture, input.permission_mode),
    // Captured here too, so a Post arriving with a different cwd cannot credit
    // the evidence to the wrong project.
    project: key,
    previousCapability: session.previousCapability,
  };
  saveSession(session);

  // In observe posture LeastGrant watches and says nothing. This is the mode
  // that lets someone try it for a week without it ever getting in the way.
  return {
    decision: verdict.decision,
    headline: verdict.headline,
    silent: config.posture === 'observe',
    reasons: verdict.reasons.map((r) => r.code),
    floor: Boolean(verdict.floor),
  };
}

/**
 * Which agent is on the other end.
 *
 * Copilot speaks Claude Code's wire format exactly, so it lands in this
 * handler and renders correctly — but it is not Claude Code, and recording it
 * as such made `leastgrant trail` attribute one agent's behaviour to another.
 * The installer writes `--agent copilot`; anything else is Claude Code.
 */
function callingAgent(): string {
  return agentFlag() === 'copilot' ? 'copilot' : 'claude-code';
}

/**
 * The value of `--agent`, however it was written.
 *
 * Both spellings, because both are ordinary: `--agent codex` and
 * `--agent=codex`. The first version of this checked
 * `argv.includes('codex') && argv.includes('--agent')`, which got the equals
 * form wrong in the worst possible way — the flag was present, the check said
 * no, and a Codex payload went to the Claude Code renderer, which answers
 * `ask`, which Codex rejects and then runs. It also matched a bare `codex`
 * token anywhere in argv, so it was simultaneously too strict and too loose.
 */
export function agentFlag(argv: string[] = process.argv): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--agent') return argv[i + 1]?.toLowerCase();
    if (arg.startsWith('--agent=')) return arg.slice('--agent='.length).toLowerCase();
  }
  return undefined;
}

function preToolUse(input: HookInput): never {
  const out = judgePre({
    agent: callingAgent(),
    cwd: input.cwd ?? '',
    tool: input.tool_name ?? 'unknown',
    input: input.tool_input ?? {},
    sessionId: input.session_id ?? 'unknown',
    toolUseId: input.tool_use_id ?? '',
    permissionMode: input.permission_mode,
  });
  if (out.silent) process.exit(0);
  emit(out.decision, out.headline);
}

/**
 * Fold the outcome of a completed call into the envelope.
 *
 * Exported for the same reason as `judgePre`: one learning path, shared.
 */
export function recordPost(sessionId: string, toolUseId: string): void {
  const session = loadSession(sessionId || 'unknown', Date.now());
  const id = toolUseId || 'anonymous';
  const pending = session.pendingById?.[id];
  if (!pending) {
    // A Post with no matching Pre. That happens legitimately (a hook installed
    // mid-session), and it is also what a desynchronised or forged event looks
    // like. Either way there is nothing we can honestly attribute, so we record
    // nothing rather than crediting the most recent call.
    return;
  }
  // Removed via `saveSession(session, id)` below rather than by mutating the
  // map here: the merge on save unions with what is on disk, so a deletion has
  // to be stated explicitly or a concurrent Pre would put it straight back.
  delete session.pendingById![id];

  // Reaching PostToolUse means the call actually ran.
  //
  // If we said `ask`, then something approved it after us: in an attended
  // session that is a human clicking allow, which is the strongest evidence we
  // can get. In an unattended session it is just the mode, which is the
  // weakest. Conflating those two is how a learning permission system gets
  // trained by the thing it is supposed to be watching — so `attended` comes
  // from the Pre event, where the question was actually put.
  const evidence = evidenceFor(pending.decision, pending.attended);

  const config = loadConfig();
  const envelope = loadEnvelope('project', pending.project);
  observe(
    envelope,
    {
      signature: pending.signature,
      capability: pending.capability,
      blast: pending.blast,
      evidence,
      at: pending.at,
      sessionId: session.sessionId,
      display: pending.display,
      ...(pending.previousCapability ? { previousCapability: pending.previousCapability } : {}),
    },
    config.thresholds,
  );
  saveEnvelope(envelope);

  session.previousCapability = pending.capability;
  saveSession(session, id);
}

function postToolUse(input: HookInput): never {
  recordPost(input.session_id ?? 'unknown', input.tool_use_id ?? '');
  process.exit(0);
}


function emit(decision: Decision, reason: string): never {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision,
        permissionDecisionReason: `LeastGrant: ${reason}`,
      },
    }),
  );
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Session state
//
// Each hook invocation is a separate process, so anything that has to persist
// across tool calls within one conversation lives in a small file. Sessions are
// pruned on read, so an abandoned session cannot accumulate forever.
// ---------------------------------------------------------------------------

interface PersistedSession extends Omit<SessionState, 'taints'> {
  taints: string[];
  previousCapability?: SessionState['lastCapability'];
  pendingById?: Record<string, {
    signature: string;
    capability: SessionState['lastCapability'] & string;
    blast: LedgerEntry['blast'];
    decision: Decision;
    display: string;
    toolUseId: string;
    at: number;
    attended: boolean;
    project: string;
    previousCapability?: SessionState['lastCapability'];
  }>;
}

type LiveSession = SessionState & {
  previousCapability?: SessionState['lastCapability'];
  pendingById?: PersistedSession['pendingById'];
};

const SESSION_TTL_MS = 24 * 3600 * 1000;

function sessionFile(id: string): string {
  const safe = id.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  return path.join(stateDir(), 'sessions', `${safe}.json`);
}

function loadSession(id: string, now: number): LiveSession {
  try {
    const p = JSON.parse(fs.readFileSync(sessionFile(id), 'utf8')) as PersistedSession;
    const s: LiveSession = {
      sessionId: p.sessionId ?? id,
      taints: new Set(p.taints ?? []) as SessionState['taints'],
      count: p.count ?? 0,
      startedAt: p.startedAt ?? now,
    };
    if (p.lastCapability) s.lastCapability = p.lastCapability;
    if (p.previousCapability) s.previousCapability = p.previousCapability;
    if (p.pendingById) s.pendingById = p.pendingById;
    return s;
  } catch {
    return newSession(id, now) as LiveSession;
  }
}

/**
 * Keep the in-flight map small.
 *
 * A Pre with no matching Post leaves an entry behind — an interrupted call, a
 * crash, or an agent that simply never finishes one. Without a bound, the file
 * grows for as long as the session lives.
 */
function prunePending(
  map: NonNullable<PersistedSession['pendingById']>,
): NonNullable<PersistedSession['pendingById']> {
  const entries = Object.entries(map);
  if (entries.length <= 64) return map;
  entries.sort((a, b) => b[1].at - a[1].at);
  return Object.fromEntries(entries.slice(0, 64));
}

/**
 * Save a session, merging with whatever another process wrote meanwhile.
 *
 * Claude Code issues tool calls in parallel, and each one is a separate hook
 * process reading and rewriting the same session file. A plain overwrite means
 * the last writer discards the rest, and measured on forty concurrent calls
 * that was thirty-six of them: their `pendingById` entries vanished, so their
 * PostToolUse found nothing to attribute and LeastGrant learned from four
 * calls out of forty. A permission tool that never settles because it silently
 * drops most of its evidence is a permission tool people turn off.
 *
 * The worse half is `taints`. That set is how "a credential was read earlier in
 * this session" reaches the outbound call that would exfiltrate it, so losing
 * it is not a lost lesson, it is a lost guard.
 *
 * Both problems have the same shape and the same answer: everything in here is
 * monotone within a session. Taints only accumulate, counts only rise, pending
 * entries are independent per `tool_use_id`. So re-read and union rather than
 * overwrite. Deletions still have to win — a Post that consumed a pending entry
 * must not have it resurrected by a concurrent Pre — so they are passed
 * explicitly rather than inferred from absence.
 */
function saveSession(s: LiveSession, consumed?: string): void {
  try {
    const dir = path.join(stateDir(), 'sessions');
    fs.mkdirSync(dir, { recursive: true });

    const disk = loadSession(s.sessionId, s.startedAt);
    const pending: NonNullable<PersistedSession['pendingById']> = {
      ...(disk.pendingById ?? {}),
      ...(s.pendingById ?? {}),
    };
    if (consumed) delete pending[consumed];

    const out: PersistedSession = {
      sessionId: s.sessionId,
      taints: [...new Set([...disk.taints, ...s.taints])],
      count: Math.max(disk.count ?? 0, s.count),
      startedAt: Math.min(disk.startedAt || s.startedAt, s.startedAt),
    };
    // Ours, not the maximum of the two: `lastCapability` describes what this
    // process just decided, and a transition is only meaningful against the
    // call it actually followed. Two truly parallel calls have no order to
    // recover, and pretending otherwise would invent transitions.
    if (s.lastCapability) out.lastCapability = s.lastCapability;
    if (s.previousCapability) out.previousCapability = s.previousCapability;
    if (Object.keys(pending).length) out.pendingById = prunePending(pending);
    fs.writeFileSync(sessionFile(s.sessionId), JSON.stringify(out), 'utf8');
    pruneSessions(dir);
  } catch {
    /* session memory is an optimisation, not a requirement */
  }
}

let pruned = false;
function pruneSessions(dir: string): void {
  if (pruned) return;
  pruned = true;
  try {
    const now = Date.now();
    for (const f of fs.readdirSync(dir)) {
      const full = path.join(dir, f);
      if (now - fs.statSync(full).mtimeMs > SESSION_TTL_MS) fs.unlinkSync(full);
    }
  } catch {
    /* ignore */
  }
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => reject(new Error('stdin timeout')), 5000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
