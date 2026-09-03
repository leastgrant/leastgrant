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

import type { Decision, LedgerEntry, Request, Verdict } from '../../core/types.js';
import { decide } from '../../core/decide.js';
import { observe, applyTaint } from '../../core/envelope.js';
import { findProjectRoot, projectKey } from '../../core/paths.js';
import {
  appendLedger,
  loadConfig,
  loadEnvelope,
  logLine,
  saveEnvelope,
  stateDir,
} from '../../store/index.js';
import {
  commitPost,
  commitPre,
  loadSession,
  takePending,
  type PendingCall,
} from './session.js';

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
    // Nothing we can say about a call we cannot read — but "say nothing" does
    // not mean the same thing on every agent.
    //
    // Claude Code, Codex, Copilot and Cursor all read an empty response as an
    // abstain and fall back to their own permission flow, so silence there is
    // the honest answer. Antigravity does not: measured live, a hook that
    // prints nothing and exits 0 is treated as "no hook result" and the call
    // PROCEEDS. Silence is an allow.
    //
    // So an unreadable payload on Antigravity has to be answered, and the only
    // answer available is the one that says we could not read it. `force_ask`
    // rather than `ask`, because a cached grant must not be able to satisfy a
    // call nobody could parse, and rather than `deny` because a malformed
    // payload is our ignorance, not evidence of an attack.
    if (agentFlag() === 'antigravity') {
      process.stdout.write(
        JSON.stringify({
          decision: 'force_ask',
          reason: 'LeastGrant: this tool call did not arrive in a shape LeastGrant could read.',
        }),
      );
    }
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

    // Antigravity before Claude Code, for the same reason and a sharper one.
    //
    // It shares the `PreToolUse` / `PostToolUse` names too, and getting this
    // wrong is worse here than anywhere else: Antigravity reads a *missing*
    // decision as a DENY. The Claude Code renderer's way of standing aside is
    // to print nothing, so a misrouted Antigravity call would not fail open,
    // it would block — every tool call, until someone worked out why.
    //
    // The payloads cannot be confused. Antigravity nests the call under
    // `toolCall` and carries `conversationId`; Claude Code has flat
    // `tool_name` / `tool_input`.
    // Routed on SHAPE, never on an event name — Antigravity does not send one.
    //
    // The first version of this gated on `hook_event_name`, which occurs zero
    // times in the runtime: the event is a protobuf oneof, not a string. The
    // gate was also ANDed before the flag check, so `--agent antigravity` could
    // not rescue it. The adapter therefore never ran, and every tool call on
    // Antigravity went unenforced — while the test suite stayed green, because
    // it synthesised the field.
    const { looksLikeAntigravity, runAntigravityHook } = await import('../antigravity/hook.js');
    const flaggedAntigravity = agentFlag() === 'antigravity';
    if (flaggedAntigravity || looksLikeAntigravity(input)) {
      if (!flaggedAntigravity) {
        logLine('antigravity: routed by payload shape, not by --agent antigravity');
      }
      runAntigravityHook(input);
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
    // Fail open, loudly in the log and silently to the agent — except on
    // Antigravity, where silence IS the open failure rather than a way of
    // declining to have an opinion. Same reasoning as the parse failure above.
    logLine(`hook error: ${(err as Error)?.stack ?? String(err)}`);
    if (agentFlag() === 'antigravity') {
      process.stdout.write(
        JSON.stringify({
          decision: 'force_ask',
          reason: 'LeastGrant: LeastGrant failed while judging this call, so it is asking instead.',
        }),
      );
    }
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
  /**
   * Where the command will actually run, when the agent says so and it is not
   * the session directory. Codex's shell tool has a `workdir` parameter; a
   * per-call working directory is an implicit `cd` in front of the command.
   *
   * Deliberately separate from `cwd`. `cwd` answers "which project is this",
   * and using the execution directory for that would be worse than ignoring
   * it: a `workdir` of `~` would make the *home directory* the project root,
   * so a write to `~/anything` would come back as an in-project write. `cwd`
   * finds the project; this places the paths.
   */
  execCwd?: string;
  /**
   * Override for "was a human in the loop", when the adapter knows better than
   * `permission_mode` does.
   *
   * The only signal in a hook payload is the permission mode, and on some
   * agents it does not answer the question — see the Codex adapter, where
   * LeastGrant has no prompt at all and `default` does not imply anybody was
   * asked. An adapter that knows its agent cannot reach a human says so here
   * rather than letting the shared default manufacture `confirmed` evidence.
   */
  attended?: boolean;
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
    // The directory the command runs in, which is what every relative path in
    // it resolves against. Usually the session directory; not when the agent
    // named a different one per call.
    cwd: p.execCwd || cwd,
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
  // Keyed by tool_use_id, and stored in a file of its own: several calls can be
  // in flight in one session, and a subagent shares the session id. A single
  // slot credited whichever call finished next; a shared file lost most of them
  // to the race between the processes writing it.
  const pending: PendingCall = {
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
    // An adapter can only ever subtract here, never add. `attended: true` from
    // an adapter is not enough on its own, because the whole hazard is a
    // component talking itself into the strongest evidence class.
    attended: wasAttended(config.posture, input.permission_mode) && p.attended !== false,
    // Captured here too, so a Post arriving with a different cwd cannot credit
    // the evidence to the wrong project.
    project: key,
    ...(session.previousCapability ? { previousCapability: session.previousCapability } : {}),
  };
  commitPre(session, input.tool_use_id || 'anonymous', pending);

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
  const sid = sessionId || 'unknown';
  const id = toolUseId || 'anonymous';
  // Reading and consuming in one step, from a file this call and its Pre are
  // the only two things that ever touch. There is no shared map to merge, so a
  // concurrent Pre cannot resurrect the entry and a concurrent Post cannot
  // credit it twice.
  const pending = takePending(sid, id);
  if (!pending) {
    // A Post with no matching Pre. That happens legitimately (a hook installed
    // mid-session), and it is also what a desynchronised or forged event looks
    // like. Either way there is nothing we can honestly attribute, so we record
    // nothing rather than crediting the most recent call.
    return;
  }

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
      sessionId: sid,
      display: pending.display,
      ...(pending.previousCapability ? { previousCapability: pending.previousCapability } : {}),
    },
    config.thresholds,
  );
  saveEnvelope(envelope);

  commitPost(sid, pending.capability, Date.now());
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

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => reject(new Error('stdin timeout')), 5000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => {
      clearTimeout(timer);
      // Strip a leading byte-order mark before anything tries to parse this.
      //
      // Cursor on Windows does not write to our stdin directly. It writes the
      // payload to a temp file and pipes it in through PowerShell:
      //
      //   $OutputEncoding = [System.Text.Encoding]::UTF8;
      //   Get-Content -LiteralPath '<tmp>' -Raw | & { $input | <command> }
      //
      // Windows PowerShell 5.1 emits the UTF-8 preamble for that encoding, so
      // what arrives is EF BB BF + JSON. `JSON.parse` throws on U+FEFF, the
      // catch exits 0 with no output, and Cursor — with the `failClosed` the
      // installer now writes — reads no output as a DENY. Measured through
      // Cursor's real transport: every shell command, MCP call and file read
      // refused, including `git status` and reading README.md. Not "LeastGrant
      // is absent", but "nothing works".
      //
      // Fixed here rather than in the Cursor adapter on purpose. This is a
      // property of how a payload can arrive, not of which agent sent it, and
      // any of the other three could grow the same transport tomorrow.
      resolve(data.charCodeAt(0) === 0xfeff ? data.slice(1) : data);
    });
    process.stdin.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
