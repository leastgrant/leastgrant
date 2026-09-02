/**
 * Google Antigravity.
 *
 * The only agent LeastGrant supports where an `ask` can be made to reach a
 * person no matter what the session has already been told to auto-approve.
 * Everywhere else `ask` is the weakest verdict — Codex has none at all, Cursor
 * rejects it on `preToolUse`, Claude Code turns it into a deny under
 * `claude -p`. Antigravity has two, and the stronger one is the point of this
 * adapter.
 *
 *   ask         honours a cached "Always allow" for the same action class.
 *   force_ask   does not. `EnsurePermissions` never calls `check()` on this
 *               branch, so no prior grant and no auto-execution preset can
 *               satisfy it.
 *
 * So a floored action — a credential read, exfiltration, persistence, writing
 * outside the project — becomes `force_ask` and a merely-unfamiliar one becomes
 * `ask`. That mapping is the honest use of the distinction: LeastGrant insists
 * on a human exactly where its own rules say learning must never decide, and
 * respects the user's cached choices everywhere else.
 *
 * ---
 *
 * THREE THINGS HERE ARE THE OPPOSITE OF EVERY OTHER ADAPTER
 *
 * 1. **Silence is a DENY, not an abstain.** `applyPreToolHooks` tests
 *    `len(result.Decision) == 0` and falls back to the legacy `allow_tool`
 *    bool, whose zero value is false, which it rewrites to the literal "deny".
 *    So `{}`, `{"reason":"x"}`, or any JSON that parses without a `decision`
 *    blocks the call. Every other adapter in this repo can stand aside by
 *    printing nothing; here that wedges the agent. This file therefore always
 *    emits an explicit decision, on every path, including the error path.
 *
 * 2. **A non-zero exit throws the output away.** `executeCommandModeHook`
 *    zeroes the output slice before returning the error, so a hook that prints
 *    a perfect deny and then exits 1 is treated as a failed hook — and a failed
 *    hook fails OPEN. Printing the right answer is not enough; the process has
 *    to succeed. This file exits 0 on every path.
 *
 * 3. **Deny and ask do not have the same reach.** `deny` is enforced in the
 *    converter, before the permission manager is involved, so it applies to any
 *    tool call. `ask` and `force_ask` are read only by the permissions package,
 *    which a step reaches only if it declares permission targets. A step with
 *    none is unaffected by either. Deny is therefore strictly the more reliable
 *    verdict here, and that asymmetry is recorded in compatibility/antigravity.json
 *    rather than papered over.
 *
 * ---
 *
 * WHAT CAN SWITCH THIS OFF WITHOUT SAYING SO
 *
 * The hook engine installs only when the server-delivered experiment flag
 * `json-hooks-enabled` is true. It is per-session, not persisted, not readable
 * and not overridable from the client, so LeastGrant cannot tell an enforcing
 * session from an unenforced one. And `force_ask` is silently downgraded to an
 * allow when the host sets `auto_interaction_behavior = ALLOW_ALL` —
 * `ResolveAutoInteraction` runs before any prompt is registered and the hook
 * gets no signal.
 *
 * Both are in the compatibility record. Neither is a reason not to ship: the
 * same is true of every agent here in some form, and `deny` — the verdict that
 * matters most — is structurally mode-independent.
 *
 * Contract re-derived from the shipped 153 MB Go runtime
 * (`resources/bin/language_server.exe`, build 2026-08-26, CL 971157550) by
 * symbolising its pclntab and reading the decision sites directly, rather than
 * from the documentation, which advertises five of the eight common payload
 * fields and omits two of the six accepted verdicts.
 */

import { judgePre, recordPost, type PreOutcome } from '../claude-code/hook.js';
import type { Decision } from '../../core/types.js';

/**
 * The payload Antigravity writes to stdin.
 *
 * Flat protojson camelCase — `HookArgsCommon` and `PreToolHookArgs` merged into
 * one object, not nested under an envelope.
 */
interface AntigravityInput {
  conversationId?: string;
  workspacePaths?: unknown;
  transcriptPath?: string;
  artifactDirectoryPath?: string;
  executionId?: string;
  modelName?: string;
  isBattleMode?: boolean;
  lastUserInput?: string;
  toolCall?: { name?: string; args?: unknown };
  stepIdx?: number;
  /** PostToolUse adds this; present only when the tool failed. */
  error?: string;
}

/** Events the parser accepts, exact-cased Go field names. */
const EVENTS = new Set(['pretooluse', 'posttooluse', 'sessionstart', 'preinvocation', 'postinvocation', 'stop']);

export function isAntigravityEvent(name: string): boolean {
  return EVENTS.has(String(name).toLowerCase());
}

/**
 * Is this Antigravity's payload rather than Claude Code's?
 *
 * `PreToolUse` and `PostToolUse` are the same event names Claude Code uses, so
 * the name alone cannot route. The payloads are unmistakable though: Antigravity
 * nests the call under `toolCall` and carries `conversationId`, where Claude
 * Code has flat `tool_name`/`tool_input` and `session_id`.
 */
export function looksLikeAntigravity(input: unknown): boolean {
  if (!input || typeof input !== 'object') return false;
  const o = input as Record<string, unknown>;
  if (o['tool_name'] !== undefined || o['tool_input'] !== undefined) return false;
  return typeof o['conversationId'] === 'string' || (!!o['toolCall'] && typeof o['toolCall'] === 'object');
}

/**
 * Antigravity's tool names, mapped to the shapes the engine already reasons
 * about, so a command judged here shares its learned history with the same
 * command under any other agent.
 *
 * Only the classes whose arguments the engine can actually read are translated.
 * Everything else keeps its own name and is judged as an opaque call — which is
 * the honest answer, and is what `mcp.call` already does.
 */
const TOOL_MAP: Record<string, string> = {
  RunCommand: 'Bash',
  SendCommandInput: 'Bash',
  ViewFile: 'Read',
  ReadResource: 'Read',
  WriteToFile: 'Write',
  KnowledgeWriteToFile: 'Write',
  ReplaceFileContent: 'Edit',
  SingleReplaceFileContent: 'Edit',
  MultiReplaceFileContent: 'Edit',
  KnowledgeReplaceFileContent: 'Edit',
  SedFile: 'Edit',
  NotebookEdit: 'Edit',
  GrepSearch: 'Grep',
  Find: 'Glob',
  ListDir: 'LS',
  ReadUrlContent: 'WebFetch',
  SearchWeb: 'WebSearch',
  InvokeSubagent: 'Agent',
  BrowserSubagent: 'Agent',
};

export function toolNameOf(name: string): string {
  return TOOL_MAP[name] ?? name;
}

/** What this adapter will print. */
export type AntigravityVerdict = 'allow' | 'ask' | 'force_ask' | 'deny';

/**
 * Which of Antigravity's two asks an abstract `ask` becomes.
 *
 * The floored set is the one LeastGrant says learning may never unlock, so it
 * is exactly the set that must survive a cached "Always allow" — that is what
 * `force_ask` is for. Everything else asks the ordinary way, because a user who
 * has told Antigravity to stop asking about a class of action has made a
 * decision LeastGrant has no business overriding when its own rules do not
 * require it.
 */
export function resolve(outcome: PreOutcome): { verdict: AntigravityVerdict; reason: string } {
  if (outcome.decision === 'deny') return { verdict: 'deny', reason: outcome.headline };
  if (outcome.decision === 'allow') return { verdict: 'allow', reason: '' };
  return outcome.floor
    ? { verdict: 'force_ask', reason: outcome.headline }
    : { verdict: 'ask', reason: outcome.headline };
}

/** The result object, protojson camelCase. */
function render(verdict: AntigravityVerdict, reason: string): string {
  const out: Record<string, unknown> = { decision: verdict };
  if (reason) out['reason'] = `LeastGrant: ${reason}`;
  return JSON.stringify(out);
}

export function runAntigravityHook(raw: unknown): void {
  const input = (raw ?? {}) as AntigravityInput;
  const event = String((raw as Record<string, unknown>)?.['hook_event_name'] ?? '').toLowerCase();

  // No readable tool call. What that means depends entirely on the event, and
  // conflating the two cases turned an unreadable payload into an approval —
  // caught by the conformance suite the hour this adapter was written.
  //
  //   SessionStart, PreInvocation, Stop   genuinely have no tool call. There is
  //                                       nothing to judge, and they still need
  //                                       an explicit answer because silence is
  //                                       a deny.
  //   PreToolUse with no toolCall         is a payload shape LeastGrant does not
  //                                       recognise. That is ignorance, not
  //                                       safety, and it gets the same answer as
  //                                       a crash.
  const call = input.toolCall;
  if (!call || typeof call !== 'object' || typeof call.name !== 'string') {
    const isToolEvent = event === 'pretooluse' || event === 'posttooluse';
    if (!isToolEvent) {
      process.stdout.write(render('allow', ''));
      return;
    }
    process.stdout.write(
      render('force_ask', 'this tool call did not arrive in a shape LeastGrant could read'),
    );
    return;
  }

  const tool = toolNameOf(call.name);
  const args =
    call.args && typeof call.args === 'object' && !Array.isArray(call.args)
      ? (call.args as Record<string, unknown>)
      : {};
  const roots = Array.isArray(input.workspacePaths)
    ? input.workspacePaths.filter((p): p is string => typeof p === 'string')
    : [];
  const cwd = roots[0] ?? process.cwd();
  const sessionId = input.conversationId || 'antigravity';

  if (event === 'posttooluse') {
    // `PostToolHookResult` is an empty message, so nothing said here can change
    // anything — it is observation only. Recording it is still how a signature
    // learns it completed.
    try {
      recordPost(sessionId, String(input.executionId ?? input.stepIdx ?? ''));
    } catch {
      /* observation must never wedge the agent */
    }
    process.stdout.write(render('allow', ''));
    return;
  }

  let outcome: PreOutcome;
  try {
    outcome = judgePre({
      agent: 'antigravity',
      tool,
      input: args,
      cwd,
      sessionId,
      toolUseId: String(input.executionId ?? input.stepIdx ?? ''),
      permissionMode: undefined,
    });
  } catch (err) {
    // A crash inside LeastGrant. Exiting non-zero would make Antigravity throw
    // the answer away and fail open, so the only way to be heard is to succeed
    // and say so. `force_ask` rather than `deny`: LeastGrant does not know what
    // this call was, and "I could not judge this, please look" is the honest
    // verdict for ignorance — the same line the Codex adapter draws.
    process.stdout.write(
      render('force_ask', `could not judge this call (${(err as Error)?.message ?? 'unknown error'})`),
    );
    return;
  }

  const { verdict, reason } = resolve(outcome);
  process.stdout.write(render(verdict, reason));
}

/** What `doctor` says about running on Antigravity. */
export function antigravityCaveat(): string {
  return (
    'Antigravity: deny is enforced in the tool-call converter, so it applies in every mode. ' +
    'A floored ask becomes force_ask, which no cached grant can satisfy — the only agent here ' +
    'where LeastGrant can insist on a human. Two host-side switches can disable that silently: ' +
    'the server experiment flag json-hooks-enabled, and auto_interaction_behavior=ALLOW_ALL.'
  );
}

/** Exported for tests: the decision vocabulary the runtime actually handles. */
export const ACCEPTED_DECISIONS = [
  'allow',
  'ask',
  'force_ask',
  'deny',
  'auto_approve',
  'deny_unless_prior_grant',
] as const;
