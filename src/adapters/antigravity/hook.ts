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

/**
 * There is no event name on the wire, and assuming one cost this adapter its
 * first release.
 *
 * `hook_event_name` and `hookEventName` occur ZERO times in the 153 MB runtime.
 * The event is a protobuf *oneof* on HookArgs — pre_tool_hook_args against
 * post_tool_hook_args — so it is structural, never a string. The first version
 * of this file gated dispatch on that field, so the adapter never ran: every
 * tool call on Antigravity went unenforced, and the test suite was green
 * because it synthesised the field in all eleven cases.
 *
 * What distinguishes the two events is what the payload carries. PreToolUse has
 * `toolCall`; PostToolUse has `stepIdx` and an optional `error` and no
 * `toolCall` at all.
 */
export function isPreToolUse(input: unknown): boolean {
  if (!input || typeof input !== 'object') return false;
  const call = (input as Record<string, unknown>)['toolCall'];
  return !!call && typeof call === 'object';
}

/**
 * Is this Antigravity's payload rather than another agent's?
 *
 * Shape only, because there is no event name to route on. Claude Code and Codex
 * send flat `tool_name`/`tool_input`; Antigravity nests under `toolCall` and
 * carries `conversationId`.
 */
export function looksLikeAntigravity(input: unknown): boolean {
  if (!input || typeof input !== 'object') return false;
  const o = input as Record<string, unknown>;
  if (o['tool_name'] !== undefined || o['tool_input'] !== undefined) return false;
  if (typeof o['conversationId'] === 'string') return true;
  return !!o['toolCall'] && typeof o['toolCall'] === 'object';
}

/**
 * Antigravity's tool names and argument keys, mapped onto the shapes the engine
 * already reasons about.
 *
 * Names are snake_case: the shipped documentation says they are "derived by
 * lowercasing the step type and removing the CORTEX_STEP_TYPE_ prefix", and the
 * matcher examples are `run_command`, `view_file`, `browser_.*`. The first
 * version of this map used PascalCase converter names — `RunCommand` — which
 * matched nothing the runtime sends, so a credential read arrived as an
 * unrecognised tool and degraded from `force_ask` to an ordinary cacheable ask.
 *
 * Argument keys are Go PascalCase and differ per tool. Only the ones that could
 * be READ OUT OF THE BINARY are here:
 *
 *   run_command      {"CommandLine": "npm test", "Cwd": "/home/project/", ...}
 *   write_to_file    {"TargetFile": "...", "CodeContent": "..."}
 *   edit tools       {"TargetFile": "...", "CodeEdit": "..."}
 *
 * Deliberately nothing else. Fifty-odd more tools exist and guessing their
 * argument keys would produce exactly the failure this map was just fixed for —
 * a tool that looks translated, is not, and quietly loses its floor. An
 * unmapped tool keeps its own name and is judged as an opaque call, which asks.
 * Friction on a read is the cost; a silently-lost credential floor is not.
 */
interface Mapping {
  tool: string;
  /** Antigravity's argument key -> the key the engine expects. */
  args: Record<string, string>;
  /**
   * Arguments the engine needs that Antigravity does not send, because the
   * distinction is carried by the tool's identity there instead.
   *
   * `grep_search` searches file CONTENTS. The engine's `Grep` decides that from
   * `output_mode`, and without it treats the call as a names-only listing —
   * which deliberately does not floor, because listing filenames is not reading
   * credentials. So a content search over ~/.ssh came back as a plain
   * cacheable ask rather than force_ask.
   */
  add?: Record<string, unknown>;
}

const TOOL_MAP: Record<string, Mapping> = {
  // Wire-confirmed: the binary carries literal JSON examples for these.
  run_command: { tool: 'Bash', args: { CommandLine: 'command' } },
  send_command_input: { tool: 'Bash', args: { CommandLine: 'command' } },
  write_to_file: { tool: 'Write', args: { TargetFile: 'file_path', CodeContent: 'content' } },
  replace_file_content: { tool: 'Edit', args: { TargetFile: 'file_path', CodeEdit: 'content' } },
  single_replace_file_content: { tool: 'Edit', args: { TargetFile: 'file_path', CodeEdit: 'content' } },
  multi_replace_file_content: { tool: 'Edit', args: { TargetFile: 'file_path', CodeEdit: 'content' } },

  // Protobuf-derived: the binary has the field names (AbsolutePath with
  // StartLine/EndLine, SearchDirectory with Query and Includes) but no literal
  // JSON example, so these are one grade weaker in evidence than the six above.
  //
  // Mapping them anyway, because leaving them out was worse and because getting
  // a key wrong here FAILS SAFE — measured: `Read` with an unrecognised key
  // classifies as `Read(?)`, understood false, which floors. A wrong guess
  // costs a prompt; it cannot manufacture an approval.
  //
  // Leaving them out cost far more than a prompt. An unmapped tool is judged as
  // an opaque call, so `view_file` on README.md came back `force_ask` — an
  // unsuppressible prompt for every ordinary file read the agent makes. Safe,
  // and unusable, which in this product is its own kind of failure.
  view_file: { tool: 'Read', args: { AbsolutePath: 'file_path' } },
  read_file: { tool: 'Read', args: { AbsolutePath: 'file_path' } },
  read_resource: { tool: 'Read', args: { AbsolutePath: 'file_path' } },
  list_dir: { tool: 'LS', args: { DirectoryPath: 'path' } },
  grep_search: { tool: 'Grep', args: { SearchDirectory: 'path', Query: 'pattern' }, add: { output_mode: 'content' } },
  find_by_name: { tool: 'Glob', args: { SearchDirectory: 'path', Pattern: 'pattern' } },
  read_url_content: { tool: 'WebFetch', args: { Url: 'url' } },
};

export function toolNameOf(name: string): string {
  return TOOL_MAP[name]?.tool ?? name;
}

/** Rename the argument keys a mapped tool uses; pass everything else through. */
export function translateArgs(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const m = TOOL_MAP[name];
  if (!m) return args;
  const out: Record<string, unknown> = { ...(m.add ?? {}) };
  for (const [k, v] of Object.entries(args)) out[m.args[k] ?? k] = v;
  return out;
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
  const roots = Array.isArray(input.workspacePaths)
    ? input.workspacePaths.filter((p): p is string => typeof p === 'string')
    : [];
  const cwd = roots[0] ?? process.cwd();
  const sessionId = input.conversationId || 'antigravity';

  // PostToolUse. No `toolCall`, and the documented output is an EMPTY object —
  // not a decision. `PostToolHookResult` is an empty message, so nothing said
  // here can change anything; emitting a decision would be answering a question
  // that was not asked.
  if (!isPreToolUse(input)) {
    try {
      recordPost(sessionId, String(input.executionId ?? input.stepIdx ?? ''));
    } catch {
      /* observation must never wedge the agent */
    }
    process.stdout.write('{}');
    return;
  }

  const call = input.toolCall as { name?: string; args?: unknown };
  if (typeof call.name !== 'string' || !call.name) {
    // A tool call with no name is a payload shape LeastGrant does not
    // recognise. That is ignorance, not safety, and it gets the same answer as
    // a crash — the conformance suite caught this answering `allow`.
    process.stdout.write(
      render('force_ask', 'this tool call did not arrive in a shape LeastGrant could read'),
    );
    return;
  }

  const tool = toolNameOf(call.name);
  const rawArgs =
    call.args && typeof call.args === 'object' && !Array.isArray(call.args)
      ? (call.args as Record<string, unknown>)
      : {};
  const args = translateArgs(call.name, rawArgs);

  // `run_command` carries its own working directory, which decides where every
  // relative path in the command lands. Dropping it judged a write outside the
  // project as an in-project write — the same bug the Codex adapter had with
  // `workdir`.
  const execCwd = typeof rawArgs['Cwd'] === 'string' && rawArgs['Cwd'] ? (rawArgs['Cwd'] as string) : undefined;

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
      ...(execCwd ? { execCwd } : {}),
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
