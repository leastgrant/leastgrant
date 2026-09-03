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
 * Which event this is — and the payload cannot tell you.
 *
 * There is no event name on the wire. `hook_event_name` and `hookEventName`
 * occur ZERO times in the 153 MB runtime; the event is a protobuf *oneof* on
 * HookArgs, `pre_tool_hook_args` against `post_tool_hook_args`, so it is
 * structural and never a string. The first version of this file gated dispatch
 * on that field, so the adapter never ran: every tool call on Antigravity went
 * unenforced, and the suite was green because it synthesised the field in all
 * eleven cases.
 *
 * The version after that routed on the presence of `toolCall`, on the belief
 * that only PreToolUse carries one. That was also wrong. Symbolising the
 * runtime gives:
 *
 *   PreToolHookArgs   tool_call(1)  step_idx(2)
 *   PostToolHookArgs  step_idx(1)   tool_call(2)  error(3)  result(4)
 *
 * Both carry both. So every PostToolUse was being read as a PreToolUse: the
 * action was judged a second time after it had already run, `{"decision":…}`
 * went back where the contract wants `{}`, and — the quiet one — `recordPost`
 * never ran, so no evidence was ever recorded on this agent. Nothing would ever
 * have become familiar. That reads as caution and is a broken feedback loop.
 *
 * The fix does not look for a better field. LeastGrant writes hooks.json, so it
 * can label its own handlers: the installer now writes `--event pre` and
 * `--event post`, which is unambiguous and does not depend on payload
 * archaeology surviving the next release.
 *
 * The shape fallback stays for installs written by an earlier version, where no
 * label exists. `result` and `error` belong to PostToolUse alone, so their
 * presence is decisive; their absence is not, which is exactly why the label
 * exists and why `leastgrant install antigravity` retrofits it.
 */
export function isPreToolUse(input: unknown, event?: string): boolean {
  if (event === 'pre') return true;
  if (event === 'post') return false;
  if (!input || typeof input !== 'object') return false;
  const o = input as Record<string, unknown>;
  if ('result' in o || 'error' in o) return false;
  const call = o['toolCall'];
  return !!call && typeof call === 'object';
}

/**
 * The value of `--event`, however it was written. Same two spellings as
 * `--agent`, for the same reason.
 */
export function eventFlag(argv: string[] = process.argv): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--event') return argv[i + 1]?.toLowerCase();
    if (arg.startsWith('--event=')) return arg.slice('--event='.length).toLowerCase();
  }
  return undefined;
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

/**
 * MCP arrives as one tool carrying the real one in its arguments.
 *
 * Antigravity does not expose `mcp__server__tool` the way Claude Code does. It
 * sends a single `call_mcp_tool` with `{ServerName, ToolName, Arguments}` —
 * captured live, not guessed. Left unmapped that is an opaque call, and the
 * engine correctly refuses to account for it, so EVERY MCP call came back
 * `force_ask`: an unsuppressible prompt, forever, for `browser_snapshot` and
 * `list-clients` alike. Safe, and unusable, which in this product is its own
 * kind of failure — a layer people turn off enforces nothing.
 *
 * Rebuilding the engine's own `mcp__server__tool` spelling puts these calls
 * back under the machinery that already exists for them: the read/write tiering
 * by tool name, the argument-aware signature that stops
 * `get_document({})` from approving `get_document({destructive:true})`, and the
 * secret-path guards on MCP arguments. That is the same treatment every other
 * agent's MCP calls get. It is deliberately not weaker, and it is not stronger.
 *
 * The server and tool names are normalised the way the engine's own matcher
 * expects — `roblox-mcp` and `list-clients` become `roblox_mcp` and
 * `list_clients`, because a hyphen is not part of the `mcp__a__b` shape and a
 * name that fails to split reads as one opaque token again.
 */
const MCP_TOOL = 'call_mcp_tool';

const mcpPart = (v: unknown): string =>
  typeof v === 'string' ? v.replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') : '';

export function toolNameOf(name: string, args: Record<string, unknown> = {}): string {
  if (name === MCP_TOOL) {
    const server = mcpPart(args['ServerName']);
    const tool = mcpPart(args['ToolName']);
    // Only when BOTH are present. A half-named MCP call is exactly the kind of
    // thing that must stay unaccounted for rather than be given a plausible
    // identity it does not have.
    if (server && tool) return `mcp__${server}__${tool}`;
    return name;
  }
  return TOOL_MAP[name]?.tool ?? name;
}

/** Rename the argument keys a mapped tool uses; pass everything else through. */
export function translateArgs(name: string, args: Record<string, unknown>): Record<string, unknown> {
  if (name === MCP_TOOL) {
    // Unwrap only when the identity was actually rebuilt. A half-named call
    // keeps its whole payload: it is going to be judged as the opaque
    // `call_mcp_tool`, and handing that an empty argument object would make an
    // unaccountable call look like a trivial one.
    if (toolNameOf(name, args) === MCP_TOOL) return args;
    // Otherwise the MCP tool's own arguments are the payload; ServerName and
    // ToolName have moved into the identity. `toolAction` and `toolSummary` are
    // the model's narration and belong to no tool, so they are dropped rather
    // than signed over — they vary per call and would defeat learning.
    const inner = args['Arguments'];
    if (inner && typeof inner === 'object' && !Array.isArray(inner)) return inner as Record<string, unknown>;
    if (typeof inner === 'string') {
      try {
        const parsed: unknown = JSON.parse(inner);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parsed as Record<string, unknown>;
        }
      } catch {
        // Unparseable arguments stay opaque, which floors. Correct: we cannot
        // say what this call does.
      }
    }
    return args;
  }
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

  // PostToolUse. The documented output is an EMPTY object — not a decision.
  // `PostToolHookResult` is an empty message, so nothing said here can change
  // anything; emitting a decision would be answering a question that was not
  // asked. The event comes from the `--event` label the installer writes,
  // because the payload carries `toolCall` on both events and cannot be used to
  // tell them apart. See isPreToolUse.
  if (!isPreToolUse(input, eventFlag())) {
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

  const rawArgs =
    call.args && typeof call.args === 'object' && !Array.isArray(call.args)
      ? (call.args as Record<string, unknown>)
      : {};
  const tool = toolNameOf(call.name, rawArgs);
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
