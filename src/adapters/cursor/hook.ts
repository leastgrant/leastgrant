/**
 * The Cursor hook entry point.
 *
 * Cursor's hook contract is close enough to Claude Code's to share a decision
 * engine and different enough to need its own translation. The differences that
 * matter:
 *
 *   - Event names are camelCase and split by *what* is happening rather than
 *     by before/after a generic tool call: `beforeShellExecution`,
 *     `beforeMCPExecution`, `beforeReadFile`.
 *   - The response is `{"permission": ...}`, not Claude's nested
 *     `hookSpecificOutput`.
 *   - `ask` is honoured on `beforeShellExecution` and `beforeMCPExecution`
 *     only. `beforeReadFile` takes allow/deny and nothing else.
 *   - There is no `tool_use_id`. Calls are identified by `generation_id`
 *     plus the event, which is coarser — see `callId` below.
 *   - `cwd` is only present on shell events; everything else carries
 *     `workspace_roots`.
 *
 * Exit codes match Claude's shape: 0 with JSON is a decision, anything
 * unexpected is a non-blocking failure that lets the call through. So this file
 * has the same overriding requirement as the Claude adapter — never wedge the
 * agent — and the same answer to it: everything is wrapped, and the worst case
 * is "no opinion".
 *
 * Honesty note, because it belongs in the source and not only in the README:
 * this is written against Cursor's published hook documentation and is
 * exercised by unit tests over the request and response shapes. It has not been
 * run against a live Cursor install. If a field name here is wrong, Cursor
 * ignores our output and LeastGrant is simply absent — the same position a user
 * is in with no hook at all, not a worse one.
 */

import type { Decision } from '../../core/types.js';
import { judgePre, recordPost } from '../claude-code/hook.js';
import { loadConfig, logLine } from '../../store/index.js';

interface CursorInput {
  hook_event_name?: string;
  conversation_id?: string;
  generation_id?: string;
  workspace_roots?: unknown;
  cwd?: string;
  /** beforeShellExecution / afterShellExecution */
  command?: unknown;
  /** beforeReadFile */
  file_path?: unknown;
  /** beforeMCPExecution / afterMCPExecution */
  tool_name?: unknown;
  tool_input?: unknown;
  mcp_server_name?: unknown;
}

/**
 * A stable id for one call, so the Post event can find the Pre.
 *
 * Cursor has no `tool_use_id`. `generation_id` identifies the model turn, which
 * can contain several tool calls, so the event name and a hash of the payload
 * are folded in. Two identical commands in one generation still collide — the
 * consequence is that the second one's outcome is not recorded, which loses a
 * little learning and cannot invent any, so it fails in the safe direction.
 */
function callId(input: CursorInput, payload: string): string {
  let h = 5381;
  for (let i = 0; i < payload.length; i++) h = ((h * 33) ^ payload.charCodeAt(i)) >>> 0;
  const ev = String(input.hook_event_name ?? '').replace(/^(before|after)/, '');
  return `${input.generation_id ?? 'nogen'}:${ev}:${h.toString(36)}`;
}

function sessionOf(input: CursorInput): string {
  return String(input.conversation_id ?? 'unknown');
}

/**
 * Where the project is.
 *
 * Shell events carry `cwd`. Everything else has only `workspace_roots`, whose
 * first entry is the open project. Falling back to `process.cwd()` would be the
 * directory Cursor happened to launch the hook from, which is not the project
 * and would put the learned profile under the wrong key.
 */
function cwdOf(input: CursorInput): string {
  if (typeof input.cwd === 'string' && input.cwd) return input.cwd;
  const roots = input.workspace_roots;
  if (Array.isArray(roots) && typeof roots[0] === 'string' && roots[0]) return roots[0];
  return process.cwd();
}

/**
 * Cursor honours `ask` on shell and MCP events only.
 *
 * On `beforeReadFile` the choice is allow or deny, so an `ask` has to become
 * one or the other. It becomes `allow`, with one exception — see below. The
 * limitation is stated in the README rather than hidden here: on Cursor,
 * ordinary file reads are observed, not gated.
 */
function render(decision: Decision, reason: string, canAsk: boolean, reasons: string[] = []): string {
  // An `ask` we cannot ask becomes `allow`, except where letting it through
  // would be the specific harm the floor exists for. Reading a credential file
  // is a small, well-defined set and blocking it is recoverable — the user adds
  // a rule and moves on — whereas silently allowing it is not recoverable at
  // all. Everything else degrades to `allow`, because turning every unfamiliar
  // read into a hard block would make the integration unusable.
  const mustNotPass = reasons.some((r) => r === 'guard.secret-read' || r === 'guard.self-write');
  const permission =
    decision === 'ask' && !canAsk ? (mustNotPass ? 'deny' : 'allow') : decision;
  const out: Record<string, unknown> = { permission };
  if (decision !== 'allow') {
    out['user_message'] = `LeastGrant: ${reason}`;
    out['agent_message'] = `LeastGrant ${decision === 'deny' ? 'blocked' : 'paused'} this: ${reason}`;
  }
  return JSON.stringify(out);
}

export function runCursorHook(raw: unknown): void {
  const input = (raw ?? {}) as CursorInput;
  const event = String(input.hook_event_name ?? '').toLowerCase();

  // Map Cursor's event to the tool shape the engine already understands, so
  // that a shell command judged here and the same command judged under Claude
  // Code produce the same signature and share the same learned history.
  let tool: string;
  let toolInput: Record<string, unknown>;
  let canAsk: boolean;

  switch (event) {
    case 'beforeshellexecution':
    case 'aftershellexecution':
      tool = 'Bash';
      toolInput = { command: input.command };
      canAsk = true;
      break;
    case 'beforemcpexecution':
    case 'aftermcpexecution': {
      const server = String(input.mcp_server_name ?? 'unknown');
      const name = String(input.tool_name ?? 'unknown');
      // Cursor sends MCP parameters as a JSON *string*. Parsing it means the
      // argument shape reaches the signature the same way it does elsewhere;
      // if it will not parse we pass nothing rather than a string blob, so the
      // call is judged on its name alone instead of on an unparsed identity
      // that would differ on every whitespace change.
      let args: Record<string, unknown> = {};
      if (typeof input.tool_input === 'string') {
        try {
          const parsed: unknown = JSON.parse(input.tool_input);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) args = parsed as Record<string, unknown>;
        } catch {
          /* not JSON; judged on the name */
        }
      } else if (input.tool_input && typeof input.tool_input === 'object') {
        args = input.tool_input as Record<string, unknown>;
      }
      tool = name.startsWith('mcp__') ? name : `mcp__${server}__${name}`;
      toolInput = args;
      canAsk = true;
      break;
    }
    case 'beforereadfile':
      tool = 'Read';
      toolInput = { file_path: input.file_path };
      canAsk = false;
      break;
    default:
      // Not an event we can say anything about. Logged rather than silent, so
      // "LeastGrant is doing nothing" is discoverable.
      if (event) logLine(`cursor: unhandled hook event ${event}`);
      return;
  }

  const id = callId(input, JSON.stringify(toolInput ?? {}));

  if (event.startsWith('after')) {
    recordPost(sessionOf(input), id);
    return;
  }

  const outcome = judgePre({
    agent: 'cursor',
    cwd: cwdOf(input),
    tool,
    input: toolInput,
    sessionId: sessionOf(input),
    toolUseId: id,
    // Cursor has no equivalent of Claude's permission mode. Treating every
    // call as attended would mean every completed call it let through counted
    // as a human approval, which is the exact evidence inflation the design
    // exists to prevent. So Cursor sessions learn from observation only, and
    // that is stated in the README.
    permissionMode: 'auto',
  });

  if (outcome.silent) return;
  process.stdout.write(render(outcome.decision, outcome.headline, canAsk, outcome.reasons));
}

/** Is this an event this adapter handles? Used to route without a flag. */
export function isCursorEvent(name: string): boolean {
  return /^(before|after)(ShellExecution|MCPExecution|ReadFile)$/i.test(name);
}

/** Exported for tests: the posture check the adapter relies on. */
export function cursorPosture(): string {
  try {
    return loadConfig().posture;
  } catch {
    return 'assist';
  }
}
