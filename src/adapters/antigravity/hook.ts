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
 * 1. **An abstain is an ALLOW, and JSON without a decision is a DENY.** These
 *    are not the same thing, and the difference was measured live:
 *
 *      empty stdout, exit 0        -> the call RUNS
 *      `{}` or `{"reason":"x"}`    -> the call is BLOCKED
 *      unparseable stdout          -> BLOCKED
 *      an unrecognised decision    -> BLOCKED
 *
 *    The block comes from `applyPreToolHooks` falling back to the legacy
 *    `allow_tool` bool, whose zero value is false, which it rewrites to "deny".
 *    The allow comes from the runtime trimming the output and treating an empty
 *    result as "no hook result" at all.
 *
 *    So on every other agent LeastGrant can stand aside by printing nothing;
 *    here that is permission to proceed. This file emits an explicit decision on
 *    every path, and so do the two catch blocks in the Claude Code entry point,
 *    which answer `force_ask` for this agent alone when they cannot produce a
 *    real verdict.
 *
 * 2. **A non-zero exit throws the output away — and blocks.** The output half
 *    is as read from the binary: `executeCommandModeHook` zeroes the slice
 *    before returning the error, so printing a perfect deny and then exiting 1
 *    is treated as a failed hook. The consequence was recorded as fail-OPEN from
 *    a static read of `applyPreToolHooks` logging and continuing. Live, it fails
 *    CLOSED: the call is blocked and the model is told the handler failed by
 *    name. The static read describes iteration over the remaining hooks; the
 *    caller aborts. Timeouts behave the same way.
 *
 *    This file still exits 0 on every path. Not because a non-zero exit is
 *    unsafe — it is now known to be the safe direction — but because it discards
 *    our verdict, and an `allow` we meant to give would become a block.
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
 * Every argument name the engine reads, gathered from the mappings themselves.
 *
 * A key with one of these names may appear in a translated call ONLY because a
 * mapping put it there. Anything else carrying that name is dropped.
 *
 * The hole this closes: `translateArgs` wrote renamed keys and pass-through
 * keys into one object with no collision check, and the model chooses the key
 * order. So `{"CommandLine":"cat ~/.ssh/id_rsa","command":"ls"}` translated to
 * `{command:"ls"}` — the engine judged `ls`, and the host, which ignores fields
 * it does not know, ran the credential read. Measured: an honest control gave
 * `force_ask`, the decoy gave a plain cacheable `ask`, and eight observations
 * later it gave `allow`. The same one-key trick worked on every mapped tool,
 * including an edit to `.agents/hooks.json` — LeastGrant approving the file
 * that installs an `auto_approve` handler over the top of it.
 */
const ENGINE_KEYS = new Set<string>([
  ...Object.values(TOOL_MAP).flatMap((m) => Object.values(m.args)),
  ...Object.values(TOOL_MAP).flatMap((m) => Object.keys(m.add ?? {})),
  // Read by the engine for tools this adapter does not currently map. Listed so
  // that adding a mapping later cannot quietly open the same door.
  'old_string',
  'new_string',
  'edits',
  'notebook_path',
  'prompt',
  'timeout',
]);

/**
 * The source keys a mapping cannot do without.
 *
 * If a mapped tool arrives with none of them, the engine is handed a tool with
 * no arguments — and `Bash` with no `command` is not a no-op, it is a shell
 * call nobody could read. The engine classified that as understood, blast-free
 * and promotable, so every unreadable `run_command` collapsed onto one
 * `(no command)` signature that reached `allow` after eight sightings. Since Go
 * unmarshals JSON field names case-insensitively, `{"commandLine": "..."}`
 * missed our exact-match lookup and still ran host-side.
 */
const REQUIRED: Record<string, string[]> = {
  Bash: ['command'],
  Write: ['file_path'],
  Edit: ['file_path'],
  Read: ['file_path'],
  LS: ['path'],
  Grep: ['pattern'],
  Glob: ['pattern'],
  WebFetch: ['url'],
};

/** Fold a tool or argument name for lookup: trimmed, lowercased, dashes as underscores. */
const fold = (s: string): string => s.trim().toLowerCase().replace(/-/g, '_');

/**
 * The mapping for a tool name, tolerant of the spellings the engine's own
 * normaliser already accepts.
 *
 * `normalizeTool` in core maps `Run_Command`, `runCommand` and `run_command `
 * onto the shell family, so those reached the engine as a shell tool while this
 * exact-match table missed them and left `CommandLine` untranslated — a shell
 * call with no command, which is the promotable identity above. Folding here
 * keeps the two in step. Homoglyph spellings still miss, and should: they are
 * not the same name.
 */
const FOLDED_TOOLS = new Map(Object.entries(TOOL_MAP).map(([k, v]) => [fold(k), v] as const));
const mappingFor = (name: string): Mapping | undefined => TOOL_MAP[name] ?? FOLDED_TOOLS.get(fold(name));

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
  if (fold(name) === MCP_TOOL) {
    const server = mcpPart(args['ServerName']);
    const tool = mcpPart(args['ToolName']);
    // Only when BOTH are present. A half-named MCP call is exactly the kind of
    // thing that must stay unaccounted for rather than be given a plausible
    // identity it does not have.
    if (server && tool) return `mcp__${server}__${tool}`;
    return name;
  }
  return mappingFor(name)?.tool ?? name;
}

/** Rename the argument keys a mapped tool uses; pass everything else through. */
export function translateArgs(name: string, args: Record<string, unknown>): Record<string, unknown> {
  if (fold(name) === MCP_TOOL) {
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
  const m = mappingFor(name);
  // An unmapped tool keeps its own name, so the engine judges it as an opaque
  // call — but its arguments must not be able to masquerade as engine ones.
  if (!m) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(args)) if (!ENGINE_KEYS.has(k)) out[k] = v;
    return out;
  }

  // Source keys, matched exactly first and case-insensitively second — the same
  // order Go's json.Unmarshal uses host-side, so we read what the host reads.
  const folded = new Map(Object.entries(args).map(([k, v]) => [fold(k), [k, v]] as const));
  const out: Record<string, unknown> = { ...(m.add ?? {}) };
  const consumed = new Set<string>();
  for (const [src, target] of Object.entries(m.args)) {
    const hit = src in args ? ([src, args[src]] as const) : folded.get(fold(src));
    if (!hit) continue;
    out[target] = hit[1];
    consumed.add(hit[0]);
  }

  // Everything else passes through under its own name — unless that name is one
  // the engine reads, in which case it is dropped. A key the engine reads may
  // only be present because the mapping above put it there.
  for (const [k, v] of Object.entries(args)) {
    if (consumed.has(k)) continue;
    if (ENGINE_KEYS.has(k)) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Did the translation lose the thing that makes this call readable?
 *
 * Returned separately rather than folded into `translateArgs` so the caller can
 * answer `force_ask` instead of handing the engine a shell call with no command
 * and letting it conclude that nothing happens.
 */
export function unreadable(name: string, translated: Record<string, unknown>): boolean {
  const m = mappingFor(name);
  if (!m) return false;
  const need = REQUIRED[m.tool];
  if (!need) return false;
  return !need.some((k) => {
    const v = translated[k];
    return typeof v === 'string' ? v.length > 0 : v !== undefined && v !== null;
  });
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
/**
 * Reason codes that must reach a person even though no guard floored them.
 *
 * `floor` alone was the test, and it let through the exact sequence this
 * adapter's own header lists as the thing `force_ask` is for. Measured: a
 * credential read floored, and then the outbound call that followed it in the
 * same session — the taint concern, "already read a credential file, and this
 * call sends data off the machine" — came back as a plain, cacheable `ask`,
 * while an *unrecognised* tool got the unsuppressible one. Exactly backwards:
 * the better LeastGrant understood the attack, the weaker its answer.
 *
 * `session.taint` is the exfiltration shape. `gap.blast` is the case the engine
 * describes as more than it will ever approve on its own, which is by
 * definition not something a cached "Always allow" should settle.
 */
const NEVER_CACHEABLE = new Set(['session.taint', 'gap.blast']);

export function resolve(outcome: PreOutcome): { verdict: AntigravityVerdict; reason: string } {
  if (outcome.decision === 'deny') return { verdict: 'deny', reason: outcome.headline };
  if (outcome.decision === 'allow') return { verdict: 'allow', reason: '' };
  const insist = outcome.floor || (outcome.reasons ?? []).some((r) => NEVER_CACHEABLE.has(r));
  return insist
    ? { verdict: 'force_ask', reason: outcome.headline }
    : { verdict: 'ask', reason: outcome.headline };
}

/** The result object, protojson camelCase. */
function render(verdict: AntigravityVerdict, reason: string): string {
  const out: Record<string, unknown> = { decision: verdict };
  if (reason) out['reason'] = `LeastGrant: ${reason}`;
  return JSON.stringify(out);
}

/**
 * Which of the host's workspace paths may serve as a containment boundary.
 *
 * Taken verbatim, they could not. Two ways that went wrong, both measured:
 *
 *   A drive or filesystem root — `C:\`, `/`, `C:\Users` — makes everything on
 *   the machine in-project, so `guard.write-outside` never fires and a write to
 *   `C:\Users\Public` signs as the same ordinary `Write(<path>)` as editing a
 *   source file. Approvals of project edits then pay for writes anywhere. Not
 *   model-controlled, but "open a folder at C:\\" is a thing people do.
 *
 * Judged from the string alone — nothing here touches the filesystem.
 *
 * An earlier version also dropped roots that do not exist, which sounded
 * thorough and bought nothing: a directory that is not there cannot contain
 * anything, so it is already no weaker as a boundary. What it did buy was a
 * blocking stat, and against an absent Windows device that costs ~21 SECONDS
 * with no way to bound a synchronous call. It also quietly changed the verdict
 * for any workspace path that happens not to exist yet.
 *
 * The dead-drive stall is therefore NOT fixed here, and is recorded as a
 * limitation rather than described away: a workspace on a disconnected drive
 * makes every tool call wait on the device and then be blocked by the host
 * timeout. Safe direction, unusable agent, and the same would be true of
 * Antigravity itself.
 *
 * Dropping a root is always the safe direction: fewer roots means more paths
 * count as outside the project, never fewer.
 */
export function usableRoots(paths: unknown): string[] {
  if (!Array.isArray(paths)) return [];
  const out: string[] = [];
  for (const p of paths) {
    if (typeof p !== 'string' || !p.trim()) continue;
    const norm = p.replace(/\\/g, '/').replace(/\/+$/, '');
    // A drive root normalises to `c:` and a POSIX root to the empty string.
    if (norm === '' || /^[a-z]:$/i.test(norm)) continue;
    // One level below a POSIX root is still too wide to be a project: `/home`,
    // `/Users`, `/etc`. A single segment under a Windows drive — `C:/Users` —
    // is the same case and is caught by the segment count below.
    const segments = norm.replace(/^[a-z]:/i, '').split('/').filter(Boolean);
    if (segments.length < 2 && !/^[a-z]:/i.test(norm)) continue;
    if (/^[a-z]:/i.test(norm) && segments.length < 1) continue;
    if (/^[a-z]:\/(users|windows|program files|programdata)$/i.test(norm)) continue;
    out.push(p);
  }
  return out;
}

/**
 * The id that pairs a PostToolUse with the PreToolUse it completes.
 *
 * `??` was wrong here, and only on the empty string. The runtime marshals hook
 * arguments with `EmitUnpopulated = true`, so every field is present even when
 * empty — an `executionId` that exists in the proto arrives as `""` on every
 * payload, `??` passes it through because it is not null, and a perfectly good
 * `stepIdx` never gets a look in. Every in-flight call in the conversation then
 * collapses onto one pending slot: measured, three Pres with distinct stepIdx
 * left ONE pending, and the Post for the first banked evidence for the third.
 *
 * With neither, the id was `''` and every call in the conversation shared the
 * single `anonymous` slot — a Post for `npm test` consumed the pending left by
 * `rm -rf build` and recorded the delete as the evidence.
 *
 * So: the first value that is actually there. And when nothing is, the id is
 * made unique per call rather than shared, because an unpaired Post that finds
 * nothing is a lost observation, while one that finds somebody else's is a
 * wrong one.
 */
function callId(input: AntigravityInput): string {
  for (const v of [input.executionId, input.stepIdx]) {
    if (typeof v === 'string' && v !== '') return v;
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  return '';
}

export function runAntigravityHook(raw: unknown): void {
  const input = (raw ?? {}) as AntigravityInput;
  const roots = usableRoots(input.workspacePaths);
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
      recordPost(sessionId, callId(input));
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

  // A mapped tool whose defining argument did not survive translation is a call
  // LeastGrant cannot read. Saying so is the whole point: handing the engine
  // `Bash` with no `command` produced an understood, blast-free, promotable
  // no-op, and every unreadable shell call shared that one identity.
  if (unreadable(call.name, args)) {
    process.stdout.write(
      render('force_ask', `this ${call.name} call did not carry an argument LeastGrant could read`),
    );
    return;
  }

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
      toolUseId: callId(input),
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
