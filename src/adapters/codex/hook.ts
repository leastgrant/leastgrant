/**
 * Codex CLI.
 *
 * Codex grew lifecycle hooks, and they are close enough to Claude Code's that
 * the same engine drives both — same `judgePre`, same `recordPost`, same
 * signatures, so a command approved under one agent is familiar to the other.
 * Two differences matter, and the second one is the whole reason this file
 * exists rather than reusing the Claude Code handler.
 *
 * 1. `PermissionRequest` is a Codex event with no Claude Code equivalent. It
 *    fires only when Codex is already about to prompt, and takes a different
 *    response shape: `decision: { behavior, message }` rather than
 *    `permissionDecision`.
 *
 * 2. **Codex has no `ask`.** `permissionDecision: "ask"` is parsed and then
 *    rejected — the binary carries the string "PreToolUse hook returned
 *    unsupported permissionDecision:ask" — and Codex *proceeds with the call*.
 *    Emitting Claude Code's response shape into Codex would therefore turn
 *    every `ask` into a silent allow, which is precisely the failure this
 *    project exists to prevent. Verified against codex-cli 0.152.0.
 *
 * ---
 *
 * WHAT `ask` BECOMES HERE
 *
 * Codex offers exactly two ways to say something other than deny: return
 * nothing (abstain) and let its own approval flow run, or deny. Which one is
 * right depends on whether abstaining can actually reach a human, and the
 * payload's `permission_mode` is the only signal available.
 *
 *   mode reaches a human   →  abstain. Codex prompts. This is a real `ask`.
 *
 *   mode reaches nobody    →  the abstain would be an allow, so:
 *     ask from a floor     →  deny, with the rule that would permit it
 *     ask from unfamiliarity → abstain
 *
 * That split is the honest one. The floors are the set the README describes as
 * what learning will never unlock — credentials, exfiltration, persistence,
 * privilege, writing outside the project, code that cannot be read. Letting
 * those through unannounced in an unattended run is the specific harm they
 * exist for. Everything else asks only because LeastGrant has not seen it
 * often enough yet, and turning a fresh install into a wall of blocks would
 * make it unusable — the same trade the Cursor adapter makes on `beforeRead`.
 *
 * 3. **`allow` is not a verdict on `PreToolUse` either.** Measured against
 *    0.152.0's parser: `permissionDecision: "allow"` *without* an
 *    `updatedInput` is rejected as an unsupported value, the hook run is marked
 *    Failed and surfaced to the user, and the call proceeds. On `PreToolUse`,
 *    `allow` is only the carrier for an input rewrite. So the two things this
 *    adapter can express there are DENY and ABSTAIN, and an allow verdict is
 *    rendered as an abstain: identical in effect, minus a spurious hook error
 *    in the transcript. The one place an allow is genuinely enforced is
 *    `PermissionRequest`, whose `decision.behavior = "allow"` really does
 *    cancel the prompt Codex was about to show.
 *
 * The consequence, stated plainly because it belongs in the open: in every mode
 * that cannot prompt, LeastGrant on Codex is a veto, not a prompt. It is
 * strictly better than running Codex without it, and weaker than LeastGrant on
 * an agent that can express `ask` at all — though note that Claude Code's `ask`
 * also degrades to a deny wherever no prompt surface exists (`claude -p`), so
 * the difference is that Codex has no prompt surface to degrade *from*.
 *
 * ---
 *
 * TRANSLATING THE WIRE, NOT JUST THE TOOL NAME
 *
 * This adapter used to rename `apply_patch` to `Edit` and `shell` to `Bash` and
 * consider its job done. Renaming the tool while passing its arguments through
 * unread is the whole bug class this file now exists to prevent: the engine is
 * handed a payload it *appears* to understand, and answers confidently about
 * something it never saw.
 *
 * The measured case: Codex's shell tool sends `command` as an argv ARRAY
 * (`{"command":["sudo","rm","-rf","/var"],"workdir":"..."}`), which is the
 * normal shape and not an edge case. Passed through, `String(array)` made it
 * the single token `sudo,rm,-rf,/var`, whose program name is `var` — so
 * `sudo rm -rf /var`, `ls -la /var` and `cp /root/.ssh/id_rsa /var` all
 * collapsed onto one learnable signature with no targets and no floor. The
 * identical command as a string denied.
 *
 * See {@link translate}. Every field Codex sends is either read deliberately or
 * declared untranslatable; nothing is forwarded on the assumption that whatever
 * it holds must be a string.
 */

import * as os from 'node:os';
import * as path from 'node:path';
import { judgePre, recordPost, type PreOutcome } from '../claude-code/hook.js';
import { logLine } from '../../store/index.js';
import type { Decision } from '../../core/types.js';

/** The payload Codex writes to stdin. Shared fields plus its own additions. */
interface CodexInput {
  hook_event_name?: string;
  session_id?: string;
  turn_id?: string;
  cwd?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown> | string;
  tool_use_id?: string;
  permission_mode?: string;
  /** A Codex extension; also one of the signals that this is not Claude Code. */
  model?: string;
}

/**
 * Modes in which abstaining still reaches a person.
 *
 * An allowlist rather than a blocklist of the unattended ones: a mode Codex
 * adds later that this file has never heard of should be treated as unable to
 * prompt, so a new mode makes LeastGrant stricter rather than quietly toothless.
 *
 * The set used to be `['default','acceptedits','plan','ask','']`, which was
 * three kinds of wrong measured against codex-cli 0.152.0.
 *
 *   `ask` is not a permission mode at all — it is a *permissionDecision* value.
 *   That entry could never match anything and was pure noise in a security
 *   allowlist, which is the worst place for noise.
 *
 *   `acceptedits` and `plan` are in the shipped JSON schema but the runtime
 *   never emits them: `hook_permission_mode()` maps `AskForApproval::Never` to
 *   `bypassPermissions` and every other policy to `default`, full stop. Keeping
 *   them was harmless only for as long as they stayed unreachable — and if
 *   `acceptEdits` ever does become reachable it means "stop asking about
 *   edits", which is the opposite of what this set is asserting about it.
 *
 *   `''` — no mode — was read as "a human is there". `permission_mode` is a
 *   *required* field on Codex's payloads, so its absence means the payload is
 *   not a shape this adapter has verified, which is precisely the case the
 *   allowlist exists to make strict. Copilot's missing mode taught this lesson
 *   once already, in `wasAttended`.
 *
 * What is left is the one live discriminator: `default` versus
 * `bypassPermissions`. And `default` is a weaker signal than it reads as —
 * see {@link canPromptAHuman}.
 */
const PROMPTS_A_HUMAN = new Set(['default']);

/**
 * Can abstaining still reach a person?
 *
 * "Can", not "will", and the gap is real enough to write down. `default` is
 * derived from the approval policy alone and ignores the sandbox, so it covers
 * `-a on-request` (where the *model* decides when to ask) and `-a granular`
 * (which can auto-reject rather than prompt). Most calls under `on-request`
 * with a workspace-write sandbox never reach an approval prompt at all.
 *
 * So abstaining in `default` does not create a prompt. It preserves whatever
 * Codex would have done, which is sometimes nothing.
 *
 * That is why {@link resolve} checks the floor BEFORE it consults this. For an
 * action that is merely unfamiliar, preserving Codex's own flow is right, and
 * denying everything unrecognised in the ordinary interactive mode would block
 * most of a normal session. For a floored one — a credential, exfiltration,
 * persistence, privilege — "sometimes nothing" is not good enough, and since a
 * hook cannot manufacture a prompt on Codex in any mode, the only two honest
 * answers are deny or let it happen.
 *
 * So this predicate no longer decides whether a floor is enforced. It decides
 * what happens to the rest.
 */
export function canPromptAHuman(mode: string | undefined): boolean {
  return PROMPTS_A_HUMAN.has(String(mode ?? '').toLowerCase());
}

/** Events this adapter answers. */
export function isCodexEvent(name: string): boolean {
  return /^(PreToolUse|PermissionRequest|PostToolUse)$/i.test(String(name));
}

/**
 * Is this payload from Codex rather than Claude Code?
 *
 * Both agents send `PreToolUse` and `PostToolUse` with the same field names, so
 * the event alone cannot route. The installer writes `--agent codex` into the
 * hook command and that is the signal used in practice; this exists so a
 * hand-edited `hooks.json` that lost the flag still lands in the right handler
 * instead of emitting a response shape Codex rejects.
 */
export function looksLikeCodex(input: CodexInput): boolean {
  // `PermissionRequest` is the one unambiguous signal: no other agent has that
  // event.
  //
  // Everything weaker has been removed. `dontAsk` was used here on the belief
  // that it was Codex-only; it is a documented Claude Code permission mode too,
  // so it routed Claude Code payloads into this adapter and silenced an `ask`
  // that Claude Code would have honoured. `turn_id` and `model` were no better:
  // both are plausible additions to any agent's payload, and guessing wrong in
  // that direction turns a working prompt into silence.
  //
  // Being wrong in the other direction is cheap by comparison — a Codex payload
  // that reaches the Claude Code renderer gets an `ask` that Codex rejects, and
  // Codex logs "PreToolUse Failed" loudly. Loud and wrong beats quiet and
  // wrong, so the sniff is now deliberately narrow and the installer's
  // `--agent codex` is the real mechanism.
  return /^PermissionRequest$/i.test(String(input.hook_event_name ?? ''));
}

/** The result of reading a Codex payload into something the engine can judge. */
export interface Translation {
  /** False when this adapter could not faithfully read the call. */
  ok: boolean;
  /** The tool input as the engine's vocabulary spells it. */
  input: Record<string, unknown>;
  /**
   * Where the command will actually run.
   *
   * Distinct from the session `cwd`: `workdir` changes where every relative
   * path in the command lands, but it does not change which project this is.
   * Only set when the payload named one.
   */
  execCwd?: string;
  /** Why not, when `ok` is false. Shown to the user in the deny reason. */
  why?: string;
}

/** Tool kinds whose call is meaningless without a command we can read. */
function isShellTool(tool: string): boolean {
  return /^(Bash|shell)$/i.test(tool);
}

/** Tool kinds whose call is meaningless without a path we can read. */
function isPatchTool(tool: string): boolean {
  return /^(Edit|Write)$/i.test(tool);
}

/**
 * Read one Codex payload, or say that it could not be read.
 *
 * The distinction is the whole point. An earlier version returned `{}` for
 * anything it did not recognise, and `{}` is not "unknown", it is "a call with
 * no arguments" — which the engine judges as a fully-understood no-op:
 * capability `meta`, nil blast, no guards, no floor. That was fixed for a
 * `tool_input` that was *itself* the wrong type, and left wide open for the
 * case that actually occurs: a well-formed object whose `command` is not a
 * string.
 *
 * So the rule is now positional rather than structural. For a shell tool the
 * command must be readable *as a command*; for a patch tool a target path must
 * be readable *as a path*. A payload that satisfies neither is untranslatable,
 * and the caller fails strict. Nothing is forwarded on the assumption that
 * whatever a key holds must be a string, because that assumption is exactly
 * what `String(["sudo","rm","-rf","/var"])` exploits.
 *
 * @param tool the tool name already normalised by {@link toolNameOf}.
 */
export function translate(input: CodexInput, tool: string): Translation {
  const envelope = envelopeOf(input, tool);
  if (!envelope) return { ok: false, input: {}, why: 'unrecognised argument shape' };

  const out: Record<string, unknown> = { ...envelope };
  const result: Translation = { ok: true, input: out };

  // --- workdir --------------------------------------------------------------
  //
  // A documented parameter of Codex's shell tool, and the one field whose loss
  // silently rewrites the meaning of the command: with `workdir` outside the
  // project, `echo x > out.txt` is a write outside the project, not a write to
  // the project root. Dropped, it produced capability `fs.write.workspace`, no
  // floor, and — worse — the *same* signature as the benign in-project form, so
  // a dozen approvals of the harmless twin promoted the escape to `allow`.
  //
  // It is an implicit `cd` in front of the command, so it is handled the way
  // the engine already handles `cd`: it moves where relative paths resolve, and
  // it does not move which project we are in.
  if ('workdir' in out) {
    const wd = out['workdir'];
    delete out['workdir'];
    if (typeof wd === 'string' && wd.trim()) result.execCwd = absoluteWorkdir(wd, input.cwd);
    else if (wd !== undefined && wd !== null) {
      return { ok: false, input: {}, why: 'workdir is present but not a path' };
    }
  }

  // --- with_escalated_permissions ------------------------------------------
  //
  // Codex's own flag for "run this outside the sandbox". The engine already
  // models exactly that under Claude Code's spelling: it joins the signature
  // and is never learnable, so training on the sandboxed form cannot cover the
  // unsandboxed one. Translating the name means one profile covers both agents
  // rather than the flag being invisible on one of them.
  if (out['with_escalated_permissions'] === true) {
    delete out['with_escalated_permissions'];
    out['dangerouslyDisableSandbox'] = true;
  }

  // --- the command ----------------------------------------------------------
  if (isShellTool(tool)) {
    const command = commandOf(out);
    if (command === undefined) {
      return { ok: false, input: {}, why: 'no readable command in a shell call' };
    }
    delete out['input'];
    out['command'] = command;
    return result;
  }

  // --- the patch target -----------------------------------------------------
  if (isPatchTool(tool)) {
    if (patchTargetPath(out)) return result;
    return { ok: false, input: {}, why: 'no target path found' };
  }

  return result;
}

/**
 * A `workdir` as somewhere the engine can resolve paths against.
 *
 * Two spellings have to be handled before it is usable as a base directory. A
 * relative `workdir` is relative to the session directory, and resolving it
 * against this hook process's own cwd instead would place every path in the
 * command somewhere arbitrary. A leading `~` is expanded because the engine
 * expands it in every path argument, and a base directory that behaved
 * differently from the arguments resolved against it would be its own trap.
 */
function absoluteWorkdir(workdir: string, sessionCwd: string | undefined): string {
  let wd = workdir;
  if (wd === '~' || wd.startsWith('~/') || wd.startsWith('~\\')) {
    const rest = wd.slice(1).replace(/^[\\/]+/, '');
    const home = os.homedir().replace(/[\\/]+$/, '');
    wd = rest ? home + path.sep + rest : home;
  }
  if (path.isAbsolute(wd)) return wd;
  return sessionCwd ? path.resolve(sessionCwd, wd) : wd;
}

/**
 * The outer shape: get to an object, or fail.
 *
 * The top-level forms (a bare argv array, a bare command string, a JSON string)
 * are kept because they were observed and are cheap to accept. The object form
 * is the normal one.
 */
function envelopeOf(input: CodexInput, tool: string): Record<string, unknown> | undefined {
  const raw = input.tool_input;

  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw as Record<string, unknown>;

  if (Array.isArray(raw)) {
    const argv = quoteArgv(raw);
    return argv === undefined ? undefined : { command: argv };
  }

  if (typeof raw === 'string') {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      /* not JSON */
    }
    // A bare string on a shell tool is the command itself.
    if (isShellTool(tool)) return { command: raw };
    return undefined;
  }

  // No arguments at all. Legitimate for a tool that takes none; caught below
  // for the tools where it cannot be.
  if (raw === undefined || raw === null) return {};

  return undefined;
}

/**
 * The command a shell call will run, as one shell string, or undefined.
 *
 * `command` is the shell tool's key and `input` is unified exec's; both carry
 * either a string or an argv array. Anything else — a number, an object, an
 * array with a non-string in it, or nothing at all — is not a command this
 * adapter can claim to have read, and saying so is the whole point of the
 * function. `String(value)` is deliberately never called.
 */
function commandOf(obj: Record<string, unknown>): string | undefined {
  for (const key of ['command', 'input']) {
    if (!(key in obj)) continue;
    const v = obj[key];
    if (typeof v === 'string') return v;
    if (Array.isArray(v)) return quoteArgv(v);
    return undefined;
  }
  return undefined;
}

/**
 * An argv array as one shell string that parses back to the same command.
 *
 * Each element is re-quoted rather than joined with spaces. A plain join is
 * lossy in the direction that matters: `["bash","-lc","cat ~/.ssh/id_rsa"]`
 * becomes `bash -lc cat ~/.ssh/id_rsa`, where the payload has fallen out of the
 * `-c` argument and become positional noise. The parser then sees a different,
 * harmless command — two distinct actions collapsing onto one signature, which
 * SECURITY.md names as a vulnerability in its own right.
 *
 * An array holding anything other than strings is not an argv, so it comes back
 * undefined rather than being coerced.
 */
function quoteArgv(argv: unknown[]): string | undefined {
  if (!argv.length) return undefined;
  if (!argv.every((p) => typeof p === 'string')) return undefined;
  return (argv as string[]).map(quoteArg).join(' ');
}

/**
 * One argv element as a shell word, so the reconstruction parses back to the
 * same command. Single quotes: no expansion happens inside them, and an
 * embedded quote is closed, escaped and reopened.
 */
function quoteArg(arg: string): string {
  if (arg !== '' && !/[^A-Za-z0-9_@%+=:,./-]/.test(arg)) return arg;
  return `'${arg.split("'").join(`'\\''`)}'`;
}

/**
 * The path a patch will write to, and where the engine will look for it.
 *
 * Codex calls the patch tool `apply_patch` and carries the edit in its own
 * shape. Renaming it to `Edit` without moving the payload produced an `Edit`
 * with zero targets — so every path-keyed floor (credentials, outside the
 * project, persistence) had nothing to match against, and a patch writing
 * anywhere at all came back floorless.
 *
 * Two shapes are read. A payload that already names the file in a key the
 * engine knows is used as-is. Otherwise a `*** Begin Patch` envelope is scanned
 * for the file it touches — and *only* if it names exactly one, because the
 * engine judges a structured edit against a single target and picking one of
 * several would be the same "confident answer about something it did not see"
 * this whole file is guarding against. A multi-file patch stays untranslatable
 * and fails strict.
 *
 * Mutates: sets `file_path` when it recovered one from an envelope, because
 * `file_path` is the key the engine reads.
 */
function patchTargetPath(toolInput: Record<string, unknown>): boolean {
  for (const key of ['file_path', 'path', 'filePath', 'target_file', 'filename', 'notebook_path']) {
    if (typeof toolInput[key] === 'string' && toolInput[key]) return true;
  }

  const files = new Set<string>();
  for (const v of Object.values(toolInput)) {
    if (typeof v !== 'string' || !/^\*\*\* /m.test(v)) continue;
    for (const m of v.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)) {
      files.add(m[1]!.trim());
    }
    // `*** Move to:` renames the file the preceding Update named, so the
    // destination is written to as well and has to count as a target.
    for (const m of v.matchAll(/^\*\*\* Move to: (.+)$/gm)) files.add(m[1]!.trim());
  }
  if (files.size !== 1) return false;
  toolInput['file_path'] = [...files][0]!;
  return true;
}

/**
 * Codex names the patch tool `apply_patch`; the engine's knowledge and the
 * learned signatures are written against Claude Code's names. Translating here
 * means one profile covers both agents instead of the same edit being a
 * stranger depending on which editor was open.
 */
export function toolNameOf(name: string | undefined): string {
  const raw = String(name ?? 'unknown');
  if (/^apply_patch$/i.test(raw)) return 'Edit';
  if (/^shell$/i.test(raw)) return 'Bash';
  return raw;
}

/** What we will actually tell Codex. */
export type CodexAction =
  | { kind: 'allow' }
  | { kind: 'deny'; message: string }
  | { kind: 'abstain'; why: string };

/** The two Codex events that carry a verdict, which do not accept the same ones. */
export type CodexVerdictEvent = 'PreToolUse' | 'PermissionRequest';

/**
 * Turn a LeastGrant verdict into something Codex can express.
 *
 * Pure, and exported, because this is the part worth testing exhaustively:
 * every combination of verdict, floor, permission mode and event has one right
 * answer and getting one of them wrong is a silent hole.
 *
 * `event` is a parameter because the two events do not accept the same
 * vocabulary. `PermissionRequest` takes allow and deny. `PreToolUse` takes only
 * deny: measured against 0.152.0, `permissionDecision:"allow"` with no
 * `updatedInput` is rejected as unsupported, the run is marked Failed, the
 * error is shown, and the call proceeds — so every LeastGrant allow was being
 * reported to the user as a hook failure. An abstain has the identical effect
 * on the call and does not lie about having decided something.
 */
export function resolve(
  outcome: PreOutcome,
  mode: string | undefined,
  event: CodexVerdictEvent = 'PermissionRequest',
): CodexAction {
  if (outcome.decision === 'allow') {
    return event === 'PreToolUse'
      ? { kind: 'abstain', why: 'allow: PreToolUse cannot express it, so standing aside' }
      : { kind: 'allow' };
  }
  if (outcome.decision === 'deny') return { kind: 'deny', message: outcome.headline };

  // decision === 'ask', which Codex cannot express.
  //
  // The floor is checked BEFORE the mode, and the order is the whole point.
  //
  // It used to be the other way round, so `default` short-circuited to abstain
  // and a credential read in an ordinary interactive session was never gated at
  // all. The reasoning for abstaining there — that denying everything
  // unfamiliar would block most of a normal session — is right, and it is an
  // argument about *unfamiliar*, not about *floored*. This branch only ever
  // fires on the floored set: credential reads, piping the network into a
  // shell, sudo, writes to LeastGrant's own state. Denying those does not block
  // a normal session, because a normal session does not do them.
  //
  // And `default` cannot be relied on to prompt. It is derived from the
  // approval policy alone, so it covers `-a on-request`, where the model
  // decides whether to ask, and `-a granular`, which can auto-reject without
  // ever showing anything. A hook cannot manufacture a prompt on Codex in any
  // mode, so for the floored set the choice is deny or let it happen.
  //
  // Same trade the Cursor adapter already makes on `beforeReadFile`: blocking
  // is recoverable — add a rule and move on — and reading the credential is not.
  if (outcome.floor && !onlyBecauseUnreadable(outcome)) {
    return {
      kind: 'deny',
      message:
        `${outcome.headline} LeastGrant would have asked, but Codex cannot prompt ` +
        `for one in any mode (this is ${String(mode)}), so it is blocked instead. ` +
        `To permit it, add a rule: leastgrant allow "<pattern>" --force`,
    };
  }
  if (canPromptAHuman(mode)) {
    return { kind: 'abstain', why: 'ask: deferring to whatever Codex would have done' };
  }
  return {
    kind: 'abstain',
    why: outcome.floor
      ? `ask in ${String(mode)}: not understood, but nothing known-dangerous — not gated`
      : `ask with no floor in ${String(mode)}: not gated, no human to ask`,
  };
}

/**
 * Was the only thing wrong that LeastGrant could not read the command?
 *
 * This is the line between "I know this is dangerous" and "I do not know what
 * this is", and in a mode with no prompt they deserve opposite answers.
 *
 * Measured on the shipped classifier, roughly half of real commands are marked
 * not-understood — `node --version`, `make test`, `./deploy.sh`, anything with
 * an inline script or a program the knowledge modules have no opinion about.
 * Escalating all of that to deny would block most of a `codex exec` run, and a
 * gate that blocks most of your work is a gate people remove. The result would
 * be less protection, not more.
 *
 * So ignorance abstains and knowledge blocks. A credential read, exfiltration,
 * persistence, privilege escalation, running just-downloaded code, an
 * irreversible delete, or a write outside the project is still denied, because
 * for those the harm *is* letting them through. `python -c '<anything>'` gets
 * through, and that is a real hole — but it is the same hole the user already
 * has by running an unattended mode at all, so LeastGrant is not making it
 * worse. It is stated in the README rather than hidden here.
 *
 * The `guard.` filter matters: a verdict carrying no guard at all is one the
 * engine could not evaluate (`engine.error`), and that must escalate rather
 * than slip through this exemption.
 */
function onlyBecauseUnreadable(outcome: PreOutcome): boolean {
  const guards = outcome.reasons.filter((r) => r.startsWith('guard.'));
  return guards.length > 0 && guards.every((r) => r === 'guard.not-understood');
}

/**
 * Render for `PreToolUse`, which uses Claude Code's field names but accepts
 * only one of its values.
 *
 * `deny` or nothing. An `allow` never reaches here — `resolve` turns it into an
 * abstain for this event — and the assertion is kept rather than typed away
 * because emitting one is not a cosmetic mistake: 0.152.0 rejects it as an
 * unsupported value, marks the run Failed and shows the user an error for what
 * was meant to be an approval.
 */
function renderPreToolUse(action: CodexAction): string | null {
  if (action.kind !== 'deny') return null;
  const out = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `LeastGrant: ${action.message}`,
    },
  };
  return JSON.stringify(out);
}

/** Render for `PermissionRequest`, which uses Codex's own decision object. */
function renderPermissionRequest(action: CodexAction): string | null {
  if (action.kind === 'abstain') return null;
  const out = {
    hookSpecificOutput: {
      hookEventName: 'PermissionRequest',
      decision:
        action.kind === 'allow'
          ? { behavior: 'allow' }
          : { behavior: 'deny', message: `LeastGrant: ${action.message}` },
    },
  };
  return JSON.stringify(out);
}

/**
 * A stable id for one tool call.
 *
 * Codex supplies `tool_use_id` on `PreToolUse` but not on `PermissionRequest`,
 * and the learning path needs a Pre and its Post to agree on one. Falling back
 * to the turn keeps them paired within a turn, which is the granularity Codex
 * gives us.
 */
function callId(input: CodexInput): string {
  return String(input.tool_use_id ?? input.turn_id ?? '');
}

export function runCodexHook(raw: unknown): void {
  const input = (raw ?? {}) as CodexInput;
  const event = String(input.hook_event_name ?? '');

  if (/^PostToolUse$/i.test(event)) {
    recordPost(String(input.session_id ?? 'unknown'), callId(input));
    return;
  }

  const isPre = /^PreToolUse$/i.test(event);
  const isPermission = /^PermissionRequest$/i.test(event);
  if (!isPre && !isPermission) {
    if (event) logLine(`codex: unhandled hook event ${event}`);
    return;
  }

  const tool = toolNameOf(input.tool_name);
  const translation = translate(input, tool);

  // Could this call be translated faithfully into something the engine can
  // judge? If not, no verdict about it means anything.
  //
  // It fails for an argument shape this adapter does not recognise, for a shell
  // call whose command is not readable as a command, and for a patch whose
  // target path is not readable as a path. All of them used to sail through as
  // a confident, floorless, fully-understood verdict — the worst possible
  // answer, because it is indistinguishable from "checked and fine".
  if (!translation.ok) {
    logLine(
      `codex: could not translate ${String(input.tool_name)} faithfully (${String(translation.why)})`,
    );
    if (!canPromptAHuman(input.permission_mode)) {
      const body =
        isPre
          ? renderPreToolUse({
              kind: 'deny',
              message:
                `LeastGrant could not read this ${String(input.tool_name)} call well enough to ` +
                `judge it, and this Codex mode cannot prompt, so it is blocked rather than ` +
                `assumed safe.`,
            })
          : renderPermissionRequest({
              kind: 'deny',
              message: `LeastGrant could not read this ${String(input.tool_name)} call well enough to judge it.`,
            });
      if (body) process.stdout.write(body);
      return;
    }
    // A human can be asked, so let Codex ask them.
    return;
  }

  const outcome = judgePre({
    agent: 'codex',
    cwd: input.cwd ?? '',
    ...(translation.execCwd ? { execCwd: translation.execCwd } : {}),
    tool,
    input: translation.input,
    sessionId: String(input.session_id ?? 'unknown'),
    toolUseId: callId(input),
    permissionMode: input.permission_mode,
    // Nothing LeastGrant says on Codex ever reaches a person.
    //
    // `evidenceFor` banks a completed `ask` as `confirmed` — the strongest
    // evidence class, and the only one that promotes a signature — on the
    // reasoning that a human saw our prompt and clicked allow. On Codex there
    // is no prompt to click: an `ask` is an abstain here, and
    // `permission_mode: "default"` does not mean a human was consulted, since
    // it is derived from the approval policy alone and covers `-a on-request`
    // (where the *model* decides whether to ask) and `-a granular` (which can
    // auto-reject without showing anything).
    //
    // PostToolUse compounds it: Codex fires it only when the call SUCCEEDED, so
    // the evidence stream is not even a record of what was attempted. Banking
    // `confirmed` off that is the tool manufacturing its own strongest
    // evidence, and the escalation is concrete — a promoted signature makes
    // LeastGrant answer `allow` on PermissionRequest, actively cancelling a
    // prompt Codex was about to show.
    //
    // The cost, stated rather than hidden: Codex learns by observation only,
    // and observation cannot promote anything that leaves the workspace.
    attended: false,
  });

  // `observe` posture: watch, say nothing.
  if (outcome.silent) return;

  const action = resolve(outcome, input.permission_mode, isPre ? 'PreToolUse' : 'PermissionRequest');

  // An abstain is a real outcome, not a failure, but it is also the one that
  // leaves an action ungated. Logging it means "LeastGrant let that through"
  // is discoverable in `leastgrant trail` rather than being invisible.
  if (action.kind === 'abstain') {
    logLine(`codex: ${action.why} — ${outcome.headline}`);
    return;
  }

  const body = isPre ? renderPreToolUse(action) : renderPermissionRequest(action);
  if (body) process.stdout.write(body);
}

/**
 * A one-line summary for `leastgrant doctor`.
 *
 * The gap this reports is not a bug to be fixed later; it is what the agent
 * supports. Somebody deciding whether to rely on this needs it in front of
 * them, not in a changelog.
 */
export function codexCaveat(mode: string | undefined): string {
  const shared =
    'Codex enforces only deny, and only on PreToolUse — an allow there is rejected as ' +
    'unsupported and the call proceeds, so LeastGrant stands aside instead. An allow is ' +
    'honoured on PermissionRequest, which fires only when Codex was already going to prompt.';
  return canPromptAHuman(mode)
    ? `${shared} In ${String(mode)}, an ask defers to whatever Codex’s own approval policy ` +
        'would have done — which, under -a on-request or -a granular, may be nothing.'
    : `${shared} In ${String(mode)} nothing can prompt you, so an ask becomes deny at a floor ` +
        'and is ungated otherwise.';
}
