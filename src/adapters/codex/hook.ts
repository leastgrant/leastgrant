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
 * Codex offers exactly two ways to say something other than allow or deny:
 * return nothing (abstain) and let its own approval flow run, or deny. Which
 * one is right depends on whether abstaining can actually reach a human, and
 * the payload tells us — `permission_mode` is one of `default`, `acceptEdits`,
 * `plan`, `dontAsk`, `bypassPermissions`.
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
 * The consequence, stated plainly because it belongs in the open: in `dontAsk`
 * and `bypassPermissions`, LeastGrant on Codex is a veto, not a prompt. It is
 * strictly better than running Codex without it, and strictly weaker than
 * LeastGrant on Claude Code, where an `ask` reaches you in every mode.
 */

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
 */
const PROMPTS_A_HUMAN = new Set(['default', 'acceptedits', 'plan', 'ask', '']);

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

/**
 * Normalise `tool_input`, or say that it could not be normalised.
 *
 * The distinction is the whole point. This used to return `{}` for anything it
 * did not recognise — a string, an array, a primitive — and `{}` is not
 * "unknown", it is "a call with no arguments". The engine dutifully judged that
 * as a fully-understood no-op: capability `meta`, nil blast, no guards, no
 * floor. So a shell command sent as a bare string, or as Codex's argv array,
 * came back floorless and the adapter stood aside. `cat ~/.ssh/id_rsa` sent
 * that way was ungated.
 *
 * An adapter that cannot faithfully translate a call must not produce a
 * confident verdict about it. Now it says so, and the caller fails strict.
 */
function toolInputOf(input: CodexInput): { input: Record<string, unknown>; translated: boolean } {
  const raw = input.tool_input;

  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { input: raw as Record<string, unknown>, translated: true };
  }

  // Codex may send a shell call as an argv array: ["bash","-lc","cat x"].
  //
  // Each element is re-quoted rather than joined with spaces. A plain join is
  // lossy in the direction that matters: ["bash","-lc","cat ~/.ssh/id_rsa"]
  // becomes `bash -lc cat ~/.ssh/id_rsa`, where the payload has fallen out of
  // the -c argument and become positional noise. The parser then sees a
  // different, harmless command — two distinct actions collapsing onto one
  // signature, which SECURITY.md names as a vulnerability in its own right.
  if (Array.isArray(raw) && raw.every((p) => typeof p === 'string')) {
    const command = (raw as string[]).map(quoteArg).join(' ');
    return { input: { command }, translated: true };
  }

  if (typeof raw === 'string') {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { input: parsed as Record<string, unknown>, translated: true };
      }
    } catch {
      /* not JSON */
    }
    // A bare string on a shell tool is the command itself.
    if (/^(Bash|shell)$/i.test(String(input.tool_name ?? ''))) {
      return { input: { command: raw }, translated: true };
    }
  }

  if (raw === undefined || raw === null) return { input: {}, translated: true };

  return { input: {}, translated: false };
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
 * Tools whose arguments name a path, and the keys the engine reads them from.
 *
 * Codex calls the patch tool `apply_patch` and carries the edit in its own
 * shape. Renaming it to `Edit` without moving the payload produced an `Edit`
 * with zero targets — so every path-keyed floor (credentials, outside the
 * project, persistence) had nothing to match against, and a patch writing
 * anywhere at all came back floorless.
 *
 * Rather than guess at a payload shape that is not documented and may change,
 * this reports whether a recognised target could be found. If not, the call is
 * untranslatable and fails strict.
 */
function patchTargetsPresent(toolInput: Record<string, unknown>): boolean {
  for (const key of ['file_path', 'path', 'filePath', 'target_file', 'filename', 'notebook_path']) {
    if (typeof toolInput[key] === 'string' && toolInput[key]) return true;
  }
  return false;
}

/**
 * Codex names the patch tool `apply_patch`; the engine's knowledge and the
 * learned signatures are written against Claude Code's names. Translating here
 * means one profile covers both agents instead of the same edit being a
 * stranger depending on which editor was open.
 */
function toolNameOf(name: string | undefined): string {
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

/**
 * Turn a LeastGrant verdict into something Codex can express.
 *
 * Pure, and exported, because this is the part worth testing exhaustively:
 * every combination of verdict, floor and permission mode has one right answer
 * and getting one of them wrong is a silent hole.
 */
export function resolve(outcome: PreOutcome, mode: string | undefined): CodexAction {
  if (outcome.decision === 'allow') return { kind: 'allow' };
  if (outcome.decision === 'deny') return { kind: 'deny', message: outcome.headline };

  // decision === 'ask', which Codex cannot express.
  if (canPromptAHuman(mode)) {
    return { kind: 'abstain', why: 'ask: deferring to the Codex approval prompt' };
  }
  if (outcome.floor && !onlyBecauseUnreadable(outcome)) {
    return {
      kind: 'deny',
      message:
        `${outcome.headline} LeastGrant would have asked, but this Codex mode ` +
        `(${String(mode)}) cannot prompt, so it is blocked instead. To permit it, add a ` +
        `rule: leastgrant allow "<pattern>" --force`,
    };
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

/** Render for `PreToolUse`, which uses Claude Code's field names. */
function renderPreToolUse(action: CodexAction): string | null {
  if (action.kind === 'abstain') return null;
  const out = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: action.kind,
      ...(action.kind === 'deny' ? { permissionDecisionReason: `LeastGrant: ${action.message}` } : {}),
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
  const { input: toolInput, translated } = toolInputOf(input);

  // Could this call be translated faithfully into something the engine can
  // judge? If not, no verdict about it means anything.
  //
  // Two ways it fails: an argument shape this adapter does not recognise, and
  // a patch whose target path is somewhere the engine will not find. Both used
  // to sail through as a confident, floorless, fully-understood verdict — the
  // worst possible answer, because it is indistinguishable from "checked and
  // fine".
  const untranslatable =
    !translated || (/^(Edit|Write)$/.test(tool) && !patchTargetsPresent(toolInput));

  if (untranslatable) {
    logLine(
      `codex: could not translate ${String(input.tool_name)} faithfully ` +
        `(${translated ? 'no target path found' : 'unrecognised argument shape'})`,
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
    tool,
    input: toolInput,
    sessionId: String(input.session_id ?? 'unknown'),
    toolUseId: callId(input),
    permissionMode: input.permission_mode,
  });

  // `observe` posture: watch, say nothing.
  if (outcome.silent) return;

  const action = resolve(outcome, input.permission_mode);

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
  return canPromptAHuman(mode)
    ? 'Codex: allow and deny are enforced; ask defers to Codex’s own approval prompt.'
    : `Codex in ${String(mode)}: nothing can prompt you, so ask becomes deny at a floor and ` +
        'is ungated otherwise.';
}
