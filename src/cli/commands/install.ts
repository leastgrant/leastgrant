/**
 * `leastgrant install [agent]` / `leastgrant uninstall [agent]`
 *
 * Wiring LeastGrant into an agent means editing that agent's settings file —
 * a file the user cares about and did not ask us to reformat. So:
 *
 *   - we read, mutate the smallest possible subtree, and write back with the
 *     original indentation;
 *   - we copy the file to <name>.leastgrant-backup first, at the same
 *     permissions, because an agent settings file can hold API keys. It is one
 *     backup, not a timestamped series: a second install overwrites it, which
 *     is the right trade for a file that may carry credentials;
 *   - we are idempotent, so running it twice is not a bug;
 *   - we never remove a hook we did not add.
 *
 * If any of that fails we say so and change nothing.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { c, para, sym } from '../ui.js';
import type { Argv } from '../index.js';

export type AgentTarget = 'claude-code' | 'cursor' | 'copilot' | 'codex' | 'antigravity';

interface Installed {
  agent: AgentTarget;
  scope: 'user' | 'project';
  file: string;
  changed: boolean;
  note?: string;
}

/**
 * The command an agent will run to reach LeastGrant.
 *
 * It must contain no double quote at all, and that is a stronger rule than it
 * looks. Antigravity spawns the handler as `exec.CommandContext("cmd", "/c",
 * <command>)` — three separate arguments — so Go's `EscapeArg` rewrites any
 * embedded `"` as `\"`, which `cmd` does not unescape. The handler then fails
 * to start, and since a failing PreToolUse hook fails CLOSED on that runtime,
 * every tool call is blocked and the user's only remedy is to remove
 * LeastGrant.
 *
 * That is not a corner case. The default `npm i -g` location is
 * `%APPDATA%
pm
ode_modules\...`, and any Windows account whose name
 * contains a space puts a space in that path. The live verification was done
 * from a space-free directory, so this had never been exercised.
 *
 * So both tokens get the 8.3 short form, not just the first. If either cannot
 * be made quote-free, `install` refuses rather than writing a command that
 * cannot run — a refusal a user can act on beats an install that reports
 * success and blocks everything.
 */
function selfCommand(): string {
  return `${nodeInvocation()} ${scriptToken(selfBin())} hook`;
}

/**
 * The script path as a token safe to embed.
 *
 * Same reasoning as `nodeInvocation`, applied to the second token: on Windows
 * the 8.3 short form when the volume has one, and otherwise a quoted path,
 * which `assertRunnable` then rejects for the agents that cannot survive it.
 */
function scriptToken(p: string): string {
  if (!/[\s$`"']/.test(p)) return p;
  if (process.platform === 'win32') {
    const short = shortPath(p);
    if (short && !/[\s$`"']/.test(short)) return short;
  }
  return shellQuote(p);
}

/**
 * Refuse to write a command the agent cannot start.
 *
 * Only for the agents whose runtime escapes per argument — Antigravity is the
 * one measured. The others take the command line verbatim or run it through a
 * shell that unquotes properly, and quoting there is not merely safe but
 * required.
 */
function assertRunnable(command: string, agent: AgentTarget): void {
  if (agent !== 'antigravity' || !command.includes('"')) return;
  throw new Error(
    `LeastGrant cannot be installed into ${agent} from this location.
` +
      `  The path contains a character that has to be quoted:
    ${selfBin()}
` +
      `  Antigravity runs hook commands as cmd /c with per-argument escaping, which turns an
` +
      `  embedded quote into \\" and stops the handler starting. A handler that cannot start
` +
      `  blocks every tool call on that agent.
` +
      `  Install LeastGrant somewhere without spaces or shell characters in the path, or
` +
      `  enable 8.3 short names on that volume.`,
  );
}

/** dist/src/cli/commands/install.js -> ../../../../bin/leastgrant.js */
function selfBin(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..', '..', '..', '..', 'bin', 'leastgrant.js');
}

/**
 * How to name the Node executable so that no shell can misparse it.
 *
 * Agents run hook commands through a shell, and on Windows that shell is
 * PowerShell — Codex and Copilot both do. PowerShell reads a statement that
 * begins with a *quoted* string as a string expression rather than a command:
 *
 *     "C:\Program Files\nodejs\node.exe" hook.js
 *     → Unexpected token 'hook.js' in expression or statement.
 *
 * Since the default Windows install of Node lives in `C:\Program Files\nodejs`,
 * quoting is unavoidable, so the hook never started. The two agents then failed
 * in opposite directions and both were wrong: Codex failed open and enforced
 * nothing, Copilot failed closed and blocked everything.
 *
 * Only the *first* token has this problem — later arguments may be quoted
 * freely. So the fix is to make the first token a space-free absolute path.
 * On Windows that is the 8.3 short form when the volume has one; everywhere
 * else the path is already fine, or gets quoted and the agent's shell is POSIX.
 */
function nodeInvocation(): string {
  const exe = process.execPath;
  if (!/[\s$`"']/.test(exe)) return exe;

  // An absolute path with no shell-special characters, found by asking the
  // filesystem rather than the PATH.
  //
  // The first attempt here resolved `node` on PATH and, if it was the same
  // binary, wrote the bare word `node` into the hook command. That was a
  // serious mistake: the hook then names a *program to be looked up* rather
  // than a file, and the lookup happens later, in the agent's environment, at
  // every tool call. A `node.exe` or `node.cmd` dropped in the working
  // directory or anywhere earlier on PATH would then be executed as the
  // permission layer itself — a repository could hand itself approval for
  // everything by shipping a file.
  //
  // So: never a bare name. On Windows the 8.3 short form gives a space-free
  // absolute path when the volume has short names, and it is the same file by
  // construction rather than by lookup.
  if (process.platform === 'win32') {
    const short = shortPath(exe);
    if (short && !/[\s$`"']/.test(short)) return short;
  }
  return shellQuote(exe);
}

/**
 * The 8.3 short form of a path, or null.
 *
 * Short names can be disabled per volume, so this is an optimisation rather
 * than a guarantee; the caller falls back to quoting.
 */
function shortPath(full: string): string | null {
  // The target goes through the environment rather than the command line, so
  // nothing about the path can be read as PowerShell syntax.
  const r = spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      '(New-Object -ComObject Scripting.FileSystemObject).GetFile([string]$env:LG_TARGET).ShortPath',
    ],
    { encoding: 'utf8', windowsHide: true, env: { ...process.env, LG_TARGET: full } },
  );

  const out = (r.stdout ?? '').trim();
  if (!out || !fs.existsSync(out)) return null;

  // It is the same file by construction — the short name was derived from this
  // exact path — but confirm rather than assume. `realpath` is no use here:
  // Node does not expand 8.3, so the two spellings never compare equal as
  // strings even when they are one file.
  try {
    const a = fs.statSync(out);
    const b = fs.statSync(full);
    if (a.size !== b.size || a.mtimeMs !== b.mtimeMs) return null;
  } catch {
    return null;
  }
  return out;
}

/**
 * Quote a path for the shell that will run it.
 *
 * `JSON.stringify` looks like it does this and does not: it escapes
 * backslashes, so `C:\Program Files\nodejs\node.exe` comes out as
 * `"C:\\Program Files\\nodejs\\node.exe"`. Windows happens to collapse the
 * doubled separators, so that has always worked — but it works by accident,
 * it is confusing to anyone reading their own config file, and it would break
 * on any runner that passes the string to a shell which treats a backslash as
 * an escape.
 *
 * A Windows path cannot contain `"`, so wrapping is enough there. A POSIX path
 * can contain almost anything, so single-quote it and close-escape-reopen
 * around any embedded quote.
 */
function shellQuote(s: string): string {
  if (process.platform === 'win32') {
    return /[\s&|<>^()]/.test(s) ? `"${s.replace(/"/g, '')}"` : s;
  }
  return /[^A-Za-z0-9_@%+=:,./-]/.test(s) ? `'${s.split("'").join(`'\\''`)}'` : s;
}

/**
 * The same command, written for PowerShell.
 *
 * Codex runs hook commands through PowerShell on Windows, and PowerShell reads
 * a statement that begins with a quoted string as a *string expression*, not a
 * command:
 *
 *     "C:\Program Files\nodejs\node.exe" script.js
 *     → Unexpected token 'script.js' in expression or statement.
 *
 * Since the default Node install lives in `C:\Program Files\nodejs`, the path
 * always needs quoting, so the hook always failed to start — and a hook that
 * fails to start fails open. It was found by running a real Codex session and
 * watching it print "PreToolUse Failed" and then run the command anyway.
 *
 * The call operator `&` is what makes PowerShell execute rather than evaluate.
 * Single quotes because PowerShell does not interpolate inside them, so a `$`
 * in a path cannot become a variable; a literal quote is escaped by doubling.
 */
function powershellQuote(s: string): string {
  return `'${s.split("'").join("''")}'`;
}

/**
 * How we recognise our own hook entries.
 *
 * It used to be the bare substring `leastgrant`, matched with `.includes()`
 * against the whole command string. That is not an identity: a third-party
 * hook whose command merely mentions the word — `node ~/leastgrant-notify.js`,
 * or anything under a directory called `leastgrant` — was treated as ours.
 * Install would overwrite it and then decline to add our own entry; uninstall
 * would delete it. The module's own header promises "we never remove a hook we
 * did not add", and it was removing other people's hooks.
 *
 * The marker is now the specific thing we write and nothing else: our entry
 * point followed by the `hook` subcommand.
 */
const MARKER = /(^|[\\/"'\s])(bin[\\/])?leastgrant\.js["']?\s+hook(\s|$)/i;

/** Is this a hook entry LeastGrant installed? */
function isOurs(command: string | undefined): boolean {
  return MARKER.test(String(command ?? ''));
}

export async function installCommand(argv: Argv): Promise<number> {
  const uninstall = argv.command === 'uninstall';
  const which = (argv.positional[0] as AgentTarget | undefined) ?? 'claude-code';
  const scope: 'user' | 'project' = argv.flags['project'] ? 'project' : 'user';

  if (
    which !== 'claude-code' &&
    which !== 'cursor' &&
    which !== 'copilot' &&
    which !== 'codex' &&
    which !== 'antigravity'
  ) {
    process.stderr.write(
      `\n  ${c.red('Unknown agent')} ${which}\n  ${c.gray('Supported: claude-code, cursor, copilot, codex, antigravity')}\n\n`,
    );
    return 2;
  }

  let result: Installed;
  try {
    result =
      which === 'cursor'
        ? cursor(scope, uninstall)
        : which === 'copilot'
          ? copilot(scope, uninstall)
          : which === 'codex'
            ? codex(scope, uninstall)
            : which === 'antigravity'
              ? antigravity(scope, uninstall)
              : claudeCode(scope, uninstall);
  } catch (err) {
    process.stderr.write(`\n  ${c.red('Could not update the settings file.')} ${(err as Error).message}\n\n`);
    return 1;
  }

  if (argv.flags['json']) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return 0;
  }

  const out: string[] = [''];
  if (!result.changed) {
    out.push(`  ${c.gray(sym.bullet)} ${uninstall ? 'Nothing to remove' : 'Already installed'} for ${c.bold(result.agent)} (${result.scope}).`);
    out.push(c.gray(`    ${result.file}`));
  } else {
    out.push(`  ${c.green(sym.allow)} ${uninstall ? 'Removed from' : 'Installed into'} ${c.bold(result.agent)} (${result.scope}).`);
    out.push(c.gray(`    ${result.file}`));
    if (!uninstall) {
      out.push('');
      out.push(para(c.gray('Restart your agent for this to take effect. New sessions will route every tool call through LeastGrant.'), 4));
    }
  }
  if (result.note) {
    out.push('');
    out.push(para(c.yellow(result.note), 4));
  }
  out.push('');
  process.stdout.write(out.join('\n'));
  return 0;
}

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

interface HookEntry {
  type?: string;
  command?: string;
  timeout?: number;
}
interface HookMatcher {
  matcher?: string;
  hooks?: HookEntry[];
}
interface ClaudeSettings {
  hooks?: Record<string, HookMatcher[]>;
  [k: string]: unknown;
}

export function claudeSettingsPath(scope: 'user' | 'project', cwd = process.cwd()): string {
  const base = process.env['CLAUDE_CONFIG_DIR']
    ? path.resolve(process.env['CLAUDE_CONFIG_DIR'])
    : path.join(os.homedir(), '.claude');
  return scope === 'user'
    ? path.join(base, 'settings.json')
    : path.join(cwd, '.claude', 'settings.json');
}

/**
 * We register on both PreToolUse and PostToolUse.
 *
 * PreToolUse is the decision. PostToolUse is how LeastGrant finds out that a
 * call it asked about actually ran — which is the only way it can tell "the
 * human approved this" from "the mode approved this". Without the second hook
 * the tool still protects you, but it never learns, and the whole premise is
 * that it should get quieter over time.
 *
 * The matcher is "*": Claude Code treats a matcher containing characters
 * outside [A-Za-z0-9_\- ,|] as an unanchored regex, and "*" as "everything".
 */
function claudeCode(scope: 'user' | 'project', uninstall: boolean): Installed {
  const file = claudeSettingsPath(scope);
  const settings = readJson<ClaudeSettings>(file) ?? {};
  const command = selfCommand();

  settings.hooks ??= {};
  let changed = false;

  for (const event of ['PreToolUse', 'PostToolUse']) {
    const list = (settings.hooks[event] ??= []);
    const ours = (m: HookMatcher) => (m.hooks ?? []).some((h) => isOurs(h.command));

    if (uninstall) {
      const before = list.length;
      // Remove only the individual hook entries we recognise, then drop a
      // matcher block only if it is left empty. Someone else's hook on the
      // same matcher must survive.
      for (const m of list) {
        if (!m.hooks) continue;
        const kept = m.hooks.filter((h) => !isOurs(h.command));
        if (kept.length !== m.hooks.length) changed = true;
        m.hooks = kept;
      }
      settings.hooks[event] = list.filter((m) => (m.hooks ?? []).length > 0);
      if (settings.hooks[event]!.length !== before) changed = true;
      if (settings.hooks[event]!.length === 0) delete settings.hooks[event];
      continue;
    }

    if (list.some(ours)) {
      // Present already — but refresh it if the command has gone stale.
      //
      // Idempotent used to mean "leave it alone", which quietly broke anyone
      // who moved their checkout or changed Node version: the hook still
      // pointed at a path that no longer existed, the agent could not run it,
      // and a hook that fails to start fails open. Reinstalling is the obvious
      // thing to try and it did nothing.
      for (const m of list) {
        for (const h of m.hooks ?? []) {
          if (isOurs(h.command) && h.command !== command) {
            h.command = command;
            changed = true;
          }
        }
      }
      continue;
    }
    list.push({
      matcher: '*',
      hooks: [{ type: 'command', command, timeout: 10 }],
    });
    changed = true;
  }

  if (uninstall && Object.keys(settings.hooks).length === 0) delete settings.hooks;

  if (changed) writeJsonPreservingStyle(file, settings);

  const result: Installed = { agent: 'claude-code', scope, file, changed };
  if (!uninstall) {
    // Worth saying out loud: a hook `deny` is absolute, but a hook `allow` is
    // not — the user's own deny/ask rules still win. People should know which
    // half of the promise is which.
    result.note =
      'A LeastGrant block is final, even in bypass mode. A LeastGrant approval is not: your own deny and ask rules in settings.json still take precedence.';
  }
  return result;
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

interface CursorHook {
  command: string;
  /** Refuse the tool call if the hook cannot answer. See `cursor()`. */
  failClosed?: boolean;
  /** Which tool classes a generic step applies to. `preToolUse` only. */
  matcher?: string;
  [k: string]: unknown;
}

interface CursorHooks {
  version?: number;
  hooks?: Record<string, CursorHook[]>;
  [k: string]: unknown;
}

/**
 * Cursor's hook contract is close enough to Claude Code's to share a decision
 * engine, but only `beforeShellExecution` and `beforeMCPExecution` honour all
 * three of allow/deny/ask — the generic `preToolUse` cannot ask. So we register
 * on the specific events where our answer is actually respected, and on the
 * matching `after*` events, which are what lets a Cursor session learn.
 *
 * The handler lives in `src/adapters/cursor/hook.ts`. It shares `judgePre` and
 * `recordPost` with the Claude adapter, so both agents reach the same verdict
 * for the same command — there is a test that asserts exactly that.
 */
function cursor(scope: 'user' | 'project', uninstall: boolean): Installed {
  const file =
    scope === 'user'
      ? path.join(os.homedir(), '.cursor', 'hooks.json')
      : path.join(process.cwd(), '.cursor', 'hooks.json');

  const cfg = readJson<CursorHooks>(file) ?? { version: 1, hooks: {} };
  const hooks: Record<string, CursorHook[]> = (cfg.hooks ??= {});
  const command = selfCommand().replace(/ hook$/, ' hook --agent cursor');
  let changed = false;

  /**
   * `failClosed` asks Cursor to refuse the tool call if this hook cannot
   * answer, rather than running it.
   *
   * Cursor has supported it per-script for some time and LeastGrant was writing
   * bare `{command}` entries, which take the default: on a crash, a timeout, or
   * a node that will not start, the call proceeds unchecked. That is the one
   * failure mode a permission layer cannot shrug at, because it is silent and
   * it is exactly when something is already wrong.
   *
   * It is not free. If LeastGrant is broken, Cursor stops working rather than
   * merely stopping being protected, and the fix is to remove the hook. That is
   * the right way round for a tool whose whole claim is that it gates things,
   * and it matches Copilot, where the same choice is made for us.
   *
   * Only on the `before*` events. On an `after*` event the command has already
   * run, so there is no longer anything to refuse — failing closed there would
   * reject the *result* of work that already happened, which protects nothing
   * and turns a broken hook into corrupted output.
   */
  const GATES = new Set(['preToolUse', 'beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile']);

  /**
   * The generic gate, scoped to the surfaces the specialised hooks cannot cover.
   *
   * Without it Cursor was a read-only integration: writes and deletes reached no
   * hook at all — measured, zero invocations — and reads arrived at
   * `beforeReadFile` with the file already loaded, so a deny suppressed the
   * content without preventing the read.
   *
   * `preToolUse` fixes both. Verified against 3.18.25: `Write` arrives with
   * `{file_path, content}` and a deny stops the write; `Delete` arrives with
   * `{file_path}` and a deny stops the delete; `Read` arrives with `{file_path}`
   * and NO content, and denying it means `beforeReadFile` never fires — the
   * bytes are never read.
   *
   * The matcher is not decoration. Shell and MCP keep their specialised hooks
   * because those have a real `ask` that reaches a person, and `preToolUse`'s
   * `ask` does not — it is accepted, merged, and the action proceeds silently.
   * Routing Shell through here as well would place a silent-allow surface
   * beside a prompting one on the same call. Verified to scope: a shell command
   * fires `beforeShellExecution` and does not fire this.
   */
  const MATCHERS: Record<string, string> = {
    // Wider than the three names Cursor was observed sending, deliberately.
    //
    // A live edit produced `Read` and `Write` only — Cursor surfaced its
    // StrReplace as a `Write` — but the model visibly reached for a second edit
    // tool by another name when the first was refused. A matcher that misses a
    // rename does not fail loudly; it silently stops covering a tool class,
    // which is the failure mode this integration already had for writes.
    //
    // Every name here is a file operation. Shell and MCP are deliberately
    // absent and must stay absent: they have a real `ask` that reaches a
    // person, and `preToolUse`'s `ask` is a silent allow, so routing them
    // through here as well would put a silent-allow surface beside a prompting
    // one on the same call. `test/cursor-pretooluse.test.ts` asserts both
    // halves of that.
    // Anchored, and every name in it verified to map to a FILE kind in the
    // engine before being added.
    //
    // Two mistakes are baked into this list as scar tissue. The first version
    // was unanchored, so `Write` also matched `TodoWrite` — inert, allowed
    // anyway, but a process spawn on every todo update. The second included
    // `Move` and `Rename` on the reasoning that they sound like file
    // operations; both map to `unknown`, which FLOORS, so if Cursor ever sent
    // one LeastGrant would have refused it outright. That is the same
    // "recognised or refused" trap that `Delete` fell into, added speculatively
    // an hour after being warned about. They are out until there is both an
    // engine mapping and an observation.
    //
    // Cursor's bundle carries TWO tool namespaces — PascalCase (`Read`,
    // `Write`, `Delete`) and snake_case (`read_file`, `delete_file`,
    // `search_replace`) — and an anchored matcher that covers one and not the
    // other is not partially effective, it is absent. Only PascalCase was
    // observed live; the snake_case names are covered defensively.
    //
    // Shell and MCP stay out. They have a real `ask` that reaches a person and
    // this surface silently allows one. Anchoring is what keeps
    // `WriteShellStdin` out despite starting with `Write`.
    preToolUse:
      '^(Read|Write|Delete|Edit|MultiEdit|ApplyPatch|StrReplace|SearchReplace|CreateFile|DeleteFile' +
      '|read_file|write_file|delete_file|edit_file|search_replace)$',
  };

  for (const event of [
    'preToolUse',
    'beforeShellExecution',
    'beforeMCPExecution',
    'beforeReadFile',
    // The `after*` pair is how evidence is recorded. Without them Cursor would
    // be gated but would never learn, so it would ask about the same command
    // forever.
    'afterShellExecution',
    'afterMCPExecution',
  ]) {
    const entry: CursorHook = GATES.has(event) ? { command, failClosed: true } : { command };
    if (MATCHERS[event]) entry.matcher = MATCHERS[event];
    const list: CursorHook[] = (hooks[event] ??= []);
    const idx = list.findIndex((h) => isOurs(h.command));
    if (uninstall) {
      if (idx >= 0) {
        list.splice(idx, 1);
        changed = true;
      }
      if (list.length === 0) delete hooks[event];
    } else if (idx < 0) {
      list.push({ ...entry });
      changed = true;
    } else {
      // Bring an existing entry up to date, not just its path.
      //
      // This only refreshed `command`, so anyone who installed before
      // `failClosed` existed kept a fail-open entry forever, silently, while
      // compatibility/cursor.json told them Cursor refuses on a hook failure.
      // Re-running the installer did not fix it and reported "already
      // installed". An upgrade path that cannot deliver a security setting is
      // not an upgrade path.
      const want = { ...entry };
      const have = list[idx]!;
      // A matcher that has drifted is as bad as a missing one: narrowed, it
      // silently stops covering a tool class; widened, it starts shadowing
      // Shell. Reconciled like everything else, so an upgrade delivers it.
      const stale =
        have.command !== want.command ||
        Boolean(have.failClosed) !== Boolean(want.failClosed) ||
        (want.matcher ?? '') !== (have.matcher ?? '');
      if (stale) {
        // `want` last, and the matcher deleted when we no longer want one, so a
        // stale matcher cannot survive by merge.
        const merged: CursorHook = { ...have, ...want };
        if (!want.matcher) delete merged.matcher;
        list[idx] = merged;
        changed = true;
      }
    }
  }

  if (changed) writeJsonPreservingStyle(file, cfg);
  return {
    agent: 'cursor',
    scope,
    file,
    changed,
    note: uninstall
      ? undefined
      : 'Cursor now covers shell, MCP, reads, writes and deletes. Shell and MCP can raise a real prompt; reads, writes and deletes cannot, so on those a floored action is refused outright and an unfamiliar one is allowed — LeastGrant will not pretend a human was consulted when the host has no way to consult one. The generic preToolUse gate stops a credential read before the file is opened.',
  } as Installed;
}

// ---------------------------------------------------------------------------
// Codex CLI
// ---------------------------------------------------------------------------

/**
 * Codex reads `~/.codex/hooks.json`, or `<project>/.codex/hooks.json` for a
 * project scope. The event names are Claude Code's, but the handler must know
 * it is talking to Codex — Codex rejects `ask` and then runs the call anyway —
 * so the command carries `--agent codex`.
 *
 * `PermissionRequest` is registered as well as `PreToolUse`. It fires only when
 * Codex was already going to prompt, which is exactly where suppressing a
 * prompt for something familiar is worth the most.
 */
function codex(scope: 'user' | 'project', uninstall: boolean): Installed {
  const dir = scope === 'user' ? path.join(os.homedir(), '.codex') : path.join(process.cwd(), '.codex');
  const file = path.join(dir, 'hooks.json');
  const command = `${selfCommand()} --agent codex`;

  // On Windows, also write the PowerShell form. Codex runs hook commands
  // through PowerShell, where the plain form does not execute at all.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const bin = path.resolve(here, '..', '..', '..', '..', 'bin', 'leastgrant.js');
  const commandWindows =
    process.platform === 'win32'
      ? `& ${powershellQuote(process.execPath)} ${powershellQuote(bin)} hook --agent codex`
      : undefined;
  const entry = (): CodexEntry =>
    commandWindows
      ? { type: 'command', command, commandWindows }
      : { type: 'command', command };

  interface CodexEntry {
    type?: string;
    command?: string;
    /**
     * Codex's own Windows override. It exists precisely because the two
     * platforms need different command strings, and here they do: PowerShell
     * needs the call operator.
     */
    commandWindows?: string;
  }
  interface CodexGroup {
    matcher?: string;
    hooks?: CodexEntry[];
  }
  interface CodexHooks {
    hooks?: Record<string, CodexGroup[]>;
  }

  const cfg = (readJson<CodexHooks>(file) ?? {}) as CodexHooks;
  const hooks: Record<string, CodexGroup[]> = (cfg.hooks ??= {});
  let changed = false;

  for (const event of ['PreToolUse', 'PermissionRequest', 'PostToolUse']) {
    const groups: CodexGroup[] = (hooks[event] ??= []);
    let found = false;
    for (const group of groups) {
      const list: CodexEntry[] = group.hooks ?? [];
      const idx = list.findIndex((h) => isOurs(h.command));
      if (idx >= 0) {
        found = true;
        if (uninstall) {
          list.splice(idx, 1);
          changed = true;
        } else if (list[idx]!.command !== command || list[idx]!.commandWindows !== commandWindows) {
          // Refresh a stale path rather than leaving a hook that cannot start.
          // The Windows form counts: an install from before it existed left a
          // hook PowerShell silently refused to run.
          list[idx]! = entry();
          changed = true;
        }
      }
    }
    if (uninstall) {
      const kept = groups.filter((g: CodexGroup) => (g.hooks ?? []).length > 0);
      if (kept.length === 0) delete hooks[event];
      else hooks[event] = kept;
    } else if (!found) {
      groups.push({ matcher: '*', hooks: [entry()] });
      changed = true;
    }
  }

  if (changed) {
    fs.mkdirSync(dir, { recursive: true });
    writeJsonPreservingStyle(file, cfg);
  }

  return {
    agent: 'codex',
    scope,
    file,
    changed,
    note: uninstall
      ? undefined
      : 'Codex has no "ask": it rejects that decision and runs the call anyway. So allow and deny ' +
        'are enforced, and an ask defers to Codex’s own approval prompt. In dontAsk or ' +
        'bypassPermissions nothing can prompt you, and there an ask becomes a deny at a floor ' +
        '(credentials, exfiltration, persistence, unreadable code) and is left ungated otherwise. ' +
        'Codex also requires you to trust a hook before it runs: open Codex and run /hooks. ' +
        'Written against codex-cli 0.152.0 and unit-tested, but not yet verified against a live install.',
  } as Installed;
}

// ---------------------------------------------------------------------------
// GitHub Copilot CLI
// ---------------------------------------------------------------------------

/**
 * Copilot CLI reads Claude-format hook definitions, including the PascalCase
 * event names, so the same handler works. It looks in `~/.copilot/hooks/` and
 * `<project>/.github/hooks/`.
 */
function copilot(scope: 'user' | 'project', uninstall: boolean): Installed {
  const dir =
    scope === 'user'
      ? path.join(os.homedir(), '.copilot', 'hooks')
      : path.join(process.cwd(), '.github', 'hooks');
  const file = path.join(dir, 'leastgrant.json');

  if (uninstall) {
    const existed = fs.existsSync(file);
    if (existed) fs.unlinkSync(file);
    return { agent: 'copilot', scope, file, changed: existed };
  }

  // `--agent copilot` only changes attribution. Copilot speaks Claude Code's
  // wire format — snake_case fields in, `hookSpecificOutput` out, and it
  // honours all three verdicts — so the Claude handler renders for it
  // correctly. Without the flag though, every Copilot call was recorded in the
  // ledger as `claude-code`, so `leastgrant trail` credited one agent's
  // behaviour to another.
  const command = `${selfCommand()} --agent copilot`;
  const body = {
    hooks: {
      PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command }] }],
      PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command }] }],
    },
  };
  const next = JSON.stringify(body, null, 2) + '\n';
  const prev = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  if (prev === next) return { agent: 'copilot', scope, file, changed: false };

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, next, 'utf8');
  return { agent: 'copilot', scope, file, changed: true };
}

// ---------------------------------------------------------------------------

function readJson<T>(file: string): T | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'ENOENT') return null;
    // A settings file we cannot parse is one we must not overwrite.
    throw new Error(
      `${file} could not be read as JSON (${e.message}). LeastGrant has not changed it — fix the file and try again.`,
    );
  }

  // Valid JSON is not the same as a settings file.
  //
  // A top-level array, or a string, or `true`, parses fine and then every
  // property assignment against it either vanishes or lands somewhere useless.
  // The installer went on to report "✓ Installed" and exit 0 having written
  // nothing — the worst outcome available, because the user now believes they
  // are protected. Anything that is not a plain object is refused out loud.
  if (parsed === null) return null;
  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(
      `${file} is ${Array.isArray(parsed) ? 'a JSON array' : `a JSON ${typeof parsed}`}, not a settings object. ` +
        `LeastGrant has not changed it — fix the file and try again.`,
    );
  }
  return parsed as T;
}

/**
 * Write JSON back, matching the file's existing indentation so the diff is only
 * the lines we meant to change.
 */
function writeJsonPreservingStyle(file: string, value: unknown): void {
  let indent: string | number = 2;
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const m = /\n(\s+)"/.exec(raw);
    if (m?.[1]) indent = m[1].includes('\t') ? '\t' : m[1].length;
    // Back up whatever was there before we touch it, with the same permissions.
    //
    // An agent settings file can hold API keys in its env block — LeastGrant's
    // own secret rules say so, which is why `~/.claude/settings.json` is a
    // credential path to the classifier. Writing a copy of one at default
    // permissions creates a second, more readable copy of the user's keys that
    // they did not ask for and will not think to clean up.
    const backup = `${file}.leastgrant-backup`;
    fs.writeFileSync(backup, raw, 'utf8');
    try {
      fs.chmodSync(backup, fs.statSync(file).mode & 0o777);
    } catch {
      // Windows, or a filesystem with no modes to copy. The write still stands.
    }
  } catch {
    /* no existing file: nothing to preserve or back up */
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, indent) + '\n', 'utf8');
  fs.renameSync(tmp, file);
}

/** Is the Claude Code hook currently installed? Used by `doctor` and `init`. */
export function isClaudeInstalled(scope: 'user' | 'project'): boolean {
  const settings = (() => {
    try {
      return JSON.parse(fs.readFileSync(claudeSettingsPath(scope), 'utf8')) as ClaudeSettings;
    } catch {
      return null;
    }
  })();
  const pre = settings?.hooks?.['PreToolUse'] ?? [];
  return pre.some((m) => (m.hooks ?? []).some((h) => isOurs(h.command)));
}

/**
 * Antigravity's hook config.
 *
 * `~/.gemini/config/hooks.json` globally, or `<repo>/.agents/hooks.json` for a
 * workspace. The top level is a map of hook NAME to spec, and the event keys
 * are the exact-cased Go field names — `PreToolUse`, not `preToolUse`.
 *
 * The command is run through `cmd /c` on Windows with the working directory set
 * to the directory containing hooks.json, so the first token has the same
 * quoting problem Codex and Copilot had and gets the same answer: a space-free
 * absolute path via `nodeInvocation()`.
 *
 * A timeout is written explicitly. The default is 30 seconds and a hook that
 * overruns it is a failed hook, which fails open — 10 matches what the other
 * adapters ask for and leaves a wide margin over a p95 of about 100ms.
 */
function antigravity(scope: 'user' | 'project', uninstall: boolean): Installed {
  const dir =
    scope === 'user'
      ? path.join(os.homedir(), '.gemini', 'config')
      : path.join(process.cwd(), '.agents');
  const file = path.join(dir, 'hooks.json');
  // The event has to be written into the command, because the payload cannot
  // say which one it is: `PreToolHookArgs` and `PostToolHookArgs` both carry
  // `tool_call` and `step_idx`, so a shape test reads every PostToolUse as a
  // PreToolUse. That silently stopped `recordPost` from ever running, which
  // meant nothing on this agent ever became familiar. Labelling our own
  // handlers is the fix; nothing about it depends on the payload.
  const commandFor = (event: 'pre' | 'post') => {
    const c = `${selfCommand()} --agent antigravity --event ${event}`;
    assertRunnable(c, 'antigravity');
    return c;
  };

  interface Handler { command?: string; timeout?: number; [k: string]: unknown }
  interface Group { matcher?: string; hooks?: Handler[] }
  interface Spec { enabled?: boolean; PreToolUse?: Group[]; PostToolUse?: Group[]; [k: string]: unknown }

  const cfg = readJson<Record<string, Spec>>(file) ?? {};
  const existing = cfg['leastgrant'];
  // A `leastgrant` value that is not a plain object is not a spec we can add to.
  // `{"leastgrant": []}` used to report a successful install and write nothing:
  // `spec[event] = groups` sets a named property on an Array, which
  // `JSON.stringify` discards. `readJson` refuses a non-object at the top level
  // for exactly this reason — "the user now believes they are protected" — and
  // the same check was missing one level down.
  if (existing !== undefined && (typeof existing !== 'object' || existing === null || Array.isArray(existing))) {
    throw new Error(
      `${file} has a "leastgrant" entry that is ${Array.isArray(existing) ? 'an array' : typeof existing}, ` +
        `not a hook specification. Fix or remove it and try again — LeastGrant will not write ` +
        `over something it did not put there.`,
    );
  }
  const spec: Spec = (existing as Spec | undefined) ?? {};
  let changed = false;

  // A spec-level `enabled: false` switches every handler under it off, silently
  // — it is documented, `JSONHookSpec.Enabled` is a `*bool` where nil means
  // true, and nothing on our side could see it. Reinstalling over one reported
  // "Already installed" and left enforcement entirely off.
  if (!uninstall && spec.enabled !== undefined && spec.enabled !== true) {
    spec.enabled = true;
    changed = true;
  }

  for (const event of ['PreToolUse', 'PostToolUse'] as const) {
    const command = commandFor(event === 'PreToolUse' ? 'pre' : 'post');
    const groups: Group[] = Array.isArray(spec[event]) ? (spec[event] as Group[]) : [];
    if (uninstall) {
      for (const g of groups) {
        if (!g || !Array.isArray(g.hooks)) continue;
        const before = g.hooks.length;
        g.hooks = g.hooks.filter((h) => !isOurs(String(h?.command ?? '')));
        if (g.hooks.length !== before) changed = true;
      }
      const kept = groups.filter((g) => Array.isArray(g?.hooks) && g.hooks.length > 0);
      if (kept.length) spec[event] = kept;
      else delete spec[event];
      continue;
    }

    // Reconcile EVERY entry of ours, in every group — not the first match in
    // the first `*` group. Repairing only the first left three real layouts
    // broken, and one of them is worse than not installing: a handler carrying
    // `--event post` sitting on PreToolUse answers `{}`, which this runtime
    // reads as a hard DENY of every tool call.
    let ours = 0;
    for (const g of groups) {
      if (!g || !Array.isArray(g.hooks)) continue;
      const kept: Handler[] = [];
      for (const h of g.hooks) {
        if (!isOurs(String(h?.command ?? ''))) {
          kept.push(h);
          continue;
        }
        // Ours. The first one becomes canonical wherever it sits; any further
        // copy is a duplicate and goes.
        if (ours++ > 0) {
          changed = true;
          continue;
        }
        if (h.command !== command || h.timeout !== 10 || g.matcher !== '*') changed = true;
        kept.push({ ...h, command, timeout: 10 });
        g.matcher = '*';
      }
      if (kept.length !== g.hooks.length) changed = true;
      g.hooks = kept;
    }

    if (ours === 0) {
      // One group matching every tool. `*` is the documented catch-all and the
      // only honest choice: a matcher listing tool names would silently stop
      // covering whatever Antigravity adds next.
      let group = groups.find((g) => g && g.matcher === '*' && Array.isArray(g.hooks));
      if (!group) {
        group = { matcher: '*', hooks: [] };
        groups.push(group);
      }
      group.hooks ??= [];
      group.hooks.push({ command, timeout: 10 });
      changed = true;
    }

    spec[event] = groups.filter((g) => g && Array.isArray(g.hooks) && g.hooks.length > 0);
  }

  if (uninstall) {
    if (!spec['PreToolUse'] && !spec['PostToolUse']) delete cfg['leastgrant'];
    else cfg['leastgrant'] = spec;
  } else {
    cfg['leastgrant'] = spec;
  }

  if (changed) {
    fs.mkdirSync(dir, { recursive: true });
    writeJsonPreservingStyle(file, cfg);
  }

  return {
    agent: 'antigravity',
    scope,
    file,
    changed,
    note: uninstall
      ? undefined
      : 'Antigravity is the one agent where LeastGrant can insist on a human: a floored ask becomes force_ask, which no cached "Always allow" can satisfy. Deny is enforced in the tool-call converter, so it holds in every mode. Two host-side switches can disable enforcement without telling anyone — the server experiment flag json-hooks-enabled, and auto_interaction_behavior=ALLOW_ALL.',
  } as Installed;
}
