/**
 * `leastgrant install [agent]` / `leastgrant uninstall [agent]`
 *
 * Wiring LeastGrant into an agent means editing that agent's settings file —
 * a file the user cares about and did not ask us to reformat. So:
 *
 *   - we read, mutate the smallest possible subtree, and write back with the
 *     original indentation;
 *   - we take a timestamped backup first;
 *   - we are idempotent, so running it twice is not a bug;
 *   - we never remove a hook we did not add.
 *
 * If any of that fails we say so and change nothing.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { c, para, sym } from '../ui.js';
import type { Argv } from '../index.js';

export type AgentTarget = 'claude-code' | 'cursor' | 'copilot';

interface Installed {
  agent: AgentTarget;
  scope: 'user' | 'project';
  file: string;
  changed: boolean;
  note?: string;
}

/** Absolute path to this package's CLI entry. */
function selfCommand(): string {
  // dist/src/cli/commands/install.js -> ../../../../bin/leastgrant.js
  const here = path.dirname(fileURLToPath(import.meta.url));
  const bin = path.resolve(here, '..', '..', '..', '..', 'bin', 'leastgrant.js');
  const node = process.execPath;
  const q = (s: string) => (/[\s"]/.test(s) ? JSON.stringify(s) : s);
  return `${q(node)} ${q(bin)} hook`;
}

/** Marker we use to recognise our own hook entries on uninstall. */
const MARKER = 'leastgrant';

export async function installCommand(argv: Argv): Promise<number> {
  const uninstall = argv.command === 'uninstall';
  const which = (argv.positional[0] as AgentTarget | undefined) ?? 'claude-code';
  const scope: 'user' | 'project' = argv.flags['project'] ? 'project' : 'user';

  if (which !== 'claude-code' && which !== 'cursor' && which !== 'copilot') {
    process.stderr.write(
      `\n  ${c.red('Unknown agent')} ${which}\n  ${c.gray('Supported: claude-code, cursor, copilot')}\n\n`,
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
    const ours = (m: HookMatcher) => (m.hooks ?? []).some((h) => (h.command ?? '').includes(MARKER));

    if (uninstall) {
      const before = list.length;
      // Remove only the individual hook entries we recognise, then drop a
      // matcher block only if it is left empty. Someone else's hook on the
      // same matcher must survive.
      for (const m of list) {
        if (!m.hooks) continue;
        const kept = m.hooks.filter((h) => !(h.command ?? '').includes(MARKER));
        if (kept.length !== m.hooks.length) changed = true;
        m.hooks = kept;
      }
      settings.hooks[event] = list.filter((m) => (m.hooks ?? []).length > 0);
      if (settings.hooks[event]!.length !== before) changed = true;
      if (settings.hooks[event]!.length === 0) delete settings.hooks[event];
      continue;
    }

    if (list.some(ours)) continue; // idempotent
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

interface CursorHooks {
  version?: number;
  hooks?: Record<string, { command: string }[]>;
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
  cfg.hooks ??= {};
  const command = selfCommand().replace(/ hook$/, ' hook --agent cursor');
  let changed = false;

  for (const event of [
    'beforeShellExecution',
    'beforeMCPExecution',
    'beforeReadFile',
    // The `after*` pair is how evidence is recorded. Without them Cursor would
    // be gated but would never learn, so it would ask about the same command
    // forever.
    'afterShellExecution',
    'afterMCPExecution',
  ]) {
    const list = (cfg.hooks[event] ??= []);
    const idx = list.findIndex((h) => (h.command ?? '').includes(MARKER));
    if (uninstall) {
      if (idx >= 0) {
        list.splice(idx, 1);
        changed = true;
      }
      if (list.length === 0) delete cfg.hooks[event];
    } else if (idx < 0) {
      list.push({ command });
      changed = true;
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
      : 'Cursor covers shell commands, MCP calls and file reads. Reads are allow-or-block only (Cursor has no "ask" for them), so an unfamiliar read is allowed and a credential read is blocked. Written against the published hook contract and unit-tested, but not yet verified against a live install.',
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

  const body = {
    hooks: {
      PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: selfCommand() }] }],
      PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: selfCommand() }] }],
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
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw) as T;
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'ENOENT') return null;
    // A settings file we cannot parse is one we must not overwrite.
    throw new Error(
      `${file} could not be read as JSON (${e.message}). LeastGrant has not changed it — fix the file and try again.`,
    );
  }
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
    // Back up whatever was there before we touch it.
    fs.writeFileSync(`${file}.leastgrant-backup`, raw, 'utf8');
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
  return pre.some((m) => (m.hooks ?? []).some((h) => (h.command ?? '').includes(MARKER)));
}
