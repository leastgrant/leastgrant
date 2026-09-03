/**
 * Cursor's generic gate, and the three things it changed.
 *
 * Until this existed, Cursor was a read-only integration: writes and deletes
 * reached no hook at all — measured, zero invocations — and reads arrived at
 * `beforeReadFile` with the file already loaded, so a deny suppressed the
 * content without preventing the read.
 *
 * `preToolUse` fixes all three. Verified live against 3.18.25:
 *
 *   Write   {file_path, content}  a deny stops the write
 *   Delete  {file_path}           a deny stops the delete
 *   Read    {file_path}, NO content, fired BEFORE the file is opened —
 *           denying it means `beforeReadFile` is never requested at all
 *
 * The last one narrows a limitation this project published for weeks.
 *
 * Three properties here are load-bearing and easy to break by accident:
 *
 *   1. `ask` on this surface is a SILENT ALLOW. Measured: Cursor accepts it,
 *      logs it as a valid response, merges it, and the action proceeds with no
 *      prompt. So an abstract `ask` must never be sent as `ask` here.
 *   2. Shell and MCP must NOT be routed through it. They have a real `ask`;
 *      putting a silent-allow surface beside a prompting one on the same call
 *      would weaken them.
 *   3. The event name collides with Claude Code's `PreToolUse` when case-folded.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { isCursorEvent } from '../src/adapters/cursor/hook.js';
import { normalizeTool } from '../src/core/classify.js';

function repoRoot(from = import.meta.dirname): string {
  let dir = from;
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error('repo root not found');
}
const CLI = path.join(repoRoot(), 'bin', 'leastgrant.js');

let HOME = '';
let WS = '';
before(() => {
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-cpt-home-'));
  WS = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-cpt-ws-'));
  fs.mkdirSync(path.join(WS, '.git'), { recursive: true });
});
after(() => {
  fs.rmSync(HOME, { recursive: true, force: true });
  fs.rmSync(WS, { recursive: true, force: true });
});

let seq = 0;
/** A preToolUse call in the shape Cursor really sends, through the real binary. */
function pre(toolName: string, toolInput: Record<string, unknown>) {
  const body = {
    hook_event_name: 'preToolUse',
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: `t${seq++}`,
    conversation_id: 'c',
    generation_id: 'g',
    cursor_version: '3.18.25',
    cwd: WS,
    workspace_roots: [WS],
  };
  const r = spawnSync(process.execPath, [CLI, 'hook', '--agent', 'cursor'], {
    input: JSON.stringify(body),
    encoding: 'utf8',
    env: { ...process.env, LEASTGRANT_HOME: path.join(HOME, '.leastgrant'), HOME, USERPROFILE: HOME },
    timeout: 120_000,
  });
  const out = (r.stdout ?? '').trim();
  let json: Record<string, unknown> | null = null;
  try {
    json = out ? (JSON.parse(out) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { out, exit: r.status, permission: json?.['permission'] as string | undefined };
}

describe('the generic gate carries the surfaces the specialised hooks cannot', () => {
  test('the event is recognised, and the Claude collision is routed around', () => {
    assert.equal(isCursorEvent('preToolUse'), true);
    assert.equal(isCursorEvent('pretooluse'), true);
    // Case-folded, Cursor's `preToolUse` and Claude Code's `PreToolUse` are one
    // string. The shared switch used to claim it and answer a Cursor call in
    // Claude's wire format — which Cursor discards, so the hook ran and nothing
    // was enforced. Routing keys on `--agent cursor` first; this asserts the
    // answer comes back in CURSOR's shape.
    const r = pre('Read', { file_path: path.join(WS, 'src', 'a.ts') });
    assert.ok(r.out.length > 0, 'no answer at all');
    assert.ok(!r.out.includes('hookSpecificOutput'), `answered in Claude Code's format: ${r.out}`);
    assert.ok(r.permission, `no permission field: ${r.out}`);
  });

  test('a floored action is refused, because this surface cannot ask', () => {
    // The degradation that matters. There is no human-review primitive here, so
    // a floor has to become a refusal — letting it through is the exact harm
    // the floor exists for, and blocking is recoverable.
    const cases: [string, Record<string, unknown>][] = [
      ['Read', { file_path: path.join(WS, '.env') }],
      ['Write', { file_path: path.join(WS, '.cursor', 'hooks.json'), content: '{}' }],
      ['Write', { file_path: 'C:/Users/Public/lg-evil.txt', content: 'x' }],
      ['Delete', { file_path: path.join(WS, 'package.json') }],
    ];
    for (const [tool, input] of cases) {
      const r = pre(tool, input);
      assert.equal(r.permission, 'deny', `${tool} ${JSON.stringify(input)} came back ${r.permission}`);
    }
  });

  test('an ordinary action is not, or the integration would be unusable', () => {
    // The control for the test above, and a real product constraint. Turning
    // every unfamiliar read or write into a hard block would get LeastGrant
    // uninstalled, and an uninstalled permission layer enforces nothing.
    for (const [tool, input] of [
      ['Read', { file_path: path.join(WS, 'src', 'a.ts') }],
      ['Write', { file_path: path.join(WS, 'note.md'), content: 'hi' }],
      ['Delete', { file_path: path.join(WS, 'note.md') }],
    ] as [string, Record<string, unknown>][]) {
      const r = pre(tool, input);
      assert.notEqual(r.permission, 'deny', `${tool} on an ordinary project file came back deny`);
    }
  });

  test('an abstract ask is never sent as `ask` on this surface', () => {
    // Measured: Cursor accepts `ask` here, logs it as valid, merges it — and
    // the action proceeds with no prompt. It is a silent allow wearing the word
    // "ask", so emitting it would be claiming a human was consulted.
    for (const [tool, input] of [
      ['Read', { file_path: path.join(WS, 'src', 'a.ts') }],
      ['Write', { file_path: path.join(WS, 'note.md'), content: 'hi' }],
      ['Read', { file_path: path.join(WS, '.env') }],
    ] as [string, Record<string, unknown>][]) {
      const r = pre(tool, input);
      assert.notEqual(r.permission, 'ask', `${tool} was answered with a verdict this host silently allows`);
      assert.ok(['allow', 'deny'].includes(String(r.permission)), `unexpected permission ${r.permission}`);
    }
  });

  test('a structured Delete is understood rather than merely unknown', () => {
    // Cursor is the first supported agent to expose a delete as a structured
    // tool call. With no kind for it, it fell to `unknown` — which floors — and
    // every delete would have been refused. That is not caution, it is an
    // unusable integration.
    assert.equal(normalizeTool('Delete'), 'delete');
    assert.equal(normalizeTool('DeleteFile'), 'delete');
    // And recognising it did not make it free: see the floored/ordinary pair
    // above, where deleting package.json is refused and deleting note.md is not.
  });

  test('the installed matcher covers every file tool and no execution tool', () => {
    // Read out of the installer rather than restated, so the two cannot drift.
    // An execution tool appearing here would put a silent-allow surface beside
    // Shell's real prompt on the same call.
    const src = fs.readFileSync(path.join(repoRoot(), 'src', 'cli', 'commands', 'install.ts'), 'utf8');
    const m = src.match(/preToolUse:\s*\n?\s*'([^']+)'/);
    assert.ok(m, 'could not find the preToolUse matcher in the installer');
    const re = new RegExp(m[1]!);

    for (const t of ['Read', 'Write', 'Delete', 'Edit', 'MultiEdit', 'ApplyPatch', 'StrReplace', 'DeleteFile']) {
      assert.ok(re.test(t), `the matcher does not cover ${t}`);
    }
    for (const t of ['Shell', 'MCP', 'Task', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'TodoWrite']) {
      assert.ok(!re.test(t), `the matcher covers ${t}, which has its own hook or is inert`);
    }
  });
});
