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

/**
 * Somewhere that is outside the workspace on every platform.
 *
 * This was `C:/Users/Public/lg-evil.txt`, which is absolute on Windows and
 * RELATIVE everywhere else — so on Linux and macOS it resolved inside the
 * workspace and the "outside the project" assertion tested the opposite of what
 * it claimed. It passed on the machine it was written on and failed on CI.
 */
const OUTSIDE = path.join(os.tmpdir(), 'lg-outside-the-project.txt');

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
      ['Write', { file_path: OUTSIDE, content: 'x' }],
      ['Delete', { file_path: path.join(WS, 'package.json') }],
    ];
    for (const [tool, input] of cases) {
      const r = pre(tool, input);
      assert.equal(r.permission, 'deny', `${tool} ${JSON.stringify(input)} came back ${r.permission}`);
    }
  });

  test('an ordinary read or write is not, or the integration would be unusable', () => {
    // The control for the test above, and a real product constraint. Turning
    // every unfamiliar read or write into a hard block would get LeastGrant
    // uninstalled, and an uninstalled permission layer enforces nothing.
    for (const [tool, input] of [
      ['Read', { file_path: path.join(WS, 'src', 'a.ts') }],
      ['Write', { file_path: path.join(WS, 'note.md'), content: 'hi' }],
    ] as [string, Record<string, unknown>][]) {
      const r = pre(tool, input);
      assert.notEqual(r.permission, 'deny', `${tool} on an ordinary project file came back deny`);
    }
  });

  test('a delete is refused here, and that is a deliberate strictness increase', () => {
    // Deletes are the one file operation this surface will not pass. The engine
    // marks every delete `gap.blast` — "more than LeastGrant will ever approve
    // on its own", meaning a person has to decide — and it does the same for a
    // shell `rm`, with the same `hard` reversibility. On Cursor's file surface
    // there is no person to decide, so the faithful translation of "a human
    // must approve this" is a refusal, not a silent allow.
    //
    // This IS a behaviour change and a usability cost: before the generic gate,
    // deletes on Cursor reached no hook at all and simply happened. It is
    // recorded as a change rather than smoothed over, and the agent_message
    // points at the surface that can ask — a terminal `rm` goes through
    // beforeShellExecution, which prompts.
    const r = pre('Delete', { file_path: path.join(WS, 'note.md') });
    assert.equal(r.permission, 'deny', 'an ordinary delete should be refused on this surface');
    assert.match(r.out, /terminal will ask/, 'the refusal does not say what to do instead');
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

  /** The matcher as the installer actually writes it. */
  function installedMatcher(): { pattern: string; names: string[] } {
    const src = fs.readFileSync(path.join(repoRoot(), 'src', 'cli', 'commands', 'install.ts'), 'utf8');
    const at = src.indexOf('preToolUse:');
    assert.ok(at > 0, 'could not find the preToolUse matcher in the installer');
    const m = /'([^']+)'\s*\+\s*'([^']+)'/.exec(src.slice(at));
    assert.ok(m, 'could not parse the matcher literal');
    const pattern = m[1]! + m[2]!;
    return { pattern, names: pattern.replace(/^\^\(/, '').replace(/\)\$$/, '').split('|') };
  }

  test('every name the matcher covers maps to a FILE kind in the engine', () => {
    // The invariant that would have caught the mistake this test was written
    // after. `Move` and `Rename` were added to the matcher because they sound
    // like file operations; both map to `unknown`, which FLOORS — so had
    // Cursor ever sent one, LeastGrant would have refused it outright.
    // Registering a gate for a tool the engine cannot classify does not make
    // it safer, it makes it unusable. Same trap `Delete` fell into, repeated
    // within the hour of writing the comment warning about it.
    const { names } = installedMatcher();
    assert.ok(names.length >= 10, `only ${names.length} names in the matcher`);
    for (const n of names) {
      const kind = normalizeTool(n);
      assert.ok(
        ['read', 'write', 'edit', 'delete'].includes(kind),
        `the matcher covers "${n}", which the engine classifies as "${kind}" — give it a file ` +
          'kind or take it out of the matcher',
      );
    }
  });

  test('the matcher covers both of the tool namespaces in the bundle', () => {
    // Cursor's bundle carries PascalCase and snake_case names for the same
    // operations. Only PascalCase was observed live; an anchored matcher that
    // covers one and not the other is not partially effective, it is absent.
    const re = new RegExp(installedMatcher().pattern);
    for (const t of ['Read', 'Write', 'Delete', 'Edit', 'MultiEdit', 'ApplyPatch', 'StrReplace', 'DeleteFile']) {
      assert.ok(re.test(t), `the matcher does not cover ${t}`);
    }
    for (const t of ['read_file', 'write_file', 'delete_file', 'edit_file', 'search_replace']) {
      assert.ok(re.test(t), `the matcher does not cover the snake_case name ${t}`);
    }
  });

  test('and covers nothing with its own hook, nothing inert, nothing opaque', () => {
    const re = new RegExp(installedMatcher().pattern);
    for (const t of [
      // A real ask of their own; routing them here would weaken them.
      'Shell', 'shell', 'MCP', 'WriteShellStdin', 'FetchMcpResource', 'ListMcpResources',
      // Inert, or not a file operation.
      'TodoWrite', 'Task', 'WebFetch', 'WebSearch', 'ComputerUse', 'RecordScreen',
      // Sound like file operations and classify as `unknown`, which floors.
      'Move', 'Rename', 'List', 'ReadLints',
    ]) {
      assert.ok(!re.test(t), `the matcher covers ${t}`);
    }
  });
});
