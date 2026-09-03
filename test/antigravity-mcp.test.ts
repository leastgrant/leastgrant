/**
 * MCP on Antigravity arrives as one tool carrying the real one inside it.
 *
 * Captured live: `call_mcp_tool` with `{ServerName, ToolName, Arguments,
 * toolAction, toolSummary}`. Nothing about that shape was guessed.
 *
 * Left unmapped it is an opaque call, which the engine refuses to account for,
 * so every MCP call came back `force_ask` — an unsuppressible prompt, forever,
 * for `list-clients` as much as for `browser_evaluate`. Safe and unusable, and
 * a permission layer people turn off enforces nothing.
 *
 * The adapter now rebuilds the engine's own `mcp__server__tool` spelling, which
 * puts these calls under machinery that already exists: tiering by tool name,
 * the argument-aware signature, and the secret guards on MCP arguments. The
 * tests below are mostly about the ways that could go wrong — an identity
 * invented from half a name, a loosening that outruns what other agents get,
 * and a secret argument slipping through because the call now looks ordinary.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { toolNameOf, translateArgs } from '../src/adapters/antigravity/hook.js';

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
before(() => {
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-agmcp-'));
});
after(() => fs.rmSync(HOME, { recursive: true, force: true }));

/** The live payload shape, with the MCP call swapped in. */
let mcpSeq = 0;
const payload = (args: Record<string, unknown>) => ({
  // A fresh conversation each time. The control below must not inherit the
  // taint the attack above deposits — a session that just read a credential
  // makes every later outbound call force_ask, which is correct behaviour and
  // would make the control prove nothing.
  conversationId: `c-mcp-${mcpSeq++}`,
  workspacePaths: ['D:/proj'],
  transcriptPath: 'D:/proj/t.jsonl',
  artifactDirectoryPath: 'D:/proj/a',
  modelName: 'gemini-3.8-flash-high',
  stepIdx: 4,
  toolCall: { name: 'call_mcp_tool', args },
});

function hook(body: unknown) {
  const r = spawnSync(process.execPath, [CLI, 'hook', '--agent', 'antigravity', '--event', 'pre'], {
    input: JSON.stringify(body),
    encoding: 'utf8',
    env: { ...process.env, LEASTGRANT_HOME: path.join(HOME, '.leastgrant'), HOME, USERPROFILE: HOME },
    timeout: 30_000,
  });
  const out = (r.stdout ?? '').trim();
  let json: Record<string, unknown> | null = null;
  try {
    json = out ? (JSON.parse(out) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { out, exit: r.status, decision: json?.['decision'] as string | undefined, reason: String(json?.['reason'] ?? '') };
}

describe('MCP calls through Antigravity', () => {
  test('a named MCP call becomes the identity the engine already understands', () => {
    const args = { ServerName: 'roblox-mcp', ToolName: 'list-clients', Arguments: {}, toolAction: 'x', toolSummary: 'y' };
    assert.equal(toolNameOf('call_mcp_tool', args), 'mcp__roblox_mcp__list_clients');
    // Hyphens normalise, because `mcp__a__b` splits on underscores and a name
    // that fails to split reads as one opaque token again.
    assert.equal(
      toolNameOf('call_mcp_tool', { ServerName: 'a-b', ToolName: 'c-d' }),
      'mcp__a_b__c_d',
    );
  });

  test('the inner arguments become the arguments, and the narration is dropped', () => {
    const args = {
      ServerName: 'vault',
      ToolName: 'get_secret',
      Arguments: { name: 'db-password' },
      toolAction: 'Fetching a secret',
      toolSummary: 'Get secret',
    };
    assert.deepEqual(translateArgs('call_mcp_tool', args), { name: 'db-password' });
  });

  test('half a name never becomes a whole identity', () => {
    // The failure worth preventing: inventing a plausible identity for a call
    // we cannot actually name, which would make an unaccountable action
    // learnable. It must stay opaque — and keep its full payload, because
    // handing the opaque branch an empty argument object would make an
    // unaccountable call look like a trivial one.
    for (const args of [
      { ServerName: '', ToolName: 'list', Arguments: { a: 1 } },
      { ServerName: 'srv', ToolName: '', Arguments: { a: 1 } },
      { ServerName: 'srv', Arguments: { a: 1 } },
      { ServerName: 5, ToolName: 7, Arguments: { a: 1 } },
      { ServerName: '---', ToolName: '???', Arguments: { a: 1 } },
    ] as Record<string, unknown>[]) {
      assert.equal(toolNameOf('call_mcp_tool', args), 'call_mcp_tool', JSON.stringify(args));
      assert.deepEqual(translateArgs('call_mcp_tool', args), args, JSON.stringify(args));
    }
  });

  test('unparseable arguments stay opaque rather than becoming empty', () => {
    const args = { ServerName: 'srv', ToolName: 'tool', Arguments: 'not json {' };
    assert.equal(toolNameOf('call_mcp_tool', args), 'mcp__srv__tool');
    // The identity resolved, so the payload is unwrapped — and an unparseable
    // string is not an object, so the whole args object is kept. What must not
    // happen is a silent `{}`, which would sign as "this call takes no
    // arguments".
    assert.notDeepEqual(translateArgs('call_mcp_tool', args), {});
  });

  test('a secret in an MCP argument still floors, through the real binary', () => {
    const v = hook(
      payload({
        ServerName: 'files',
        ToolName: 'get_file',
        Arguments: { path: '~/.ssh/id_rsa' },
        toolAction: 'x',
        toolSummary: 'y',
      }),
    );
    assert.equal(v.exit, 0);
    assert.equal(v.decision, 'force_ask', `a credential-bearing MCP call came back ${v.decision}: ${v.out}`);

    // A READ-shaped MCP tool on both sides, deliberately. The first version of
    // this used shell/run, which the engine rightly treats as high blast — so the
    // control floored too and the pair could not isolate what was being tested.
    // A control that fails for its own good reasons is not a control.
    const ok = hook(
      payload({ ServerName: 'files', ToolName: 'get_file', Arguments: { path: 'D:/proj/README.md' }, toolAction: 'x', toolSummary: 'y' }),
    );
    assert.notEqual(
      ok.decision,
      'force_ask',
      `the same MCP tool on an ordinary file is also force_ask (${ok.reason}), so the secret result proves nothing`,
    );
  });

  test('an unnameable MCP call is still not waved through', () => {
    // The loosening must not extend to calls we cannot name.
    const v = hook(payload({ ServerName: '', ToolName: '', Arguments: { command: 'rm -rf /' } }));
    assert.equal(v.exit, 0);
    assert.ok(v.out.length > 0, 'printed nothing, which the host reads as allow');
    assert.ok(
      v.decision === 'force_ask' || v.decision === 'deny',
      `an unnameable MCP call came back ${v.decision}`,
    );
  });

  test('nothing about non-MCP tools changed', () => {
    // `toolNameOf` grew a second parameter; this is the guard that the first
    // one still behaves exactly as it did.
    assert.equal(toolNameOf('run_command', { CommandLine: 'ls' }), 'Bash');
    assert.equal(toolNameOf('view_file', { AbsolutePath: '/x' }), 'Read');
    assert.equal(toolNameOf('not_a_tool', {}), 'not_a_tool');
    assert.deepEqual(translateArgs('run_command', { CommandLine: 'ls' }), { command: 'ls' });
  });
});
