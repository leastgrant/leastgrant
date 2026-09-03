/**
 * The Antigravity installer, against hooks.json files somebody else wrote.
 *
 * Four findings, all of them silent: the install reported success and
 * enforcement was off, or worse than off.
 *
 *   `enabled: false` on our own spec switched every handler under it off, and
 *   reinstalling over it said "Already installed".
 *
 *   `{"leastgrant": []}` produced "✓ Installed" and wrote zero handlers —
 *   `spec[event] = groups` sets a named property on an Array, which
 *   `JSON.stringify` drops.
 *
 *   Reinstall repaired only the first entry in the first `*` group, so a stale
 *   handler carrying `--event post` could sit on PreToolUse permanently. That
 *   one is worse than not installing: a PostToolUse handler answers `{}`, which
 *   this runtime reads as a hard DENY of every tool call.
 *
 *   A quoted token in the command stops the handler starting at all, and the
 *   default `npm i -g` path contains a space on any Windows account whose name
 *   does. The live verification ran from a space-free directory, so this had
 *   never been exercised.
 *
 * Everything runs against a temp HOME. Nothing here touches a real profile.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

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
let HOOKS = '';

beforeEach(() => {
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-agin-'));
  HOOKS = path.join(HOME, '.gemini', 'config', 'hooks.json');
  fs.mkdirSync(path.dirname(HOOKS), { recursive: true });
});
afterEach(() => fs.rmSync(HOME, { recursive: true, force: true }));

function install(uninstall = false) {
  const r = spawnSync(process.execPath, [CLI, uninstall ? 'uninstall' : 'install', 'antigravity'], {
    encoding: 'utf8',
    cwd: HOME,
    env: { ...process.env, LEASTGRANT_HOME: path.join(HOME, '.leastgrant'), HOME, USERPROFILE: HOME },
    timeout: 30_000,
  });
  return { out: (r.stdout ?? '') + (r.stderr ?? ''), exit: r.status };
}

const write = (o: unknown) => fs.writeFileSync(HOOKS, JSON.stringify(o, null, 2));
const read = () => JSON.parse(fs.readFileSync(HOOKS, 'utf8')) as Record<string, unknown>;

/** Every handler of ours, across every group, for one event. */
function ourHandlers(event: 'PreToolUse' | 'PostToolUse'): { command: string; timeout?: number }[] {
  const spec = read()['leastgrant'] as Record<string, unknown> | undefined;
  const groups = (spec?.[event] as { hooks?: { command?: string; timeout?: number }[] }[] | undefined) ?? [];
  return groups
    .flatMap((g) => g.hooks ?? [])
    .filter((h) => /leastgrant/i.test(String(h.command ?? '')))
    .map((h) => ({ command: String(h.command), timeout: h.timeout }));
}

describe('installing over what somebody else wrote', () => {
  test('a fresh install produces exactly one labelled handler per event', () => {
    fs.rmSync(HOOKS, { force: true });
    assert.equal(install().exit, 0);
    for (const [event, label] of [
      ['PreToolUse', '--event pre'],
      ['PostToolUse', '--event post'],
    ] as const) {
      const hs = ourHandlers(event);
      assert.equal(hs.length, 1, `${event} has ${hs.length} of our handlers`);
      assert.ok(hs[0]!.command.includes(label), `${event} handler is not labelled ${label}`);
    }
  });

  test('the command carries no double quote, whatever the install path looks like', () => {
    // The one that blocks every tool call when it goes wrong, because
    // Antigravity escapes per argument and a failing hook fails closed.
    fs.rmSync(HOOKS, { force: true });
    assert.equal(install().exit, 0);
    for (const event of ['PreToolUse', 'PostToolUse'] as const) {
      for (const h of ourHandlers(event)) {
        assert.ok(!h.command.includes('"'), `${event}: the command is quoted — ${h.command}`);
      }
    }
  });

  test('a spec disabled with enabled:false is re-enabled, not reported as fine', () => {
    fs.rmSync(HOOKS, { force: true });
    install();
    const cfg = read();
    (cfg['leastgrant'] as Record<string, unknown>)['enabled'] = false;
    fs.writeFileSync(HOOKS, JSON.stringify(cfg, null, 2));

    const r = install();
    assert.equal(r.exit, 0);
    assert.notEqual(
      (read()['leastgrant'] as Record<string, unknown>)['enabled'],
      false,
      'enabled:false survived a reinstall, so enforcement is still entirely off',
    );
  });

  test('a "leastgrant" value that is not a spec is refused, not silently ignored', () => {
    // `[]` was the silent one: named properties on an Array vanish through
    // JSON.stringify, so the install reported success and wrote no handlers.
    for (const bad of [[], 'off', 0, true]) {
      write({ leastgrant: bad });
      const r = install();
      assert.equal(r.exit, 1, `${JSON.stringify(bad)} was accepted`);
      assert.deepEqual(read()['leastgrant'], bad, 'the file was modified despite the refusal');
    }
  });

  test('a stale handler is repaired wherever it sits, not only first-in-first-group', () => {
    // Three layouts that reinstall used to leave broken. The last is the one
    // that hard-denies every call.
    const stale = 'node /old/path/leastgrant.js hook --agent antigravity --event post';
    const layouts: Record<string, unknown>[] = [
      { leastgrant: { PreToolUse: [{ matcher: 'run_command', hooks: [{ command: stale, timeout: 10 }] }] } },
      {
        leastgrant: {
          PreToolUse: [
            { matcher: '*', hooks: [] },
            { matcher: '*', hooks: [{ command: stale, timeout: 10 }] },
          ],
        },
      },
      {
        leastgrant: {
          PreToolUse: [
            {
              matcher: '*',
              hooks: [
                { command: 'node /x/leastgrant.js hook --agent antigravity --event pre', timeout: 10 },
                { command: stale, timeout: 10 },
              ],
            },
          ],
        },
      },
    ];

    for (const layout of layouts) {
      write(layout);
      assert.equal(install().exit, 0);
      const hs = ourHandlers('PreToolUse');
      assert.equal(hs.length, 1, `left ${hs.length} handlers behind: ${JSON.stringify(hs)}`);
      assert.ok(hs[0]!.command.includes('--event pre'), `PreToolUse handler says ${hs[0]!.command}`);
      assert.ok(!hs[0]!.command.includes('/old/path'), 'the stale path survived');
    }
  });

  test('tampered timeout and narrowed matcher are repaired too', () => {
    fs.rmSync(HOOKS, { force: true });
    install();
    const cfg = read();
    const spec = cfg['leastgrant'] as Record<string, { matcher?: string; hooks: { timeout?: number }[] }[]>;
    spec['PreToolUse']![0]!.hooks[0]!.timeout = 0;
    spec['PreToolUse']![0]!.matcher = 'run_command';
    fs.writeFileSync(HOOKS, JSON.stringify(cfg, null, 2));

    assert.equal(install().exit, 0);
    const hs = ourHandlers('PreToolUse');
    assert.equal(hs.length, 1);
    assert.equal(hs[0]!.timeout, 10, 'a zero timeout survived');
    const after = read()['leastgrant'] as Record<string, { matcher?: string }[]>;
    assert.equal(after['PreToolUse']![0]!.matcher, '*', 'a narrowed matcher survived');
  });

  test('another vendor is left alone, on install and on uninstall', () => {
    // The promise `isOurs` exists to keep. Checked semantically rather than
    // byte-for-byte, because the writer reflows inline objects.
    const other = {
      zeta: { PreToolUse: [{ matcher: '*', hooks: [{ command: 'node C:/tools/notify.js', timeout: 5 }] }] },
    };
    write(other);
    assert.equal(install().exit, 0);
    assert.deepEqual(read()['zeta'], other.zeta, 'install disturbed another vendor');

    assert.equal(install(true).exit, 0);
    assert.deepEqual(read()['zeta'], other.zeta, 'uninstall disturbed another vendor');
    assert.equal(read()['leastgrant'], undefined, 'uninstall left our entry behind');
  });

  test('uninstall removes every copy of ours, from every group', () => {
    fs.rmSync(HOOKS, { force: true });
    install();
    // Plant a duplicate in a second group, the shape reinstall used to create.
    const cfg = read();
    const spec = cfg['leastgrant'] as Record<string, unknown[]>;
    const first = (spec['PreToolUse'] as { hooks: unknown[] }[])[0]!;
    spec['PreToolUse']!.push({ matcher: '*', hooks: [{ ...(first.hooks[0] as object) }] });
    fs.writeFileSync(HOOKS, JSON.stringify(cfg, null, 2));

    assert.equal(install(true).exit, 0);
    assert.equal(ourHandlers('PreToolUse').length, 0, 'a copy of ours survived uninstall');
  });
});
