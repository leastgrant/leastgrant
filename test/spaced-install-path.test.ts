/**
 * Installing from a path that contains a space.
 *
 * This is the ordinary case on Windows — `C:\Users\First Last\...`, and the
 * default `npm i -g` location sits under exactly that. It is also the one case
 * no CI runner has ever exercised: every runner checks out to `D:\a\...` or
 * `/home/runner/...`, so the whole branch was green everywhere and broken on
 * the machines most likely to run it.
 *
 * What goes wrong there: to keep the command free of quotes, `scriptToken`
 * writes the Windows 8.3 short form of our entry point — `LEASTG~1.JS`, not
 * `leastgrant.js`. Recognition matched only the long spelling, so the installer
 * could not see handlers it had written itself. A second install duplicated
 * every entry, and uninstall reported success while removing none of them. On a
 * runtime that fails closed, debris left pointing at a deleted file blocks every
 * tool call.
 *
 * The fix resolves the short name through the OS rather than guessing at it,
 * which is what the last test here defends: shape is not identity. A file called
 * `leastgrant-notify.js` in the same directory is also `LEASTG~1.JS`, and this
 * module promises never to remove a hook it did not add.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { repoRoot } from './helpers/repo-root.js';
import { isOurCommand } from './helpers/our-command.js';

/** 8.3 short names are a Windows filesystem feature; elsewhere the path is quoted instead. */
const WINDOWS = process.platform === 'win32';

/**
 * A runnable copy of the package under a directory whose name has a space.
 *
 * The installer works out its own location from the module it was loaded from,
 * so the branch can only be reached by genuinely running from such a path. The
 * package declares no runtime dependencies, so this is all of it.
 */
const STAGED = (() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lg spaced '));
  for (const part of ['bin', 'dist', 'package.json']) {
    fs.cpSync(path.join(repoRoot(), part), path.join(dir, part), { recursive: true });
  }
  return dir;
})();
const CLI = path.join(STAGED, 'bin', 'leastgrant.js');

assert.ok(STAGED.includes(' '), 'the staged checkout must contain a space, or this file tests nothing');

const CONFIG: Record<string, string> = {
  'claude-code': '.claude/settings.json',
  cursor: '.cursor/hooks.json',
  antigravity: '.gemini/config/hooks.json',
};

/** Every `command` string anywhere in a config, at any depth. */
function commands(file: string): string[] {
  if (!fs.existsSync(file)) return [];
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (k === 'command' && typeof x === 'string') out.push(x);
        else walk(x);
      }
    }
  };
  try {
    walk(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch {
    /* unreadable */
  }
  return out;
}

/**
 * Ours in either spelling.
 *
 * The test has to recognise both, because which one is written depends on the
 * platform — and it must not simply reuse the product's own predicate, or a bug
 * in that predicate would agree with itself.
 */
const ours = (cmds: string[]) => cmds.filter(isOurCommand);

function sandbox(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lg-spaced-home-'));
}

function run(home: string, cmd: string, agent: string) {
  return spawnSync(process.execPath, [CLI, cmd, agent], {
    encoding: 'utf8',
    cwd: home,
    env: { ...process.env, HOME: home, USERPROFILE: home, LEASTGRANT_HOME: path.join(home, '.leastgrant') },
    timeout: 120_000,
  });
}

describe('install: a path with a space in it is still a path we recognise', () => {
  for (const agent of Object.keys(CONFIG)) {
    test(`${agent}: install, reinstall, uninstall`, () => {
      const home = sandbox();
      const file = path.join(home, CONFIG[agent]!);

      const first = run(home, 'install', agent);
      assert.equal(first.status, 0, `install failed: ${first.stderr}`);
      const after1 = ours(commands(file));
      assert.ok(after1.length > 0, `${agent} wrote no handler from a spaced path`);

      // The duplication half. Reconciliation has to find what it just wrote.
      assert.equal(run(home, 'install', agent).status, 0);
      assert.equal(
        ours(commands(file)).length,
        after1.length,
        `${agent}: a second install duplicated the handler (${after1.length} -> ${ours(commands(file)).length})`,
      );

      // The debris half, and the one that actually harms a user: uninstall
      // reporting success while leaving every handler in place.
      assert.equal(run(home, 'uninstall', agent).status, 0);
      assert.deepEqual(ours(commands(file)), [], `${agent}: uninstall left its own handler behind`);

      fs.rmSync(home, { recursive: true, force: true });
    });
  }

  test('on Windows the command really is the short form, or this file proves nothing', { skip: !WINDOWS && '8.3 names are Windows-only' }, () => {
    const home = sandbox();
    run(home, 'install', 'claude-code');
    const [command] = ours(commands(path.join(home, CONFIG['claude-code']!)));
    assert.ok(command, 'no handler written');
    assert.match(
      command,
      /LEASTG~\d+\.JS\s+hook/i,
      `expected the 8.3 spelling from a spaced path, got: ${command}`,
    );
    assert.ok(!command.includes('"'), `the command must stay quote-free: ${command}`);
    fs.rmSync(home, { recursive: true, force: true });
  });

  test('a third party whose short name collides with ours is left alone', { skip: !WINDOWS && '8.3 names are Windows-only' }, () => {
    // Not a hypothetical collision: a file named `leastgrant-notify.js` alone in
    // a directory is given the short name `LEASTG~1.JS`, the same one our own
    // entry point gets. Matching the shape would delete somebody else's hook —
    // which is the exact bug the narrow marker was introduced to fix, so the
    // repair for the short spelling must not reintroduce it.
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-third-'));
    const notify = path.join(other, 'leastgrant-notify.js');
    fs.writeFileSync(notify, '// somebody else\n');

    const short = spawnSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '(New-Object -ComObject Scripting.FileSystemObject).GetFile([string]$env:LG_T).ShortPath',
      ],
      { encoding: 'utf8', windowsHide: true, env: { ...process.env, LG_T: notify } },
    );
    const shortName = (short.stdout ?? '').trim();
    if (!/LEASTG~\d+\.JS$/i.test(shortName)) {
      // 8.3 generation can be switched off per volume. Without it there is no
      // collision to survive, and asserting one would be asserting a fiction.
      fs.rmSync(other, { recursive: true, force: true });
      return;
    }

    const theirs = `${process.execPath} ${shortName} hook`;
    const home = sandbox();
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    const file = path.join(home, '.claude', 'settings.json');
    fs.writeFileSync(
      file,
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: theirs }] }] } }, null, 2),
    );

    assert.equal(run(home, 'install', 'claude-code').status, 0);
    assert.ok(
      commands(file).includes(theirs),
      'install removed a third-party hook whose 8.3 name resembles ours',
    );

    assert.equal(run(home, 'uninstall', 'claude-code').status, 0);
    assert.ok(
      commands(file).includes(theirs),
      'uninstall removed a third-party hook whose 8.3 name resembles ours',
    );

    fs.rmSync(other, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  });

  test('a short-named script that is not invoked as a hook is not ours', { skip: !WINDOWS && '8.3 names are Windows-only' }, () => {
    // `LEASTG~1.JS status` is not the command we write. Recognition keys on the
    // subcommand as well as the file, so the pair has to match.
    const home = sandbox();
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    const file = path.join(home, '.claude', 'settings.json');
    const theirs = `${process.execPath} C:\\tools\\LEASTG~1.JS status`;
    fs.writeFileSync(
      file,
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: theirs }] }] } }, null, 2),
    );

    assert.equal(run(home, 'install', 'claude-code').status, 0);
    assert.equal(run(home, 'uninstall', 'claude-code').status, 0);
    assert.ok(commands(file).includes(theirs), 'a non-hook invocation was treated as ours');

    fs.rmSync(home, { recursive: true, force: true });
  });
});
