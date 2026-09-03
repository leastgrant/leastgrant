/**
 * The installer.
 *
 * This file exists because an adversarial review pointed out that the module
 * which edits four different people's configuration files had no tests at all,
 * and then found four real bugs in it. Every case below is one of those.
 *
 * The module's header states the contract: idempotent, minimal edits, and "we
 * never remove a hook we did not add". Two of these tests exist because that
 * last promise was not being kept.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { isOurCommand } from './helpers/our-command.js';

const CLI = path.resolve('bin/leastgrant.js');
const AGENTS = ['claude-code', 'cursor', 'copilot', 'codex'] as const;

function sandbox(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lg-install-'));
}

function run(home: string, ...args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      LEASTGRANT_HOME: path.join(home, '.leastgrant'),
      NO_COLOR: '1',
    },
    timeout: 30000,
  });
}

/** Where each agent's config lands, and how to read our commands out of it. */
const CONFIG: Record<string, { file: (home: string) => string }> = {
  'claude-code': { file: (h) => path.join(h, '.claude', 'settings.json') },
  cursor: { file: (h) => path.join(h, '.cursor', 'hooks.json') },
  copilot: { file: (h) => path.join(h, '.copilot', 'hooks', 'leastgrant.json') },
  codex: { file: (h) => path.join(h, '.codex', 'hooks.json') },
};

/** Every `command` string anywhere in a config. */
function commands(file: string): string[] {
  if (!fs.existsSync(file)) return [];
  const found: string[] = [];
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) return value.forEach(walk);
    if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) {
        if (k === 'command' && typeof v === 'string') found.push(v);
        else walk(v);
      }
    }
  };
  try {
    walk(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch {
    /* unreadable */
  }
  return found;
}

/**
 * Ours, in either spelling.
 *
 * From a checkout whose path contains a space the installer writes the Windows
 * 8.3 short form — `LEASTG~1.JS` — to keep the command quote-free. Matching only
 * the long name made this whole file fail on any developer machine under
 * `C:\Users\First Last\`, while passing on every CI runner. What that spelling
 * means for the product is covered in `spaced-install-path.test.ts`; here it
 * only has to be recognised.
 */
const ours = (cmds: string[]) => cmds.filter(isOurCommand);

// ---------------------------------------------------------------------------

describe('install: the command names a file, not a program to look up', () => {
  for (const agent of AGENTS) {
    test(`${agent} writes an absolute executable path`, () => {
      const home = sandbox();
      run(home, 'install', agent);
      const [command] = ours(commands(CONFIG[agent]!.file(home)));
      assert.ok(command, `${agent} wrote no hook command`);

      // The first token is resolved at every tool call, in the agent's
      // environment. A bare `node` would let a `node.exe` earlier on PATH — in
      // the working directory, say — be executed as the permission layer, so a
      // repository could approve itself by shipping a file.
      const first = command.trim().split(/\s+/)[0]!.replace(/^["']|["']$/g, '');
      assert.ok(path.isAbsolute(first), `${agent}: first token is not absolute: ${first}`);
      assert.ok(fs.existsSync(first), `${agent}: first token does not exist: ${first}`);

      fs.rmSync(home, { recursive: true, force: true });
    });
  }

  test('the first token needs no quoting, so no shell can misparse it', () => {
    // PowerShell — which Codex and Copilot both use on Windows — reads a
    // statement beginning with a quoted string as a string expression, not a
    // command. The hook then never starts, and Codex fails open.
    const home = sandbox();
    run(home, 'install', 'codex');
    const [command] = ours(commands(CONFIG['codex']!.file(home)));
    const first = command!.trim().split(/\s+/)[0]!;
    assert.ok(!/["']/.test(first), `the executable is quoted: ${first}`);
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('install: it never touches a hook it did not add', () => {
  // `MARKER` was the bare substring "leastgrant", matched against the whole
  // command. Anything merely mentioning the word was treated as ours.
  const theirs = 'node /home/me/leastgrant-notify.js --watch';

  const seed: Record<string, unknown> = {
    'claude-code': { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: theirs }] }] } },
    cursor: { version: 1, hooks: { beforeShellExecution: [{ command: theirs }] } },
    codex: { hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: theirs }] }] } },
  };

  for (const agent of ['claude-code', 'cursor', 'codex']) {
    test(`${agent}: a third-party hook survives install and uninstall`, () => {
      const home = sandbox();
      const file = CONFIG[agent]!.file(home);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify(seed[agent], null, 2));

      run(home, 'install', agent);
      assert.ok(commands(file).includes(theirs), `${agent}: install clobbered a third-party hook`);
      assert.equal(ours(commands(file)).length > 0, true, `${agent}: install added nothing of ours`);

      run(home, 'uninstall', agent);
      assert.ok(commands(file).includes(theirs), `${agent}: uninstall removed a third-party hook`);
      assert.equal(ours(commands(file)).length, 0, `${agent}: uninstall left our own behind`);

      fs.rmSync(home, { recursive: true, force: true });
    });
  }
});

describe('install: Cursor is asked to fail closed on the gates', () => {
  // Cursor supports `failClosed` per script and LeastGrant was not using it, so
  // a hook that crashed, timed out, or could not start left the call to proceed
  // unchecked — silently, and precisely when something was already wrong.
  test('the before* events carry failClosed and the after* events do not', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-failclosed-'));
    fs.mkdirSync(path.join(home, '.cursor'), { recursive: true });
    const file = path.join(home, '.cursor', 'hooks.json');
    fs.writeFileSync(file, '{"version":1,"hooks":{}}');

    run(home, 'install', 'cursor');
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8')) as {
      hooks: Record<string, { command: string; failClosed?: boolean }[]>;
    };

    for (const event of ['beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile']) {
      const ours = cfg.hooks[event]?.find((h) => isOurCommand(h.command));
      assert.ok(ours, `no LeastGrant entry on ${event}`);
      assert.equal(ours.failClosed, true, `${event} would let the call through if the hook broke`);
    }

    for (const event of ['afterShellExecution', 'afterMCPExecution']) {
      const ours = cfg.hooks[event]?.find((h) => isOurCommand(h.command));
      assert.ok(ours, `no LeastGrant entry on ${event}`);
      assert.notEqual(
        ours.failClosed,
        true,
        `${event} is an observation — the command already ran, so failing closed there ` +
          `rejects the result of work that already happened and protects nothing`,
      );
    }
  });
});

describe('install: it refuses rather than pretending', () => {
  for (const shape of ['[]', '"a string"', '42', '{"hooks":"not an object"}']) {
    test(`a config that is ${shape} is refused out loud`, () => {
      // Valid JSON is not a settings file. These parse, then every assignment
      // against them vanishes — and the installer used to print "✓ Installed"
      // and exit 0 having written nothing, which is the worst outcome
      // available: the user now believes they are protected.
      const home = sandbox();
      const file = CONFIG['codex']!.file(home);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, shape);

      const r = run(home, 'install', 'codex');
      const wrote = ours(commands(file)).length > 0;
      const claimedSuccess = r.status === 0 && /Installed/.test(r.stdout ?? '');
      assert.ok(!claimedSuccess || wrote, `claimed success on ${shape} without writing anything`);

      fs.rmSync(home, { recursive: true, force: true });
    });
  }

  test('an unparseable config is left alone', () => {
    const home = sandbox();
    const file = CONFIG['codex']!.file(home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '{ this is not json');

    const r = run(home, 'install', 'codex');
    assert.notEqual(r.status, 0);
    assert.equal(fs.readFileSync(file, 'utf8'), '{ this is not json');

    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('install: idempotent, but not blind', () => {
  test('running twice changes nothing the second time', () => {
    const home = sandbox();
    const file = CONFIG['codex']!.file(home);
    run(home, 'install', 'codex');
    const first = fs.readFileSync(file, 'utf8');
    run(home, 'install', 'codex');
    assert.equal(fs.readFileSync(file, 'utf8'), first);
    fs.rmSync(home, { recursive: true, force: true });
  });

  for (const agent of ['claude-code', 'cursor', 'codex']) {
    test(`${agent}: a stale command is repaired, not ignored`, () => {
      // Idempotent used to mean "an entry exists, leave it". So moving the
      // checkout left a hook pointing at a path that no longer resolved — and
      // a hook that cannot start fails open on most agents. Reinstalling, the
      // obvious remedy, did nothing.
      const home = sandbox();
      const file = CONFIG[agent]!.file(home);
      run(home, 'install', agent);
      const good = ours(commands(file))[0]!;

      const stale = fs.readFileSync(file, 'utf8').split(good).join('node /gone/bin/leastgrant.js hook');
      fs.writeFileSync(file, stale);

      run(home, 'install', agent);
      assert.ok(
        ours(commands(file)).includes(good),
        `${agent}: a hook pointing at a path that no longer exists was left in place`,
      );
      fs.rmSync(home, { recursive: true, force: true });
    });
  }
});

describe('install: agent attribution', () => {
  test('each adapter is told which agent it is serving', () => {
    const home = sandbox();
    const expected: Record<string, RegExp> = {
      'claude-code': /(leastgrant\.js|LEASTG~\d+\.JS)["']?\s+hook\s*$/i,
      cursor: /--agent cursor$/,
      copilot: /--agent copilot$/,
      codex: /--agent codex$/,
    };
    for (const agent of AGENTS) {
      run(home, 'install', agent);
      const [command] = ours(commands(CONFIG[agent]!.file(home)));
      assert.match(command!.trim(), expected[agent]!, agent);
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  test('an unknown agent is rejected', () => {
    const home = sandbox();
    const r = run(home, 'install', 'emacs');
    assert.equal(r.status, 2);
    assert.match(r.stderr ?? '', /Unknown agent/);
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('the version is not written down twice', () => {
  test('the CLI reports the version in package.json', () => {
    // It was a literal in src/main.ts, and `npm version` does not edit source.
    // So 0.2.0 shipped while `leastgrant --version` still said 0.1.0 — in a
    // tool whose bug-report template asks you to quote your version.
    const pkg = JSON.parse(fs.readFileSync(path.resolve('package.json'), 'utf8')) as { version: string };
    const r = spawnSync(process.execPath, [CLI, '--version'], { encoding: 'utf8', timeout: 30000 });
    assert.equal((r.stdout ?? '').trim(), `leastgrant ${pkg.version}`);
  });
});

describe('install: re-running upgrades an entry, not just its path', () => {
  // The refresh only ever rewrote `command`, so anyone who installed before
  // `failClosed` existed kept a fail-open entry forever — silently, while
  // compatibility/cursor.json told them Cursor refuses on a hook failure.
  // Re-running the installer reported "already installed" and changed nothing.
  // An upgrade path that cannot deliver a security setting is not one.
  test('a pre-upgrade Cursor entry gains failClosed on reinstall', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-retrofit-'));
    fs.mkdirSync(path.join(home, '.cursor'), { recursive: true });
    const file = path.join(home, '.cursor', 'hooks.json');

    run(home, 'install', 'cursor');
    const before = JSON.parse(fs.readFileSync(file, 'utf8')) as {
      hooks: Record<string, { command: string; failClosed?: boolean }[]>;
    };
    // Roll back to what an older install produced.
    for (const list of Object.values(before.hooks)) for (const h of list) delete h.failClosed;
    fs.writeFileSync(file, JSON.stringify(before, null, 2));

    run(home, 'install', 'cursor');
    const after = JSON.parse(fs.readFileSync(file, 'utf8')) as {
      hooks: Record<string, { command: string; failClosed?: boolean }[]>;
    };
    for (const event of ['beforeShellExecution', 'beforeMCPExecution', 'beforeReadFile']) {
      const ours = after.hooks[event]?.find((h) => isOurCommand(h.command));
      assert.ok(ours, `no entry on ${event}`);
      assert.equal(ours.failClosed, true, `${event} was not upgraded, so it still fails open`);
    }
  });
});
