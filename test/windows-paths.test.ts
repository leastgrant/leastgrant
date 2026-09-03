/**
 * A native Windows path inside a shell command.
 *
 * This parser reads POSIX rules. On Windows the agents run cmd or PowerShell,
 * where a backslash is an ordinary path character — so
 *
 *   type C:\Users\me\.ssh\id_rsa
 *
 * de-escaped to `C:Usersme.sshid_rsa`, which `looksLikePath` then rejected for
 * having no separator. No path target was produced at all, and every
 * path-keyed floor is keyed on targets — `guard.secret-read`,
 * `guard.write-outside`, `guard.agent-config`, `guard.persistence` all went
 * silent together. That is the failure `UNPLACEABLE` exists to prevent,
 * arriving by a door it does not cover: the path never becomes a path.
 *
 * It did not stop at a missing floor. The residue signed as `type <text>`, the
 * same signature as any ordinary read spelled that way, so twelve in-project
 * reads promoted it and the credential read that followed came back ALLOW with
 * no floors. Measured, before the fix:
 *
 *   trained on `type C:\proj\src\*.ts` x12  ->  `type C:\Users\me\.ssh\id_rsa`  ALLOW
 *   30 approvals of an ordinary write       ->  `echo {} > C:\Users\me\.gemini\config\hooks.json`  ALLOW
 *
 * This is not Antigravity-specific. Every agent LeastGrant supports runs on
 * Windows, and a native path is the natural spelling a model emits there.
 *
 * The tests are all PAIRS: the backslash spelling against the forward-slash
 * spelling of the same command, which always worked. Asserting they agree says
 * the parser reads them as the same command, which is the actual property —
 * far better than pinning a list of guard names that a later change would have
 * to be edited around.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';
import { tokenize } from '../src/core/shell/tokenize.js';

const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-winpaths-'));
fs.mkdirSync(path.join(WS, '.git'), { recursive: true });
const AT = 1_760_000_000_000;

const run = (command: string) =>
  decide(
    { agent: 't', tool: 'Bash', input: { command }, cwd: WS, sessionId: 's', at: AT },
    {
      roots: [WS],
      secretPatterns: [],
      config: { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] },
      envelope: newEnvelope('project', WS),
      session: newSession('s', AT),
      stateDir: path.join(os.tmpdir(), 'lg-winpaths-state'),
      projectKey: WS,
    },
  );

const floors = (cmd: string) => run(cmd).flooredGuards.slice().sort();

/**
 * Whether `C:\...` is an absolute path on the machine running this.
 *
 * The tokenizer fix is pure string work and is asserted everywhere. What cannot
 * be asserted everywhere is what happens AFTER tokenization: on POSIX a
 * Windows-shaped path is a relative filename, so it resolves inside the
 * workspace, is not a credential, and floors nothing — correctly, because on
 * that platform it is not a path to anywhere. Gating those assertions is not a
 * gap in coverage; asserting them on POSIX would be asserting something false.
 */
const WINDOWS = process.platform === 'win32';

/** Backslash spelling, forward-slash spelling of the same command. */
const PAIRS: [string, string][] = [
  ['cat C:\\Users\\me\\.ssh\\id_rsa', 'cat C:/Users/me/.ssh/id_rsa'],
  ['type C:\\Users\\me\\.ssh\\id_rsa', 'type C:/Users/me/.ssh/id_rsa'],
  ['more C:\\Users\\me\\.aws\\credentials', 'more C:/Users/me/.aws/credentials'],
  ['head C:\\Users\\me\\.ssh\\id_ed25519', 'head C:/Users/me/.ssh/id_ed25519'],
  ['grep -r secret C:\\Users\\me\\.ssh', 'grep -r secret C:/Users/me/.ssh'],
  ['echo {} > C:\\Users\\me\\.gemini\\config\\hooks.json', 'echo {} > C:/Users/me/.gemini/config/hooks.json'],
  ['echo {} > C:\\Users\\me\\.gemini\\config\\config.json', 'echo {} > C:/Users/me/.gemini/config/config.json'],
  ['cp a.json C:\\Users\\me\\.claude\\settings.json', 'cp a.json C:/Users/me/.claude/settings.json'],
  ['rm C:\\Users\\me\\.bashrc', 'rm C:/Users/me/.bashrc'],
];

describe('a Windows path is a path, not an escape sequence', () => {
  test('the tokenizer keeps the backslashes', () => {
    const words = (cmd: string) =>
      (tokenize(cmd, {}).tokens ?? []).filter((t) => t.type === 'word').map((t) => t.text);
    assert.deepEqual(words('cat C:\\Users\\me\\.ssh\\id_rsa'), ['cat', 'C:\\Users\\me\\.ssh\\id_rsa']);
    assert.deepEqual(words('dir \\\\server\\share\\x'), ['dir', '\\\\server\\share\\x']);
  });

  test('POSIX escaping is untouched, which is the whole reason this is narrow', () => {
    // The first version of the rule matched a single leading backslash and
    // turned `echo \$HOME` into a literal `\$HOME`. Only a drive letter with a
    // separator, or a UNC prefix of TWO backslashes, may take the raw spelling.
    const words = (cmd: string) =>
      (tokenize(cmd, {}).tokens ?? []).filter((t) => t.type === 'word').map((t) => t.text);
    assert.deepEqual(words('echo \\$HOME'), ['echo', '$HOME']);
    assert.deepEqual(words('echo a\\;b'), ['echo', 'a;b']);
    assert.deepEqual(words('cat my\\ file.txt'), ['cat', 'my file.txt']);
    // Quoted already worked, and must keep working.
    assert.deepEqual(words('cat "C:\\Users\\me\\.env"'), ['cat', 'C:\\Users\\me\\.env']);
  });

  test('each spelling reaches the same floors as its forward-slash twin', { skip: !WINDOWS && 'Windows path resolution' }, () => {
    for (const [back, fwd] of PAIRS) {
      assert.deepEqual(floors(back), floors(fwd), `"${back}" and "${fwd}" disagree`);
    }
  });

  test('and those floors are not empty, or the agreement would be vacuous', { skip: !WINDOWS && 'Windows path resolution' }, () => {
    // One pair is excluded, and the reason is a separate finding rather than an
    // inconvenience: a credential DIRECTORY is recognised by being under the
    // real home, not by its name, so `grep -r secret C:/Users/me/.ssh` reaches
    // no floor — and neither does the backslash spelling, which is why the
    // agreement test above still passes on it. A FILE under that directory does
    // floor, by name, in both spellings. Recorded in THREAT-MODEL rather than
    // fixed here: widening it to any directory called `.ssh` would floor a
    // repository's test fixtures, and that trade deserves its own decision.
    const separateFinding = PAIRS.find(([b]) => b.startsWith('grep '))![0];
    for (const [back] of PAIRS) {
      if (back === separateFinding) continue;
      assert.ok(floors(back).length > 0, `"${back}" reaches no floor at all`);
    }
    assert.deepEqual(floors(separateFinding), [], 'the excluded pair now floors — remove the exclusion');
  });

  test('ordinary in-project work spelled with backslashes is still free', { skip: !WINDOWS && 'Windows path resolution' }, () => {
    // The control for everything above. Without it, "they all floor" could mean
    // a rule that floors any command containing a backslash, which would be a
    // different and worse bug.
    const local = WS.replace(/\//g, '\\');
    for (const cmd of [`type ${local}\\src\\a.ts`, `cat ${local}\\README.md`, `head ${local}\\src\\b.ts`]) {
      assert.deepEqual(floors(cmd), [], `"${cmd}" is floored and should not be`);
    }
  });

  test('a credential read cannot inherit the approvals of ordinary reads', { skip: !WINDOWS && 'Windows path resolution' }, () => {
    // The promotion half. Before the fix both collapsed onto `type <text>`, so
    // twelve approved in-project reads paid for the credential read.
    const secret = run('type C:\\Users\\me\\.ssh\\id_rsa').actions?.[0]?.signature;
    const ordinary = run('type C:\\proj\\src\\a.ts').actions?.[0]?.signature;
    assert.ok(secret, 'no action produced for the credential read');
    assert.notEqual(secret, ordinary, `both sign as ${secret}`);
    assert.ok(/secret/.test(String(secret)), `the credential read signs as ${secret}`);
  });

  test('type and more are read as readers when handed a path, and not otherwise', { skip: !WINDOWS && 'Windows path resolution' }, () => {
    // Two commands wearing one name each. POSIX `type ls` reports how a name
    // resolves; cmd's `type file` is `cat`. Telling them apart by the argument
    // is the only honest signal, so both halves are asserted.
    assert.ok(floors('type C:/Users/me/.ssh/id_rsa').includes('guard.secret-read'));
    assert.ok(floors('more C:/Users/me/.ssh/id_rsa').includes('guard.secret-read'));
    assert.deepEqual(floors('type node'), [], '`type node` asks how a command resolves and touches nothing');
    assert.deepEqual(floors('type git'), []);
  });
});
