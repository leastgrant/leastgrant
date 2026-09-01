/**
 * Symlink traversal.
 *
 * The recorded defect was narrow to describe and wide in effect: `canonicalize`
 * called `path.resolve` before `realpath`, so `..` was collapsed in the string
 * before any link was followed. Given `proj/escape -> /elsewhere`, the string
 * `proj/escape/../id_rsa` collapsed to `proj/id_rsa` — inside the project —
 * while a POSIX kernel serves `/id_rsa` from outside it. LeastGrant reported
 * "inside" for a read taken from somewhere else, which is the exact shape of
 * miss the tool exists to prevent.
 *
 * Two things make this hard to test honestly:
 *
 *   1. **The right answer is platform-dependent.** POSIX resolves `..` after a
 *      symlink physically; Win32 collapses it lexically before the object
 *      manager sees the reparse point. Both were verified by reading a real
 *      file through the construction. So there is no single expected path — and
 *      worse, on POSIX a Python script calling `os.path.abspath` before `open`
 *      gets the *lexical* file while the shell gets the physical one. The
 *      ambiguity is real, not a platform detail to be settled once.
 *   2. **Creating a link needs privilege on Windows** and behaves differently
 *      per filesystem, so a test needing a real link cannot run everywhere.
 *
 * So this file tests at two levels. The resolution *rules* are tested against a
 * virtual filesystem — a literal map of link to target — which runs on every
 * machine and covers the variants no real fixture could conveniently build
 * (loops, 60-deep chains, relative targets). The *containment decision* is then
 * tested against real links where the machine allows it, asserting the
 * invariant that holds on every platform: a path is contained only if every
 * reading of it is contained.
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  candidatesOf,
  canonicalDir,
  canonicalize,
  inWorkspace,
  resolvePhysical,
  samePath,
  type PathIO,
} from '../src/core/paths.js';
import { analyze } from '../src/core/classify.js';
import { blastTier } from '../src/core/types.js';
import { UNRESOLVED } from '../src/core/shell/tokenize.js';

const WIN = process.platform === 'win32';
const BS = String.fromCharCode(92);
const norm = (p: string): string => p.split(BS).join('/');

// ---------------------------------------------------------------------------
// Level one: the resolution rules, against a filesystem that is a map.
// ---------------------------------------------------------------------------

/**
 * A filesystem described by a table. Anything not listed under `missing`
 * exists; anything listed in `links` is a symlink to the given target.
 */
function vfs(links: Record<string, string>, missing: string[] = []): PathIO {
  return {
    isSymlink(p: string): boolean {
      const n = norm(p);
      if (missing.some((m) => n === m || n.startsWith(m + '/'))) throw new Error('ENOENT');
      return Object.prototype.hasOwnProperty.call(links, n);
    },
    readlink: (p: string): string => links[norm(p)] as string,
    realpath: (p: string): string => p,
  };
}

describe('physical resolution: the rules', () => {
  const cases: [string, string, Record<string, string>, string][] = [
    // The defect itself, and the shapes immediately around it.
    ['.. straight after a symlink', '/proj/escape/../id_rsa', { '/proj/escape': '/home/me' }, '/home/id_rsa'],
    ['.. twice after a symlink', '/proj/escape/../../x', { '/proj/escape': '/home/me/deep' }, '/home/x'],
    ['.. several components later', '/proj/escape/a/b/../../../x', { '/proj/escape': '/home/me' }, '/home/x'],
    ['.. before the symlink', '/proj/sub/../escape/x', { '/proj/escape': '/out' }, '/out/x'],
    ['dot components are ignored', '/proj/./escape/./../x', { '/proj/escape': '/out' }, '/x'],

    // Symlink targets that are themselves relative or chained.
    ['relative target', '/proj/escape/../x', { '/proj/escape': '../../outside/sub' }, '/outside/x'],
    ['relative target with no climb', '/proj/escape/../x', { '/proj/escape': 'sub/deep' }, '/proj/sub/x'],
    ['chained links', '/proj/a/../x', { '/proj/a': '/proj/b', '/proj/b': '/out/sub' }, '/out/x'],
    ['chain that returns inside', '/proj/a/../x', { '/proj/a': '/out/sub', '/out/sub': '/proj/deep' }, '/proj/x'],
    ['link to the root, then ..', '/proj/r/../etc/passwd', { '/proj/r': '/' }, '/etc/passwd'],

    // Climbing, clamping, and names that merely look like climbing.
    ['.. clamps at the root', '/proj/../../../../etc/passwd', {}, '/etc/passwd'],
    ['..hidden is a name', '/proj/..hidden/x', {}, '/proj/..hidden/x'],
    ['... is a name', '/proj/.../x', {}, '/proj/.../x'],
    ['..foo/bar is a name', '/proj/..foo/bar', {}, '/proj/..foo/bar'],
    ['a file named ..something', '/proj/..gitignore', {}, '/proj/..gitignore'],

    // No symlink anywhere: the physical and lexical rules must agree.
    ['plain .. with no link', '/proj/src/../lib/a.ts', {}, '/proj/lib/a.ts'],
    ['doubled separators', '/proj//src///../lib/a.ts', {}, '/proj/lib/a.ts'],

    // The interesting compound: escaping, coming back, escaping again. After
    // the first hop the second `/proj` is relative to where we landed.
    ['interleaved escapes', '/proj/e/../proj/e/../x', { '/proj/e': '/out/sub' }, '/out/proj/x'],

    // A link pointing back inside must stay inside.
    ['link back into the project', '/proj/inner/../a.ts', { '/proj/inner': '/proj/src' }, '/proj/a.ts'],
    [
      'workspace-style package link',
      '/proj/node_modules/@s/p/../q/index.js',
      { '/proj/node_modules/@s/p': '/proj/packages/p' },
      '/proj/packages/q/index.js',
    ],
  ];

  for (const [name, input, links, want] of cases) {
    test(name, () => {
      const got = resolvePhysical(input, '/proj', vfs(links));
      assert.equal(got.exhausted, false, 'resolution should complete');
      assert.equal(norm(got.abs), want, input);
    });
  }

  test('a symlink loop is exhausted rather than hanging', () => {
    const got = resolvePhysical('/proj/a/x', '/proj', vfs({ '/proj/a': '/proj/b', '/proj/b': '/proj/a' }));
    assert.equal(got.exhausted, true);
    assert.equal(got.abs, '', 'an exhausted walk must not hand back a plausible-looking path');
  });

  test('a self-referential link is exhausted', () => {
    const got = resolvePhysical('/proj/a/x', '/proj', vfs({ '/proj/a': '/proj/a' }));
    assert.equal(got.exhausted, true);
  });

  test('a long chain within budget still resolves', () => {
    const links: Record<string, string> = {};
    for (let i = 0; i < 30; i++) links[`/proj/l${i}`] = `/proj/l${i + 1}`;
    links['/proj/l30'] = '/out/final';
    const got = resolvePhysical('/proj/l0/x', '/proj', vfs(links));
    assert.equal(got.exhausted, false);
    assert.equal(norm(got.abs), '/out/final/x');
  });

  test('a chain past the budget is exhausted, not truncated', () => {
    const links: Record<string, string> = {};
    for (let i = 0; i < 100; i++) links[`/proj/l${i}`] = `/proj/l${i + 1}`;
    const got = resolvePhysical('/proj/l0/x', '/proj', vfs(links));
    assert.equal(got.exhausted, true);
  });

  test('a path 200 components deep resolves without giving up', () => {
    const deep = '/proj/' + Array.from({ length: 200 }, (_, i) => `d${i}`).join('/');
    const got = resolvePhysical(deep, '/proj', vfs({}));
    assert.equal(got.exhausted, false);
    assert.equal(norm(got.abs), deep);
  });

  test('nothing under a missing directory is inspected further', () => {
    // Once a component does not exist, nothing below it can be a link, so `..`
    // there is unambiguous. This is also the not-yet-created-file case.
    const got = resolvePhysical('/proj/nope/../x', '/proj', vfs({}, ['/proj/nope']));
    assert.equal(norm(got.abs), '/proj/x');
  });

  test('a missing leaf under a link still lands past the link', () => {
    const got = resolvePhysical('/proj/escape/newfile', '/proj', vfs({ '/proj/escape': '/out' }, ['/out/newfile']));
    assert.equal(norm(got.abs), '/out/newfile');
  });

  test('followed is false when no link was crossed', () => {
    // This flag is what suppresses the second candidate. If it were wrong in
    // the permissive direction the fix would silently stop applying; if it
    // were wrong the other way every `..` would produce a spurious ambiguity.
    assert.equal(resolvePhysical('/proj/a/../b', '/proj', vfs({})).followed, false);
    assert.equal(resolvePhysical('/proj/a/../b', '/proj', vfs({ '/proj/a': '/out' })).followed, true);
  });
});

// ---------------------------------------------------------------------------
// Level two: the containment decision, against real links.
// ---------------------------------------------------------------------------

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-trav-'));
after(() => fs.rmSync(TMP, { recursive: true, force: true }));

const WS = path.join(TMP, 'proj');
const OUT = path.join(TMP, 'out');
fs.mkdirSync(path.join(WS, 'src'), { recursive: true });
fs.mkdirSync(path.join(WS, 'packages', 'b'), { recursive: true });
fs.mkdirSync(path.join(WS, 'node_modules', '@scope'), { recursive: true });
fs.mkdirSync(path.join(OUT, '.ssh'), { recursive: true });
fs.writeFileSync(path.join(WS, 'src', 'a.ts'), 'export {};\n');
fs.writeFileSync(path.join(WS, 'packages', 'b', 'index.js'), '\n');
fs.writeFileSync(path.join(OUT, 'secret.txt'), 'shh\n');
fs.writeFileSync(path.join(OUT, '.ssh', 'id_rsa'), 'KEY\n');
fs.writeFileSync(path.join(TMP, 'planted.txt'), 'planted\n');

function link(target: string, at: string): boolean {
  try {
    fs.symlinkSync(target, at, WIN ? 'junction' : 'dir');
    return true;
  } catch {
    return false;
  }
}

const LINKED =
  link(OUT, path.join(WS, 'escape')) &&
  link(path.join(WS, 'src'), path.join(WS, 'inner')) &&
  link(path.join(WS, 'packages', 'b'), path.join(WS, 'node_modules', '@scope', 'b'));

const SKIP = LINKED ? false : 'this machine will not create a symlink/junction here';
const WSC = canonicalDir(WS);
const S = path.sep;
/** Join without normalising — `path.join` would collapse the `..` under test. */
const raw = (...parts: string[]): string => parts.join(S);

/** True only if every reading of this path stays inside the project. */
function contained(input: string): boolean {
  const c = canonicalize(input, WS);
  const cands = candidatesOf(c);
  return cands.length > 0 && cands.every((a) => inWorkspace(a, [WSC]));
}

describe('traversal through a real link is not contained', { skip: SKIP }, () => {
  const escapes: [string, string][] = [
    ['.. off the end of the link', raw(WS, 'escape', '..', 'planted.txt')],
    ['.. twice', raw(WS, 'escape', '..', '..', 'planted.txt')],
    ['.. then back down to a credential', raw(WS, 'escape', '..', 'out', '.ssh', 'id_rsa')],
    ['a dot in the middle', raw(WS, 'escape', '.', '..', 'planted.txt')],
    ['doubled separators', WS + S + 'escape' + S + S + '..' + S + 'planted.txt'],
    ['deeper then back', raw(WS, 'escape', '.ssh', '..', '..', 'planted.txt')],
    ['straight through the link', raw(WS, 'escape', 'secret.txt')],
    ['a file that does not exist yet', raw(WS, 'escape', 'newfile.txt')],
    ['a credential through the link', raw(WS, 'escape', '.ssh', 'id_rsa')],
    ['forward slashes', norm(WS) + '/escape/../planted.txt'],
  ];

  for (const [name, input] of escapes) {
    test(name, () => {
      assert.equal(contained(input), false, `${input}\n  candidates: ${candidatesOf(canonicalize(input, WS)).join(' | ')}`);
    });
  }

  test('the ambiguous ones record both readings', () => {
    const c = canonicalize(raw(WS, 'escape', '..', 'planted.txt'), WS);
    assert.equal(candidatesOf(c).length, 2);
  });
});

describe('ordinary paths are still contained', { skip: SKIP }, () => {
  const ok: [string, string][] = [
    ['a plain file', raw(WS, 'src', 'a.ts')],
    ['.. with no link involved', raw(WS, 'src', '..', 'src', 'a.ts')],
    ['.. twice with no link', raw(WS, 'src', '..', '..', 'proj', 'src', 'a.ts')],
    ['a link pointing back inside', raw(WS, 'inner', 'a.ts')],
    ['.. after a link that points inside', raw(WS, 'inner', '..', 'src', 'a.ts')],
    ['a workspace package link', raw(WS, 'node_modules', '@scope', 'b', 'index.js')],
    ['.. through a workspace package link', raw(WS, 'node_modules', '@scope', 'b', '..', 'b', 'index.js')],
    ['a dot component', raw(WS, '.', 'src', 'a.ts')],
    ['a trailing separator', raw(WS, 'src') + S],
  ];

  for (const [name, input] of ok) {
    test(name, () => {
      assert.equal(contained(input), true, `${input}\n  candidates: ${candidatesOf(canonicalize(input, WS)).join(' | ')}`);
    });
  }

  test('an unambiguous path has exactly one candidate', () => {
    // The cost control. If the fix produced two candidates for everything it
    // would be indistinguishable from "call every path outside".
    for (const [, input] of ok) {
      assert.equal(candidatesOf(canonicalize(input, WS)).length, 1, input);
    }
  });
});

// ---------------------------------------------------------------------------
// Level three: what a command is actually judged as.
// ---------------------------------------------------------------------------

describe('the classifier sees the escape', { skip: SKIP }, () => {
  const judge = (command: string) =>
    analyze(
      { agent: 't', tool: 'Bash', input: { command }, cwd: WS, sessionId: 's', at: Date.now() },
      { roots: [WS], secretPatterns: [] },
    ).actions[0];

  test('a read through a traversal is a read outside the project', () => {
    const a = judge('cat escape/../planted.txt');
    assert.notEqual(a?.capability, 'fs.read.workspace', `judged as ${a?.capability}: ${a?.signature}`);
    assert.match(a?.signature ?? '', /<path:outside/);
  });

  test('a traversal onto a credential is a credential read', () => {
    const a = judge('cat escape/../out/.ssh/id_rsa');
    assert.equal(a?.capability, 'secret.read', `judged as ${a?.capability}: ${a?.signature}`);
    assert.ok(blastTier(a!.blast) >= 3);
  });

  test('a write through a traversal is a write outside the project', () => {
    const a = judge('echo x > escape/../planted.txt');
    assert.notEqual(a?.capability, 'fs.write.workspace', `judged as ${a?.capability}: ${a?.signature}`);
  });

  test('and ordinary work is untouched', () => {
    for (const command of ['cat src/a.ts', 'cat src/../src/a.ts', 'cat inner/../src/a.ts']) {
      const a = judge(command);
      assert.equal(a?.capability, 'fs.read.workspace', `${command} judged as ${a?.capability}`);
    }
  });

  test('a cd through a traversal loses the working directory rather than guessing', () => {
    // Two possible destinations means every later relative path would be
    // resolved against a coin flip.
    const a = analyze(
      { agent: 't', tool: 'Bash', input: { command: 'cd escape/.. && cat planted.txt' }, cwd: WS, sessionId: 's', at: Date.now() },
      { roots: [WS], secretPatterns: [] },
    );
    const read = a.actions.find((x) => x.capability.startsWith('fs.read'));
    assert.ok(read, 'the read should still be classified');
    assert.notEqual(read?.capability, 'fs.read.workspace', `judged as ${read?.capability}: ${read?.signature}`);
  });
});

describe('resolution failures are never contained', () => {
  test('a path with an unresolved expansion has no candidates at all', () => {
    const c = canonicalize('/proj/' + UNRESOLVED + '/x', WS);
    assert.equal(c.unknown, true);
    assert.equal(candidatesOf(c).length, 0);
  });

  test('an exhausted walk yields no candidates rather than a plausible path', () => {
    // A chain past the symlink budget. The dangerous outcome would be handing
    // back the literal string, which looks ordinary and reads as contained.
    const links: Record<string, string> = {};
    for (let i = 0; i < 100; i++) links[`/proj/l${i}`] = `/proj/l${i + 1}`;
    const got = resolvePhysical('/proj/l0/x', '/proj', vfs(links));
    assert.equal(got.exhausted, true);
    assert.equal(inWorkspace(got.abs, ['/proj']), false);
  });
});

// ---------------------------------------------------------------------------
// Level four: the ways the fix could be bypassed on its own way in.
// ---------------------------------------------------------------------------

describe('nothing normalises the path before the `..` detector', { skip: SKIP }, () => {
  // The physical walk only runs when the input still contains a `..`. Anything
  // that rewrites the string earlier and happens to normalise it therefore
  // switches the whole fix off silently — no error, no second candidate, just
  // the old lexical answer. `~` expansion did exactly that: it used
  // `path.join`, which collapses `..`, so `~/proj/link/../id_rsa` was resolved
  // the pre-fix way. Found by attacking the fix rather than the original bug.
  test('a tilde path is treated exactly like its expanded form', () => {
    const home = process.platform === 'win32' ? process.env['USERPROFILE'] : process.env['HOME'];
    const set = (v: string) => {
      if (process.platform === 'win32') process.env['USERPROFILE'] = v;
      else process.env['HOME'] = v;
    };
    try {
      set(TMP);
      const tilde = '~' + S + 'proj' + S + 'escape' + S + '..' + S + 'planted.txt';
      const spelled = raw(TMP, 'proj', 'escape', '..', 'planted.txt');
      const a = canonicalize(tilde, WS);
      const b = canonicalize(spelled, WS);
      assert.equal(candidatesOf(a).length, candidatesOf(b).length, 'the two spellings disagree');
      assert.equal(candidatesOf(a).length, 2, 'the tilde form lost its second candidate');
      assert.equal(contained(tilde), false, 'a tilde traversal must not read as contained');
    } finally {
      if (home === undefined) {
        if (process.platform === 'win32') delete process.env['USERPROFILE'];
        else delete process.env['HOME'];
      } else set(home);
    }
  });

  test('a tilde path with no traversal is still ordinary', () => {
    const home = process.platform === 'win32' ? process.env['USERPROFILE'] : process.env['HOME'];
    const set = (v: string) => {
      if (process.platform === 'win32') process.env['USERPROFILE'] = v;
      else process.env['HOME'] = v;
    };
    try {
      set(TMP);
      const c = canonicalize('~' + S + 'proj' + S + 'src' + S + 'a.ts', WS);
      assert.equal(candidatesOf(c).length, 1);
      assert.equal(inWorkspace(c.abs, [WSC]), true);
    } finally {
      if (home === undefined) {
        if (process.platform === 'win32') delete process.env['USERPROFILE'];
        else delete process.env['HOME'];
      } else set(home);
    }
  });
});

describe('resolution cannot be sidestepped by the shape of the input', () => {
  test('a NUL byte makes a path unplaceable, not contained', () => {
    // The truncation class: a checker that reads `secret\0.txt` and an opener
    // that reads `secret`. Node rejects NUL outright so nothing opens either
    // way, but "cannot be placed" is the honest answer and no real path has one.
    const c = canonicalize('src' + String.fromCharCode(0) + 'x.ts', WS);
    assert.equal(c.unknown, true);
    assert.equal(candidatesOf(c).length, 0);
  });

  test('a drive-relative path with a traversal is unplaceable', () => {
    // `C:foo` is relative to the current directory *of that drive*, which is
    // process state we do not have. Skipping the physical walk for it would
    // suppress the second candidate on a syntactic property of the input
    // rather than on any proof that the two readings agree.
    const c = canonicalize('C:escape' + S + '..' + S + 'notes.txt', WS);
    assert.equal(candidatesOf(c).length, 0, 'must not resolve to a single confident answer');
  });

  test('a drive-relative path without a traversal is unaffected', () => {
    const c = canonicalize('C:foo' + S + 'bar.ts', WS);
    assert.equal(candidatesOf(c).length, 1);
  });

  test('an unreadable component is unplaceable, not silently lexical', () => {
    // If `lstat` is refused rather than answering "missing", carrying on would
    // quietly degrade the physical walk to a lexical one for the rest of the
    // path — which is the behaviour the walk exists to replace.
    const denied: PathIO = {
      isSymlink() {
        const e = new Error('EACCES') as NodeJS.ErrnoException;
        e.code = 'EACCES';
        throw e;
      },
      readlink: () => '',
      realpath: (p) => p,
    };
    const got = resolvePhysical('/proj/secret/../x', '/proj', denied);
    assert.equal(got.exhausted, true);
    assert.equal(got.abs, '');
  });

  test('a genuinely missing component is still resolved, not refused', () => {
    // The other side: `ENOENT` must stay cheap and must keep working, or every
    // not-yet-created file becomes a prompt.
    const missing: PathIO = {
      isSymlink() {
        const e = new Error('ENOENT') as NodeJS.ErrnoException;
        e.code = 'ENOENT';
        throw e;
      },
      readlink: () => '',
      realpath: (p) => p,
    };
    const got = resolvePhysical('/proj/nope/../x', '/proj', missing);
    assert.equal(got.exhausted, false);
    assert.equal(norm(got.abs), '/proj/x');
  });
});
