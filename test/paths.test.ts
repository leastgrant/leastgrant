/**
 * Containment tests.
 *
 * Every question this module answers is a security question wearing a
 * filesystem costume. "Is this file inside the project?" decides whether a
 * write is routine or an escape, whether a read is your source or your SSH key.
 * A wrong answer here is not a cosmetic bug: it is a file outside the project
 * judged to be inside it, and everything downstream trusts that judgement.
 *
 * The reverse error is not free either. A file that really is in the project
 * but reads as "outside" turns routine work into a prompt, and — worse —
 * collapses `<path>` and `<path:outside>` into one signature, which is a
 * distinction the promotion model depends on. So every "this escape is caught"
 * case below is paired with an "and this ordinary lookalike is not".
 *
 * Most of the cases here are regressions. They are here because they were wrong
 * at some point during development — the sibling-prefix match, the `..hidden`
 * false escape, the 8.3 short-path root, the trailing-dot traversal. They are
 * not hypotheticals.
 *
 * Determinism rules this file keeps:
 *   - nothing depends on the clock;
 *   - nothing writes outside the temp directory it created itself, and that
 *     directory is removed (and the removal verified) in after();
 *   - nothing touches the network;
 *   - os.homedir() is *read* — canonicalize and displayPath both consult it, so
 *     testing them at all requires it — but only ever joined with names that do
 *     not exist, and never written to;
 *   - where a case genuinely cannot run on this machine (no symlink privilege,
 *     a tmpdir with no 8.3 alias) it is reported as a skip with a reason, never
 *     as a green test that quietly asserted nothing.
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { UNRESOLVED } from '../src/core/shell/tokenize.js';
import {
  CASE_INSENSITIVE,
  candidatesOf,
  canonicalDir,
  canonicalRoots,
  canonicalize,
  displayPath,
  findProjectRoot,
  inWorkspace,
  isInside,
  looksLikePath,
  samePath,
} from '../src/core/paths.js';

const WIN = process.platform === 'win32';

/**
 * An absolute path on whatever the current drive/root is, so the string tests
 * below work identically on POSIX and Windows.
 */
function abs(...segments: string[]): string {
  return path.resolve(path.sep + segments.join(path.sep));
}

/**
 * Create a directory link. Returns `false` (node:test's "do not skip") on
 * success, or a reason string when the machine will not let us — so the caller
 * can hand it straight to `{ skip }` instead of silently returning from a test
 * body that then asserts nothing.
 */
function tryLink(target: string, linkPath: string): string | false {
  try {
    fs.symlinkSync(target, linkPath, WIN ? 'junction' : 'dir');
    return false;
  } catch {
    return 'this machine will not create a symlink/junction here';
  }
}

// ---------------------------------------------------------------------------
// A real directory tree. Created once, removed in after().
// ---------------------------------------------------------------------------

/**
 * The fixture root, canonicalized.
 *
 * `os.tmpdir()` is itself behind a symlink on macOS — `/var` is a link to
 * `/private/var` — so the raw `mkdtemp` result and everything this suite
 * compares it against (which goes through `realpath`) are two different
 * strings for one directory. Resolving it once here is the difference between
 * testing path containment and testing whether the fixture happens to live on
 * a tidy filesystem.
 */
const TMP = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'lg-paths-')));

after(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
  // If a junction or a lock defeated the removal we want to know, not to leave
  // a directory behind on every run.
  assert.equal(fs.existsSync(TMP), false, `temp directory leaked: ${TMP}`);
});

/** The workspace under test. */
const WS = path.join(TMP, 'ws');
/** A directory deliberately outside the workspace, for the symlink escape. */
const OUTSIDE = path.join(TMP, 'outside');
/**
 * A perfectly ordinary directory inside the workspace whose name begins with
 * `..`. path.relative renders it as `..hidden/...`, which is exactly what a
 * traversal looks like to a prefix test.
 */
const DOTDOT = path.join(WS, '..hidden');

fs.mkdirSync(path.join(WS, 'src'), { recursive: true });
fs.mkdirSync(OUTSIDE, { recursive: true });
fs.mkdirSync(DOTDOT, { recursive: true });
fs.writeFileSync(path.join(WS, 'src', 'a.ts'), 'export {};\n');
fs.writeFileSync(path.join(DOTDOT, 'x.txt'), 'ordinary\n');
fs.writeFileSync(path.join(OUTSIDE, 'secret.txt'), 'shh\n');

/** The workspace as the rest of the code would hold it: canonical. */
const WSC = canonicalDir(WS);
const OUTSIDEC = canonicalDir(OUTSIDE);

/** A link out of the workspace, and a link that stays inside it. */
const ESCAPE_LINK = path.join(WS, 'escape');
const ESCAPE_SKIP = tryLink(OUTSIDE, ESCAPE_LINK);
const INNER_LINK = path.join(WS, 'inner-link');
const INNER_SKIP = tryLink(path.join(WS, 'src'), INNER_LINK);
/** The workspace reached under a second, non-canonical name. */
const WS_ALIAS = path.join(TMP, 'ws-alias');
const ALIAS_SKIP = tryLink(WS, WS_ALIAS);

// ---------------------------------------------------------------------------
// isInside — the core predicate
// ---------------------------------------------------------------------------

describe('isInside', () => {
  const root = abs('proj');

  test('a path equal to the root is inside it', () => {
    assert.equal(isInside(root, root), true);
  });

  test('a child is inside', () => {
    assert.equal(isInside(path.join(root, 'src', 'a.ts'), root), true);
  });

  test('a deep child is inside', () => {
    assert.equal(isInside(path.join(root, 'a', 'b', 'c', 'd', 'e.txt'), root), true);
  });

  test('the parent of the root is not inside it', () => {
    assert.equal(isInside(path.dirname(root), root), false);
  });

  /**
   * The classic startsWith bug. `/proj-evil/x`.startsWith(`/proj`) is true, so
   * any implementation that compares prefixes hands an attacker the whole
   * filesystem for the price of one directory name.
   */
  test('SIBLING PREFIX: /proj-evil/x is not inside /proj', () => {
    const evil = abs('proj-evil');
    // The bug this guards against, stated plainly:
    assert.equal(path.join(evil, 'x').startsWith(root), true);
    // And the behaviour we actually require:
    assert.equal(isInside(path.join(evil, 'x'), root), false);
    assert.equal(isInside(evil, root), false);
  });

  /**
   * The mirror of the sibling-prefix case, and a regression in the opposite
   * direction. `path.relative('/proj', '/proj/..hidden/x')` is `..hidden/x`, so
   * a `rel.startsWith('..')` test calls a genuine child an escape. Only a first
   * component of exactly `..` is a climb out.
   */
  test('LOOKALIKE: a child whose directory name begins with .. is still inside', () => {
    const child = path.join(root, '..hidden', 'x.txt');
    // The trap, stated plainly:
    assert.equal(path.relative(root, child).startsWith('..'), true);
    // And the behaviour we actually require:
    assert.equal(isInside(child, root), true);
    assert.equal(isInside(path.join(root, '..hidden'), root), true);
    assert.equal(isInside(path.join(root, '..a', '..b', 'c.txt'), root), true);
    // A component of three dots is a legal directory name, not navigation.
    assert.equal(isInside(path.join(root, '...', 'y'), root), true);
    // ...while a component of exactly `..` still climbs out.
    assert.equal(isInside(path.resolve(root, '..'), root), false);
  });

  test('a sibling that shares no prefix is not inside', () => {
    assert.equal(isInside(abs('other', 'x'), root), false);
  });

  test('../ traversal is not inside', () => {
    // path.relative is fed already-resolved paths in production, but the
    // predicate must still refuse an unresolved climb out.
    assert.equal(isInside(path.resolve(root, '..', 'etc', 'passwd'), root), false);
  });

  test('a traversal that starts plausibly is not inside', () => {
    const escaped = path.resolve(root, 'src', '..', '..', '..', 'etc', 'passwd');
    assert.equal(isInside(escaped, root), false);
  });

  test('an empty child or root is never inside', () => {
    assert.equal(isInside('', root), false);
    assert.equal(isInside(root, ''), false);
    assert.equal(isInside('', ''), false);
  });

  test('case handling follows the platform', () => {
    const shouty = path.join(root.toUpperCase(), 'src');
    assert.equal(isInside(shouty, root), CASE_INSENSITIVE);
  });

  test('samePath follows the same platform rule', () => {
    assert.equal(samePath(root, root), true);
    assert.equal(samePath(root.toUpperCase(), root), CASE_INSENSITIVE);
    assert.equal(samePath('', root), false);
  });
});

describe('inWorkspace', () => {
  test('true when any root contains the path', () => {
    const roots = [abs('a'), abs('b')];
    assert.equal(inWorkspace(path.join(abs('b'), 'x.ts'), roots), true);
  });

  test('false when no root contains the path', () => {
    assert.equal(inWorkspace(abs('c', 'x.ts'), [abs('a'), abs('b')]), false);
  });

  test('false for no roots at all', () => {
    assert.equal(inWorkspace(abs('a', 'x.ts'), []), false);
  });
});

// ---------------------------------------------------------------------------
// canonicalize
// ---------------------------------------------------------------------------

describe('canonicalize', () => {
  test('resolves ../ segments', () => {
    const c = canonicalize(path.join('src', '..', 'src', 'a.ts'), WSC);
    assert.equal(samePath(c.abs, path.join(WSC, 'src', 'a.ts')), true);
    assert.equal(c.unknown, false);
  });

  test('a plausible-looking traversal really does leave the workspace', () => {
    const c = canonicalize(path.join('src', '..', '..', 'outside', 'secret.txt'), WSC);
    assert.equal(samePath(c.abs, path.join(OUTSIDEC, 'secret.txt')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  /**
   * The `..hidden` case end to end, against a directory that really exists:
   * a `..`-prefixed name must survive resolution and stay in the workspace.
   */
  test('LOOKALIKE: a real file under a ..-prefixed directory stays in the workspace', () => {
    const c = canonicalize(path.join('..hidden', 'x.txt'), WSC);
    assert.equal(c.unknown, false);
    assert.equal(samePath(c.abs, path.join(WSC, '..hidden', 'x.txt')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
    assert.equal(displayPath(c.abs, WSC), '..hidden/x.txt');
  });

  test('a trailing .. climbs out of the workspace', () => {
    // Regression: a Windows-only rewrite that strips trailing dots must not eat
    // the `..` component, or `ls ..` reads as "the workspace itself".
    const c = canonicalize('..', WSC);
    assert.equal(samePath(c.abs, canonicalDir(path.dirname(WSC))), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  test('a relative path is resolved against cwd, not process.cwd()', () => {
    const c = canonicalize('src', WSC);
    assert.equal(samePath(c.abs, path.join(WSC, 'src')), true);
  });

  test('an absolute input ignores cwd', () => {
    const target = path.join(OUTSIDEC, 'secret.txt');
    const c = canonicalize(target, WSC);
    assert.equal(samePath(c.abs, target), true);
  });

  test('expands a leading ~', () => {
    // os.homedir() is read, never written: both names below are joined onto it
    // only to be resolved as strings.
    const home = canonicalDir(os.homedir());
    assert.equal(samePath(canonicalize('~', WSC).abs, home), true);
    assert.equal(
      samePath(canonicalize('~/lg-no-such-file.txt', WSC).abs, path.join(home, 'lg-no-such-file.txt')),
      true,
    );
  });

  test('does not expand a ~ that is not the first component', () => {
    const c = canonicalize(path.join('src', '~', 'x'), WSC);
    assert.equal(samePath(c.abs, path.join(WSC, 'src', '~', 'x')), true);
  });

  test('does not expand ~user', () => {
    // We cannot resolve another account's home, and guessing is worse than
    // treating it as a relative name.
    const c = canonicalize('~root/x', WSC);
    assert.equal(samePath(c.abs, path.join(WSC, '~root', 'x')), true);
  });

  test('does not expand a ~ buried in a filename', () => {
    // `backup~/x` and `a~b` are ordinary names; only a leading `~` component
    // is a home reference.
    assert.equal(samePath(canonicalize('backup~/x', WSC).abs, path.join(WSC, 'backup~', 'x')), true);
    assert.equal(samePath(canonicalize('a~b.txt', WSC).abs, path.join(WSC, 'a~b.txt')), true);
  });

  test('an unresolved expansion yields abs="" and unknown=true', () => {
    const c = canonicalize(`/tmp/${UNRESOLVED}/x`, WSC);
    assert.equal(c.abs, '');
    assert.equal(c.unknown, true);
    assert.equal(c.realpathed, false);
    assert.equal(c.raw, `/tmp/${UNRESOLVED}/x`);
  });

  test('an empty input is unknown', () => {
    const c = canonicalize('', WSC);
    assert.equal(c.abs, '');
    assert.equal(c.unknown, true);
  });

  test('an unknown path is never inside a workspace', () => {
    assert.equal(inWorkspace(canonicalize(UNRESOLVED, WSC).abs, [WSC]), false);
  });

  test('raw preserves the input as written', () => {
    const c = canonicalize('src/../src/a.ts', WSC);
    assert.equal(c.raw, 'src/../src/a.ts');
    assert.notEqual(c.abs, c.raw);
  });
});

describe('canonicalize of paths that do not exist yet', () => {
  test('a non-existent file in an existing directory still resolves', () => {
    const c = canonicalize(path.join(WSC, 'src', 'brand-new.ts'), WSC);
    assert.equal(c.unknown, false);
    assert.equal(path.isAbsolute(c.abs), true);
    assert.equal(samePath(c.abs, path.join(WSC, 'src', 'brand-new.ts')), true);
    // The existing ancestor was realpathed, so this counts as resolved.
    assert.equal(c.realpathed, true);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
  });

  test('several non-existent segments deep still resolves', () => {
    const c = canonicalize(path.join(WSC, 'no', 'such', 'dir', 'file.txt'), WSC);
    assert.equal(samePath(c.abs, path.join(WSC, 'no', 'such', 'dir', 'file.txt')), true);
    assert.equal(c.realpathed, true);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
  });

  test('a write to a not-yet-existing file outside the workspace is caught', () => {
    const c = canonicalize(path.join(OUTSIDEC, 'not-created-yet.txt'), WSC);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  test('a path whose ancestors do not exist at all resolves to that same path', () => {
    const target = abs('lg-nonexistent-root', 'a', 'b');
    const c = canonicalize(target, WSC);
    assert.equal(c.unknown, false);
    assert.equal(path.isAbsolute(c.abs), true);
    // Not merely "absolute": the exact path, unchanged apart from normalization.
    assert.equal(samePath(c.abs, target), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });
});

// ---------------------------------------------------------------------------
// canonicalDir / canonicalRoots — the boundary itself must be canonical
// ---------------------------------------------------------------------------

describe('canonicalDir and canonicalRoots', () => {
  test('a root given with a ./ segment still contains its children', () => {
    const root = canonicalDir(path.join(WS, '.', 'src'));
    assert.equal(isInside(canonicalize(path.join(WS, 'src', 'a.ts'), WS).abs, root), true);
  });

  test('a root given with a ../ segment still contains its children', () => {
    // `<ws>/src/..` is the workspace. A root written that way must behave
    // exactly like the workspace, or containment silently narrows.
    const root = canonicalDir(path.join(WS, 'src', '..'));
    assert.equal(samePath(root, WSC), true);
    assert.equal(isInside(canonicalize(path.join(WS, 'src', 'a.ts'), WS).abs, root), true);
  });

  test('a root with a trailing separator still contains its children', () => {
    const root = canonicalDir(WS + path.sep);
    assert.equal(isInside(canonicalize(path.join(WS, 'src', 'a.ts'), WS).abs, root), true);
  });

  test('canonicalDir of an empty string is empty', () => {
    assert.equal(canonicalDir(''), '');
  });

  test('canonicalDir is idempotent on an already-canonical root', () => {
    // The repair must be a fixed point, or a root canonicalized twice by two
    // different call sites would stop comparing equal to itself.
    assert.equal(samePath(canonicalDir(WSC), WSC), true);
    assert.equal(samePath(canonicalDir(canonicalDir(WSC)), WSC), true);
  });

  test('canonicalRoots drops empties and de-duplicates', () => {
    const roots = canonicalRoots([WS, '', WS + path.sep, path.join(WS, 'src', '..'), OUTSIDE, WS]);
    assert.equal(roots.length, 2);
    // Membership, not position. Nothing downstream reads these by index —
    // inWorkspace uses `.some` — so pinning the order would only make a
    // harmless reordering look like a regression.
    assert.equal(roots.some((r) => samePath(r, WSC)), true, 'the workspace root must survive');
    assert.equal(roots.some((r) => samePath(r, OUTSIDEC)), true, 'the second root must survive');
  });

  test('canonicalRoots output actually contains the files under each root', () => {
    const roots = canonicalRoots([WS, OUTSIDE]);
    assert.equal(inWorkspace(canonicalize(path.join(WS, 'src', 'a.ts'), WS).abs, roots), true);
    assert.equal(inWorkspace(canonicalize(path.join(OUTSIDE, 'secret.txt'), WS).abs, roots), true);
  });

  test('a file under os.tmpdir() is inside canonicalDir(os.tmpdir())', () => {
    const child = canonicalize(path.join(TMP, 'ws', 'src', 'a.ts'), TMP);
    assert.equal(isInside(child.abs, canonicalDir(os.tmpdir())), true);
  });
});

/**
 * The 8.3 case and the symlinked-root case are one bug: a boundary held in a
 * form that realpath would rewrite. On Windows `os.tmpdir()` often comes back
 * short (`C:\Users\RUNNER~1\AppData\Local\Temp`) while realpath of a child
 * returns the long form; on POSIX a root reached through a symlink does the
 * same. Compare a resolved child against an unresolved root and every file in
 * the workspace reads as "outside".
 *
 * A link we create ourselves reproduces it deterministically on both platforms,
 * instead of hoping this machine's tmpdir happens to have an 8.3 alias.
 */
describe('a root held in a non-canonical form', { skip: ALIAS_SKIP }, () => {
  test('the raw alias fails to contain the child, and canonicalDir repairs it', () => {
    const child = canonicalize(path.join(WS, 'src', 'a.ts'), WS);
    assert.equal(samePath(WS_ALIAS, WSC), false, 'precondition: the alias is a different string');
    assert.equal(isInside(child.abs, WS_ALIAS), false, 'the un-canonicalized root must fail');
    assert.equal(samePath(canonicalDir(WS_ALIAS), WSC), true, 'canonicalDir must resolve the alias');
    assert.equal(isInside(child.abs, canonicalDir(WS_ALIAS)), true, 'and must repair containment');
  });

  test('canonicalRoots repairs an alias root too, and folds it into the real one', () => {
    const roots = canonicalRoots([WS_ALIAS, WS]);
    assert.equal(roots.length, 1, 'the alias and the real path are one root');
    assert.equal(inWorkspace(canonicalize(path.join(WS, 'src', 'a.ts'), WS).abs, roots), true);
    // ...and the repair did not widen the boundary to something outside.
    assert.equal(inWorkspace(canonicalize(path.join(OUTSIDE, 'secret.txt'), WS).abs, roots), false);
  });
});

/**
 * Windows-only, and only meaningful where the machine actually hands out an 8.3
 * alias. When it does not, that is a skip with a reason — not a test body that
 * returns early and reports green having asserted nothing.
 */
const SHORT_TMP_SKIP: string | false = !WIN
  ? 'windows only'
  : samePath(os.tmpdir(), canonicalDir(os.tmpdir()))
    ? "this machine's os.tmpdir() is already long-form; no 8.3 alias to test"
    : false;

test('WINDOWS 8.3: the short-form root does not contain the long-form child', { skip: SHORT_TMP_SKIP }, () => {
  const short = os.tmpdir();
  const long = canonicalDir(os.tmpdir());
  const child = canonicalize(path.join(TMP, 'ws', 'src', 'a.ts'), TMP);
  assert.equal(isInside(child.abs, short), false, 'expected the raw short-form root to fail');
  assert.equal(isInside(child.abs, long), true, 'canonicalDir must repair it');
});

// ---------------------------------------------------------------------------
// Symlink escape — and the link that does not escape
// ---------------------------------------------------------------------------

describe('symlink escape', { skip: ESCAPE_SKIP }, () => {
  test('a file reached through the link resolves outside the workspace', () => {
    const c = canonicalize(path.join(ESCAPE_LINK, 'secret.txt'), WS);
    assert.equal(c.realpathed, true);
    assert.equal(samePath(c.abs, path.join(OUTSIDEC, 'secret.txt')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  test('the link directory itself resolves outside', () => {
    const c = canonicalize(ESCAPE_LINK, WS);
    assert.equal(samePath(c.abs, OUTSIDEC), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  test('a not-yet-created file through the link also resolves outside', () => {
    // The dangerous one: a write to a file that does not exist yet, inside a
    // directory that is a link out. Walking back to the longest existing
    // ancestor is what makes this catchable.
    const c = canonicalize(path.join(ESCAPE_LINK, 'planted.txt'), WS);
    assert.equal(samePath(c.abs, path.join(OUTSIDEC, 'planted.txt')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  /**
   * `escape\..\x` on Windows. Win32 collapses `..` in the path string before
   * the object manager ever follows a reparse point, so this really does open
   * `<ws>\x`. Resolving it lexically is therefore the correct answer here, not
   * a miss.
   */
  test(
    'WINDOWS: .. after a junction is lexical natively, and the ambiguity is recorded',
    { skip: !WIN ? 'windows only' : false },
    () => {
      const trav = [WS, 'escape', '..', 'src', 'a.ts'].join(path.sep);
      const c = canonicalize(trav, WS);
      // `abs` is what this OS would really do: Win32 collapses `..` in the
      // string before the object manager follows the reparse point. Verified
      // by reading a file through exactly this construction.
      assert.equal(samePath(c.abs, path.join(WSC, 'src', 'a.ts')), true);
      assert.equal(inWorkspace(c.abs, [WSC]), true);
      // But the physical reading is recorded too, because the same string
      // means something else to a POSIX kernel — and to anything running under
      // WSL or Cygwin on this very machine.
      assert.ok(c.alt, 'the second candidate should be recorded');
      assert.equal(inWorkspace(c.alt as string, [WSC]), false);
    },
  );

  /**
   * POSIX is the other way round: the kernel follows the symlink first, so
   * `ws/escape/..` is the *target's* parent, outside the workspace.
   *
   * This was a recorded defect — `canonicalize` called `path.resolve` before
   * `realpath`, which collapsed the `..` lexically, so it reported "inside" for
   * a read the kernel serves from somewhere else. It now resolves per component
   * and this is the primary answer on POSIX.
   */
  test(
    'POSIX: .. after a symlink is physical',
    { skip: WIN ? 'posix only' : false },
    () => {
      const trav = [WS, 'escape', '..', 'planted.txt'].join(path.sep);
      const c = canonicalize(trav, WS);
      // The kernel reads <tmp>/planted.txt, which is not in the workspace.
      assert.equal(inWorkspace(c.abs, [WSC]), false);
      assert.equal(samePath(c.abs, path.join(TMP, 'planted.txt')), true);
    },
  );

  /**
   * The platform-independent half, and the one that actually protects anybody:
   * whatever this OS does natively, both readings are kept, and nothing is
   * called contained unless every reading agrees.
   */
  test('both readings are recorded, and containment requires both', () => {
    const trav = [WS, 'escape', '..', 'planted.txt'].join(path.sep);
    const c = canonicalize(trav, WS);
    const cands = candidatesOf(c);
    assert.equal(cands.length, 2, `expected two candidates, got ${JSON.stringify(cands)}`);
    assert.equal(
      cands.every((a) => inWorkspace(a, [WSC])),
      false,
      'one reading lands outside the project, so the path is not contained',
    );
  });

  test('a link that stays inside produces one candidate and no ambiguity', () => {
    // The negative control. If every `..` started producing two candidates the
    // fix would just be "call everything outside", which is not a fix.
    const c = canonicalize([WS, 'src', '..', 'src', 'a.ts'].join(path.sep), WS);
    assert.equal(candidatesOf(c).length, 1);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
  });
});

/**
 * The negative half. Symlink resolution exists to catch escapes; it must not
 * start reporting escapes for links that never leave. A link is not evidence.
 */
describe('a link that does not escape', { skip: INNER_SKIP }, () => {
  test('a link pointing inside the workspace stays inside', () => {
    const c = canonicalize(path.join(INNER_LINK, 'a.ts'), WS);
    assert.equal(c.realpathed, true);
    assert.equal(samePath(c.abs, path.join(WSC, 'src', 'a.ts')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
  });

  test('a not-yet-created file through an inward link is also inside', () => {
    const c = canonicalize(path.join(INNER_LINK, 'brand-new.ts'), WS);
    assert.equal(samePath(c.abs, path.join(WSC, 'src', 'brand-new.ts')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), true);
  });
});

// ---------------------------------------------------------------------------
// looksLikePath
// ---------------------------------------------------------------------------

describe('looksLikePath', () => {
  const yes = [
    './x',
    '/etc/passwd',
    'src/a.ts',
    '.env',
    'package.json',
    'src/*.ts',
    '..',
    '~',
    '~/.ssh/id_rsa',
    'C:\\Windows\\System32',
    '.npmrc',
    'dist/index.js',
  ];
  for (const arg of yes) {
    test(`true for ${JSON.stringify(arg)}`, () => {
      assert.equal(looksLikePath(arg), true);
    });
  }

  const no: Array<[string, string]> = [
    ['-rf', 'a flag'],
    ['--no-verify', 'a long flag'],
    ['', 'empty'],
    ['status', 'a bare word'],
    ['https://example.com', 'a URL'],
    ['git+ssh://host/repo.git', 'a URL with a compound scheme'],
    ['echo hi; rm -rf /', 'shell punctuation'],
    ['$HOME/x', 'a dollar expansion'],
    ['`whoami`', 'a command substitution'],
    ['a && b', 'an operator'],
    ['"quoted"', 'quotes'],
    ['import os\nos.system("id")', 'a multi-line python program'],
    ['a\tb', 'a tab'],
    [`x${UNRESOLVED}y`, 'an unresolved expansion'],
    ['HEAD', 'a git ref'],
    ['--file=src/a.ts', 'a flag that embeds a path'],
    ['a:b', 'a colon-separated pair that is not a drive'],
  ];
  for (const [arg, why] of no) {
    test(`false for ${why}`, () => {
      assert.equal(looksLikePath(arg), false);
    });
  }

  test('a long POSIX path is still a path', () => {
    // This used to be capped at 260 (the old Windows MAX_PATH), which was a
    // security bug rather than a nicety: the signature layer called anything
    // longer `<text>` while the capability layer still resolved it as a file,
    // so two different files shared one learned identity. POSIX paths are
    // routinely longer than 260 bytes.
    const long = 'src/' + 'a'.repeat(300) + '.ts';
    assert.equal(long.length > 260, true);
    assert.equal(looksLikePath(long), true);
    assert.equal(looksLikePath('src/' + 'a'.repeat(50) + '.ts'), true);
  });

  test('but something absurdly long is not a path', () => {
    assert.equal(looksLikePath('src/' + 'a'.repeat(5000) + '.ts'), false);
  });

  test('parentheses appear in real Windows paths', () => {
    // `Program Files (x86)` was being rejected, with the same
    // signature-versus-capability split as the length cap.
    assert.equal(looksLikePath('C:/Program Files (x86)/app/tool.exe'), true);
    assert.equal(looksLikePath('./build (copy)/out.js'), true);
  });

  test('a Windows drive letter is not mistaken for a URL scheme', () => {
    assert.equal(looksLikePath('C:/Users/me/x.txt'), true);
    assert.equal(looksLikePath('C:'), true);
  });

  test('a real multi-line program is rejected even when it contains slashes', () => {
    assert.equal(looksLikePath('for f in /etc/*; do\n  cat "$f"\ndone'), false);
  });
});

// ---------------------------------------------------------------------------
// Windows path aliasing
// ---------------------------------------------------------------------------

describe('windows path aliasing', { skip: !WIN ? 'windows only' : false }, () => {
  test('secrets.txt::$DATA is the same path as secrets.txt', () => {
    const plain = canonicalize(path.join(WS, 'secrets.txt'), WS);
    const ads = canonicalize(path.join(WS, 'secrets.txt') + '::$DATA', WS);
    assert.equal(samePath(ads.abs, plain.abs), true);
  });

  test('a named stream suffix is stripped too', () => {
    const plain = canonicalize(path.join(WS, 'secrets.txt'), WS);
    const ads = canonicalize(path.join(WS, 'secrets.txt') + '::hidden:$DATA', WS);
    assert.equal(samePath(ads.abs, plain.abs), true);
  });

  test('an ADS suffix does not smuggle a file out of the workspace check', () => {
    const c = canonicalize(path.join(OUTSIDE, 'secret.txt') + '::$DATA', WS);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
    assert.equal(samePath(c.abs, path.join(OUTSIDEC, 'secret.txt')), true);
  });

  /**
   * The negative half of the ADS strip. It must fire on the `::…$DATA` suffix
   * and nothing else — truncating an ordinary filename would point every
   * downstream check at a different file than the one being opened.
   */
  test('LOOKALIKE: a filename that merely contains $DATA is left intact', () => {
    for (const name of ['my$DATA.txt', 'notes.txt.$DATA', '$DATA', 'DATA.txt']) {
      const c = canonicalize(path.join(WS, name), WS);
      assert.equal(path.basename(c.abs), name, `${name} must not be truncated`);
      assert.equal(inWorkspace(c.abs, [WSC]), true);
    }
  });

  test('a \\\\?\\ extended-length prefix normalizes away', () => {
    const plain = canonicalize(path.join(WS, 'src', 'a.ts'), WS);
    const ext = canonicalize('\\\\?\\' + path.join(WS, 'src', 'a.ts'), WS);
    assert.equal(samePath(ext.abs, plain.abs), true);
    assert.equal(inWorkspace(ext.abs, [WSC]), true);
  });

  test('a \\\\.\\ device prefix normalizes away', () => {
    const plain = canonicalize(path.join(WS, 'src', 'a.ts'), WS);
    const dev = canonicalize('\\\\.\\' + path.join(WS, 'src', 'a.ts'), WS);
    assert.equal(samePath(dev.abs, plain.abs), true);
  });

  test('an extended-length prefix does not smuggle a file in', () => {
    // The prefix strip must not be usable to relabel an outside file as inside.
    const c = canonicalize('\\\\?\\' + path.join(OUTSIDE, 'secret.txt'), WS);
    assert.equal(samePath(c.abs, path.join(OUTSIDEC, 'secret.txt')), true);
    assert.equal(inWorkspace(c.abs, [WSC]), false);
  });

  test('trailing dots and spaces are stripped', () => {
    const plain = canonicalize(path.join(WS, 'src', 'a.ts'), WS);
    assert.equal(samePath(canonicalize(path.join(WS, 'src', 'a.ts') + '.', WS).abs, plain.abs), true);
    assert.equal(samePath(canonicalize(path.join(WS, 'src', 'a.ts') + ' ', WS).abs, plain.abs), true);
    assert.equal(
      samePath(canonicalize(path.join(WS, 'src', 'a.ts') + '. . ', WS).abs, plain.abs),
      true,
    );
  });

  test('stripping trailing dots does not eat a . or .. component', () => {
    // Regression: `<ws>\..` must be the parent of the workspace, not the
    // workspace. Stripping the dots turns an escape into a no-op.
    assert.equal(
      samePath(canonicalize(WS + '\\..', WS).abs, canonicalDir(path.dirname(WSC))),
      true,
    );
    assert.equal(samePath(canonicalize(WS + '\\src\\.', WS).abs, path.join(WSC, 'src')), true);
    assert.equal(samePath(canonicalize(WS + '\\src\\..', WS).abs, WSC), true);
  });

  test('LOOKALIKE: an interior dot in a filename is not touched', () => {
    // The strip is anchored to the end of a component. A name that merely
    // contains dots must come through byte for byte.
    for (const name of ['a.b.c.ts', '.hidden.rc', 'v1.2.3']) {
      assert.equal(path.basename(canonicalize(path.join(WS, name), WS).abs), name);
    }
  });

  test('the case of a drive letter does not change containment', () => {
    const upper = WSC.charAt(0).toUpperCase() + WSC.slice(1);
    const lower = WSC.charAt(0).toLowerCase() + WSC.slice(1);
    assert.equal(isInside(path.join(upper, 'src', 'a.ts'), lower), true);
  });
});

describe('posix path handling', { skip: WIN ? 'posix only' : false }, () => {
  test('a ::$DATA suffix is left alone off Windows', () => {
    // It is a legal (if silly) filename on POSIX and stripping it would point
    // us at the wrong file.
    const c = canonicalize(path.join(WS, 'secrets.txt::$DATA'), WS);
    assert.equal(path.basename(c.abs), 'secrets.txt::$DATA');
  });

  test('a trailing dot is a real filename character off Windows', () => {
    const c = canonicalize(path.join(WS, 'weird.'), WS);
    assert.equal(path.basename(c.abs), 'weird.');
  });

  test('case sensitivity follows the filesystem, not the platform', () => {
    // Not "off Windows means case-sensitive": macOS is POSIX and its default
    // filesystem is case-*in*sensitive, which is why `CASE_INSENSITIVE` covers
    // darwin too. Asserting the platform rather than the behaviour is how this
    // failed on every macOS runner while passing on Linux.
    const upper = path.join(WSC.toUpperCase(), 'src');
    assert.equal(
      isInside(upper, WSC),
      CASE_INSENSITIVE,
      CASE_INSENSITIVE
        ? 'on a case-insensitive filesystem the upper-case spelling is the same directory'
        : 'on a case-sensitive filesystem it is a different directory entirely',
    );
  });
});

// ---------------------------------------------------------------------------
// displayPath
// ---------------------------------------------------------------------------

describe('displayPath', () => {
  test('renders a workspace-relative path with forward slashes', () => {
    assert.equal(displayPath(path.join(WSC, 'src', 'a.ts'), WSC), 'src/a.ts');
    assert.equal(displayPath(path.join(WSC, 'a', 'b', 'c.txt'), WSC), 'a/b/c.txt');
  });

  test('the root itself renders as .', () => {
    assert.equal(displayPath(WSC, WSC), '.');
  });

  /**
   * The behaviour that matters for an unknown path is that it renders as
   * *something* which cannot be mistaken for a real location — not that the
   * placeholder is spelled any particular way.
   */
  test('an unknown path renders as a placeholder, not as a location', () => {
    const shown = displayPath('', WSC);
    assert.notEqual(shown, '', 'must render something');
    assert.notEqual(shown, '.', "'.' already means the workspace root");
    assert.equal(path.isAbsolute(shown), false, 'must not look like an absolute path');
    assert.equal(/[\\/]/.test(shown), false, 'must not look like a relative path');
    assert.equal(shown, displayPath('', canonicalDir(TMP)), 'must not depend on the root');
  });

  test('a path under home but outside the workspace renders with ~', () => {
    // Built from the raw homedir, because that is the string displayPath
    // itself compares against; this stays correct on a machine whose home has
    // an 8.3 or symlinked alias.
    const home = os.homedir();
    const p = path.join(home, 'lg-not-a-real-dir', 'x.txt');
    assert.equal(isInside(p, WSC), false, 'precondition: the probe path is outside the workspace');
    assert.equal(displayPath(p, WSC), '~/lg-not-a-real-dir/x.txt');
  });

  test('LOOKALIKE: a sibling of home is not rendered as ~', () => {
    // `<home>-evil` shares a prefix with home and must not borrow its `~`.
    const evil = os.homedir() + '-evil';
    const shown = displayPath(path.join(evil, 'x.txt'), WSC);
    assert.equal(shown.startsWith('~'), false, `expected an absolute render, got ${shown}`);
    assert.equal(shown.endsWith('-evil/x.txt'), true);
  });

  test('a path outside both renders absolute with forward slashes', () => {
    const p = abs('lg-definitely-outside', 'x.txt');
    const shown = displayPath(p, WSC);
    assert.equal(shown.includes('\\'), false);
    assert.equal(shown.endsWith('lg-definitely-outside/x.txt'), true);
  });

  test('a sibling-prefix directory is not rendered as workspace-relative', () => {
    const evil = WSC + '-evil';
    const shown = displayPath(path.join(evil, 'x.txt'), WSC);
    assert.equal(shown.startsWith('x.txt'), false);
    assert.equal(shown.includes('-evil/x.txt'), true);
  });
});

// ---------------------------------------------------------------------------
// findProjectRoot
// ---------------------------------------------------------------------------

describe('findProjectRoot', () => {
  const repo = path.join(TMP, 'repo');
  const deep = path.join(repo, 'a', 'b', 'c');
  fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
  fs.mkdirSync(deep, { recursive: true });

  const pkgRepo = path.join(TMP, 'pkgrepo');
  const pkgDeep = path.join(pkgRepo, 'src', 'core');
  fs.mkdirSync(pkgDeep, { recursive: true });
  fs.writeFileSync(path.join(pkgRepo, 'package.json'), '{}\n');

  test('walks up to a directory containing .git', () => {
    assert.equal(samePath(findProjectRoot(deep), canonicalDir(repo)), true);
  });

  test('walks up to a directory containing package.json', () => {
    assert.equal(samePath(findProjectRoot(pkgDeep), canonicalDir(pkgRepo)), true);
  });

  test('a directory that is itself the root returns itself', () => {
    assert.equal(samePath(findProjectRoot(repo), canonicalDir(repo)), true);
  });

  test('the result is canonical, so it works as a containment boundary', () => {
    const root = findProjectRoot(deep);
    assert.equal(path.isAbsolute(root), true);
    assert.equal(samePath(root, canonicalDir(root)), true);
    const child = canonicalize(path.join(deep, 'file.ts'), deep);
    assert.equal(isInside(child.abs, root), true);
  });

  test('the nearest root wins over an outer one', () => {
    const inner = path.join(repo, 'a', 'inner');
    fs.mkdirSync(path.join(inner, '.git'), { recursive: true });
    assert.equal(samePath(findProjectRoot(inner), canonicalDir(inner)), true);
  });

  test('a non-canonical cwd finds the same root', () => {
    assert.equal(samePath(findProjectRoot(path.join(deep, '..', 'b')), canonicalDir(repo)), true);
  });

  /**
   * The negative. A `.gitignore` is not a `.git`, and a `package.json.bak` is
   * not a `package.json`. Treating a lookalike as a marker would silently move
   * the containment boundary — and every project-scoped thing keyed off it.
   *
   * The assertion is "not this directory" rather than "the cwd", because what
   * lies above the temp directory is the machine's business; the claim under
   * test is only that the lookalikes did not match.
   */
  test('LOOKALIKE: marker-shaped filenames are not project roots, but a real marker is', () => {
    const fake = path.join(TMP, 'lookalike');
    const fakeDeep = path.join(fake, 'a', 'b');
    fs.mkdirSync(fakeDeep, { recursive: true });
    for (const name of ['.gitignore', 'gitignore', 'package.json.bak', 'Cargo.toml.orig', 'go.mod.txt']) {
      fs.writeFileSync(path.join(fake, name), '');
    }
    assert.equal(
      samePath(findProjectRoot(fakeDeep), canonicalDir(fake)),
      false,
      'a .gitignore is not a .git',
    );

    // Same tree, one real marker added: now it is the root. This is what makes
    // the assertion above about the marker names and not about the walk.
    fs.mkdirSync(path.join(fake, '.git'));
    assert.equal(samePath(findProjectRoot(fakeDeep), canonicalDir(fake)), true);
  });
});

// ---------------------------------------------------------------------------
// The memo must not confuse two different questions
// ---------------------------------------------------------------------------

describe('canonicalization cache', () => {
  test('the same input under two cwds gives two answers', () => {
    const a = canonicalize('x.txt', path.join(WSC, 'src'));
    const b = canonicalize('x.txt', WSC);
    assert.equal(samePath(a.abs, b.abs), false);
  });

  /**
   * The memo key is `cwd + NUL + input`. If it were joined with a space,
   * `("<t>/sp", "x y")` and `("<t>/sp x", "y")` would be the same key and the
   * second lookup would get the first one's answer. Home directories with
   * spaces are common ("C:\Users\Some User") and so are filenames with spaces,
   * so this pins the separator down.
   */
  test('a cwd containing a space does not collide with a different pair', () => {
    const dirA = path.join(TMP, 'sp');
    const dirB = path.join(TMP, 'sp x');
    fs.mkdirSync(dirA, { recursive: true });
    fs.mkdirSync(dirB, { recursive: true });
    // The two (cwd, input) pairs that a space-joined key would flatten together:
    assert.equal(`${dirA} x y`, `${dirB} y`, 'precondition: a space-joined key would collide');
    const a = canonicalize('x y', dirA); // -> <tmp>/sp/x y
    const b = canonicalize('y', dirB); // -> <tmp>/sp x/y
    assert.equal(samePath(a.abs, path.join(canonicalDir(dirA), 'x y')), true);
    assert.equal(samePath(b.abs, path.join(canonicalDir(dirB), 'y')), true);
    assert.equal(samePath(a.abs, b.abs), false);
  });

  test('a repeated lookup is served from the memo, with the same answer', () => {
    const first = canonicalize(path.join('src', 'a.ts'), WSC);
    for (let i = 0; i < 5; i++) {
      const again = canonicalize(path.join('src', 'a.ts'), WSC);
      assert.equal(again.abs, first.abs);
      // Object identity, not just equal values: a recomputed result would be a
      // fresh object. Without this the test would pass for an implementation
      // with no cache at all, since canonicalize is deterministic anyway.
      assert.equal(again, first, 'expected the cached object, not a recomputation');
    }
  });
});
