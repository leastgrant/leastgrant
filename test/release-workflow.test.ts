/**
 * The release pipeline, checked the way the rest of this project checks things.
 *
 * A release workflow is security-critical code that normally gets reviewed once
 * and then never again, in a language with no type checker and no tests. The
 * properties below are the ones that would be quietly lost by an ordinary,
 * well-meaning edit: someone adds `contents: write` to the publish job to fix
 * an unrelated problem, or bumps an action to a floating tag, or renames the
 * file and breaks the npm trusted-publisher binding without any error until the
 * next release.
 *
 * These are assertions about the *text* of the workflows rather than about a
 * parsed model. That is deliberate: a hand-written YAML parser would be a
 * second thing that could be wrong, and would give false confidence. Block
 * extraction by indentation is crude but it is obvious, and every assertion
 * below fails loudly if the shape it depends on changes.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * The repository root, found by walking up to the nearest package.json.
 *
 * This test reads files that are not compiled, so it cannot use a fixed
 * relative depth: it runs from `dist/test/` after a build and from `test/`
 * if run directly.
 */
function repoRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error('could not locate the repository root');
}
const ROOT = repoRoot();
const WF = path.join(ROOT, '.github', 'workflows');

const read = (name: string): string => fs.readFileSync(path.join(WF, name), 'utf8');

/**
 * The same file with `#` comments removed.
 *
 * Several assertions below are of the form "this string must not appear". The
 * workflows explain in comments exactly why those strings are absent, so
 * without this the prose would trip the check it documents.
 */
const uncommented = (yaml: string): string =>
  yaml
    .split(/\r?\n/)
    .map((l) => (/^\s*#/.test(l) ? '' : l.replace(/\s+#\s.*$/, '')))
    .join('\n');

const RELEASE = read('release.yml');
const VERIFY = read('verify.yml');
const CI = read('ci.yml');

/**
 * The lines of one `jobs:` entry, from its key to the next key at the same
 * indentation. Job keys are indented two spaces in all three files.
 */
function jobBlock(yaml: string, job: string): string {
  const lines = yaml.split(/\r?\n/);
  const start = lines.findIndex((l) => l === `  ${job}:`);
  assert.notEqual(start, -1, `job ${job} not found`);
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i] as string;
    if (/^  \S/.test(l)) break; // next job
    out.push(l);
  }
  return out.join('\n');
}

/** The `permissions:` mapping of a job block, as a set of `scope: level`. */
function permissionsOf(block: string): Set<string> {
  const lines = block.split('\n');
  const start = lines.findIndex((l) => l.trim() === 'permissions:');
  if (start === -1) return new Set();
  const indent = (lines[start] as string).search(/\S/);
  const out = new Set<string>();
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i] as string;
    if (!l.trim()) continue;
    if (l.search(/\S/) <= indent) break;
    const m = /^\s*([a-z-]+):\s*([a-z]+)/.exec(l);
    if (m) out.add(`${m[1]}: ${m[2]}`);
  }
  return out;
}

// ---------------------------------------------------------------------------

describe('release is triggered only by a deliberate version tag', () => {
  test('the trigger is a tag push, not a branch push', () => {
    const on = RELEASE.slice(RELEASE.indexOf('\non:'), RELEASE.indexOf('\npermissions:'));
    assert.match(on, /push:/);
    assert.match(on, /tags:/);
    assert.ok(!/branches:/.test(on), 'a release must never be triggered by a branch push');
    // Defining only `tags` means the workflow does not run for branch pushes at
    // all, which is the behaviour being relied on here.
  });

  test('the tag pattern is anchored to a semver shape', () => {
    assert.match(RELEASE, /- 'v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+'/);
    assert.match(RELEASE, /- 'v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+-\*'/);
    // `?` and `+` are quantifiers on the preceding character in Actions' glob
    // dialect, so a pattern like `v?.?.?` would silently match the wrong thing.
    const patterns = [...uncommented(RELEASE).matchAll(/^\s+- '(v[^']+)'/gm)].map((m) => m[1] as string);
    assert.ok(patterns.length >= 2, `expected tag patterns, found ${JSON.stringify(patterns)}`);
    for (const p of patterns) {
      assert.ok(!/\?/.test(p), `${p} uses ?, which quantifies the preceding character here`);
    }
  });

  test('no pull_request trigger anywhere near the release', () => {
    assert.ok(!/pull_request/.test(RELEASE), 'a release must not be reachable from a pull request');
    assert.ok(!/pull_request_target/.test(RELEASE + VERIFY + CI));
  });
});

describe('permissions are the minimum each job needs', () => {
  test('nothing is granted at the top level', () => {
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      assert.match(yaml, /^permissions: \{\}$/m, `${name} should start from no permissions at all`);
    }
  });

  test('the publish job can mint an OIDC token and nothing else', () => {
    const perms = permissionsOf(jobBlock(RELEASE, 'publish'));
    assert.deepEqual([...perms].sort(), ['contents: read', 'id-token: write']);
  });

  test('the release job can write releases and cannot mint tokens', () => {
    const perms = permissionsOf(jobBlock(RELEASE, 'release'));
    assert.deepEqual([...perms].sort(), ['contents: write']);
  });

  test('no single job can both publish and write to the repository', () => {
    // The reason the two are separate jobs. If they merge, a compromised step
    // in either half gains the other half's authority.
    for (const job of ['guard', 'verify', 'publish', 'release']) {
      const perms = permissionsOf(jobBlock(RELEASE, job));
      const both = perms.has('id-token: write') && perms.has('contents: write');
      assert.equal(both, false, `job ${job} holds both an OIDC token and write access`);
    }
  });

  test('the verification jobs are read-only', () => {
    for (const job of ['test', 'bypass', 'fuzz', 'dependencies', 'package']) {
      const perms = permissionsOf(jobBlock(VERIFY, job));
      assert.deepEqual([...perms], ['contents: read'], `job ${job} should be read-only`);
    }
  });
});

describe('no long-lived publishing credential', () => {
  test('no npm token is referenced anywhere', () => {
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      assert.ok(!/NPM_TOKEN/.test(yaml), `${name} references NPM_TOKEN`);
      assert.ok(!/NODE_AUTH_TOKEN/.test(yaml), `${name} references NODE_AUTH_TOKEN`);
      assert.ok(!/secrets\.NPM/.test(yaml), `${name} reads an npm secret`);
    }
  });

  test('the publish job asks for the OIDC token', () => {
    assert.match(jobBlock(RELEASE, 'publish'), /id-token: write/);
  });

  test('provenance is left to npm rather than forced with a flag', () => {
    // Trusted publishing generates provenance automatically for a public
    // package from a public repo. Passing `--provenance` turns an automatic
    // path into an explicit one with its own failure modes.
    const bare = uncommented(RELEASE).replace(/--(expect|provenance)-(provenance|advisory)/g, '');
    assert.ok(!/--provenance/.test(bare), 'do not pass --provenance under trusted publishing');
    // But its absence must still be checked after the fact.
    assert.match(RELEASE, /--expect-provenance/);
  });
});

describe('actions are pinned', () => {
  test('every action is pinned to a full commit sha with a version comment', () => {
    const unpinned: string[] = [];
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      for (const line of yaml.split(/\r?\n/)) {
        const m = /^\s*(?:-\s*)?uses:\s*(\S+)/.exec(line);
        if (!m) continue;
        const ref = m[1] as string;
        if (ref.startsWith('./')) continue; // a local reusable workflow, versioned with the repo
        if (!/@[0-9a-f]{40}$/.test(ref)) unpinned.push(`${name}: ${ref}`);
        else if (!/#\s*v\d/.test(line)) unpinned.push(`${name}: ${ref} (no version comment)`);
      }
    }
    assert.deepEqual(unpinned, []);
  });

  test('only first-party actions are used', () => {
    const third: string[] = [];
    for (const yaml of [RELEASE, VERIFY, CI]) {
      for (const m of yaml.matchAll(/uses:\s*([^@\s]+)@/g)) {
        const owner = (m[1] as string).split('/')[0];
        if (owner === '.' || owner === 'actions') continue;
        third.push(m[1] as string);
      }
    }
    // Not a prohibition on ever adding one, but adding one should be a decision
    // somebody makes on purpose, in a diff that shows this test changing.
    assert.deepEqual(third, [], 'a third-party action entered the release path');
  });
});

describe('the workflow cannot be tricked by its own inputs', () => {
  test('no untrusted context is interpolated into a shell script', () => {
    // `${{ github.event.* }}` and friends are attacker-influenced strings; put
    // one inside a `run:` block and it is concatenated into the script before
    // the shell ever sees it. The safe form is to pass it through `env:`.
    const bad: string[] = [];
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      const lines = yaml.split(/\r?\n/);
      let inRun = false;
      let runIndent = 0;
      for (const line of lines) {
        if (/^\s*(?:-\s*)?run:\s*\|/.test(line)) {
          inRun = true;
          runIndent = line.search(/\S/);
          continue;
        }
        if (inRun && line.trim() && line.search(/\S/) <= runIndent) inRun = false;
        const oneLineRun = /^\s*(?:-\s*)?run:\s*\S/.test(line);
        if (!inRun && !oneLineRun) continue;
        for (const m of line.matchAll(/\$\{\{\s*([^}]+?)\s*\}\}/g)) {
          const expr = (m[1] as string).trim();
          // `env.*` and `runner.*` are workflow-defined, not attacker-supplied.
          if (/^(env|runner|matrix|inputs)\./.test(expr)) continue;
          bad.push(`${name}: ${expr}`);
        }
      }
    }
    assert.deepEqual(bad, [], 'interpolate through env:, not into the script body');
  });

  test('the tag name reaches scripts through the environment', () => {
    const guard = jobBlock(RELEASE, 'guard');
    assert.match(guard, /GITHUB_REF_NAME: \$\{\{ github\.ref_name \}\}/);
    assert.match(guard, /run: node scripts\/release-guard\.mjs/);
  });
});

describe('verification gates the publish, and cannot be weaker than CI', () => {
  test('both CI and release call the same reusable verification', () => {
    assert.match(CI, /uses: \.\/\.github\/workflows\/verify\.yml/);
    assert.match(RELEASE, /uses: \.\/\.github\/workflows\/verify\.yml/);
  });

  test('publish waits for the guard and the verification', () => {
    assert.match(RELEASE, /publish:[\s\S]*?needs: \[guard, verify\]/);
  });

  test('the release job waits for the publish', () => {
    assert.match(RELEASE, /release:[\s\S]*?needs: \[guard, publish\]/);
  });

  test('the release build does not reuse a dependency cache', () => {
    assert.match(RELEASE, /use-cache: false/);
    const publish = jobBlock(RELEASE, 'publish');
    assert.ok(!/cache:/.test(publish), 'the publish job must not restore a cache');
  });

  test('the artifact is verified and smoke-tested before it is published', () => {
    const publish = jobBlock(RELEASE, 'publish');
    const at = (needle: string) => publish.indexOf(needle);
    assert.ok(at('scripts/verify-tarball.mjs') > 0, 'the tarball is never inspected');
    assert.ok(at('scripts/smoke-tarball.mjs') > 0, 'the tarball is never installed and run');
    assert.ok(at('npm publish') > at('scripts/verify-tarball.mjs'), 'publish happens before inspection');
    assert.ok(at('npm publish') > at('scripts/smoke-tarball.mjs'), 'publish happens before the smoke test');
  });

  test('publishing is skipped when the version is already on the registry', () => {
    const publish = jobBlock(RELEASE, 'publish');
    assert.match(publish, /--exists/);
    assert.match(publish, /if: steps\.exists\.outputs\.already_published == 'false'/);
  });

  test('the registry is checked after the fact, whether or not we published', () => {
    const publish = jobBlock(RELEASE, 'publish');
    const proof = publish.indexOf('--integrity');
    assert.ok(proof > publish.indexOf('npm publish'), 'the proof must come after the publish');
    // No `if:` on the proof step — it runs on the already-published path too.
    const block = publish.slice(publish.indexOf('Prove the registry holds'), proof);
    assert.ok(!/if:/.test(block), 'the registry proof must not be conditional');
  });

  test('lifecycle scripts cannot rebuild the tree between verification and publish', () => {
    // Without `--ignore-scripts`, `npm publish` runs `prepublishOnly`, which
    // rebuilds dist/ — so the bytes published would not be the bytes verified.
    assert.match(RELEASE, /npm publish --ignore-scripts/);
  });
});

describe('re-running cannot produce a half-release', () => {
  test('a release run is never cancelled by a newer one', () => {
    const concurrency = RELEASE.slice(RELEASE.indexOf('\nconcurrency:'), RELEASE.indexOf('\nenv:'));
    assert.match(concurrency, /cancel-in-progress: false/);
    assert.match(concurrency, /group: release-/);
  });

  test('ordinary CI does the opposite, on purpose', () => {
    assert.match(CI, /cancel-in-progress: true/);
  });

  test('the GitHub Release step is idempotent', () => {
    const rel = jobBlock(RELEASE, 'release');
    assert.match(rel, /gh release view/);
    assert.match(rel, /gh release edit/);
    assert.match(rel, /--clobber/);
  });

  test('everything is built from one commit, not from the tag', () => {
    // A tag can be moved. Pinning every checkout to the sha the run started
    // with means moving it mid-run cannot change what is released.
    const checkouts = [...uncommented(RELEASE).matchAll(/^\s+ref: (.+)$/gm)].map((m) => (m[1] as string).trim());
    assert.ok(checkouts.length >= 3, `expected several pinned checkouts, found ${checkouts.length}`);
    for (const ref of checkouts) {
      assert.ok(
        ref === '${{ github.sha }}' || ref === '${{ needs.guard.outputs.sha }}',
        `a checkout uses ${ref} rather than the pinned commit`,
      );
    }
  });
});

describe('the npm trusted publisher binding is documented and consistent', () => {
  test('the workflow filename is the one the binding names', () => {
    // npm binds a trusted publisher to a bare workflow filename. Renaming this
    // file breaks publishing with a confusing E404/ENEEDAUTH and nothing else.
    assert.ok(fs.existsSync(path.join(WF, 'release.yml')));
    assert.match(RELEASE, /release\.yml/, 'the file should say its own name for the reader');
  });

  test('the environment name is fixed and documented', () => {
    assert.match(jobBlock(RELEASE, 'publish'), /name: npm-release/);
    const releasing = fs.readFileSync(path.join(ROOT, 'RELEASING.md'), 'utf8');
    assert.match(releasing, /npm-release/);
    assert.match(releasing, /release\.yml/);
  });

  test('package metadata points at the repository the binding names', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    // npm requires repository.url to match the publishing repository exactly,
    // or provenance generation refuses.
    assert.match(pkg.repository.url, /github\.com\/leastgrant\/leastgrant/);
    assert.match(pkg.homepage, /github\.com\/leastgrant\/leastgrant/);
    assert.match(pkg.bugs.url, /github\.com\/leastgrant\/leastgrant/);
  });
});

// ---------------------------------------------------------------------------
// The guard, exercised rather than read.
// ---------------------------------------------------------------------------

describe('the release guard refuses an inconsistent tag', () => {
  const GUARD = path.join(ROOT, 'scripts', 'release-guard.mjs');
  const version = (JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as { version: string })
    .version;

  /** Run the guard on a tag; returns its exit code and output. */
  function guard(tag: string, env: Record<string, string> = {}) {
    const r = spawnSync(process.execPath, [GUARD, tag], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_OUTPUT: '', ...env },
    });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  }

  test('the tag matching package.json passes', () => {
    const r = guard(`v${version}`);
    assert.equal(r.code, 0, r.out);
  });

  test('a tag that does not match the package is refused', () => {
    const r = guard('v99.99.99');
    assert.equal(r.code, 1);
    assert.match(r.out, /tag\/package version mismatch/);
  });

  for (const [why, tag] of [
    ['no v prefix', '1.2.3'],
    ['not semver', 'v1.2'],
    ['leading zero', 'v01.2.3'],
    ['trailing junk', 'v1.2.3.4'],
    ['a branch name', 'main'],
    ['empty-ish', 'v'],
  ] as [string, string][]) {
    test(`${why} (${tag}) is refused`, () => {
      const r = guard(tag);
      assert.notEqual(r.code, 0, `${tag} was accepted:\n${r.out}`);
    });
  }

  test('build metadata is refused because npm cannot represent it', () => {
    const r = guard('v1.2.3+build.5');
    assert.equal(r.code, 1);
    assert.match(r.out, /build metadata/);
  });

  test('a prerelease tag is accepted and routed to the next dist-tag', () => {
    // Version must still match, so this only checks the classification path.
    const r = guard(`v${version}-rc.1`);
    assert.match(r.out, /prerelease/);
  });

  test('releasing from the wrong repository is refused', () => {
    const r = guard(`v${version}`, { GITHUB_REPOSITORY: 'someone-else/leastgrant' });
    assert.equal(r.code, 1);
    assert.match(r.out, /may only be released from leastgrant\/leastgrant/);
  });

  test('the same repository in a different case is accepted', () => {
    const r = guard(`v${version}`, { GITHUB_REPOSITORY: 'LeastGrant/LeastGrant' });
    assert.equal(r.code, 0, r.out);
  });

  test('it writes the outputs the workflow consumes', () => {
    const out = path.join(os.tmpdir(), `lg-guard-out-${process.pid}`);
    fs.writeFileSync(out, '');
    const r = spawnSync(process.execPath, [GUARD, `v${version}`], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_OUTPUT: out },
    });
    assert.equal(r.status, 0, r.stderr);
    const written = fs.readFileSync(out, 'utf8');
    fs.rmSync(out, { force: true });
    for (const key of ['version=', 'tag=', 'npm_tag=', 'prerelease=', 'tarball=']) {
      assert.match(written, new RegExp(`^${key}`, 'm'), `the guard did not emit ${key}`);
    }
    assert.match(written, /^npm_tag=latest$/m);
  });
});

describe('the workflow files are structurally sound', () => {
  // Not a YAML parser — a check for the one corruption that a text-editing
  // mistake actually produces, and that no other test here would notice: a
  // line inside a `run: |` block losing its indentation, which silently ends
  // the block and turns the rest of the script into invalid YAML keys.
  test('every line of a block scalar is indented under it', () => {
    const bad: string[] = [];
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      const lines = yaml.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const m = /^(\s*)(?:-\s*)?(?:run|if|name):\s*[|>][-+]?\s*$/.exec(lines[i] as string);
        if (!m) continue;
        const keyIndent = (m[1] as string).length;
        for (let j = i + 1; j < lines.length; j++) {
          const l = lines[j] as string;
          if (!l.trim()) continue;
          const indent = l.search(/\S/);
          if (indent <= keyIndent) break; // the block ended normally
          // Inside the block. A line that looks like a shell fragment starting
          // at column 0 would already have ended it, so nothing to do here —
          // the check is that we reached this point at all.
        }
        // Re-scan: the first non-blank line after the key must be deeper.
        let k = i + 1;
        while (k < lines.length && !(lines[k] as string).trim()) k++;
        if (k < lines.length && (lines[k] as string).search(/\S/) <= keyIndent) {
          bad.push(`${name}:${i + 1} block scalar has no body`);
        }
      }
      // A bare quote or a lone `'` at the start of a line is what a mangled
      // escape leaves behind.
      lines.forEach((l, i) => {
        if (/^['"]\s/.test(l)) bad.push(`${name}:${i + 1} line begins with a stray quote: ${l.slice(0, 40)}`);
      });
    }
    assert.deepEqual(bad, []);
  });

  test('no tab characters, which YAML forbids for indentation', () => {
    for (const [name, yaml] of [['release.yml', RELEASE], ['verify.yml', VERIFY], ['ci.yml', CI]] as const) {
      assert.ok(!/^\t/m.test(yaml), `${name} indents with a tab`);
    }
  });
});
