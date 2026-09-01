/**
 * The release, rehearsed locally, without publishing anything.
 *
 *   npm run release:check
 *
 * Runs the same sequence `.github/workflows/release.yml` runs, in the same
 * order, stopping where the workflow would contact the registry. Two uses:
 * a maintainer can find out before pushing a tag whether it would fail, and a
 * change to the release path can be exercised without cutting a release to
 * find out.
 *
 * What it deliberately does NOT do: publish, create a tag, create a release, or
 * touch the network beyond a single read-only registry lookup. It ends by
 * reporting the artifact fingerprint the workflow would compare against the
 * registry, so the two can be checked by eye.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WIN = process.platform === 'win32';
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = pkg.version;
const TAG = process.argv[2] || `v${VERSION}`;
const OUT = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-rehearse-'));

let step = 0;
const banner = (s) => console.log(`\n── ${++step}. ${s} ${'─'.repeat(Math.max(0, 58 - s.length))}`);

/**
 * Run a command, streaming its output; abort the rehearsal if it fails.
 *
 * Only a `.cmd` needs a shell, and only on Windows (Node refuses to spawn one
 * directly). Everything else is a direct spawn with no shell, which avoids
 * having to quote a command whose own path contains a space.
 */
function must(cmd, args, opts = {}) {
  const shown = [cmd, ...args].join(String.fromCharCode(32));
  const needsShell = WIN && cmd.endsWith('.cmd');
  const r = needsShell
    ? spawnSync(
        [cmd, ...args.map((a) => (/[\s"&|<>^]/.test(a) ? JSON.stringify(a) : a))].join(String.fromCharCode(32)),
        { cwd: ROOT, stdio: 'inherit', shell: true, ...opts },
      )
    : spawnSync(cmd, args, { cwd: ROOT, stdio: 'inherit', shell: false, ...opts });
  if (r.status !== 0) {
    console.error(String.fromCharCode(10) + 'FAILED: ' + shown);
    console.error('The release workflow would stop here and publish nothing.');
    process.exit(1);
  }
}

const npmCmd = WIN ? 'npm.cmd' : 'npm';

console.log(`Rehearsing the release of ${pkg.name}@${VERSION} as ${TAG}`);
console.log(`(nothing is published, tagged, or uploaded)`);

// 1 — the guard, exactly as the workflow runs it.
banner('guard: the tag and the package must agree');
must(process.execPath, [path.join(ROOT, 'scripts', 'release-guard.mjs'), TAG]);

// 2 — the tree is what is committed. The workflow gets this for free from a
// clean checkout; locally it is the thing most likely to differ.
banner('working tree is clean');
{
  const r = spawnSync('git', ['status', '--porcelain'], { cwd: ROOT, encoding: 'utf8' });
  const dirty = (r.stdout || '').trim();
  if (dirty) {
    console.log(dirty);
    console.log(
      '\n  note  the workflow builds from a clean checkout of the tagged commit.\n' +
        '        Anything above is in your rehearsal but would not be in the release.',
    );
  } else {
    console.log('  ok    nothing uncommitted');
  }
}

// 3-6 — the verification the workflow runs before it packs.
banner('typecheck');
must(npmCmd, ['run', 'typecheck']);
banner('build');
must(npmCmd, ['run', 'build']);
banner('tests');
must(npmCmd, ['test']);
banner('randomised symlink topologies');
must(process.execPath, [path.join(ROOT, 'scripts', 'fuzz-paths.mjs')]);

// 7 — pack, then inspect and use the artifact itself.
banner('pack');
must(npmCmd, ['pack', '--pack-destination', OUT]);
const TGZ = path.join(OUT, `${pkg.name}-${VERSION}.tgz`);
if (!fs.existsSync(TGZ)) {
  console.error(`expected ${TGZ} to exist after packing`);
  process.exit(1);
}

banner('inspect the artifact');
must(process.execPath, [path.join(ROOT, 'scripts', 'verify-tarball.mjs'), TGZ, '--expect-version', VERSION]);

banner('install it into an empty directory and use it');
must(process.execPath, [path.join(ROOT, 'scripts', 'smoke-tarball.mjs'), TGZ, '--expect-version', VERSION]);

// 8 — the fingerprint the workflow would compare against the registry.
banner('fingerprint');
const bytes = fs.readFileSync(TGZ);
const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
console.log(`  integrity  ${integrity}`);
console.log(`  sha256     ${sha256}`);

// `npm pack` is byte-reproducible, and the workflow relies on that to prove the
// published artifact is the verified one. Cheap to confirm rather than assume.
banner('packing twice gives the same bytes');
const OUT2 = path.join(OUT, 'again');
fs.mkdirSync(OUT2, { recursive: true });
must(npmCmd, ['pack', '--pack-destination', OUT2]);
const again = crypto.createHash('sha256').update(fs.readFileSync(path.join(OUT2, path.basename(TGZ)))).digest('hex');
if (again !== sha256) {
  console.error(`  ERROR: two packs differ (${sha256} vs ${again}).`);
  console.error('  The workflow proves what it published by comparing hashes; that proof needs this.');
  process.exit(1);
}
console.log('  ok    reproducible');

// 9 — what the registry currently holds.
banner('registry');
{
  const r = spawnSync(
    process.execPath,
    [path.join(ROOT, 'scripts', 'verify-published.mjs'), pkg.name, VERSION, '--exists'],
    { cwd: ROOT, encoding: 'utf8' },
  );
  process.stdout.write(r.stdout || '');
  if (r.status === 0) {
    console.log(`  note  ${pkg.name}@${VERSION} is already published.`);
    console.log('        A release run would skip publishing and only verify and tag.');
  } else if (r.status === 3) {
    console.log('  ok    this version has not been published yet');
  } else {
    console.log('  note  could not reach the registry; a real run would stop here rather than guess');
  }
}

fs.rmSync(OUT, { recursive: true, force: true });

console.log(`\n${TAG} would release cleanly.`);
console.log('To do it for real:');
console.log(`    git push origin main`);
console.log(`    git push origin ${TAG}`);
