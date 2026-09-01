/**
 * Verify a packed tarball — the actual bytes that would be published.
 *
 * Not the source tree, not `dist/`, not what `files` says should be there: the
 * artifact itself, unpacked and inspected. The audit found three problems that
 * were invisible from the source tree and existed only in the tarball — a dead
 * `exports` map that made the package unimportable, the author's username baked
 * into a comment, and scratch directories that were nearly shipped.
 *
 *   node scripts/verify-tarball.mjs ./leastgrant-0.1.0.tgz [--expect-version 0.1.0]
 *
 * The tarball is unpacked here rather than by shelling out to `tar`. That is
 * not gold-plating: `tar` reads `D:\x` as a remote host spec, GNU and BSD tar
 * disagree about `--force-local`, and a verifier that behaves differently on
 * the machine cutting the release than on the machine checking it is worth very
 * little. Reading the 512-byte headers directly needs only `node:zlib` and
 * behaves identically everywhere.
 *
 * Exits non-zero having reported every problem found, not just the first.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

const CI = Boolean(process.env['GITHUB_ACTIONS']);
const problems = [];
const fail = (msg) => problems.push(msg);
const ok = (msg) => console.log(`  ok    ${msg}`);

const tarballArg = process.argv[2];
if (!tarballArg) {
  console.error('usage: node scripts/verify-tarball.mjs <tarball.tgz> [--expect-version X.Y.Z]');
  process.exit(2);
}
const tarball = path.resolve(tarballArg);
if (!fs.existsSync(tarball)) {
  console.error(`no such tarball: ${tarball}`);
  process.exit(2);
}
const expectIdx = process.argv.indexOf('--expect-version');
const expectVersion = expectIdx > 0 ? process.argv[expectIdx + 1] : '';

// --- unpack -------------------------------------------------------------------

/**
 * Read a gzipped tar into a map of path -> contents.
 *
 * Handles the header forms npm produces: plain ustar, GNU long names (`L`), and
 * pax extended headers (`x`) for paths that do not fit the 100-byte name field.
 * Directories are skipped; only regular files matter to the checks below.
 */
function readTar(file) {
  const buf = zlib.gunzipSync(fs.readFileSync(file));
  const entries = new Map();
  const str = (b, off, len) => {
    const s = b.subarray(off, off + len);
    const end = s.indexOf(0);
    return s.subarray(0, end === -1 ? s.length : end).toString('utf8');
  };

  let pendingPath = '';
  for (let off = 0; off + 512 <= buf.length; ) {
    const header = buf.subarray(off, off + 512);
    let allZero = true;
    for (const b of header) {
      if (b !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) break; // end-of-archive marker

    const name = str(header, 0, 100);
    const size = parseInt(str(header, 124, 12).trim(), 8) || 0;
    const type = String.fromCharCode(header[156]);
    const prefix = str(header, 345, 155);
    const body = buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;

    if (type === 'x' || type === 'X') {
      const rec = /(?:^|\n)\d+ path=([^\n]*)/.exec(body.toString('utf8'));
      if (rec) pendingPath = rec[1];
      continue;
    }
    if (type === 'g') continue; // global pax header
    if (type === 'L') {
      pendingPath = body.toString('utf8').replace(/\0+$/, '');
      continue;
    }

    const full = pendingPath || (prefix ? prefix + '/' + name : name);
    pendingPath = '';
    if (type === '5' || full.endsWith('/')) continue; // directory
    if (type !== '' && type !== '0' && type !== '\0') continue; // links, devices
    entries.set(full.split('\\').join('/'), body);
  }
  return entries;
}

let raw;
try {
  raw = readTar(tarball);
} catch (e) {
  console.error(`could not read ${tarball}: ${e.message}`);
  process.exit(2);
}

// npm tarballs put everything under a single top-level `package/` directory.
const PREFIX = 'package/';
if (![...raw.keys()].some((k) => k.startsWith(PREFIX))) {
  console.error('tarball does not contain the expected top-level "package/" directory');
  process.exit(2);
}
/** Path relative to `package/` -> contents. */
const entries = new Map();
for (const [k, v] of raw) if (k.startsWith(PREFIX)) entries.set(k.slice(PREFIX.length), v);

const names = new Set(entries.keys());
const files = [...names];
const readText = (n) => entries.get(n).toString('utf8');
const isBinary = (n) => entries.get(n).includes(0);
/** Present as a file, or as a directory holding at least one file. */
const has = (n) => names.has(n) || files.some((k) => k.startsWith(n + '/'));

console.log(
  `${path.basename(tarball)}: ${files.length} files, ${(fs.statSync(tarball).size / 1024).toFixed(0)} kB packed\n`,
);

// --- 1. the manifest must describe things that exist --------------------------

const pkg = JSON.parse(readText('package.json'));

if (expectVersion && pkg.version !== expectVersion) {
  fail(`tarball version is ${pkg.version}, expected ${expectVersion}`);
} else if (expectVersion) {
  ok(`version is ${pkg.version}`);
}

let manifestBroken = 0;
for (const [field, value] of [
  ['bin.leastgrant', pkg.bin?.leastgrant],
  ['bin.lg', pkg.bin?.lg],
  ['exports["."].default', pkg.exports?.['.']?.default],
  ['exports["."].types', pkg.exports?.['.']?.types],
  ['types', pkg.types],
]) {
  if (!value) {
    fail(`${field} is not set`);
    manifestBroken++;
    continue;
  }
  const target = value.replace(/^\.\//, '');
  if (!names.has(target)) {
    fail(`${field} points at ${value}, which is not in the tarball`);
    manifestBroken++;
  }
}
if (!manifestBroken) ok('every bin / exports / types entry resolves inside the tarball');

// --- 2. nothing that should not ship ------------------------------------------

const FORBIDDEN = [
  '.audit',
  '.research',
  '.workflows',
  'node_modules',
  'test',
  'dist/test',
  'scripts',
  '.github',
  '.git',
  'examples',
];
const shipped = FORBIDDEN.filter((d) => has(d));
if (shipped.length) fail(`these must never be published: ${shipped.join(', ')}`);
else ok(`none of ${FORBIDDEN.length} scratch/dev paths are present`);

const stray = files.filter((n) => /\.(tgz|tsbuildinfo|log)$/.test(n) || n.startsWith('.env'));
if (stray.length) fail(`stray files in the tarball: ${stray.join(', ')}`);

// --- 3. no trace of the machine that built it ---------------------------------
//
// Documented placeholders (`/home/you/project`) appear throughout the docs and
// are fine. What must never appear is a path belonging to whichever machine ran
// `npm pack`: a home directory, a checkout location, a username.

const buildPaths = [
  process.env['HOME'],
  process.env['USERPROFILE'],
  process.env['GITHUB_WORKSPACE'],
  process.env['RUNNER_TEMP'],
  process.cwd(),
].filter((p) => p && p.length > 3);

const leaked = new Set();
for (const f of files) {
  if (isBinary(f)) continue;
  const body = readText(f);
  for (const needle of buildPaths) if (body.includes(needle)) leaked.add(`${f} :: ${needle}`);
  const winUser = /[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9 ._-]+/.exec(body);
  if (winUser) leaked.add(`${f} :: ${winUser[0]}`);
}
if (leaked.size) for (const l of leaked) fail(`build-machine path in the artifact: ${l}`);
else ok(`no build-machine paths (${buildPaths.length} prefixes over ${files.length} files)`);

// --- 4. source maps must not embed the build tree -----------------------------

const maps = files.filter((n) => n.endsWith('.map'));
let mapProblems = 0;
for (const m of maps) {
  let j;
  try {
    j = JSON.parse(readText(m));
  } catch {
    fail(`${m} is not valid JSON`);
    mapProblems++;
    continue;
  }
  if (j.sourcesContent) {
    fail(`${m} embeds sourcesContent`);
    mapProblems++;
  }
  for (const s of j.sources || []) {
    if (path.isAbsolute(s) || /^[A-Za-z]:/.test(s) || s.startsWith('file:')) {
      fail(`${m} has a non-relative source: ${s}`);
      mapProblems++;
    }
  }
}
if (maps.length && !mapProblems) ok(`${maps.length} source maps carry only relative sources`);

// --- 5. zero runtime dependencies, in the artifact ----------------------------

const depCount = Object.keys(pkg.dependencies || {}).length;
if (depCount) fail(`the published manifest declares ${depCount} runtime dependencies`);
else ok('zero runtime dependencies');

// Nothing shipped may import a bare module: that would be a dependency the
// manifest does not declare, and it would fail at the user's first run.
const BARE = /(?:^|\n)\s*(?:import|export)[^'"\n]*from\s+['"]([^.'"][^'"]*)['"]/g;
const undeclared = new Set();
for (const f of files.filter((n) => /\.(js|mjs|cjs|ts)$/.test(n) && !n.endsWith('.d.ts'))) {
  for (const match of readText(f).matchAll(BARE)) {
    if (match[1].startsWith('node:')) continue;
    undeclared.add(`${f} imports ${match[1]}`);
  }
}
if (undeclared.size) for (const u of undeclared) fail(`undeclared import: ${u}`);
else ok('no bare imports outside node: builtins');

// --- 6. credential-shaped strings ---------------------------------------------

const SECRET_SHAPES = [
  [/\bsk-[A-Za-z0-9_-]{16,}/, 'api key'],
  [/\bghp_[A-Za-z0-9]{20,}/, 'github token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/, 'github pat'],
  [/\bnpm_[A-Za-z0-9]{30,}/, 'npm token'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'aws key id'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, 'jwt'],
];
let secretHits = 0;
for (const f of files) {
  if (isBinary(f)) continue;
  const body = readText(f);
  for (const [rx, what] of SECRET_SHAPES) {
    const hit = rx.exec(body);
    if (hit) {
      fail(`${what}-shaped string in ${f}: ${hit[0].slice(0, 12)}...`);
      secretHits++;
    }
  }
}
if (!secretHits) ok('no credential-shaped strings');

// --- 6b. line endings, because one of them is executable ------------------------
//
// bin/leastgrant.js begins with a #!/usr/bin/env node shebang. If that line ends
// CRLF, the kernel looks for an interpreter whose name ends in a carriage return
// and the CLI does not start on Linux or macOS. npm pack packs the working tree
// verbatim, and Git on Windows checks out CRLF by default, so a release cut from
// a Windows clone without this repository's .gitattributes would ship a binary
// that cannot run.
//
// It also decides whether two machines packing the same commit produce the same
// bytes, which is what lets the release workflow prove that what it published is
// what it verified.

const CR = String.fromCharCode(13);
const shebanged = files.filter((f) => !isBinary(f) && readText(f).startsWith("#!"));
let crlf = 0;
for (const f of shebanged) {
  const first = readText(f).split(String.fromCharCode(10))[0];
  if (first.endsWith(CR)) {
    fail(f + " has a CRLF shebang, which is not executable on Linux or macOS");
    crlf++;
  }
}
if (shebanged.length && !crlf) ok(shebanged.length + " executable file(s) have a clean shebang");

const withCR = files.filter(
  (f) => /\.(js|mjs|cjs|json|ts)$/.test(f) && !isBinary(f) && readText(f).includes(CR + String.fromCharCode(10)),
);
if (withCR.length) {
  fail(
    withCR.length +
      " shipped file(s) use CRLF, so this tarball is not reproducible on another platform: " +
      withCR.slice(0, 3).join(", "),
  );
} else {
  ok("no CRLF in shipped code");
}

// --- 7. the documented files are actually there --------------------------------

let missingDoc = 0;
for (const required of ['README.md', 'LICENSE', 'SECURITY.md', 'THREAT-MODEL.md', 'CONTRIBUTING.md', 'RELEASING.md']) {
  if (!names.has(required)) {
    fail(`${required} is listed in "files" but is not in the tarball`);
    missingDoc++;
  }
}
if (!missingDoc) ok('every documented file is present');

// Relative links inside shipped markdown must resolve inside the tarball, or
// they render as dead links on npmjs.com — where most readers meet this package.
const brokenLinks = new Set();
for (const md of files.filter((n) => n.endsWith('.md'))) {
  for (const match of readText(md).matchAll(/\]\((?!https?:|mailto:|#)([^)#\s]+)/g)) {
    // A link to a directory is written with a trailing slash, which survives
    // `normalize` and then matches nothing. Strip it before looking.
    const target = path.posix
      .normalize(path.posix.join(path.posix.dirname(md), match[1]))
      .replace(/\/+$/, '');
    if (!names.has(target) && !has(target)) brokenLinks.add(`${md} -> ${match[1]}`);
  }
}
if (brokenLinks.size) for (const b of brokenLinks) fail(`dead relative link in a shipped file: ${b}`);
else ok('relative links in shipped markdown all resolve');

// --- report ---------------------------------------------------------------------

if (problems.length) {
  console.error('');
  for (const p of problems) console.error(CI ? `::error::${p}` : `  ERROR: ${p}`);
  console.error(`\n${problems.length} problem(s) in the tarball; refusing to publish.`);
  process.exit(1);
}
console.log('\ntarball verification passed');
