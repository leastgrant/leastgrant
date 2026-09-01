/**
 * Everything that must be true about a release before anything is published.
 *
 * This runs first in the release workflow and it is deliberately offline and
 * fast: nothing here needs the network, so there is no reason for a release to
 * get halfway to npm before discovering that the tag and the package disagree.
 *
 * It is a script rather than a pile of `run:` steps for three reasons. It can
 * be read in one place by someone auditing the release path; it can be run
 * locally by a maintainer before they push a tag; and it can be unit-tested,
 * which YAML cannot.
 *
 *   node scripts/release-guard.mjs v0.1.0
 *   node scripts/release-guard.mjs            # reads GITHUB_REF_NAME
 *
 * Exit 0 means "this tag may proceed to verification". Any other exit means
 * stop, and says why. There is no path through this file that passes silently.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CI = Boolean(process.env['GITHUB_ACTIONS']);

/** The repository this package is allowed to be released from. */
const EXPECTED_REPO = 'leastgrant/leastgrant';
const EXPECTED_NAME = 'leastgrant';

const problems = [];
const notes = [];
const fail = (msg) => problems.push(msg);
const note = (msg) => notes.push(msg);

/**
 * The official SemVer 2.0.0 grammar, from semver.org.
 *
 * Written out rather than pulled from a package: this project has no runtime
 * dependencies and the release path is the last place to start adding any.
 */
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

const tag = (process.argv[2] || process.env['GITHUB_REF_NAME'] || '').trim();
if (!tag) {
  console.error('usage: node scripts/release-guard.mjs vX.Y.Z   (or set GITHUB_REF_NAME)');
  process.exit(2);
}

// --- the tag itself ---------------------------------------------------------

if (!tag.startsWith('v')) fail(`tag ${JSON.stringify(tag)} does not start with "v"`);
const tagVersion = tag.replace(/^v/, '');
const m = SEMVER.exec(tagVersion);
if (!m) fail(`tag ${JSON.stringify(tag)} is not v<semver>: ${JSON.stringify(tagVersion)} fails the SemVer 2.0.0 grammar`);

// Build metadata cannot be expressed on npm, so a `+build` tag would publish
// something whose version does not match the tag it came from.
if (m && m[5]) fail(`tag ${tag} carries SemVer build metadata (+${m[5]}), which npm cannot represent`);

const prerelease = Boolean(m && m[4]);

// --- the package it claims to be --------------------------------------------

let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
} catch (e) {
  console.error(`cannot read package.json: ${e.message}`);
  process.exit(2);
}

if (pkg.name !== EXPECTED_NAME) {
  // The npm trusted publisher is bound to one package name. A rename would
  // either fail at publish or, worse, publish under a name nobody is watching.
  fail(`package name is ${JSON.stringify(pkg.name)}, expected ${JSON.stringify(EXPECTED_NAME)}`);
}

if (pkg.version !== tagVersion) {
  fail(
    `tag/package version mismatch: tag says ${JSON.stringify(tagVersion)}, ` +
      `package.json says ${JSON.stringify(pkg.version)}`,
  );
}

if (pkg.private === true) fail('package.json has "private": true, which cannot be published');

// --- metadata that ends up in the provenance statement ----------------------
//
// npm records the source repository in the provenance attestation, and the
// registry page links to `repository`, `homepage` and `bugs`. Wrong values here
// are not cosmetic: they point a user verifying the supply chain at the wrong
// place.

const repoUrl = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url;
if (!repoUrl || !repoUrl.includes(EXPECTED_REPO)) {
  fail(`package.json repository does not point at ${EXPECTED_REPO}: ${JSON.stringify(repoUrl)}`);
}
if (!String(pkg.homepage || '').includes(EXPECTED_REPO)) {
  fail(`package.json homepage does not point at ${EXPECTED_REPO}: ${JSON.stringify(pkg.homepage)}`);
}
if (!String(pkg.bugs?.url || '').includes(EXPECTED_REPO)) {
  fail(`package.json bugs.url does not point at ${EXPECTED_REPO}: ${JSON.stringify(pkg.bugs?.url)}`);
}

// The workflow refuses to release from anywhere else, so a mismatch between the
// repo we are running in and the repo the package claims is a real conflict.
const actualRepo = process.env['GITHUB_REPOSITORY'];
if (actualRepo && actualRepo.toLowerCase() !== EXPECTED_REPO.toLowerCase()) {
  fail(`running in ${actualRepo}, but this package may only be released from ${EXPECTED_REPO}`);
}

// --- the shape of what would ship -------------------------------------------

const deps = Object.keys(pkg.dependencies || {});
if (deps.length) {
  // Checked here as well as in CI, because this is the last gate before the
  // artifact becomes something strangers install.
  fail(`runtime dependencies must be empty; found ${deps.length}: ${deps.join(', ')}`);
}

for (const [field, value] of [
  ['bin.leastgrant', pkg.bin?.leastgrant],
  ['exports["."].default', pkg.exports?.['.']?.default],
  ['exports["."].types', pkg.exports?.['.']?.types],
  ['types', pkg.types],
]) {
  if (!value) fail(`package.json ${field} is missing`);
}

if (!Array.isArray(pkg.files) || !pkg.files.length) {
  fail('package.json has no "files" allowlist, so the tarball contents are unbounded');
}

// --- results -----------------------------------------------------------------

const npmTag = prerelease ? 'next' : 'latest';
if (prerelease) {
  note(`${tag} is a prerelease, so it publishes under the "next" dist-tag and is marked pre-release on GitHub`);
} else {
  note(`${tag} is a stable release, so it publishes under "latest"`);
}

for (const n of notes) console.log(`  ${n}`);

if (problems.length) {
  console.error('');
  for (const p of problems) console.error(CI ? `::error::${p}` : `  ERROR: ${p}`);
  console.error(`\n${problems.length} problem(s); refusing to release.`);
  process.exit(1);
}

console.log(`\nrelease guard passed for ${tag} (npm dist-tag: ${npmTag})`);

const out = process.env['GITHUB_OUTPUT'];
if (out) {
  fs.appendFileSync(
    out,
    [
      `version=${tagVersion}`,
      `tag=${tag}`,
      `npm_tag=${npmTag}`,
      `prerelease=${prerelease}`,
      `tarball=${EXPECTED_NAME}-${tagVersion}.tgz`,
      '',
    ].join('\n'),
  );
}
