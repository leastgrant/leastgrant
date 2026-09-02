/**
 * The gate between shipping an adapter and documenting one.
 *
 *   node scripts/verify-agent-docs.mjs           # records, docs, claims
 *   node scripts/verify-agent-docs.mjs --site    # also check the built pages
 *
 * Everything a user is told about an agent — the README table, `leastgrant
 * doctor`, the website's Agents pages — is generated from `compatibility/*.json`.
 * That makes drift between those surfaces impossible and creates one new way to
 * be wrong instead: the record itself claiming more than was established, or an
 * adapter existing with no record at all. Neither shows up as a broken build.
 * Both show up here.
 *
 * The five failures this refuses, in the order they have nearly happened:
 *
 *   1. an adapter ships and nothing documents it
 *   2. a record claims a live test with no version, OS, date, or first-hand fact
 *   3. a declared `supported` level is stronger than the derived one
 *   4. a capability claim contradicts what the conformance suite actually drives
 *   5. an adapter is documented that does not exist on disk
 *
 * Three of those were real states of this repository during the sprint that
 * built it. The Cursor adapter shipped in a release having never been driven by
 * the conformance suite; the Antigravity record said `enforcing` while every
 * derived surface said otherwise; and the first Agents page carried a status
 * two releases out of date because it was written rather than generated.
 *
 * Exit 0 clean, 1 on any finding. Prints every finding rather than the first,
 * because these tend to arrive in families.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCompatibility, assess, deriveVerification, verificationProblems } from '../dist/src/core/compatibility.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const wantSite = process.argv.includes('--site');

/** Directories under src/adapters that are an integration rather than shared code. */
const SHARED = new Set(['shared', 'common', 'lib']);

const problems = [];
const fail = (s) => problems.push(s);

const records = loadCompatibility();
if (records.length < 5) fail(`only ${records.length} compatibility records loaded — the data is not being found`);

const byId = new Map(records.map((a) => [a.id, a]));

// --- 1 & 5. adapters and records account for each other ----------------------
//
// Matched by the file each record names rather than by directory name, because
// an adapter can be renamed and a record can be pointed at the wrong file, and
// the second is the quiet one.
const adapterDirs = fs
  .readdirSync(path.join(ROOT, 'src', 'adapters'), { withFileTypes: true })
  .filter((d) => d.isDirectory() && !SHARED.has(d.name))
  .map((d) => d.name);

const claimed = new Map();
for (const a of records) {
  if (!a.adapter) continue;
  const abs = path.join(ROOT, a.adapter);
  if (!fs.existsSync(abs)) {
    fail(`${a.id}: the record points at ${a.adapter}, which does not exist`);
    continue;
  }
  claimed.set(path.relative(path.join(ROOT, 'src', 'adapters'), abs).split(path.sep)[0], a);
}

for (const dir of adapterDirs) {
  if (!claimed.has(dir)) {
    fail(
      `src/adapters/${dir} ships an integration that no compatibility record claims. ` +
        `Add compatibility/${dir}.json — the README table, doctor and the website all read it, ` +
        `so an undocumented adapter is an adapter nobody can find out anything about.`,
    );
  }
}

// --- 2 & 3. no record claims more than it establishes ------------------------
for (const a of records) {
  for (const p of verificationProblems(a)) fail(p);

  // `supported` says whether an adapter ships and, if not, why. It must not be
  // able to say how good one is — that field held `enforcing` for five agents
  // at once, three of which the same file's own evidence graded lower.
  const SUPPORT = new Set(['shipped', 'evaluated-not-yet-shipped', 'evaluated-and-deferred']);
  if (!SUPPORT.has(a.supported)) {
    fail(
      `${a.id}: supported is "${a.supported}". That field says whether an adapter ships, not how ` +
        `strong it is; strength is derived by assess() so it cannot be declared ahead of the data.`,
    );
  }
  if (Boolean(a.adapter) !== (a.supported === 'shipped')) {
    fail(
      `${a.id}: supported is "${a.supported}" and adapter is ${a.adapter ? `"${a.adapter}"` : 'null'} — ` +
        `the two disagree about whether anything ships`,
    );
  }

  // Control paths are the other half of an integration. An adapter that ships
  // without recording what decides its behaviour later has an off switch nobody
  // has looked for — and three of those were found unfloored on the day this
  // check was written, one of them the host's own standing-grant store.
  const cps = a.controlPaths ?? [];
  if (!cps.length) {
    fail(
      `${a.id}: records no controlPaths. Every agent has files that decide what it may do later — ` +
        `its hook config, its permission grants, its MCP wiring, the memory a later session is ` +
        `handed. test/control-files.test.ts floors whatever is listed, so an empty list means ` +
        `nothing is floored on purpose.`,
    );
  }
  for (const cp of cps) {
    if (!cp.path || !cp.what || !cp.why) fail(`${a.id}: incomplete control path ${JSON.stringify(cp)}`);
    else if (cp.what.length <= 25) fail(`${a.id}: "${cp.path}" does not say what it decides`);
  }
  // The install path is a control path by definition; a record that names one
  // and not the other has two lists that can disagree.
  for (const m of (a.configPath ?? '').matchAll(/(~|<repo>)([\\/][\w.\-/\\]+)/g)) {
    const named = `${m[1]}${m[2].replace(/\\/g, '/')}`;
    if (!cps.some((c) => c.path === named)) {
      fail(`${a.id}: configPath names ${named}, which is absent from controlPaths`);
    }
  }

  // A grade is a summary of the runs; the runs are the fact. If the summary can
  // be reached without them the axis is decorative.
  const grade = deriveVerification(a);
  if (grade === 'LIVE VERIFIED' && !a.verification?.live?.done) {
    fail(`${a.id}: graded LIVE VERIFIED with no completed live run`);
  }
  if (grade !== 'UNVERIFIED' && !a.adapter) {
    fail(`${a.id}: graded ${grade} while shipping no adapter`);
  }
}

// --- 4. the conformance claim matches what the suite drives ------------------
//
// Read out of the suite's own shape table rather than trusted from the record,
// which is the direction that catches a claim added without a test.
const conformance = fs.readFileSync(path.join(ROOT, 'test', 'conformance.test.ts'), 'utf8');
const shapes = new Set([...conformance.matchAll(/^\s{2}(?:'([a-z-]+)'|([a-z-]+)):\s*\{/gm)].map((m) => m[1] ?? m[2]));
for (const a of records) {
  const driven = shapes.has(a.id) && Boolean(a.adapter);
  const claims = Boolean(a.verification?.conformance?.done);
  if (claims && !driven) {
    fail(`${a.id}: claims the conformance suite drives it, and the suite has no shape for it`);
  }
  if (driven && !claims) {
    fail(`${a.id}: the conformance suite drives it and the record does not say so`);
  }
}

// --- the built pages, when asked --------------------------------------------
if (wantSite) {
  const dist = path.join(ROOT, 'site', 'dist', 'docs', 'agents');
  if (!fs.existsSync(dist)) {
    fail('site/dist/docs/agents is missing — run `npm run site:build` before checking the site');
  } else {
    const index = fs.readFileSync(path.join(dist, 'index.html'), 'utf8');
    for (const a of records) {
      const page = path.join(dist, a.id, 'index.html');
      if (!fs.existsSync(page)) {
        fail(`${a.id}: no /docs/agents/${a.id}/ page was generated`);
        continue;
      }
      if (!index.includes(`/docs/agents/${a.id}/`)) fail(`${a.id}: the agents index does not link to its page`);
      const html = fs.readFileSync(page, 'utf8');
      const grade = deriveVerification(a);
      if (!html.includes(grade)) fail(`${a.id}: the page does not show its derived grade ${grade}`);
    }
    // A page for an agent that no longer has a record is a page nothing keeps
    // true.
    for (const d of fs.readdirSync(dist, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      if (!byId.has(d.name)) fail(`site/dist/docs/agents/${d.name} has no compatibility record behind it`);
    }
  }
}

if (problems.length) {
  console.error(`agent documentation is out of step with the evidence (${problems.length}):\n`);
  for (const p of problems) console.error(`  ! ${p}`);
  console.error('');
  process.exit(1);
}

console.log(
  `${records.length} agents: every adapter has a record, every record is within its evidence` +
    (wantSite ? ', and every page matches it' : ''),
);
