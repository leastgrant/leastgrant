/**
 * Check the PUBLISHED site over real HTTP against the canonical records.
 *
 *   node scripts/verify-site-live.mjs [https://leastgrant.xyz]
 *
 * Not a rerun of the build tests. Those read `site/dist` on the machine that
 * built it. This reads what a stranger actually receives, after the origin has
 * rebuilt from `main`, the tunnel has carried it and the edge has cached it —
 * and deployment here is a pull-based timer, so "the tests passed" and "the
 * site says it" are separated by up to ten minutes and a machine nobody is
 * looking at.
 *
 * It compares the live HTML against `compatibility/*.json` on this checkout,
 * which means running it before the deploy lands reports the difference rather
 * than hiding it. That is the intended behaviour: the failure it exists to
 * catch is a site that has stopped agreeing with the data, and "not yet
 * deployed" is one honest reason for that.
 *
 * Exit 0 clean, 1 on any disagreement.
 */
import { loadCompatibility, assess, deriveVerification, LEVEL_LABEL } from '../dist/src/core/compatibility.js';

const BASE = (process.argv[2] ?? 'https://leastgrant.xyz').replace(/\/$/, '');
const records = loadCompatibility();
let bad = 0;
const fail = (s) => {
  bad++;
  console.log(`  ! ${s}`);
};

async function get(p) {
  const r = await fetch(BASE + p, { redirect: 'manual' });
  const body = r.status === 200 ? await r.text() : '';
  return { status: r.status, body, type: r.headers.get('content-type') ?? '' };
}

console.log(`GET ${BASE} — checking the published pages against compatibility/*.json\n`);

// --- the index ---------------------------------------------------------------
const index = await get('/docs/agents/');
console.log(`/docs/agents/  ${index.status}  ${(index.body.length / 1024).toFixed(1)} KB`);
if (index.status !== 200) fail(`the agents index is ${index.status}`);

for (const a of records) {
  if (!index.body.includes(`/docs/agents/${a.id}/`)) fail(`the index does not link to ${a.name}`);
  if (!index.body.includes(a.name)) fail(`the index does not name ${a.name}`);
}

// --- one page per agent ------------------------------------------------------
for (const a of records) {
  const p = `/docs/agents/${a.id}/`;
  const page = await get(p);
  const grade = deriveVerification(a);
  const level = LEVEL_LABEL[assess(a).level];
  const notes = [];

  if (page.status !== 200) {
    fail(`${p} is ${page.status}`);
    console.log(`${p.padEnd(30)} ${page.status}`);
    continue;
  }

  if (!page.body.includes(grade)) fail(`${a.id}: the published page does not show its grade ${grade}`);
  if (!page.body.includes(`>${level}<`)) fail(`${a.id}: the published page does not show enforcement "${level}"`);
  if (!page.body.includes(a.versionTested)) fail(`${a.id}: no version ${a.versionTested} on the published page`);
  if (!page.body.includes(a.lastVerified)) fail(`${a.id}: no last-verified date on the published page`);

  // A stronger grade must be absent, not merely unstated.
  const stronger = {
    'REAL TRANSPORT PROBED': ['LIVE VERIFIED'],
    'CONTRACT / BINARY VERIFIED': ['LIVE VERIFIED', 'REAL TRANSPORT PROBED'],
    UNVERIFIED: ['LIVE VERIFIED', 'REAL TRANSPORT PROBED'],
  }[grade] ?? [];
  for (const s of stronger) {
    if (page.body.includes(`>${s}<`)) fail(`${a.id}: published as ${grade} while badging ${s}`);
  }

  // Every recorded limitation reached the reader.
  for (const limit of [...(a.upstreamLimitations ?? []), ...(a.leastgrantLimitations ?? [])]) {
    const frag = limit.split(/[.—]/)[0].trim().slice(0, 40);
    if (frag.length < 12) continue;
    const esc = frag.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    if (!page.body.includes(esc)) fail(`${a.id}: a limitation is missing from the published page ("${frag}…")`);
  }

  // And the blocked runs say why, in public.
  for (const [kind, run] of Object.entries(a.verification ?? {})) {
    if (run?.done) continue;
    const frag = (run?.blockedBy ?? '').slice(0, 40);
    const esc = frag.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;').replace(/`/g, '<code>');
    if (frag && !page.body.includes(frag.split('`')[0].slice(0, 30))) {
      notes.push(`${kind} reason may be reworded on the page`);
    }
  }

  console.log(
    `${p.padEnd(30)} ${String(page.status)}  ${(page.body.length / 1024).toFixed(1).padStart(5)} KB  ${level} · ${grade}` +
      (notes.length ? `   (${notes.join('; ')})` : ''),
  );
}

// --- the home page's pips ----------------------------------------------------
const home = await get('/');
const pips = [...home.body.matchAll(/data-level="([a-z]+)"[^>]*><\/span>([^<]+)</g)].map((m) => ({
  level: m[1],
  agent: m[2].trim(),
}));
console.log(`\n/  ${home.status}  pips: ${pips.map((p) => `${p.agent}=${p.level}`).join(', ') || 'none found'}`);
for (const a of records.filter((x) => x.adapter)) {
  const pip = pips.find((p) => p.agent === a.name);
  if (!pip) {
    fail(`the published home page has no pip for ${a.name}`);
    continue;
  }
  const grade = deriveVerification(a);
  const want = grade === 'LIVE VERIFIED' ? 'verified' : grade === 'UNVERIFIED' ? 'none' : 'unverified';
  if (pip.level !== want) fail(`published home page: ${a.name} is ${grade} but its pip says "${pip.level}"`);
}

// --- nothing 404s that the site links to -------------------------------------
const links = [...index.body.matchAll(/href="(\/[^"#?]*)"/g)].map((m) => m[1]);
for (const href of [...new Set(links)]) {
  if (/\.(css|js|png|svg|woff2|webmanifest|ico)$/.test(href)) continue;
  const r = await fetch(BASE + href, { method: 'HEAD', redirect: 'manual' });
  if (r.status >= 400) fail(`the agents index links to ${href}, which is ${r.status}`);
}

console.log(bad ? `\n${bad} problem(s) on the published site` : '\nthe published site matches the records');
process.exit(bad ? 1 : 0);
