/**
 * The Agents documentation is a release surface, and these are its guards.
 *
 * Everything here tests SEMANTIC agreement between the built pages and the
 * canonical `compatibility/*.json` records — never a marketing string. An
 * honestly re-measured figure or a lowered grade must not require weakening a
 * test, because a test you have to weaken is a test people learn to edit.
 *
 * The failures these exist to prevent, in the order they are most likely:
 *
 *   an adapter ships and no page documents it
 *   a page claims a stronger grade than the recorded runs support
 *   a page and the record disagree about a verdict, a coverage class, or a version
 *   `live` is claimed with nothing recorded about what was run, on what, when
 *   a capability claim contradicts what the conformance suite actually drives
 *
 * Each of those has been a real state of this repository at some point today.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadCompatibility,
  assess,
  deriveVerification,
  verificationProblems,
  LEVEL_LABEL,
  GRADE_MEANING,
} from '../../dist/src/core/compatibility.js';

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(SITE, 'dist');

let records = [];
const pageFor = (id) => {
  const f = path.join(DIST, 'docs', 'agents', id, 'index.html');
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
};

before(() => {
  assert.ok(fs.existsSync(DIST), 'site/dist is missing — run `npm run site:build` first');
  records = loadCompatibility();
  assert.ok(records.length >= 5, `only ${records.length} compatibility records loaded`);
});

describe('every agent is documented', () => {
  test('each compatibility record has its own page', () => {
    // The "new adapter, no docs" guard. Pages are generated per record, so this
    // fails only if the generator stops covering one — which is exactly the
    // silent case worth catching.
    for (const a of records) {
      assert.ok(pageFor(a.id), `no /docs/agents/${a.id}/ page for ${a.name}`);
    }
  });

  test('the index links to every one of them', () => {
    const index = fs.readFileSync(path.join(DIST, 'docs', 'agents', 'index.html'), 'utf8');
    for (const a of records) {
      assert.ok(
        index.includes(`/docs/agents/${a.id}/`),
        `the agents index does not link to ${a.name}`,
      );
      assert.ok(index.includes(a.name), `the agents index does not name ${a.name}`);
    }
  });

  test('an agent with an adapter is reachable from the docs index', () => {
    const docs = fs.readFileSync(path.join(DIST, 'docs', 'index.html'), 'utf8');
    assert.ok(docs.includes('/docs/agents/'), 'the docs index does not link to agent support');
  });
});

describe('no page claims more than its record establishes', () => {
  test('the recorded runs justify the grade shown', () => {
    for (const a of records) {
      const grade = deriveVerification(a);
      const html = pageFor(a.id);
      assert.ok(html.includes(grade), `${a.name}'s page does not show its derived grade ${grade}`);

      // And the grade is not merely present — a stronger one must be absent,
      // because a page that mentions "LIVE VERIFIED" anywhere reads as one.
      const stronger = {
        'REAL TRANSPORT PROBED': ['LIVE VERIFIED'],
        'CONTRACT / BINARY VERIFIED': ['LIVE VERIFIED', 'REAL TRANSPORT PROBED'],
        'CONFORMANCE TESTED': ['LIVE VERIFIED', 'REAL TRANSPORT PROBED', 'CONTRACT / BINARY VERIFIED'],
        UNVERIFIED: ['LIVE VERIFIED', 'REAL TRANSPORT PROBED'],
      }[grade] ?? [];
      for (const s of stronger) {
        assert.ok(
          !html.includes(`>${s}<`),
          `${a.name} is ${grade} but its page renders the stronger badge ${s}`,
        );
      }
    }
  });

  test('a claimed run records what, on what version, on which OS, and when', () => {
    // The `live=true with nothing behind it` guard. The build throws on this
    // too; this is the version that names the agent in a test report.
    const problems = records.flatMap(verificationProblems);
    assert.deepEqual(problems, [], `records claim more than they establish:\n  ${problems.join('\n  ')}`);
  });

  test('a run that did not happen says why', () => {
    // Silence reads as an oversight and hides whether the thing is even
    // possible. "Cursor has no headless mode" is the useful answer; a blank is
    // not.
    for (const a of records) {
      for (const [kind, run] of Object.entries(a.verification ?? {})) {
        if (run?.done) continue;
        assert.ok(
          run?.blockedBy && run.blockedBy.length > 30,
          `${a.id}: ${kind} is not done and gives no substantive reason`,
        );
      }
    }
  });
});

describe('the pages and the records agree on the facts', () => {
  test('every verdict note on a page comes from the record', () => {
    for (const a of records) {
      const html = pageFor(a.id);
      for (const key of ['allow', 'ask', 'deny']) {
        const note = a.verdicts?.[key]?.note;
        if (!note) continue;
        // Compared on a distinctive fragment rather than the whole string,
        // because the renderer escapes entities. What matters is that the page
        // is quoting the record rather than paraphrasing it.
        const fragment = note.split(/[.—]/)[0].trim().slice(0, 40);
        if (fragment.length < 12) continue;
        assert.ok(
          html.includes(escapeHtml(fragment)),
          `${a.id}: the page does not carry the recorded note for ${key} ("${fragment}…")`,
        );
      }
    }
  });

  test('the version and OS on a page are the ones recorded', () => {
    for (const a of records) {
      const html = pageFor(a.id);
      assert.ok(html.includes(a.versionTested), `${a.id}: page does not show version ${a.versionTested}`);
      assert.ok(html.includes(a.lastVerified), `${a.id}: page does not show last-verified ${a.lastVerified}`);
      for (const os of a.osTested ?? []) {
        assert.ok(html.includes(os), `${a.id}: page does not show tested OS ${os}`);
      }
    }
  });

  test('every limitation in the record reaches the page', () => {
    // The one most tempting to trim, and the one whose absence would matter
    // most to somebody deciding whether to trust an integration.
    for (const a of records) {
      const html = pageFor(a.id);
      for (const limit of [...(a.upstreamLimitations ?? []), ...(a.leastgrantLimitations ?? [])]) {
        // Backticks stripped from both sides: they are Markdown in the record
        // and <code> on the page, so neither spelling matches the other.
        const fragment = limit.split(/[.—]/)[0].trim().slice(0, 40).replace(/`/g, '');
        if (fragment.length < 12) continue;
        const text = html
          .replace(/<[^>]+>/g, '')
          .replace(/&#39;/g, "'")
          .replace(/&quot;/g, '"')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&amp;/g, '&');
        assert.ok(
          text.includes(fragment),
          `${a.id}: a recorded limitation is missing from the page ("${fragment}…")`,
        );
      }
    }
  });

  test('every control path in the record is named on the page', () => {
    // The paths that decide what an agent may do LATER are the ones a reader
    // most needs and is least likely to guess: Antigravity has fourteen, and
    // the one that matters most is the host's own standing-grant store, which
    // is neither where LeastGrant installs itself nor anything the published
    // docs point at. A page that lists the install path and stops is telling
    // somebody they have seen the surface when they have seen one file of it.
    for (const a of records) {
      const html = pageFor(a.id);
      const cps = a.controlPaths ?? [];
      assert.ok(cps.length, `${a.id}: the record has no controlPaths to show`);
      for (const cp of cps) {
        assert.ok(
          html.includes(escapeHtml(cp.path)),
          `${a.id}: the page does not name the control path ${cp.path}`,
        );
        const fragment = cp.what.split(/[—.]/)[0].trim().slice(0, 40);
        if (fragment.length < 12) continue;
        assert.ok(
          html.includes(escapeHtml(fragment)),
          `${a.id}: the page names ${cp.path} without saying what it decides ("${fragment}…")`,
        );
      }
    }
  });

  test('a tool class the record says is not covered is not shown as gated', () => {
    for (const a of records) {
      const html = pageFor(a.id);
      for (const [cls, f] of Object.entries(a.interception ?? {})) {
        if (f?.value !== 'none') continue;
        // The row must exist and must not say "gated". Checked structurally so
        // renaming the display word does not silently pass.
        assert.ok(
          !new RegExp(`${cls}[^<]*</th>\\s*<td[^>]*><span>gated`, 'i').test(html),
          `${a.id}: ${cls} is not intercepted but the page shows it as gated`,
        );
      }
    }
  });
});

describe('the public status label is derived, not written', () => {
  test('enforcement on the page matches assess()', () => {
    // Through LEVEL_LABEL, which is the single place the enum is turned into a
    // word — README, site and `doctor` all read it. Asserting the label rather
    // than the enum is what makes "Veto only" and `degraded` provably the same
    // claim instead of two independently maintained ones.
    for (const a of records) {
      const level = assess(a).level;
      const label = LEVEL_LABEL[level];
      assert.ok(label, `no label defined for enforcement level ${level}`);
      const badges = pageFor(a.id).match(/<div class="badges">[\s\S]*?<\/div>/)?.[0] ?? '';
      assert.ok(badges, `${a.id}: page has no badge strip`);
      assert.ok(
        badges.includes(`>${label}<`),
        `${a.id}: page does not badge the derived enforcement level ${level} ("${label}")`,
      );
      // And no other enforcement word is badged in its place — a page showing
      // both "Partial" and "Enforcing" reads as the stronger one.
      for (const [other, word] of Object.entries(LEVEL_LABEL)) {
        if (other === level || word === label) continue;
        assert.ok(
          !badges.includes(`>${word}<`),
          `${a.id}: page badges "${word}" but assess() says ${level}`,
        );
      }
    }
  });

  test('every grade the index explains is one the model defines', () => {
    const index = fs.readFileSync(path.join(DIST, 'docs', 'agents', 'index.html'), 'utf8');
    for (const a of records) {
      const grade = deriveVerification(a);
      const meaning = GRADE_MEANING[grade];
      assert.ok(meaning, `no meaning defined for grade ${grade}`);
      const fragment = meaning.split(/[—,]/)[0].trim().slice(0, 36);
      assert.ok(
        index.includes(escapeHtml(fragment)),
        `the index does not explain ${grade} ("${fragment}…")`,
      );
    }
  });

  test('the home page pips mean what the records say', () => {
    // The failure this exists for is the quietest kind there is. The home page
    // coloured each agent by matching the README's status words with a regex —
    // `/^Enforcing, tested/`, `/^Enforcing/` — and when those words changed,
    // every match failed and every agent fell through to the worst level. Five
    // green pips went grey. Nothing caught it: the tests compared the README's
    // words to the site's words, and the two still agreed perfectly.
    //
    // So this asserts the derivation, not the markup. A pip is a claim about an
    // agent and has to be checked as one.
    const home = fs.readFileSync(path.join(DIST, 'index.html'), 'utf8');
    const pips = [...home.matchAll(/data-level="([a-z]+)"[^>]*><\/span>([^<]+)</g)].map((m) => ({
      level: m[1],
      agent: m[2].trim(),
    }));
    assert.ok(pips.length >= 4, `only ${pips.length} agent pips on the home page`);

    for (const a of records.filter((x) => x.adapter)) {
      const pip = pips.find((p) => p.agent === a.name);
      assert.ok(pip, `${a.name} has no pip on the home page`);
      const grade = deriveVerification(a);
      const want = grade === 'LIVE VERIFIED' ? 'verified' : grade === 'UNVERIFIED' ? 'none' : 'unverified';
      assert.equal(
        pip.level,
        want,
        `${a.name} is ${grade} and its pip says "${pip.level}" — expected "${want}"`,
      );
    }

    // And the whole set is not one value. Every regression of this shape ends
    // with all of them equal, because the derivation stopped discriminating
    // rather than producing a wrong answer for one agent.
    const distinct = new Set(records.filter((x) => x.adapter).map(deriveVerification));
    if (distinct.size > 1) {
      assert.ok(
        new Set(pips.map((p) => p.level)).size > 1,
        `the records hold ${distinct.size} different grades and every pip renders the same level — ` +
          `the derivation has stopped discriminating`,
      );
    }
  });

  test('an agent with no adapter is never shown as verified', () => {
    for (const a of records.filter((x) => !x.adapter)) {
      assert.equal(deriveVerification(a), 'UNVERIFIED', `${a.id} has no adapter but is not UNVERIFIED`);
      const html = pageFor(a.id);
      assert.ok(html.includes('No adapter ships'), `${a.id}: the page does not say no adapter ships`);
    }
  });
});

const escapeHtml = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
