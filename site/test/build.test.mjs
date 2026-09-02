/**
 * Assertions over the built site, not over the code that built it.
 *
 * The distinction matters. Most of these properties -- no inline script, no
 * third-party origin, no leaked path -- are things the generator intends, and
 * intentions do not survive a refactor. Reading the finished artifact is the
 * only check that stays true when somebody adds a page and forgets the rule.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(SITE, 'dist');

/** Every file under dist, as site-relative paths. */
function walk(dir, base = dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, base, out);
    else out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out;
}

let files = [];
let pages = [];

before(() => {
  assert.ok(
    fs.existsSync(DIST),
    'site/dist is missing -- run `npm run site:build` before the site tests',
  );
  files = walk(DIST);
  pages = files
    .filter((f) => f.endsWith('.html'))
    .map((f) => ({ file: f, html: fs.readFileSync(path.join(DIST, f), 'utf8') }));
  assert.ok(pages.length >= 10, `expected the full site, found ${pages.length} pages`);
});

// --- no inline execution -------------------------------------------------------

describe('the output needs no unsafe-inline', () => {
  test('no inline <script>', () => {
    for (const { file, html } of pages) {
      const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
      for (const [, attrs, body] of scripts) {
        assert.equal(body.trim(), '', `${file} has an inline script body`);
        assert.match(attrs, /\ssrc=/, `${file} has a <script> with no src`);
      }
    }
  });

  test('no inline <style>', () => {
    for (const { file, html } of pages) {
      assert.ok(!/<style\b/i.test(html), `${file} contains a <style> element`);
    }
  });

  test('no style attributes', () => {
    // These need style-src-attr 'unsafe-inline', which would widen the policy
    // for the whole site.
    for (const { file, html } of pages) {
      const hit = html.match(/\sstyle\s*=\s*"/i);
      assert.equal(hit, null, `${file} has a style attribute: ${hit && hit[0]}`);
    }
  });

  test('no event-handler attributes', () => {
    for (const { file, html } of pages) {
      const hit = html.match(/\son(?:click|load|error|mouseover|focus|submit|change)\s*=/i);
      assert.equal(hit, null, `${file} has an inline handler: ${hit && hit[0]}`);
    }
  });

  test('no javascript: or data: URLs', () => {
    for (const { file, html } of pages) {
      assert.ok(!/["'\s(]javascript:/i.test(html), `${file} contains a javascript: URL`);
      assert.ok(!/["'\s(]data:text\/html/i.test(html), `${file} contains a data: HTML URL`);
    }
  });
});

// --- no third parties ----------------------------------------------------------

describe('nothing loads from another origin', () => {
  const SUBRESOURCE = /<(?:script|link|img|iframe|video|audio|source|embed|object)\b[^>]*\b(?:src|href|data)\s*=\s*"([^"]+)"/gi;

  test('every subresource is same-origin and absolute-path', () => {
    for (const { file, html } of pages) {
      for (const [tag, url] of html.matchAll(SUBRESOURCE)) {
        // <link rel="canonical"> and rel="alternate" are references, not loads.
        if (/rel="(canonical|alternate)"/i.test(tag)) continue;
        assert.ok(
          url.startsWith('/'),
          `${file} loads ${url} -- subresources must be same-origin absolute paths`,
        );
      }
    }
  });

  test('no CDN or analytics hostname is ever fetched from', () => {
    // Matched against hosts of real URLs, not against the page text. The docs
    // are allowed to contain the word "plausible" in a sentence; what they may
    // not contain is a request to plausible.io.
    const banned = [
      'googletagmanager.com',
      'google-analytics.com',
      'googleapis.com',
      'gstatic.com',
      'unpkg.com',
      'jsdelivr.net',
      'cdnjs.cloudflare.com',
      'plausible.io',
      'segment.io',
      'hotjar.com',
      'sentry.io',
      'cloudflareinsights.com',
      'polyfill.io',
    ];
    for (const { file, html } of pages) {
      for (const [, url] of html.matchAll(/(?:href|src|data|content)="(https?:\/\/[^"]+)"/gi)) {
        let host;
        try {
          host = new URL(url).host.toLowerCase();
        } catch {
          continue;
        }
        for (const bad of banned) {
          assert.ok(host !== bad && !host.endsWith(`.${bad}`), `${file} references ${host}`);
        }
      }
    }
  });

  test('the only external links are the project\'s own homes', () => {
    const allowed = new Set(['github.com', 'www.npmjs.com']);
    for (const { file, html } of pages) {
      for (const [, url] of html.matchAll(/href="(https?:\/\/[^"]+)"/gi)) {
        const host = new URL(url).host;
        if (host === 'leastgrant.xyz') continue;
        assert.ok(allowed.has(host), `${file} links to ${host}`);
      }
    }
  });

  test('every external link carries rel="noopener noreferrer"', () => {
    for (const { file, html } of pages) {
      for (const [tag, url] of html.matchAll(/<a\b([^>]*href="(https?:\/\/[^"]+)"[^>]*)>/gi)) {
        if (url.includes('leastgrant.xyz')) continue;
        assert.match(tag, /rel="noopener noreferrer"/, `${file}: ${tag}`);
      }
    }
  });
});

// --- nothing about the build machine -------------------------------------------

describe('the artifact says nothing about where it was built', () => {
  test('no absolute user paths, tokens or env leakage', () => {
    const patterns = [
      [/[\\/]Users[\\/](?!you\b|&lt;you&gt;)[^\\/\s"'<)]+/i, 'a real user directory'],
      [/[\\/]home[\\/](?!you\b)[a-z0-9_.-]+[\\/]/i, 'a real home directory'],
      [/[A-Za-z]:[\\/]LeastGrant/i, 'the checkout path'],
      [/AppData[\\/]Local[\\/]Temp/i, 'a build temp directory'],
      [/npm_[A-Za-z0-9]{30,}/, 'an npm token'],
      [/gh[pousr]_[A-Za-z0-9]{20,}/, 'a GitHub token'],
      [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'a private key'],
      [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS key id'],
    ];
    for (const rel of files) {
      if (!/\.(html|css|js|json|xml|txt|svg|webmanifest)$/i.test(rel)) continue;
      const body = fs.readFileSync(path.join(DIST, rel), 'utf8');
      for (const [re, what] of patterns) {
        const hit = body.match(re);
        assert.equal(hit, null, `${rel} leaks ${what}: ${hit && hit[0]}`);
      }
    }
  });

  test('no source maps or stray development artifacts shipped', () => {
    for (const rel of files) {
      assert.ok(!rel.endsWith('.map'), `${rel} is a source map`);
      assert.ok(!/(^|\/)\.env/.test(rel), `${rel} looks like an env file`);
      assert.ok(!/(^|\/)\.(git|DS_Store)/.test(rel), `${rel} should not ship`);
      assert.ok(!/(^|\/)\.capture\//.test(rel), `${rel} is a capture sandbox leftover`);
    }
    for (const { file, html } of pages) {
      assert.ok(!/sourceMappingURL/.test(html), `${file} references a source map`);
    }
  });
});

// --- the script itself ---------------------------------------------------------

describe('the one script file', () => {
  let js = '';
  before(() => {
    const name = files.find((f) => /^app\.[0-9a-f]+\.js$/.test(f));
    assert.ok(name, 'no content-hashed app.js in the output');
    const source = fs.readFileSync(path.join(DIST, name), 'utf8');
    // Comments are stripped before scanning. The file documents the APIs it
    // refuses to use, and a check that cannot tell "we never call innerHTML"
    // from a call to innerHTML is not a check.
    js = source
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .split('\n')
      .map((line) => line.replace(/(^|[^:'"`\\])\/\/.*$/, '$1'))
      .join('\n');
  });

  test('does not evaluate strings', () => {
    for (const bad of ['eval(', 'new Function(', 'setTimeout("', 'setInterval("']) {
      assert.ok(!js.includes(bad), `app.js uses ${bad}`);
    }
  });

  test('never turns a string into markup', () => {
    for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write']) {
      assert.ok(!js.includes(bad), `app.js uses ${bad}`);
    }
  });

  test('makes no network requests', () => {
    for (const bad of ['fetch(', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', 'EventSource', 'import(']) {
      assert.ok(!js.includes(bad), `app.js uses ${bad}`);
    }
  });

  test('stores nothing', () => {
    for (const bad of ['localStorage', 'sessionStorage', 'document.cookie', 'indexedDB']) {
      assert.ok(!js.includes(bad), `app.js uses ${bad}`);
    }
  });

  test('honours prefers-reduced-motion', () => {
    assert.match(js, /prefers-reduced-motion/);
  });
});

// --- metadata ------------------------------------------------------------------

describe('metadata is correct on every page', () => {
  test('each page declares a language', () => {
    for (const { file, html } of pages) assert.match(html, /<html lang="en">/, file);
  });

  test('each page has exactly one <h1>', () => {
    for (const { file, html } of pages) {
      const count = (html.match(/<h1\b/g) || []).length;
      assert.equal(count, 1, `${file} has ${count} <h1> elements`);
    }
  });

  test('each page has a non-empty title and description', () => {
    for (const { file, html } of pages) {
      const title = html.match(/<title>([^<]*)<\/title>/);
      assert.ok(title && title[1].trim().length > 8, `${file} has a thin <title>`);
      assert.ok(title[1].length <= 70, `${file} title is ${title[1].length} chars`);

      const desc = html.match(/<meta name="description" content="([^"]*)"/);
      assert.ok(desc, `${file} has no description`);
      assert.ok(
        desc[1].length >= 60 && desc[1].length <= 200,
        `${file} description is ${desc[1].length} chars: ${desc[1]}`,
      );
    }
  });

  test('canonical URLs are absolute, on the canonical host, and match the path', () => {
    for (const { file, html } of pages) {
      const m = html.match(/<link rel="canonical" href="([^"]+)"/);
      assert.ok(m, `${file} has no canonical link`);
      const url = new URL(m[1]);
      assert.equal(url.protocol, 'https:', `${file} canonical is not https`);
      assert.equal(url.host, 'leastgrant.xyz', `${file} canonical host is ${url.host}`);

      if (file === '404.html') continue;
      const expected = '/' + file.replace(/index\.html$/, '');
      assert.equal(url.pathname, expected, `${file} canonical points at ${url.pathname}`);
    }
  });

  test('social preview metadata is complete', () => {
    for (const { file, html } of pages) {
      assert.match(html, /<meta property="og:title"/, file);
      assert.match(html, /<meta property="og:description"/, file);
      assert.match(html, /<meta property="og:image" content="https:\/\/leastgrant\.xyz\/og\.png"/, file);
      assert.match(html, /<meta property="og:image:width" content="1200"/, file);
      assert.match(html, /<meta name="twitter:card" content="summary_large_image"/, file);
      assert.match(html, /<meta property="og:image:alt"/, file);
    }
  });

  test('the share image and icons exist at the sizes declared', () => {
    for (const name of ['og.png', 'favicon.svg', 'icon-180.png', 'icon-192.png', 'icon-512.png']) {
      assert.ok(files.includes(name), `${name} is missing from the build`);
    }
  });
});

// --- links ---------------------------------------------------------------------

describe('internal links go somewhere', () => {
  test('every internal href resolves to a file in the build', () => {
    const has = new Set(files);
    for (const { file, html } of pages) {
      for (const [, href] of html.matchAll(/href="(\/[^"#?]*)(?:[#?][^"]*)?"/g)) {
        const target = href.endsWith('/') ? `${href.slice(1)}index.html` : href.slice(1);
        assert.ok(has.has(target), `${file} links to ${href}, which is not in the build`);
      }
    }
  });

  test('every same-page anchor target exists', () => {
    for (const { file, html } of pages) {
      const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
      for (const [, hash] of html.matchAll(/href="#([^"]+)"/g)) {
        assert.ok(ids.has(hash), `${file} links to #${hash}, which has no target`);
      }
    }
  });

  test('the sitemap lists the real pages and nothing else', () => {
    const xml = fs.readFileSync(path.join(DIST, 'sitemap.xml'), 'utf8');
    const listed = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => new URL(m[1]).pathname);
    assert.ok(listed.length >= 10, `sitemap has ${listed.length} entries`);
    for (const route of listed) {
      const target = route.endsWith('/') ? `${route.slice(1)}index.html` : route.slice(1);
      assert.ok(files.includes(target), `sitemap lists ${route}, which is not built`);
    }
    // The 404 body is not a destination and must not be advertised as one.
    assert.ok(!listed.some((r) => r.includes('404')), 'sitemap lists the 404 page');
  });

  test('robots.txt points at the sitemap on the canonical host', () => {
    const robots = fs.readFileSync(path.join(DIST, 'robots.txt'), 'utf8');
    assert.match(robots, /Sitemap: https:\/\/leastgrant\.xyz\/sitemap\.xml/);
  });
});

// --- accessibility floor --------------------------------------------------------

describe('the accessibility floor', () => {
  test('every page has a skip link that targets main', () => {
    for (const { file, html } of pages) {
      assert.match(html, /<a class="skip" href="#main">/, file);
      assert.match(html, /<main id="main">/, file);
    }
  });

  test('buttons have accessible text or a label', () => {
    for (const { file, html } of pages) {
      for (const [tag, inner] of html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {
        const text = inner.replace(/<[^>]+>/g, '').trim();
        assert.ok(
          text.length > 0 || /aria-label=/.test(tag),
          `${file} has a button with no accessible name: ${tag}`,
        );
      }
    }
  });

  test('decorative glyphs are hidden from assistive technology', () => {
    for (const { file, html } of pages) {
      for (const [tag] of html.matchAll(/<span class="pip"[^>]*>/g)) {
        assert.match(tag, /aria-hidden="true"/, `${file}: ${tag}`);
      }
    }
  });

  test('toggle buttons expose their pressed state', () => {
    const home = pages.find((p) => p.file === 'index.html');
    const picks = [...home.html.matchAll(/<button[^>]*data-pick[^>]*>/g)];
    assert.ok(picks.length >= 4, 'expected the decision walkthrough buttons');
    for (const [tag] of picks) assert.match(tag, /aria-pressed="(true|false)"/, tag);
  });

  test('navigation landmarks are labelled', () => {
    for (const { file, html } of pages) {
      for (const [tag] of html.matchAll(/<nav\b([^>]*)>/g)) {
        assert.match(tag, /aria-label="/, `${file} has an unlabelled <nav>: ${tag}`);
      }
    }
  });
});

// --- claims that must stay tied to the repository --------------------------------

describe('the site does not invent facts', () => {
  test('the version on the page is the version in package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(SITE, '..', 'package.json'), 'utf8'));
    const home = pages.find((p) => p.file === 'index.html').html;
    assert.ok(home.includes(`v${pkg.version}`), `home page does not mention v${pkg.version}`);
  });

  test('no page names a LeastGrant version other than the current one', () => {
    // The version reaches the page through facts.version, which is read from
    // package.json at build time, so a release updates the site by being
    // released. That only holds while nobody types a version by hand, and a
    // hardcoded one is invisible until it is months stale — the home page test
    // above would still pass, because the correct version is also present.
    //
    // Matched on our own major so the versions of other tools on these pages
    // (Cursor v2.1.240, codex-cli 0.152.0) are not swept up.
    //
    // Prose the site writes, not the Markdown it renders. THREAT-MODEL.md says
    // "what the v0.1.0 audit found" and RELEASING.md uses `v0.1.1` as the tag
    // in an example command; both are correct, and both are the repository's
    // words. A docs page that edited them to look current would be exactly the
    // drift these pages exist to avoid. If that text is wrong, it is wrong in
    // the repository, and that is where it gets fixed.
    const rendered = /^docs\/[^/]+\/index\.html$/;

    const pkg = JSON.parse(fs.readFileSync(path.join(SITE, '..', 'package.json'), 'utf8'));
    const major = pkg.version.split('.')[0];
    const ours = new RegExp(`v${major}\\.\\d+\\.\\d+`, 'g');

    const stale = [];
    for (const page of pages.filter((p) => !rendered.test(p.file))) {
      for (const found of new Set(page.html.match(ours) ?? [])) {
        if (found !== `v${pkg.version}`) stale.push(`${page.file}: ${found}`);
      }
    }
    assert.deepEqual(stale, [], `stale version strings (current is v${pkg.version})`);
  });

  test('every terminal block on the home page is a real verdict', () => {
    const home = pages.find((p) => p.file === 'index.html').html;
    // Each captured block keeps the CLI's own shape: two leading spaces, a
    // verdict glyph, the word. Anything hand-written would not match.
    const verdicts = [...home.matchAll(/class="v-(allow|ask|deny)">([✓?✗]) (allow|ask|deny)</g)];
    assert.ok(verdicts.length >= 8, `only ${verdicts.length} verdict marks on the home page`);
    for (const [, cls, , word] of verdicts) {
      assert.equal(cls, word, 'a verdict mark is coloured differently from its word');
    }
  });

  test('every hedge the README makes survives onto the site, verbatim', () => {
    // The invariant, not a list of strings: whatever status the README gives an
    // agent, the site shows that exact status. Hardcoding the wording meant
    // this test failed the day an integration was genuinely promoted, which
    // trains people to edit the test rather than read it.
    const readme = fs.readFileSync(path.join(SITE, '..', 'README.md'), 'utf8');
    const agents = pages.find((p) => p.file === 'docs/agents/index.html').html;

    const table = readme.slice(readme.indexOf('## Agent support'));
    const rows = [...table.matchAll(/^\|\s*\*\*([^|*]+)\*\*\s*\|\s*([^|]+?)\s*\|/gm)];
    assert.ok(rows.length >= 4, `parsed ${rows.length} agent rows from the README`);

    let hedged = 0;
    for (const [, agent, status] of rows) {
      assert.ok(agents.includes(status), `the agents page dropped "${status}" for ${agent}`);
      // "Partial" is the current vocabulary for a hedge, and it is a stronger
      // one than the prose it replaced: it comes from compatibility/<agent>.json
      // and carries a specific list of what is not covered, rather than a
      // sentence somebody wrote. Cursor is Partial because writes are not
      // intercepted at all and reads are seen after the fact.
      if (/not yet verified|unverified|not yet|partial/i.test(status)) hedged++;
    }
    // And at least one hedge should still exist. If every integration is
    // suddenly "tested end to end", that is worth a human looking at.
    assert.ok(hedged >= 1, 'no agent is hedged any more — did a claim get upgraded without evidence?');
  });

  test('the "sample of one" caveat travels with the numbers', () => {
    const home = pages.find((p) => p.file === 'index.html').html;
    assert.ok(home.includes('41%'), 'the home page quotes the allow rate');
    assert.match(home, /sample of one/, 'the caveat is missing from the home page');
  });

  test('the security page leads with what it is not', () => {
    const sec = pages.find((p) => p.file === 'security/index.html').html;
    assert.match(sec, /<h1[^>]*>LeastGrant is\s+not a sandbox<\/h1>/);
    assert.match(sec, /fails open/i);
    assert.match(sec, /security\/advisories\/new/);
  });
});

// --- regressions from the adversarial review --------------------------------

describe('claims the review found overstated', () => {
  let home = '';
  let sec = '';
  before(() => {
    home = pages.find((p) => p.file === 'index.html').html;
    sec = pages.find((p) => p.file === 'security/index.html').html;
  });

  test('the promotion bar mentions the weaker second route', () => {
    // The card said every promotion needs approvals across two sessions AND
    // two days. Project-local reads take a different route: 8 sightings across
    // 2 sessions, no second day. Stating only the strict rule oversells it.
    const readme = fs.readFileSync(path.join(SITE, '..', 'README.md'), 'utf8');
    assert.match(readme, /8\s*\n?sightings across 2 sessions with no second day required/);
    assert.match(home, /8 sightings across 2 sessions, no second day/);
  });

  test('the Cursor read caveat appears wherever agent support is claimed', () => {
    // The home page says "the answer does not change with the editor you
    // opened". Cursor's beforeReadFile has no "ask", so it does change; the
    // caveat has to travel with the claim.
    for (const [where, html] of [
      ['home', home],
      ['agents', pages.find((p) => p.file === 'docs/agents/index.html').html],
    ]) {
      assert.match(html, /beforeReadFile/, `${where} claims parity without the Cursor caveat`);
    }
  });

  test('the understood-share figure is attributed to one machine', () => {
    const at = home.indexOf('44.5');
    assert.ok(at > 0, 'the understood share is not on the page');
    const nearby = home.slice(at, at + 400);
    assert.match(nearby, /one machine/, 'the figure has no caveat attached to it');
  });

  test('the fuzzing claim names the platforms it actually runs on', () => {
    const workflow = fs.readFileSync(path.join(SITE, '..', '.github', 'workflows', 'verify.yml'), 'utf8');
    const fuzz = workflow.slice(workflow.indexOf('\n  fuzz:'));
    const matrix = fuzz.slice(0, fuzz.indexOf('runs-on'));
    const onMac = /macos/.test(matrix);
    assert.equal(onMac, false, 'fuzzing now runs on macOS; the security page should say so');
    assert.match(sec, /Linux and Windows/, 'the security page overstates where fuzzing runs');
  });

  test('simulate is not described as covering the posture it excludes', () => {
    const at = home.indexOf('leastgrant simulate');
    assert.ok(at > 0);
    const nearby = home.slice(at, at + 400);
    assert.match(nearby, /three postures|not in that comparison/, 'simulate is described as covering observe');
  });
});

describe('generated links resolve', () => {
  test('no rendered link escapes the repository root', () => {
    // `[../SECURITY.md](../SECURITY.md)` in docs/privacy.md became
    // `blob/main/../SECURITY.md`, which 404s. Links are resolved against the
    // source file's directory now.
    for (const { file, html } of pages) {
      for (const [, href] of html.matchAll(/href="(https:\/\/github\.com\/[^"]+)"/g)) {
        assert.ok(!href.includes('/..'), `${file} links to ${href}`);
      }
    }
  });

  test('a doc link to another published doc stays on this site', () => {
    const privacy = pages.find((p) => p.file === 'docs/privacy/index.html').html;
    assert.match(privacy, /href="\/docs\/security-policy\/"/, 'privacy still links off-site for SECURITY.md');
  });
});

describe('the implicit favicon request is answered', () => {
  test('favicon.ico exists and is a valid single-image icon', () => {
    // Browsers request /favicon.ico whether or not the HTML declares an icon.
    // Without one, every first visit logs a 404 at the origin.
    const ico = fs.readFileSync(path.join(DIST, 'favicon.ico'));
    assert.equal(ico.readUInt16LE(0), 0, 'reserved field is not zero');
    assert.equal(ico.readUInt16LE(2), 1, 'not an icon');
    assert.equal(ico.readUInt16LE(4), 1, 'expected exactly one image');
    assert.equal(ico.readUInt8(6), 32, 'not 32px wide');
    const offset = ico.readUInt32LE(18);
    assert.equal(offset, 22, 'image offset is wrong');
    assert.equal(
      ico.subarray(offset, offset + 4).toString('hex'),
      '89504e47',
      'the embedded image is not a PNG',
    );
    assert.equal(ico.readUInt32LE(14) + offset, ico.length, 'declared length does not match the file');
  });
});

describe('the docs layout reserves a sidebar only when there is one', () => {
  test('no page renders its article into an empty sidebar column', () => {
    // `.doc` declared two columns unconditionally, so a page without a table of
    // contents put its article in the 15rem track and rendered as a narrow
    // ribbon on desktop. Mobile was unaffected, which is why it shipped.
    for (const { file, html } of pages) {
      const wrapper = html.match(/<div class="shell doc([^"]*)"/);
      if (!wrapper) continue;
      const twoColumn = wrapper[1].includes('doc--toc');
      const hasToc = /<nav class="toc"/.test(html);
      assert.equal(
        twoColumn,
        hasToc,
        twoColumn
          ? `${file} reserves a sidebar column but renders no .toc`
          : `${file} renders a .toc but does not opt into the two-column layout`,
      );
    }
  });

  test('the two-column rule is keyed to the modifier, not to .doc', () => {
    const css = fs.readFileSync(path.join(SITE, 'assets', 'app.css'), 'utf8');
    const wide = css.match(/@media \(min-width: 1000px\) \{\s*\.doc[^{]*\{[^}]*grid-template-columns:[^;]+;/);
    assert.ok(wide, 'no desktop grid rule found for the docs layout');
    assert.match(wide[0], /\.doc--toc/, 'the sidebar layout still applies to every .doc');
  });
});

// --- the compatibility page -------------------------------------------------

describe('the compatibility page tells the truth about what does not work', () => {
  const html = () => pages.find((p) => p.file === 'compatibility/index.html')?.html ?? '';
  const data = () =>
    fs
      .readdirSync(path.join(SITE, '..', 'compatibility'))
      .filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(SITE, '..', 'compatibility', f), 'utf8')));

  test('the page exists and lists every agent in the data', () => {
    const page = html();
    assert.ok(page, 'no compatibility page was built');
    for (const agent of data()) {
      assert.ok(page.includes(agent.name), `${agent.name} is missing from the page`);
    }
  });

  test('every limitation in the data reaches the page', () => {
    // The failure this guards against is the tempting one: a page that renders
    // the matrix, which looks mostly fine, and quietly drops the prose saying
    // why it is not. The limitations are the content here.
    //
    // Compared as plain text against a de-entitied page rather than by regex.
    // The first version escaped each limitation into a pattern, which is a lot
    // of backslashes standing between the test and what it means, and it broke
    // on the apostrophe in "Cursor's" before it ever ran.
    const plain = html()
      .replace(/&#39;/g, "'")
      .replace(/&quot;/g, '"')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>');
    for (const agent of data()) {
      for (const limit of [...agent.upstreamLimitations, ...agent.leastgrantLimitations]) {
        assert.ok(
          plain.includes(limit),
          `${agent.id}: this limitation never reaches the page — ${limit.slice(0, 70)}`,
        );
      }
    }
  });

  test('an unknown is printed as unknown, never as a blank', () => {
    // A blank cell reads as "fine", which is the opposite of what unknown means.
    const page = html();
    const anyUnknown = data().some((a) =>
      [...Object.values(a.verdicts), ...Object.values(a.interception)].some(
        (f) => f && typeof f === 'object' && f.value === 'unknown',
      ),
    );
    if (anyUnknown) assert.match(page, /unknown/, 'the data has unknowns and the page never says so');
  });

  test('no agent is described as verified without a platform it was verified on', () => {
    const page = html();
    for (const agent of data()) {
      if (agent.osTested.length) continue;
      // Anchor on the agent's own section, not on the first place its name
      // appears — that is the summary table, whose next 1200 characters are
      // cells rather than the sentence being checked.
      const idx = page.indexOf(`id="${agent.id}"`);
      assert.ok(idx >= 0, `no section for ${agent.id}`);
      const section = page.slice(idx, idx + 1200);
      assert.ok(
        /Nobody has run LeastGrant inside it|never run inside/.test(section),
        `${agent.id} has no tested platform but the page does not say so`,
      );
    }
  });

  test('the page and the CLI agree, because both call assess()', () => {
    // Not a rendering test: a guard against someone re-deriving the grade in
    // the template. If this file ever computes a level itself, the CLI and the
    // site can disagree about the same agent, which is the whole failure the
    // data directory was created to prevent.
    const src = fs.readFileSync(path.join(SITE, 'pages', 'compatibility.mjs'), 'utf8');
    assert.ok(
      !/function\s+assess|const\s+assess\s*=/.test(src),
      'the compatibility page defines its own assess() instead of using the one in core',
    );
  });
});

// --- the bypass corpus page ---------------------------------------------------

describe('the corpus page publishes exactly what the tests run', () => {
  const html = () => pages.find((p) => p.file === 'security/corpus/index.html')?.html ?? '';
  const data = () => JSON.parse(fs.readFileSync(path.join(SITE, '..', 'corpus', 'bypasses.json'), 'utf8'));

  test('every case in the corpus appears on the page', () => {
    // The claim the page makes is that these exact inputs are regression-tested.
    // That is only true if the page shows the whole file, so a page rendering
    // some of them would be a quiet lie rather than a rendering bug.
    const plain = html().replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>');
    for (const c of data().cases) {
      assert.ok(plain.includes(c.command), `corpus case missing from the page: ${c.id}`);
    }
  });

  test('the count in the headline is the real count', () => {
    assert.match(html(), new RegExp(`>${data().cases.length} ways`), 'the headline count is not the corpus size');
  });

  test('it refuses the reading that this means secure', () => {
    // The failure mode of publishing a list of defeated attacks is that readers
    // conclude the list is exhaustive. The disclaimer is load-bearing content,
    // not decoration, so it is asserted like content.
    const page = html();
    assert.match(page, /does not mean LeastGrant is secure/i);
    assert.match(page, /nobody has thought of/i);
  });
});
