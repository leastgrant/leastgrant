/**
 * Build leastgrant.xyz.
 *
 *     npm run site:build          -> site/dist/
 *
 * Zero dependencies, by the same argument the product makes about itself: this
 * generates the public face of a tool whose pitch is that there is no
 * third-party code in the permission path, and a build with forty transitive
 * packages in it would undercut that on the first `npm audit`.
 *
 * The build is a pure function of the repository. Documentation pages render
 * the repo's Markdown, every figure is read out of source, and every terminal
 * block is captured by running the real CLI. Nothing about the product is
 * asserted here in prose that is not also true in the repo -- which is the only
 * way a website stays accurate without somebody remembering to update it.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createHash } from 'node:crypto';
import { brotliCompressSync, gzipSync, constants as zlib } from 'node:zlib';

import { gather } from './lib/facts.mjs';
import { captureVerdicts, captureHelp, assertClean, assertCleanBinary, REPO } from './lib/capture.mjs';
import { ORIGIN, setAssets } from './lib/layout.mjs';
import { iconSvg, MARK_PATHS } from './lib/brand.mjs';
import { home } from './pages/home.mjs';
import { security } from './pages/security.mjs';
import { DOCS, docPage, docsIndex, cliPage } from './pages/docs.mjs';
import { agentsIndex, agentPage } from './pages/agents.mjs';
import { notFound } from './pages/not-found.mjs';
import { compatibility } from './pages/compatibility.mjs';
import { corpus } from './pages/corpus.mjs';
import {
  loadCompatibility,
  assess,
  deriveVerification,
  verificationProblems,
  GRADE_MEANING,
} from '../dist/src/core/compatibility.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, 'dist');
const ASSETS = path.join(HERE, 'assets');
const STATIC = path.join(HERE, 'static');

function write(rel, contents) {
  const target = path.join(OUT, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  return { rel, bytes: Buffer.byteLength(contents) };
}

function copyDir(from, to, filter = () => true) {
  if (!fs.existsSync(from)) return [];
  const written = [];
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const rel = path.join(to, entry.name);
    if (entry.isDirectory()) {
      written.push(...copyDir(src, rel, filter));
    } else if (filter(entry.name)) {
      const target = path.join(OUT, rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(src, target);
      written.push({ rel: rel.split(path.sep).join('/'), bytes: fs.statSync(src).size });
    }
  }
  return written;
}

export async function build({ quiet = false } = {}) {
  const log = quiet ? () => {} : (...a) => console.log(...a);

  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  log('reading the repository');
  const facts = gather();

  log(`running leastgrant v${facts.version} to capture verdicts`);
  const verdicts = await captureVerdicts();
  const help = captureHelp();
  if (help.version !== `leastgrant ${facts.version}`) {
    throw new Error(
      `the built CLI reports ${JSON.stringify(help.version)} but package.json says ` +
        `${facts.version} -- run \`npm run build\` so the site is built against the current code`,
    );
  }

  const written = [];
  const pages = [];

  const emit = (rel, html, route) => {
    written.push(write(rel, html));
    if (route) pages.push(route);
  };

  // Hash every cacheable asset into its filename before rendering, so each page
  // points at the exact bytes this build produced.
  //
  // Fonts are hashed too, and the stylesheet's url() references are rewritten
  // to match. Without that the fonts are served `immutable` for a year under
  // names that never change, which means a font can be replaced in the build
  // and never reach anyone who has already visited.
  log('hashing assets');
  const digestOf = (body) => createHash('sha256').update(body).digest('hex').slice(0, 10);

  const fontDir = path.join(ASSETS, 'fonts');
  const fontUrls = new Map();
  for (const name of fs.readdirSync(fontDir).filter((f) => f.endsWith('.woff2')).sort()) {
    const body = fs.readFileSync(path.join(fontDir, name));
    const out = `fonts/${name.replace(/\.woff2$/, `.${digestOf(body)}.woff2`)}`;
    written.push(write(out, body));
    fontUrls.set(`/fonts/${name}`, `/${out}`);
  }

  let css = fs.readFileSync(path.join(ASSETS, 'app.css'), 'utf8');
  for (const [from, to] of fontUrls) css = css.split(from).join(to);
  if (/\/fonts\/[A-Za-z]+-[A-Za-z]+\.woff2/.test(css)) {
    throw new Error('a font URL in app.css was not rewritten to its hashed name');
  }

  const hashed = {};
  const cssBody = Buffer.from(css, 'utf8');
  const cssName = `app.${digestOf(cssBody)}.css`;
  written.push(write(cssName, cssBody));
  hashed.css = `/${cssName}`;

  const jsBody = fs.readFileSync(path.join(ASSETS, 'app.js'));
  const jsName = `app.${digestOf(jsBody)}.js`;
  written.push(write(jsName, jsBody));
  hashed.js = `/${jsName}`;

  // The preload hints in <head> have to point at the hashed names too, or the
  // browser fetches a font twice: once from the hint, once from the stylesheet.
  hashed.preload = [fontUrls.get('/fonts/IBMPlexMono-Regular.woff2'), fontUrls.get('/fonts/IBMPlexSans-Regular.woff2')];
  setAssets(hashed);

  log('rendering pages');
  emit('index.html', home(facts, verdicts), '/');
  emit('security/index.html', security(facts), '/security/');
  emit('compatibility/index.html', compatibility(facts, loadCompatibility().map(assess)), '/compatibility/');
  emit('security/corpus/index.html', corpus(facts, JSON.parse(fs.readFileSync(path.join(REPO, 'corpus', 'bypasses.json'), 'utf8'))), '/security/corpus/');
  emit('docs/index.html', docsIndex(facts), '/docs/');
  emit('docs/cli/index.html', cliPage(facts, help), '/docs/cli/');
  // The Agents reference: an index plus one page per agent, all generated from
  // compatibility/*.json.
  //
  // The build refuses to publish a record that claims more than the runs it
  // lists — a `live` test with no version, a run marked done with no date, an
  // adapter with no verification record at all. A page that overstated its
  // evidence would be worse than no page, because it would be believed.
  {
    const records = loadCompatibility();
    const problems = records.flatMap(verificationProblems);
    if (problems.length) {
      throw new Error('compatibility records claim more than they establish: ' + problems.join('; '));
    }
    const entries = records.map((agent) => ({
      agent: { ...agent, repoFile: `${facts.repo}/blob/main/compatibility/${agent.id}.json` },
      assessment: assess(agent),
      grade: deriveVerification(agent),
    }));
    emit(
      'docs/agents/index.html',
      agentsIndex({ ...facts, gradeMeaning: GRADE_MEANING }, entries),
      '/docs/agents/',
    );
    for (const e of entries) {
      emit(
        `docs/agents/${e.agent.id}/index.html`,
        agentPage(facts, e.agent, e.assessment, e.grade, GRADE_MEANING[e.grade]),
        `/docs/agents/${e.agent.id}/`,
      );
    }
  }
  for (const doc of DOCS) {
    emit(`docs/${doc.slug}/index.html`, docPage(facts, doc), `/docs/${doc.slug}/`);
  }
  // Not in the sitemap: a 404 body is not a destination.
  emit('404.html', notFound(facts), null);

  log('copying assets');
  // The unhashed app.css / app.js are not copied: every page references the
  // hashed name, and shipping a second copy under a cacheable name would be two
  // sources of truth for the same bytes.
  written.push(
    ...copyDir(
      ASSETS,
      '.',
      (name) =>
        !name.startsWith('.') &&
        name !== 'OFL.txt' &&
        name !== 'app.css' &&
        name !== 'app.js' &&
        !name.endsWith('.woff2'),
    ),
  );
  written.push(...copyDir(STATIC, '.'));
  // The font licence has to travel with the fonts.
  if (fs.existsSync(path.join(ASSETS, 'fonts', 'OFL.txt'))) {
    fs.copyFileSync(path.join(ASSETS, 'fonts', 'OFL.txt'), path.join(OUT, 'fonts', 'OFL.txt'));
    written.push({ rel: 'fonts/OFL.txt', bytes: fs.statSync(path.join(ASSETS, 'fonts', 'OFL.txt')).size });
  }

  log('writing metadata');

  // The favicon is generated from brand.mjs rather than kept as a file, so the
  // mark cannot be edited in one place and stay stale in the other. The PNG
  // icons and the share image are committed (they need a rasteriser), so the
  // check below is what stops those drifting instead.
  written.push(write('favicon.svg', iconSvg()));

  const lockup = path.join(STATIC, 'logo-lockup.svg');
  if (fs.existsSync(lockup)) {
    const body = fs.readFileSync(lockup, 'utf8');
    if (!body.includes(MARK_PATHS)) {
      throw new Error(
        'site/static/logo-lockup.svg was drawn against a different version of the mark.\n' +
          '  Regenerate it: python site/tools/make-lockup.py',
      );
    }
  }

  written.push(write('robots.txt', robots()));
  written.push(write('sitemap.xml', sitemap(pages)));
  written.push(write('site.webmanifest', manifest()));

  // --- refuse to ship a page carrying this machine's identity ---------------
  //
  // Runs over the finished HTML rather than over the inputs, because the
  // interesting failure is something that got in during rendering.
  log('checking the output');
  for (const file of walk(OUT)) {
    const rel = path.relative(OUT, file).split(path.sep).join('/');

    // SVG is markup, and one of the two that ship is a committed file produced
    // by a Python script. Copying it in and checking only that it contains the
    // right mark geometry would let anything else in the file ride along --
    // and an SVG served from this origin runs with this origin's privileges.
    if (file.endsWith('.svg')) {
      const body = fs.readFileSync(file, 'utf8');
      for (const banned of ['<script', '<foreignObject', '<image', '<use', 'xlink:href', 'href=', 'javascript:']) {
        if (body.includes(banned)) throw new Error(`${rel} contains ${banned}`);
      }
      if (/\son\w+\s*=/.test(body)) throw new Error(`${rel} contains an event handler`);
      if (/https?:\/\//.test(body.replace(/xmlns(:\w+)?="[^"]*"/g, ''))) {
        throw new Error(`${rel} references an external origin`);
      }
    }

    if (/\.(html|css|js|json|xml|txt|webmanifest|svg)$/i.test(file)) {
      assertClean(fs.readFileSync(file, 'utf8'), rel);
    } else if (/\.(png|woff2|ico|jpe?g)$/i.test(file)) {
      // Binary assets get checked too. A PNG written by a browser and a woff2
      // written by a subsetter both carry metadata chunks nobody asked for, and
      // skipping them because "they are not text" is how a build path ends up
      // on a public CDN.
      assertCleanBinary(fs.readFileSync(file), rel);
    }
  }

  // --- precompress ----------------------------------------------------------
  //
  // Done here rather than per request. The origin is a tiny process behind a
  // tunnel; compressing the same 83 KB page on every hit is work it should
  // never have to repeat, and Brotli at maximum quality is only affordable
  // because it happens once.
  log('compressing');
  let saved = 0;
  for (const file of walk(OUT)) {
    if (!/\.(html|css|js|svg|json|xml|txt|webmanifest)$/i.test(file)) continue;
    const body = fs.readFileSync(file);
    if (body.length < 1024) continue; // the headers would cost more than the saving
    const br = brotliCompressSync(body, {
      params: {
        [zlib.BROTLI_PARAM_QUALITY]: 11,
        [zlib.BROTLI_PARAM_SIZE_HINT]: body.length,
      },
    });
    const gz = gzipSync(body, { level: 9 });
    fs.writeFileSync(`${file}.br`, br);
    fs.writeFileSync(`${file}.gz`, gz);
    saved += body.length - br.length;
  }
  log(`  brotli saves ${(saved / 1024).toFixed(0)} KB over the wire`);

  const total = written.reduce((n, f) => n + f.bytes, 0);
  const html = written.filter((f) => f.rel.endsWith('.html'));
  log(
    `\n  ${written.length} files, ${(total / 1024).toFixed(0)} KB` +
      `\n  ${html.length} pages, largest ${(Math.max(...html.map((f) => f.bytes)) / 1024).toFixed(0)} KB` +
      `\n  -> ${path.relative(REPO, OUT).split(path.sep).join('/')}\n`,
  );

  return { facts, verdicts, written, pages, out: OUT };
}

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else yield full;
  }
}

function robots() {
  // Everything is public and there is nothing to hide from a crawler, so the
  // only job here is to point at the sitemap and the canonical host.
  return `User-agent: *
Allow: /

Sitemap: ${ORIGIN}/sitemap.xml
`;
}

function sitemap(routes) {
  const urls = routes
    .map((r) => `  <url><loc>${ORIGIN}${r}</loc></url>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`;
}

function manifest() {
  return (
    JSON.stringify(
      {
        name: 'LeastGrant',
        short_name: 'LeastGrant',
        description: 'Permissions that learn how you work.',
        start_url: '/',
        display: 'browser',
        background_color: '#0b0a09',
        theme_color: '#0b0a09',
        icons: [
          { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
          { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: '/icon-512.png', sizes: '512x512', type: 'image/png' },
        ],
      },
      null,
      2,
    ) + '\n'
  );
}

// Run directly, but stay importable so the tests can build into a temp tree.
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  build().catch((err) => {
    console.error(`\n  site build failed: ${err.message}\n`);
    process.exitCode = 1;
  });
}
