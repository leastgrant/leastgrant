/**
 * The document shell: head, header, footer.
 *
 * There is no inline `<style>` and no inline `<script>` anywhere in the output,
 * which is what lets the Content-Security-Policy say `script-src 'self'` and
 * `style-src 'self'` with no `unsafe-inline` and no nonce machinery. That
 * constraint is easy to hold now and very hard to reintroduce later, so it is
 * asserted in the tests rather than left as an intention.
 */

import { esc, attr } from './html.mjs';
import { markSvg } from './brand.mjs';

export const ORIGIN = 'https://leastgrant.xyz';

/**
 * Content-hashed URLs for the stylesheet and script, set by the build.
 *
 * Hashing the filename is what lets the origin serve them `immutable` for a
 * year: a changed file is a different URL, so there is no cache to bust and no
 * window where a reader gets new HTML with last week's CSS.
 */
let assets = {
  css: '/app.css',
  js: '/app.js',
  preload: ['/fonts/IBMPlexMono-Regular.woff2', '/fonts/IBMPlexSans-Regular.woff2'],
};

export function setAssets(next) {
  assets = { ...assets, ...next };
}

const NAV = [
  { href: '/docs/', label: 'docs' },
  { href: '/security/', label: 'security' },
  { href: 'https://github.com/leastgrant/leastgrant', label: 'github', off: true },
  { href: 'https://www.npmjs.com/package/leastgrant', label: 'npm', off: true, small: true },
];

/**
 * @param {object} o
 * @param {string} o.title      full <title>; the wordmark is appended unless it is the home page
 * @param {string} o.description meta description and og:description
 * @param {string} o.path       absolute site path, e.g. "/security/"
 * @param {string} o.body       page HTML
 * @param {string} [o.bodyClass]
 * @param {boolean} [o.home]
 */
export function page(o) {
  const canonical = ORIGIN + o.path;
  const title = o.home ? o.title : `${o.title} — LeastGrant`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${attr(o.description)}">
<link rel="canonical" href="${attr(canonical)}">

${assets.preload
  .map((href) => `<link rel="preload" href="${attr(href)}" as="font" type="font/woff2" crossorigin>`)
  .join('\n')}
<link rel="stylesheet" href="${attr(assets.css)}">

<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-180.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#0b0a09">
<meta name="color-scheme" content="dark">

<meta property="og:type" content="website">
<meta property="og:site_name" content="LeastGrant">
<meta property="og:title" content="${attr(o.title)}">
<meta property="og:description" content="${attr(o.description)}">
<meta property="og:url" content="${attr(canonical)}">
<meta property="og:image" content="${attr(ORIGIN)}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="LeastGrant — three terminal verdicts: allow, ask, deny.">
<meta name="twitter:card" content="summary_large_image">

<script src="${attr(assets.js)}" defer></script>
</head>
<body${o.bodyClass ? ` class="${attr(o.bodyClass)}"` : ''}>
<a class="skip" href="#main">Skip to content</a>
${header(o.path)}
<main id="main">
${o.body}
</main>
${footer()}
</body>
</html>
`;
}

function header(path) {
  const links = NAV.map((item) => {
    const current = !item.off && path.startsWith(item.href) ? ' aria-current="page"' : '';
    const rel = item.off ? ' rel="noopener noreferrer"' : '';
    const hide = item.small ? ' class="hide-sm"' : '';
    return `<a href="${attr(item.href)}"${rel}${current}${hide}>${esc(item.label)}</a>`;
  }).join('\n        ');

  return `<header class="top">
  <div class="shell top-in">
    <a class="wordmark" href="/">${markSvg({ cls: 'mark', animate: true })}LeastGrant</a>
    <nav aria-label="Main">
        ${links}
    </nav>
  </div>
</header>`;
}

function footer() {
  return `<footer>
  <div class="shell">
    <div class="foot-grid">
      <div>
        <h2>start</h2>
        <ul>
          <li><a href="/#install">Install</a></li>
          <li><a href="/docs/getting-started/">Getting started</a></li>
          <li><a href="/docs/how-it-works/">How it works</a></li>
          <li><a href="/docs/cli/">CLI reference</a></li>
        </ul>
      </div>
      <div>
        <h2>understand</h2>
        <ul>
          <li><a href="/docs/threat-model/">Threat model</a></li>
          <li><a href="/security/">Security</a></li>
          <li><a href="/docs/privacy/">Privacy</a></li>
          <li><a href="/docs/agents/">Agent support</a></li>
        </ul>
      </div>
      <div>
        <h2>source</h2>
        <ul>
          <li><a href="https://github.com/leastgrant/leastgrant" rel="noopener noreferrer">GitHub</a></li>
          <li><a href="https://www.npmjs.com/package/leastgrant" rel="noopener noreferrer">npm</a></li>
          <li><a href="/docs/contributing/">Contributing</a></li>
          <li><a href="/docs/releasing/">Releasing</a></li>
        </ul>
      </div>
      <div>
        <h2>report</h2>
        <ul>
          <li><a href="https://github.com/leastgrant/leastgrant/security/advisories/new" rel="noopener noreferrer">Private advisory</a></li>
          <li><a href="https://github.com/leastgrant/leastgrant/issues" rel="noopener noreferrer">Issues</a></li>
        </ul>
      </div>
    </div>
    <p class="colophon">
      <span>Apache-2.0</span>
      <span>No trackers, no cookies, no third-party requests.</span>
      <span><a href="https://github.com/leastgrant/leastgrant/tree/main/site" rel="noopener noreferrer">This site is in the repo</a></span>
    </p>
  </div>
</footer>`;
}
