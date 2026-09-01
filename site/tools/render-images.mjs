/**
 * Generate the share image and the PNG icons.
 *
 *     node site/tools/render-images.mjs
 *
 * Run by hand, not by the build. The outputs are committed to `site/static/`,
 * so building the site needs nothing but Node -- which matters because the
 * alternative is either a rasteriser dependency in a project that has none, or
 * a build that only works on a machine with a browser installed.
 *
 * Chrome is used purely as a renderer here. The HTML below is written for this
 * one purpose and never served: it uses the real stylesheet variables and the
 * real subset fonts so the card is typeset in the same faces as the site, which
 * a hand-drawn PNG could not be.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { iconSvg, MARK_PATHS } from '../lib/brand.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SITE = path.resolve(HERE, '..');
const STATIC = path.join(SITE, 'static');
const FONTS = path.join(SITE, 'assets', 'fonts');

const CANDIDATES = [
  process.env['CHROME'],
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter(Boolean);

function findChrome() {
  for (const candidate of CANDIDATES) if (fs.existsSync(candidate)) return candidate;
  throw new Error(
    'no Chrome or Edge found. Set CHROME=/path/to/chrome, or regenerate the images elsewhere ' +
      '-- site/static/*.png is committed, so this only needs to run when the artwork changes.',
  );
}

const fileUrl = (p) => `file:///${p.split(path.sep).join('/').replace(/^\//, '')}`;

function shoot(chrome, html, out, width, height) {
  const tmp = path.join(os.tmpdir(), `lg-render-${Date.now()}-${Math.abs(hash(out))}.html`);
  fs.writeFileSync(tmp, html);
  try {
    const r = spawnSync(
      chrome,
      [
        '--headless',
        '--disable-gpu',
        '--hide-scrollbars',
        '--force-device-scale-factor=1',
        '--default-background-color=00000000',
        `--window-size=${width},${height}`,
        `--screenshot=${out}`,
        fileUrl(tmp),
      ],
      { encoding: 'utf8', timeout: 120000 },
    );
    if (!fs.existsSync(out)) {
      throw new Error(`chrome produced nothing for ${path.basename(out)}\n${r.stderr || ''}`);
    }
    console.log(`  ${path.basename(out).padEnd(16)} ${width}x${height}  ${fs.statSync(out).size} bytes`);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

/** Stable-ish suffix so two renders in the same millisecond do not collide. */
function hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

const face = (family, file, weight) => `
  @font-face {
    font-family: '${family}';
    src: url('${fileUrl(path.join(FONTS, file))}') format('woff2');
    font-weight: ${weight};
    font-display: block;
  }`;

/**
 * The share card.
 *
 * It is the product's own output, at poster size. A reader who sees this in a
 * timeline has already been told what LeastGrant does -- three commands, three
 * different answers, one of which is the interesting one.
 */
function shareCard() {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  ${face('Plex Mono', 'IBMPlexMono-Regular.woff2', 400)}
  ${face('Plex Mono', 'IBMPlexMono-SemiBold.woff2', 600)}
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { width: 1200px; height: 630px; }
  body {
    background: #0b0a09;
    font-family: 'Plex Mono', monospace;
    color: #b0a89d;
    padding: 74px 80px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    position: relative;
  }
  .frame {
    position: absolute;
    inset: 26px;
    border: 1px solid #262220;
    border-radius: 10px;
    pointer-events: none;
  }
  h1 {
    font-size: 92px;
    font-weight: 600;
    color: #f2ede5;
    letter-spacing: -0.05em;
    line-height: 1;
  }
  .brand { display: flex; align-items: center; gap: 26px; }
  .tag {
    font-size: 32px;
    color: #b0a89d;
    letter-spacing: -0.02em;
    margin-top: 20px;
  }
  .lines { font-size: 27px; line-height: 1.85; }
  .lines div { white-space: pre; }
  .allow { color: #7ea75e; }
  .ask   { color: #e2a63f; }
  .deny  { color: #d06043; }
  .cmd   { color: #f2ede5; }
  .foot {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 22px;
    color: #7c746a;
    border-top: 1px solid #262220;
    padding-top: 22px;
  }
  </style></head><body>
    <div class="frame"></div>
    <div>
      <div class="brand">
        <svg viewBox="0 0 32 32" width="76" height="76" fill="none" stroke="#f2ede5"
             stroke-width="4.5" stroke-linecap="butt" stroke-linejoin="miter">${MARK_PATHS}</svg>
        <h1>LeastGrant</h1>
      </div>
      <p class="tag">Let routine work flow. Catch the weird stuff.</p>
    </div>
    <div class="lines">
      <div><span class="allow">&#x2713; allow</span>  <span class="cmd">npm test</span></div>
      <div><span class="ask">? ask</span>    <span class="cmd">cat ~/.ssh/id_rsa</span></div>
      <div><span class="deny">&#x2717; deny</span>   <span class="cmd">echo x &gt;&gt; ~/.leastgrant/ledger.jsonl</span></div>
    </div>
    <div class="foot">
      <span>permissions that learn how you work</span>
      <span>leastgrant.xyz</span>
    </div>
  </body></html>`;
}

/** An icon at one size: the favicon artwork, scaled. */
function iconPage(size) {
  const svg = iconSvg();
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  * { margin: 0; padding: 0; }
  html, body { width: ${size}px; height: ${size}px; background: transparent; overflow: hidden; }
  svg { display: block; width: ${size}px; height: ${size}px; }
  </style></head><body>${svg}</body></html>`;
}

const chrome = findChrome();
console.log(`rendering with ${chrome}\n`);
fs.mkdirSync(STATIC, { recursive: true });

shoot(chrome, shareCard(), path.join(STATIC, 'og.png'), 1200, 630);
for (const size of [32, 180, 192, 512]) {
  shoot(chrome, iconPage(size), path.join(STATIC, `icon-${size}.png`), size, size);
}

// --- favicon.ico -------------------------------------------------------------
//
// Every browser requests /favicon.ico whether or not the HTML declares an icon,
// so not having one is a 404 on every first visit -- visible in the origin's
// logs and pointless.
//
// An ICO is a 6-byte header, a 16-byte directory entry, and the image. Since
// Vista the image may be a PNG rather than a bitmap, so the whole file is those
// 22 bytes wrapped around icon-32.png. Written by hand because pulling in an
// icon library for 22 bytes of struct would be absurd.
{
  const png = fs.readFileSync(path.join(STATIC, 'icon-32.png'));
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(1, 4); // one image

  const entry = Buffer.alloc(16);
  entry.writeUInt8(32, 0); // width
  entry.writeUInt8(32, 1); // height
  entry.writeUInt8(0, 2); // palette size: not paletted
  entry.writeUInt8(0, 3); // reserved
  entry.writeUInt16LE(1, 4); // colour planes
  entry.writeUInt16LE(32, 6); // bits per pixel
  entry.writeUInt32LE(png.length, 8);
  entry.writeUInt32LE(header.length + entry.length, 12); // offset to the image

  const ico = Buffer.concat([header, entry, png]);
  fs.writeFileSync(path.join(STATIC, 'favicon.ico'), ico);
  console.log(`  ${'favicon.ico'.padEnd(16)} 32x32     ${ico.length} bytes`);
}

console.log('\ncommit site/static/*.png and site/static/favicon.ico');
