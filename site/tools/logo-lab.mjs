/**
 * A bench for iterating on the mark.
 *
 *   node site/tools/logo-lab.mjs
 *
 * Renders every candidate at the sizes that actually decide a logo -- 16px
 * first, because that is where most ideas die -- on dark, on light, and in the
 * one place the brand allows colour. Everything is hand-written geometry on a
 * 32-unit grid; nothing here is traced or generated.
 *
 * The direction, after eight explored and seven discarded: **the L is the
 * boundary and the G is what lives inside it.** The L is drawn as a corner, a
 * wall and a floor, which is the shape of a containment check -- and it is also
 * the project's initials. A monogram is only worth preferring over an abstract
 * mark when the letters happen to mean something, and here they do.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const OUT = path.join(process.cwd(), 'site', '.logo-lab.png');
const PAGE = path.join(process.cwd(), 'site', '.logo-lab.html');

/**
 * Build the mark from parameters, so the proportions can be reasoned about
 * rather than typed twice.
 *
 * `s` stroke weight. `gx` the G's left wall. `gt`/`gb` the G's top and bottom
 * bars. `gc` the crossbar. Every value is a stroke *centre*; the ink extends
 * s/2 either side, which is what the clearance arithmetic below checks.
 */
function mark({ s, wall = 2 + s / 2, floor, gx, gt, gb, gc, cx }) {
  return `<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="${s}" stroke-linecap="butt" stroke-linejoin="miter"><path d="M${wall} 2V${floor}H30"/><path d="M30 ${gt}H${gx}V${gb}H30V${gc}H${cx}"/></svg>`;
}

/** Report the clearances that decide whether it survives 16px. */
function clearances({ s, wall = 2 + s / 2, floor, gx, gt, gb, gc }) {
  const half = s / 2;
  return [
    `L wall ink ${(wall - half).toFixed(1)}–${(wall + half).toFixed(1)}`,
    `G gap ${(gx - half - (wall + half)).toFixed(1)}`,
    `floor gap ${(floor - half - (gb + half)).toFixed(1)}`,
    `counter ${(gb - gt - s).toFixed(1)}`,
    `aperture ${(gc - gt - s).toFixed(1)}`,
  ].join(' · ');
}

const SPECS = [
  { id: 'P2', s: 5, floor: 28, gx: 15, gt: 8.5, gb: 20.5, gc: 15, cx: 23.5 },
  { id: 'P3', s: 4, floor: 28, gx: 14, gt: 8, gb: 21, gc: 15, cx: 23 },
  { id: 'P6', s: 4.5, floor: 28, gx: 14.5, gt: 8, gb: 21.5, gc: 15, cx: 23 },
  { id: 'P7', s: 4.5, floor: 27.5, gx: 14.5, gt: 7.5, gb: 21, gc: 14.5, cx: 22.5 },
];

const CANDIDATES = SPECS.map((spec) => ({
  id: spec.id,
  name: `stroke ${spec.s} — ${clearances(spec)}`,
  svg: mark(spec),
}));

// The wordmark beside the mark, for the navbar and the lockup.
CANDIDATES.push({
  id: 'LOCK',
  name: 'lockup preview (mark + live type, not paths yet)',
  wide: true,
  svg: `<svg viewBox="0 0 172 32" fill="none"><g stroke="currentColor" stroke-width="5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M4.5 2V28H30"/><path d="M30 8.5H15V20.5H30V15H23.5"/></g></svg>`,
});

const cell = (svg, size, klass, label) =>
  `<div class="cell"><div class="${klass}" style="width:${size}px;height:${size}px">${svg.replace(
    '<svg',
    `<svg width="${size}" height="${size}"`,
  )}</div><em>${label || size}</em></div>`;

const rows = CANDIDATES.filter((c) => !c.wide)
  .map(
    (c) => `<div class="row">
    <div class="meta"><b>${c.id}</b><span>${c.name}</span></div>
    <div class="sizes">
      ${[16, 18, 20, 24, 32, 48, 96].map((s) => cell(c.svg, s, 'dark')).join('')}
      ${cell(c.svg, 32, 'light', 'light')}
      ${cell(c.svg, 32, 'amber', 'amber')}
    </div>
  </div>`,
  )
  .join('');

// A realistic navbar, because a mark that works on a swatch can still sit badly
// next to the wordmark at the size it will actually be seen.
const chosen = CANDIDATES[1].svg;
const bar = `<div class="bar">
  <span class="wm">${chosen.replace('<svg', '<svg width="19" height="19"')}<b>LeastGrant</b></span>
  <span class="nav">docs&nbsp;&nbsp;security&nbsp;&nbsp;github</span>
</div>
<div class="bar light-bar">
  <span class="wm">${chosen.replace('<svg', '<svg width="19" height="19"')}<b>LeastGrant</b></span>
  <span class="nav">docs&nbsp;&nbsp;security&nbsp;&nbsp;github</span>
</div>`;

fs.writeFileSync(
  PAGE,
  `<!doctype html><html><head><meta charset="utf-8"><style>
  body{background:#0b0a09;color:#b0a89d;font:13px ui-monospace,monospace;margin:0;padding:20px 24px}
  h1{color:#f2ede5;font-size:15px;margin:0 0 16px}
  h2{color:#8a8177;font-size:11px;margin:26px 0 8px;letter-spacing:.1em}
  .row{display:grid;grid-template-columns:330px 1fr;gap:18px;align-items:center;padding:12px 0;border-bottom:1px solid #1a1613}
  .meta b{color:#e2a63f;font-size:15px}
  .meta span{color:#8a8177;font-size:10.5px;display:block;margin-top:2px;line-height:1.5}
  .sizes{display:flex;gap:15px;align-items:flex-end;flex-wrap:wrap}
  .cell{text-align:center}
  .cell em{display:block;font-size:9px;color:#5a534b;font-style:normal;margin-top:5px}
  .dark{color:#f2ede5;display:grid;place-items:center}
  .light{color:#0b0a09;background:#f2ede5;display:grid;place-items:center;border-radius:2px}
  .amber{color:#e2a63f;display:grid;place-items:center}
  .bar{display:flex;align-items:center;justify-content:space-between;height:56px;padding:0 20px;
       background:#0b0a09;border:1px solid #262220;border-radius:5px;margin-bottom:10px}
  .light-bar{background:#f2ede5;border-color:#d8d2c8}
  .light-bar .wm b,.light-bar .wm{color:#0b0a09}
  .light-bar .nav{color:#6b6159}
  .wm{display:inline-flex;align-items:center;gap:9px;color:#f2ede5}
  .wm b{font-size:16px;letter-spacing:-.03em}
  .nav{color:#8a8177;font-size:12px}
  svg{display:block}
  </style></head><body>
  <h1>LeastGrant mark — the L is the boundary, the G is what lives inside it</h1>
  ${rows}
  <h2>IN THE NAVBAR (P2)</h2>
  ${bar}
  </body></html>`,
);

const r = spawnSync(
  CHROME,
  [
    '--headless',
    '--disable-gpu',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
    `--window-size=1320,${300 + SPECS.length * 128}`,
    `--screenshot=${OUT}`,
    `file:///${PAGE.split(path.sep).join('/')}`,
  ],
  { encoding: 'utf8', timeout: 120000 },
);

if (!fs.existsSync(OUT)) {
  console.error(r.stderr || 'chrome produced nothing');
  process.exit(1);
}
for (const spec of SPECS) console.log(spec.id.padEnd(4), clearances(spec));
console.log(`\n-> ${OUT}`);
