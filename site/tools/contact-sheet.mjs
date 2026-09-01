/**
 * Build a contact sheet from the logo workflow's output.
 *
 * The agents can write SVG but cannot see it. This turns every proposal into a
 * page I can actually look at, at the sizes that decide it -- 16px is where
 * most logo ideas die, and no amount of rationale survives seeing the mark as
 * a favicon.
 *
 *   node site/tools/contact-sheet.mjs <journal.jsonl> [out.html]
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

const journalPath = process.argv[2];
const out = process.argv[3] || path.join(process.cwd(), 'site', '.logo-sheet.html');

if (!journalPath || !fs.existsSync(journalPath)) {
  console.error('usage: node site/tools/contact-sheet.mjs <journal.jsonl> [out.html]');
  process.exit(2);
}

const entries = fs
  .readFileSync(journalPath, 'utf8')
  .trim()
  .split('\n')
  .map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  })
  .filter((e) => e && e.type === 'result');

/**
 * Only render SVG that is safe and actually is SVG.
 *
 * This content came from a subagent, which makes it untrusted by construction
 * -- and it is about to be opened in a browser on this machine. Anything with a
 * script, an external reference or an event handler is dropped rather than
 * cleaned, because there is no legitimate reason for a logo proposal to contain
 * one and a proposal that does is not a proposal I want to look at.
 */
function safe(svg) {
  if (typeof svg !== 'string') return null;
  const s = svg.trim();
  if (!s.startsWith('<svg') || !s.endsWith('</svg>')) return null;
  if (/<script|<foreignObject|<image|<use\b|xlink:href|href\s*=|on\w+\s*=|javascript:|data:/i.test(s)) {
    return null;
  }
  if (s.length > 8000) return null;
  return s;
}

const items = [];
for (const entry of entries) {
  const r = entry.result;
  if (!r || typeof r !== 'object') continue;

  // An explore result: concept + variants.
  if (Array.isArray(r.variants)) {
    r.variants.forEach((v, i) => {
      const svg = safe(v.svg);
      if (svg) {
        items.push({
          group: r.concept || 'unnamed',
          label: `v${i + 1} · ${v.label || ''}`,
          note: v.reading || '',
          svg,
        });
      }
    });
  }

  // A refine result: mark / favicon / lockup.
  if (r.mark || r.lockup) {
    for (const key of ['mark', 'favicon']) {
      const svg = safe(r[key]);
      if (svg) items.push({ group: `REFINED · ${r.concept || ''}`, label: key, note: r.rationale || '', svg, final: true });
    }
    const lock = safe(r.lockup);
    if (lock) items.push({ group: `REFINED · ${r.concept || ''}`, label: 'lockup', note: '', svg: lock, wide: true });
  }
}

if (!items.length) {
  console.error('no renderable SVG found in the journal');
  process.exit(1);
}

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const groups = new Map();
for (const item of items) {
  if (!groups.has(item.group)) groups.set(item.group, []);
  groups.get(item.group).push(item);
}

const sizes = [16, 24, 32, 64];

const body = [...groups.entries()]
  .map(
    ([group, list]) => `
  <section${list[0].final ? ' class="final"' : ''}>
    <h2>${esc(group)}</h2>
    ${list
      .map(
        (item) => `
      <div class="row${item.wide ? ' wide' : ''}">
        <div class="meta"><b>${esc(item.label)}</b><span>${esc((item.note || '').slice(0, 190))}</span></div>
        <div class="sizes">
          ${
            item.wide
              ? `<div class="cell"><div class="dark lock">${item.svg}</div><em>lockup</em></div>
                 <div class="cell"><div class="light lock">${item.svg}</div><em>light</em></div>`
              : sizes
                  .map(
                    (s) =>
                      `<div class="cell"><div class="dark s${s}">${item.svg}</div><em>${s}</em></div>`,
                  )
                  .join('') +
                `<div class="cell"><div class="light s32">${item.svg}</div><em>light</em></div>
                 <div class="cell"><div class="dark s32 amber">${item.svg}</div><em>amber</em></div>`
          }
        </div>
      </div>`,
      )
      .join('')}
  </section>`,
  )
  .join('');

fs.writeFileSync(
  out,
  `<!doctype html><html><head><meta charset="utf-8"><title>LeastGrant logo contact sheet</title>
<style>
  body { background:#0b0a09; color:#b0a89d; font:14px ui-monospace,monospace; margin:0; padding:24px 28px; }
  h1 { color:#f2ede5; font-size:18px; margin:0 0 20px; }
  h2 { color:#f2ede5; font-size:13px; margin:26px 0 10px; letter-spacing:.08em; border-bottom:1px solid #262220; padding-bottom:6px; }
  section.final h2 { color:#e2a63f; }
  .row { display:grid; grid-template-columns:230px 1fr; gap:16px; align-items:center; padding:10px 0; border-bottom:1px solid #16130f; }
  .meta b { color:#f2ede5; display:block; font-size:12px; }
  .meta span { font-size:10.5px; color:#7c746a; line-height:1.4; display:block; margin-top:3px; }
  .sizes { display:flex; gap:14px; align-items:flex-end; flex-wrap:wrap; }
  .cell { text-align:center; }
  .cell em { display:block; font-size:9px; color:#5a534b; font-style:normal; margin-top:4px; }
  .dark, .light { display:grid; place-items:center; border-radius:3px; }
  .dark { background:#0b0a09; color:#f2ede5; border:1px solid #201c19; }
  .light { background:#f2ede5; color:#0b0a09; border:1px solid #d8d2c8; }
  .amber { color:#e2a63f; }
  .s16 { width:16px; height:16px; } .s16 svg { width:16px; height:16px; }
  .s24 { width:24px; height:24px; } .s24 svg { width:24px; height:24px; }
  .s32 { width:32px; height:32px; } .s32 svg { width:32px; height:32px; }
  .s64 { width:64px; height:64px; } .s64 svg { width:64px; height:64px; }
  .lock { width:200px; height:44px; } .lock svg { width:180px; height:36px; }
  svg { display:block; }
</style></head><body>
<h1>LeastGrant — logo contact sheet (${items.length} marks)</h1>
${body}
</body></html>`,
);

console.log(`${items.length} marks across ${groups.size} directions -> ${out}`);
