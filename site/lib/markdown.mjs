/**
 * A small Markdown renderer for this repository's own documentation.
 *
 * Not a CommonMark implementation, and not trying to be. It handles the subset
 * the LeastGrant docs actually use, and anything it does not recognise comes
 * out as escaped text rather than as a guess.
 *
 * Why not `marked` + `dompurify`
 * ------------------------------
 * Those are good libraries. They are also two more dependencies with their own
 * transitive trees, in the build of a website whose entire subject is not
 * trusting code you have not read. More to the point, the usual pairing exists
 * to make *raw HTML in Markdown* safe, and the safety then rests on a sanitiser
 * keeping pace with browser parsing quirks -- mXSS, mutation after
 * serialisation, namespace confusion in `<svg>`/`<math>`. This renderer does
 * not need that arms race because it never emits HTML it did not write:
 *
 *   - Raw HTML in the source is escaped to text, never passed through.
 *   - Every text value goes through `esc` at the point of emission.
 *   - Every href goes through `safeUrl`, which is a scheme allowlist.
 *   - There is no code path that concatenates source text into a tag.
 *
 * The threat is modest -- the input is Markdown from this repository, which an
 * attacker can only change by landing a commit. It is still worth closing,
 * because "our own repo" stops being true the moment someone renders a doc from
 * a fork or a pull request, and because a renderer that is safe only for
 * trusted input is a trap for whoever reuses it next.
 */

import { esc, attr, safeUrl } from './html.mjs';

// --- inline ------------------------------------------------------------------

/**
 * Inline markup, innermost-first.
 *
 * Code spans are taken before everything else so that `` `<div>` `` and
 * `` `**not bold**` `` behave: their contents are escaped and emitted as-is,
 * with no further parsing. That ordering matters for a docs site full of
 * shell snippets.
 */
function inline(src, ctx) {
  let out = '';
  let i = 0;

  while (i < src.length) {
    const ch = src[i];

    // `code` and ``code with a ` in it``
    if (ch === '`') {
      let ticks = 0;
      while (src[i + ticks] === '`') ticks++;
      const fence = '`'.repeat(ticks);
      const end = src.indexOf(fence, i + ticks);
      if (end !== -1) {
        let code = src.slice(i + ticks, end);
        // CommonMark strips one leading and trailing space when both are there,
        // which is how you write a code span that starts with a backtick.
        if (code.length > 2 && code.startsWith(' ') && code.endsWith(' ')) code = code.slice(1, -1);
        out += `<code>${esc(code)}</code>`;
        i = end + ticks;
        continue;
      }
    }

    // [text](url) and ![alt](src)
    if (ch === '[' || (ch === '!' && src[i + 1] === '[')) {
      const image = ch === '!';
      const start = image ? i + 1 : i;
      const link = matchLink(src, start);
      if (link) {
        const href = safeUrl(ctx.resolveUrl ? ctx.resolveUrl(link.url) : link.url);
        if (image) {
          // Images are rare in these docs and every one would be another
          // request. Render the alt text and move on.
          out += esc(link.text);
        } else if (href) {
          const off = /^https?:/i.test(href);
          out += `<a href="${attr(href)}"${off ? ' rel="noopener noreferrer"' : ''}>${inline(link.text, ctx)}</a>`;
        } else {
          out += inline(link.text, ctx);
        }
        i = link.end;
        continue;
      }
    }

    // <https://example.com> autolink
    if (ch === '<') {
      const close = src.indexOf('>', i);
      const body = close === -1 ? '' : src.slice(i + 1, close);
      if (body && /^(https?:|mailto:)/i.test(body) && !/\s/.test(body)) {
        const href = safeUrl(body);
        if (href) {
          out += `<a href="${attr(href)}" rel="noopener noreferrer">${esc(body.replace(/^mailto:/i, ''))}</a>`;
          i = close + 1;
          continue;
        }
      }
      // Any other `<...>` is raw HTML, or looks enough like it. Escape it.
      out += '&lt;';
      i++;
      continue;
    }

    // **strong** and *em* / _em_
    if (ch === '*' || ch === '_') {
      const strong = src.startsWith(ch + ch, i);
      const marker = strong ? ch + ch : ch;
      const end = src.indexOf(marker, i + marker.length);
      if (end !== -1 && end > i + marker.length) {
        const body = src.slice(i + marker.length, end);
        const tag = strong ? 'strong' : 'em';
        out += `<${tag}>${inline(body, ctx)}</${tag}>`;
        i = end + marker.length;
        continue;
      }
    }

    out += esc(ch);
    i++;
  }

  return out;
}

/** Match `[text](url)` at `at`, allowing one level of nested brackets in text. */
function matchLink(src, at) {
  if (src[at] !== '[') return null;
  let depth = 0;
  let close = -1;
  for (let i = at; i < src.length; i++) {
    if (src[i] === '\\') {
      i++;
      continue;
    }
    if (src[i] === '[') depth++;
    else if (src[i] === ']') {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close === -1 || src[close + 1] !== '(') return null;

  let paren = 0;
  let end = -1;
  for (let i = close + 1; i < src.length; i++) {
    if (src[i] === '(') paren++;
    else if (src[i] === ')') {
      paren--;
      if (paren === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) return null;

  let url = src.slice(close + 2, end).trim();
  // Drop a title: [x](url "title")
  const title = url.match(/^(\S+)\s+"[^"]*"$/);
  if (title) url = title[1];

  return { text: src.slice(at + 1, close), url, end: end + 1 };
}

// --- blocks ------------------------------------------------------------------

/** A GitHub-style heading anchor: lowercase, spaces to dashes, punctuation out. */
export function slug(text) {
  return text
    .toLowerCase()
    .replace(/[`*_~]/g, '')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .slice(0, 80);
}

/**
 * Render Markdown to HTML.
 *
 * `ctx.resolveUrl` rewrites a link target -- used to turn `THREAT-MODEL.md`
 * into `/docs/threat-model/` so the rendered docs link to each other on this
 * site rather than back to GitHub. It runs before `safeUrl`, never after, so a
 * rewrite cannot introduce a scheme the allowlist would have rejected.
 */
export function render(source, ctx = {}) {
  const lines = String(source).replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  const headings = [];
  let i = 0;

  const flushParagraph = (buf) => {
    if (!buf.length) return;
    out.push(`<p>${inline(buf.join('\n'), ctx)}</p>`);
    buf.length = 0;
  };

  const para = [];

  while (i < lines.length) {
    const line = lines[i];

    // fenced code
    const fence = line.match(/^(\s*)(`{3,}|~{3,})\s*([\w+-]*)\s*$/);
    if (fence) {
      flushParagraph(para);
      const [, indent, marker, lang] = fence;
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^\\s*${marker[0]}{${marker.length},}\\s*$`).test(lines[i])) {
        body.push(lines[i].startsWith(indent) ? lines[i].slice(indent.length) : lines[i]);
        i++;
      }
      i++; // closing fence
      const label = lang && /^[\w+-]{1,20}$/.test(lang) ? lang : '';
      out.push(
        `<figure class="code"${label ? ` data-lang="${attr(label)}"` : ''}>` +
          `<pre><code>${esc(body.join('\n'))}</code></pre></figure>`,
      );
      continue;
    }

    // heading
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      flushParagraph(para);
      const level = h[1].length;
      const text = h[2].replace(/\s+#+\s*$/, '');
      const id = slug(text);
      if (level <= 3) headings.push({ level, text: text.replace(/[`*_]/g, ''), id });
      out.push(`<h${level} id="${attr(id)}">${inline(text, ctx)}</h${level}>`);
      i++;
      continue;
    }

    // horizontal rule
    if (/^\s{0,3}([-*_])\s*(\1\s*){2,}$/.test(line)) {
      flushParagraph(para);
      out.push('<hr>');
      i++;
      continue;
    }

    // table
    if (line.includes('|') && /^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(lines[i + 1] || '')) {
      flushParagraph(para);
      const head = splitRow(line);
      const align = splitRow(lines[i + 1]).map((c) => {
        const l = c.startsWith(':');
        const r = c.endsWith(':');
        return r && !l ? 'right' : l && r ? 'center' : '';
      });
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      const cell = (tag, text, n) => {
        const a = align[n] ? ` class="ta-${align[n]}"` : '';
        return `<${tag}${a}>${inline(text, ctx)}</${tag}>`;
      };
      // A header row of empty cells is a layout table -- the README uses two of
      // them. Rendering an empty <thead> just draws a blank band.
      const hasHead = head.some((c) => c.trim());
      out.push(
        '<div class="table-wrap"><table>' +
          (hasHead ? `<thead><tr>${head.map((c, n) => cell('th', c, n)).join('')}</tr></thead>` : '') +
          `<tbody>${rows
            .map((r) => `<tr>${r.map((c, n) => cell('td', c, n)).join('')}</tr>`)
            .join('')}</tbody>` +
          '</table></div>',
      );
      continue;
    }

    // blockquote
    if (/^\s{0,3}>/.test(line)) {
      flushParagraph(para);
      const body = [];
      while (i < lines.length && (/^\s{0,3}>/.test(lines[i]) || (body.length && lines[i].trim()))) {
        body.push(lines[i].replace(/^\s{0,3}>\s?/, ''));
        i++;
      }
      const inner = render(body.join('\n'), ctx);
      out.push(`<blockquote>${inner.html}</blockquote>`);
      continue;
    }

    // list
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
      flushParagraph(para);
      const { html, next } = list(lines, i, ctx);
      out.push(html);
      i = next;
      continue;
    }

    // HTML comment: dropped whole, including the multi-line kind. Rendering it
    // as text would put review notes on the page.
    if (/^\s*<!--/.test(line)) {
      flushParagraph(para);
      while (i < lines.length && !lines[i].includes('-->')) i++;
      i++;
      continue;
    }

    // raw HTML block: dropped, not passed through. The README wraps its title
    // in <div align="center">, which has no meaning here anyway.
    //
    // An autolink -- `<https://example.com>` -- starts with `<` and a letter
    // too, so it has to be excluded explicitly or every autolink on its own
    // line disappears.
    if (/^\s*<\/?[a-zA-Z][\w-]*(\s|\/?>|$)/.test(line) && !/^\s*<[a-zA-Z][\w+.-]*:/.test(line)) {
      flushParagraph(para);
      i++;
      continue;
    }

    if (!line.trim()) {
      flushParagraph(para);
      i++;
      continue;
    }

    para.push(line);
    i++;
  }
  flushParagraph(para);

  return { html: out.join('\n'), headings };
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
  const cells = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && s[i + 1] === '|') {
      cur += '|';
      i++;
    } else if (s[i] === '|') {
      cells.push(cur.trim());
      cur = '';
    } else cur += s[i];
  }
  cells.push(cur.trim());
  return cells;
}

/** One list, including nested lists, starting at `start`. */
function list(lines, start, ctx) {
  const first = lines[start].match(/^(\s*)([-*+]|\d+[.)])\s+/);
  const baseIndent = first[1].length;
  const ordered = /\d/.test(first[2]);
  const items = [];
  let i = start;
  let current = null;

  while (i < lines.length) {
    const line = lines[i];
    const m = line.match(/^(\s*)([-*+]|\d+[.)])\s+(.*)$/);

    if (m && m[1].length === baseIndent) {
      if (current) items.push(current);
      current = [m[3]];
      i++;
      continue;
    }
    if (!current) break;

    // A blank line inside a list is only a continuation if something indented
    // follows it; otherwise the list has ended.
    if (!line.trim()) {
      const nxt = lines[i + 1];
      if (nxt && /^\s+\S/.test(nxt) && nxt.match(/^(\s*)/)[1].length > baseIndent) {
        current.push('');
        i++;
        continue;
      }
      break;
    }

    const indent = line.match(/^(\s*)/)[1].length;
    if (indent > baseIndent) {
      current.push(line.slice(Math.min(indent, baseIndent + 2)));
      i++;
      continue;
    }
    break;
  }
  if (current) items.push(current);

  const tag = ordered ? 'ol' : 'ul';
  const body = items
    .map((item) => {
      const text = item.join('\n');
      // A multi-line item may contain its own blocks (a nested list, a fence).
      const complex = /\n\s*([-*+]|\d+[.)])\s+/.test('\n' + text) || /^\s*(```|~~~)/m.test(text) || /\n\n/.test(text);
      if (complex) return `<li>${render(text, ctx).html}</li>`;
      return `<li>${inline(text.replace(/\n\s*/g, ' '), ctx)}</li>`;
    })
    .join('');
  return { html: `<${tag}>${body}</${tag}>`, next: i };
}
