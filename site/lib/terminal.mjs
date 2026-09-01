/**
 * Colouring for captured CLI output.
 *
 * The input is text that came out of a subprocess. It is tokenised into
 * segments first and each segment is escaped on its way into a span, so no
 * amount of `<` in a command line can become markup. Nothing is matched
 * against the already-escaped string, which is the usual way this goes wrong:
 * highlight after escaping and `&lt;` starts looking like five characters that
 * a later rule can cut in half.
 *
 * The colouring follows the one rule the stylesheet is built on -- colour is a
 * verdict -- so only the ✓ / ? / ✗ marks and their words get any. Everything
 * else is greyscale.
 */

import { esc, attr } from './html.mjs';

const VERDICT = /^(\s*)([✓?✗])\s(allow|ask|deny)(\s+)(.*)$/;
const LABEL = /^(\s{2})(what it does|blast radius|touches|why|scope|covers|note)(\s\s+)(.*)$/;
const RUNS = /^(\s{2})(this command runs \d+ things:)$/;
const BULLET = /^(\s+)(•)(\s)(.*)$/;
const HINT = /^(\s*)(╰)(\s)(.*)$/;

const span = (className, text) => `<span class="${attr(className)}">${esc(text)}</span>`;

/** One line of CLI output as safe HTML. */
function line(text) {
  let m;

  if ((m = text.match(VERDICT))) {
    const [, indent, glyph, word, gap, rest] = m;
    const tone = word === 'allow' ? 'v-allow' : word === 'deny' ? 'v-deny' : 'v-ask';
    return esc(indent) + span(tone, `${glyph} ${word}`) + esc(gap) + span('cmd', rest);
  }

  if ((m = text.match(LABEL))) {
    const [, indent, label, gap, rest] = m;
    return esc(indent) + span('label', label) + esc(gap) + esc(rest);
  }

  if ((m = text.match(RUNS))) {
    return esc(m[1]) + span('label', m[2]);
  }

  if ((m = text.match(HINT))) {
    const [, indent, glyph, gap, rest] = m;
    return esc(indent) + span('hint', glyph + gap + rest);
  }

  if ((m = text.match(BULLET))) {
    const [, indent, dot, gap, rest] = m;
    return esc(indent) + span('bullet', dot) + esc(gap) + esc(rest);
  }

  // A bare `why` heading, and anything else, comes through as-is.
  if (/^\s{2}(why)$/.test(text)) {
    return esc(text.slice(0, 2)) + span('label', 'why');
  }

  return esc(text);
}

/** Captured output as a highlighted block. */
export function verdictBlock(text) {
  return text.split('\n').map(line).join('\n');
}

/**
 * The hero's replayable session.
 *
 * Each step is one command and the first line of its real answer. The full
 * output of every one of these is on the same page, further down and
 * unabridged; this is the index, not a substitute for it.
 *
 * Every line is emitted as a `data-line` span so the script can hide them and
 * bring them back. The finished session is what sits in the HTML, so a reader
 * without JavaScript sees the end state rather than an empty box.
 */
export function heroSession(steps) {
  const out = [];
  for (const step of steps) {
    const command = `$ leastgrant check ${JSON.stringify(step.command)}`;
    out.push(
      `<span class="prompt" data-line data-type="cmd">${esc(command)}</span>`,
    );
    out.push(`<span data-line data-type="out">${line(step.first)}</span>`);
    out.push(`<span data-line data-type="out"> </span>`);
  }
  return out.join('\n');
}

/** The verdict line of a captured block -- the first non-empty line. */
export function firstLine(text) {
  for (const l of text.split('\n')) if (l.trim()) return l;
  return '';
}
