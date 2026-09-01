/**
 * Terminal rendering, with no dependencies.
 *
 * A permission tool asks people to trust it, and a tool that pulls in forty
 * transitive packages to print coloured text has already lost part of that
 * argument. So this is hand-rolled: a few escape codes, some box characters,
 * and honest degradation when the terminal is not a terminal.
 */

const useColor = (() => {
  if (process.env['NO_COLOR']) return false;
  if (process.env['FORCE_COLOR']) return true;
  return Boolean(process.stdout.isTTY);
})();

const wrap = (open: string, close: string) => (s: string) =>
  useColor ? `\x1b[${open}m${s}\x1b[${close}m` : s;

export const c = {
  bold: wrap('1', '22'),
  dim: wrap('2', '22'),
  italic: wrap('3', '23'),
  underline: wrap('4', '24'),
  red: wrap('31', '39'),
  green: wrap('32', '39'),
  yellow: wrap('33', '39'),
  blue: wrap('34', '39'),
  magenta: wrap('35', '39'),
  cyan: wrap('36', '39'),
  gray: wrap('90', '39'),
  brightRed: wrap('91', '39'),
  brightGreen: wrap('92', '39'),
  brightYellow: wrap('93', '39'),
  bgRed: wrap('41', '49'),
  bgGreen: wrap('42', '49'),
  bgYellow: wrap('43', '49'),
};

/** Visible width, ignoring escape codes. */
export function width(s: string): number {
  return stripAnsi(s).length;
}

export function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

export function pad(s: string, n: number): string {
  const w = width(s);
  return w >= n ? s : s + ' '.repeat(n - w);
}

export function padStart(s: string, n: number): string {
  const w = width(s);
  return w >= n ? s : ' '.repeat(n - w) + s;
}

export function truncate(s: string, n: number): string {
  if (width(s) <= n) return s;
  const plain = stripAnsi(s);
  return plain.slice(0, Math.max(0, n - 1)) + '…';
}

/** Zero-width and bidi-override characters: invisible, and able to reorder what you read. */
const ZERO_WIDTH = /[\u200B-\u200F\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** C0 and C1 controls (ESC among them), DEL, and the Unicode line separators. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

/**
 * Flatten agent-supplied text to one printable line.
 *
 * Whitespace is collapsed so a multi-line command occupies one row. Then
 * everything that steers a terminal rather than showing up in it is removed:
 * escape sequences and the rest of the C0/C1 controls, plus the zero-width and
 * bidi-override characters that can make text read as something other than what
 * it says.
 *
 * Ledger text is a string an agent chose. The redactor takes credentials out of
 * it before it is written down; it does not take out `\x1b[1A\x1b[2K`, which
 * would let a logged command erase and rewrite the line above it. Nothing from
 * the ledger should reach stdout without passing through here.
 */
export function oneLine(s: string): string {
  if (typeof s !== 'string') return '';
  return s.replace(ZERO_WIDTH, '').replace(CONTROL, ' ').replace(/\s+/g, ' ').trim();
}

export const term = {
  get cols(): number {
    return Math.max(60, Math.min(process.stdout.columns || 100, 120));
  },
};

// --- symbols ---------------------------------------------------------------

/**
 * Assume a UTF-8 terminal unless we are fairly sure it is the legacy Windows
 * console. Modern Windows Terminal, VS Code, ConEmu and Git Bash all handle box
 * characters; only `cmd.exe` in a raw console reliably does not, and that
 * announces itself by having no TERM at all.
 */
const unicode =
  process.platform !== 'win32' ||
  Boolean(process.env['WT_SESSION']) ||
  Boolean(process.env['TERM_PROGRAM']) ||
  Boolean(process.env['ConEmuANSI']) ||
  /xterm|vt100|screen|ansi|cygwin/i.test(process.env['TERM'] ?? '');

export const sym = {
  allow: unicode ? '✓' : '+',
  ask: unicode ? '?' : '?',
  deny: unicode ? '✗' : 'x',
  bullet: unicode ? '•' : '*',
  arrow: unicode ? '→' : '->',
  dash: unicode ? '─' : '-',
  vbar: unicode ? '│' : '|',
  corner: unicode ? '╰' : '`',
  tee: unicode ? '├' : '|',
  block: unicode ? '█' : '#',
  half: unicode ? '▌' : '|',
  light: unicode ? '░' : '.',
};

export function verdictBadge(decision: 'allow' | 'ask' | 'deny'): string {
  if (decision === 'allow') return c.green(`${sym.allow} allow`);
  if (decision === 'deny') return c.red(`${sym.deny} deny`);
  return c.yellow(`${sym.ask} ask`);
}

// --- layout ----------------------------------------------------------------

export function rule(label?: string): string {
  const w = term.cols;
  if (!label) return c.gray(sym.dash.repeat(w));
  const text = ` ${label} `;
  const left = 2;
  const right = Math.max(0, w - left - width(text));
  return c.gray(sym.dash.repeat(left)) + c.bold(text) + c.gray(sym.dash.repeat(right));
}

export function heading(s: string): string {
  return '\n' + c.bold(s) + '\n';
}

/** Indented, wrapped paragraph. */
export function para(s: string, indent = 2, max = term.cols): string {
  const words = s.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  const limit = max - indent;
  for (const w of words) {
    if (line && width(line) + 1 + width(w) > limit) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => ' '.repeat(indent) + l).join('\n');
}

/**
 * One prefix, then wrapped text lined up underneath it.
 *
 * Label/value rows, closing notes and callouts are all this shape. Hand-rolling
 * each one is how a command ends up running off the right-hand side of a narrow
 * terminal in three different ways, so there is one implementation to get
 * right and it takes its width from the terminal.
 */
export function hang(prefix: string, text: string, indent = 2): string {
  const head = ' '.repeat(indent) + prefix;
  if (!text) return head;
  const col = indent + width(prefix) + 1;
  // Never let a deep indent squeeze the text to nothing on a narrow terminal.
  return head + ' ' + para(text, col, Math.max(col + 24, term.cols)).slice(col);
}

export interface Column {
  header: string;
  /** Fixed width; omit to size from content. */
  width?: number;
  align?: 'left' | 'right';
}

export function table(cols: Column[], rows: string[][]): string {
  const widths = cols.map((col, i) => {
    if (col.width) return col.width;
    const contentMax = Math.max(width(col.header), ...rows.map((r) => width(r[i] ?? '')));
    return contentMax;
  });

  // Shrink the widest column if we overflow, rather than wrapping raggedly.
  const total = widths.reduce((a, b) => a + b + 2, 0);
  if (total > term.cols) {
    const over = total - term.cols;
    const widest = widths.indexOf(Math.max(...widths));
    widths[widest] = Math.max(12, (widths[widest] ?? 0) - over);
  }

  // `pad`/`padStart`/`truncate` all measure visible width, so styling can be
  // applied before padding without throwing the columns off.
  const line = (cells: string[], style: (s: string) => string = (s) => s) =>
    cells
      .map((cell, i) => {
        const w = widths[i] ?? 10;
        const t = style(truncate(cell, w));
        return cols[i]?.align === 'right' ? padStart(t, w) : pad(t, w);
      })
      .join('  ')
      .replace(/\s+$/, '');

  const out = [line(cols.map((x) => x.header), c.gray)];
  for (const r of rows) out.push(line(r));
  return out.join('\n');
}

/** A horizontal bar for counts. */
export function bar(value: number, max: number, cells = 24, colour: (s: string) => string = c.cyan): string {
  if (max <= 0) return '';
  const filled = Math.max(value > 0 ? 1 : 0, Math.round((value / max) * cells));
  return colour(sym.block.repeat(filled)) + c.gray(sym.light.repeat(Math.max(0, cells - filled)));
}

/**
 * The blast-radius strip: four dimensions, shown as words.
 * Deliberately never a number — "0.73" explains nothing.
 */
export function blastStrip(b: {
  reach: string;
  reversibility: string;
  exposure: string;
  scale: string;
}): string {
  const reachColour =
    b.reach === 'workspace' || b.reach === 'none' ? c.green
    : b.reach === 'machine' || b.reach === 'network' ? c.yellow
    : c.red;
  const undoColour =
    b.reversibility === 'trivial' || b.reversibility === 'easy' ? c.green
    : b.reversibility === 'hard' ? c.yellow
    : c.red;
  const exposureColour = b.exposure === 'none' ? c.gray : c.red;

  const parts = [
    `${c.gray('reach')} ${reachColour(b.reach)}`,
    `${c.gray('undo')} ${undoColour(b.reversibility)}`,
  ];
  if (b.exposure !== 'none') parts.push(`${c.gray('secrets')} ${exposureColour(b.exposure)}`);
  if (b.scale !== 'single') parts.push(`${c.gray('scale')} ${c.yellow(b.scale)}`);
  return parts.join(c.gray('  ' + sym.vbar + '  '));
}

/** Relative time, e.g. "3 days ago". */
export function ago(then: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - then) / 1000));
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d} day${d === 1 ? '' : 's'} ago`;
  const mo = Math.round(d / 30);
  return `${mo} month${mo === 1 ? '' : 's'} ago`;
}

export function plural(n: number, word: string, suffix = 's'): string {
  return `${n.toLocaleString('en-US')} ${word}${n === 1 ? '' : suffix}`;
}

/** The wordmark, used by `init` and `--help`. */
export function logo(): string {
  return (
    c.bold('  LeastGrant  ') +
    c.gray('permissions that learn how you work')
  );
}
