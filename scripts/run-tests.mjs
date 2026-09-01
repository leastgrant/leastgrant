/**
 * Run the compiled test suite, on every Node version this project supports.
 *
 *   node scripts/run-tests.mjs                 everything, spec reporter
 *   node scripts/run-tests.mjs --dot           everything, one character per test
 *   node scripts/run-tests.mjs bypass symlink  only files whose name contains one
 *                                              of those substrings
 *
 * This exists because there is no single `node --test` invocation that works
 * everywhere. A quoted glob (`"dist/test/**\/*.test.js"`) relies on the runner
 * expanding it, which Node only learned to do in v22 — on the v20 this package
 * claims to support, the pattern is taken as a literal filename and the run
 * fails. An unquoted glob relies on the *shell*, and `cmd.exe` does not expand
 * globs at all. Passing the directory does not work either: recent Node treats
 * a directory argument as a module to execute.
 *
 * Finding the files here and handing Node an explicit list sidesteps all three.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'dist', 'test');

/** Print an error so it shows up as an annotation on the run page in CI. */
const annotate = (msg) => {
  const flat = String(msg).split(String.fromCharCode(10)).join(' | ').slice(0, 900);
  if (process.env['GITHUB_ACTIONS']) console.log('::error title=test failure::' + flat);
  else console.error(msg);
};

const args = process.argv.slice(2);
const dot = args.includes('--dot');
const filters = args.filter((a) => !a.startsWith('--'));

if (!fs.existsSync(DIR)) {
  annotate(`no compiled tests at ${DIR} — run "npm run build" first`);
  process.exit(1);
}

/** Every `*.test.js` under dist/test, at any depth. */
function collect(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) collect(full, out);
    else if (e.name.endsWith('.test.js')) out.push(full);
  }
  return out;
}

let files = collect(DIR).sort();
if (filters.length) {
  files = files.filter((f) => filters.some((needle) => path.basename(f).includes(needle)));
}

if (!files.length) {
  annotate(
    filters.length
      ? `no test files matched ${filters.join(', ')}`
      : `no test files found under ${DIR}`,
  );
  process.exit(1);
}

const r = spawnSync(
  process.execPath,
  ['--test', `--test-reporter=${dot ? 'dot' : 'spec'}`, ...files],
  { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
);

const out = `${r.stdout || ''}${r.stderr || ''}`;
process.stdout.write(out);

// In CI, say what failed in a way the run page and the API will show.
//
// A red step whose only annotation is "Process completed with exit code 1"
// forces whoever is debugging to open the raw log — which is exactly the
// moment when the person looking may not have permission to. The failing test
// names and their assertions belong in the annotation.
if (r.status !== 0 && process.env['GITHUB_ACTIONS']) {
  const lines = out.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith('✖ failing tests:'));
  const reported = [];
  if (start >= 0) {
    for (let i = start + 1; i < lines.length && reported.length < 25; i++) {
      const line = lines[i];
      if (!line.startsWith('✖ ')) continue;
      const name = line.slice(2).replace(/\s*\([\d.]+ms\)\s*$/, '');
      // The assertion message is the next indented line or two.
      const detail = lines
        .slice(i + 1, i + 4)
        .filter((l) => /^\s+\S/.test(l))
        .map((l) => l.trim())
        .join(' | ')
        .slice(0, 400);
      const where = (lines[i - 1] || '').startsWith('test at ') ? lines[i - 1].slice(8) : '';
      reported.push(`${name}${where ? ` [${where}]` : ''}${detail ? ` -- ${detail}` : ''}`);
    }
  }
  if (reported.length) {
    for (const line of reported) console.log(`::error title=test failure::${line}`);
  } else {
    // Nothing matched the expected shape — a crash at import, a runner error,
    // an out-of-memory. The tail of the output is the only useful thing left,
    // and it must reach somewhere readable without repository admin.
    const tail = lines.filter((l) => l.trim()).slice(-12);
    annotate('the run failed with no parseable test failure; last lines follow');
    for (const l of tail) annotate(l);
  }
}

// , not . Calling  straight after
// writing megabytes to stdout truncates whatever has not flushed yet — on a
// pipe those writes are asynchronous — which silently swallowed the test
// output and the annotations above, and made a red CI build report nothing
// but its exit code. Setting the code lets Node exit once the stream drains.
process.exitCode = r.status ?? 1;
