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

const args = process.argv.slice(2);
const dot = args.includes('--dot');
const filters = args.filter((a) => !a.startsWith('--'));

if (!fs.existsSync(DIR)) {
  console.error(`no compiled tests at ${DIR} — run "npm run build" first`);
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
  console.error(
    filters.length
      ? `no test files matched ${filters.join(', ')}`
      : `no test files found under ${DIR}`,
  );
  process.exit(1);
}

const r = spawnSync(
  process.execPath,
  ['--test', `--test-reporter=${dot ? 'dot' : 'spec'}`, ...files],
  { cwd: ROOT, stdio: 'inherit' },
);
process.exit(r.status ?? 1);
