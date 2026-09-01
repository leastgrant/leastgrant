/**
 * Install the packed tarball into an empty directory and use it.
 *
 * Everything else in the release path inspects the artifact. This one runs it —
 * the same way a stranger would, from a directory that has never seen this
 * project, against a scratch state directory so nothing on the machine is
 * touched.
 *
 *   node scripts/smoke-tarball.mjs ./leastgrant-0.1.0.tgz [--expect-version 0.1.0]
 *
 * The checks are deliberately behavioural rather than structural: a package can
 * be perfectly shaped and still fail to start. The security-relevant one is the
 * last: the hook must refuse a credential read even in `bypassPermissions`,
 * because that is the mode in which nothing else is checking.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

const CI = Boolean(process.env['GITHUB_ACTIONS']);
const problems = [];
const fail = (msg) => problems.push(msg);
const ok = (msg) => console.log(`  ok    ${msg}`);

const arg = process.argv[2];
if (!arg) {
  console.error('usage: node scripts/smoke-tarball.mjs <tarball.tgz> [--expect-version X.Y.Z]');
  process.exit(2);
}
const tarball = path.resolve(arg);
if (!fs.existsSync(tarball)) {
  console.error(`no such tarball: ${tarball}`);
  process.exit(2);
}
const vIdx = process.argv.indexOf('--expect-version');
const expectVersion = vIdx > 0 ? process.argv[vIdx + 1] : '';

const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-smoke-home-'));
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-smoke-'));
const env = { ...process.env, LEASTGRANT_HOME: HOME_DIR, NO_COLOR: '1' };
const WIN = process.platform === 'win32';
const npmCmd = WIN ? 'npm.cmd' : 'npm';

const run = (cmd, args, opts = {}) =>
  spawnSync(cmd, args, { cwd: DIR, encoding: 'utf8', env, shell: false, ...opts });

/**
 * npm, portably.
 *
 * Node refuses to spawn a `.cmd` without a shell on Windows (the mitigation for
 * CVE-2024-27980), so the Windows path has to go through `cmd`, which means
 * arguments have to be quoted by hand. Everywhere else it is a direct spawn
 * with no shell at all, which is the form worth preferring.
 */
const npm = (args, opts = {}) => {
  if (!WIN) return run(npmCmd, args, opts);
  // A single command string, not a string plus an args array: passing both is
  // deprecated (DEP0190) precisely because the args are concatenated rather
  // than escaped. Quoting here, once, keeps that explicit.
  const line = [npmCmd, ...args.map((a) => (/[\s"&|<>^]/.test(a) ? `"${a.replace(/"/g, '""')}"` : a))].join(' ');
  return spawnSync(line, { cwd: DIR, encoding: 'utf8', env, shell: true, ...opts });
};

// --- install -------------------------------------------------------------------

let r = npm(['init', '-y']);
if (r.status !== 0) {
  console.error(`npm init failed (exit ${r.status}): ${r.stderr || r.error?.message}`);
  process.exit(2);
}
// `--ignore-scripts` on purpose: a consumer installing this package must not
// need lifecycle scripts to run, and if the package ever grew one that mattered
// this is where it would show up.
r = npm(['install', '--ignore-scripts', tarball]);
if (r.status !== 0) {
  console.error(`npm install of the tarball failed:\n${r.stdout}\n${r.stderr}`);
  process.exit(1);
}
ok('installs into an empty directory');

const installed = path.join(DIR, 'node_modules', 'leastgrant');
if (!fs.existsSync(installed)) {
  console.error('the package is not present in node_modules after install');
  process.exit(1);
}

// Exactly one package: the zero-dependency claim, verified at install time
// rather than from the manifest.
const topLevel = fs
  .readdirSync(path.join(DIR, 'node_modules'))
  .filter((n) => !n.startsWith('.'));
if (topLevel.length !== 1 || topLevel[0] !== 'leastgrant') {
  fail(`installing pulled in more than the package itself: ${topLevel.join(', ')}`);
} else {
  ok('installing pulls in exactly one package');
}

const BIN = path.join(installed, 'bin', 'leastgrant.js');
const cli = (args, opts = {}) => run(process.execPath, [BIN, ...args], opts);

// --- it runs ---------------------------------------------------------------------

r = cli(['--version']);
const version = (r.stdout || '').trim().replace(/^leastgrant\s+/, '');
if (r.status !== 0) fail(`--version exited ${r.status}: ${r.stderr}`);
else if (expectVersion && version !== expectVersion) fail(`--version printed ${version}, expected ${expectVersion}`);
else ok(`--version reports ${version}`);

r = cli(['--help']);
if (r.status !== 0 || !/check/.test(r.stdout)) fail(`--help did not render (exit ${r.status})`);
else ok('--help renders');

r = cli(['status']);
if (r.status !== 0) fail(`status exited ${r.status} on a cold profile: ${r.stderr}`);
else ok('status works on a cold profile');

// --- it decides -------------------------------------------------------------------

r = cli(['check', 'rm -rf /']);
if (r.status !== 0) fail(`check exited ${r.status}`);
else if (!/ask|deny/.test(r.stdout)) fail(`check "rm -rf /" did not ask:\n${r.stdout}`);
else ok('check "rm -rf /" asks');

r = cli(['check', 'git push --force', '--json']);
let parsed;
try {
  parsed = JSON.parse(r.stdout);
} catch {
  fail(`check --json did not produce JSON:\n${r.stdout.slice(0, 300)}`);
}
if (parsed && parsed.decision !== 'ask') fail(`check --json gave decision ${parsed.decision}`);
else if (parsed) ok('check --json parses and asks about a force push');

// --- no colour when asked ----------------------------------------------------------

r = cli(['check', 'ls']);
if (/\[/.test(r.stdout)) fail('NO_COLOR=1 still produced ANSI escapes');
else ok('NO_COLOR is honoured');

// --- error paths are non-zero -------------------------------------------------------

r = cli(['definitely-not-a-command']);
if (r.status === 0) fail('an unknown command exited 0');
else ok(`an unknown command exits ${r.status}`);

// --- the public API is importable ----------------------------------------------------

r = run(process.execPath, [
  '-e',
  "import('leastgrant').then(m => { if (typeof m.decide !== 'function') { console.error('no decide export'); process.exit(1); } console.log(Object.keys(m).length); })",
]);
if (r.status !== 0) fail(`the documented import failed: ${r.stderr.slice(0, 300)}`);
else ok(`the public API imports (${(r.stdout || '').trim()} exports)`);

// --- the hook refuses a credential read, in the mode where nothing else checks ---------

const hookInput = JSON.stringify({
  hook_event_name: 'PreToolUse',
  session_id: 'smoke',
  cwd: DIR,
  tool_name: 'Bash',
  tool_input: { command: 'cat ~/.ssh/id_rsa' },
  tool_use_id: 't1',
  permission_mode: 'bypassPermissions',
});
r = cli(['hook'], { input: hookInput });
let decision;
try {
  decision = JSON.parse(r.stdout).hookSpecificOutput.permissionDecision;
} catch {
  fail(`the hook produced no decision for a credential read:\n${r.stdout.slice(0, 300)}`);
}
if (decision && decision !== 'ask' && decision !== 'deny') {
  fail(`the hook returned ${decision} for a credential read in bypassPermissions`);
} else if (decision) {
  ok(`the hook returns "${decision}" for a credential read in bypassPermissions`);
}

// --- it did not touch anything it should not ------------------------------------------

const strayHome = path.join(os.homedir(), '.leastgrant');
const touchedRealHome = fs.existsSync(strayHome) && !process.env['LEASTGRANT_ALLOW_REAL_HOME'];
if (touchedRealHome) {
  // Only a warning: the directory may predate this run on a developer machine.
  // On a fresh runner its existence would mean the scratch override was ignored.
  console.log(`  note  ~/.leastgrant exists; on a clean runner that would mean LEASTGRANT_HOME was ignored`);
}

fs.rmSync(DIR, { recursive: true, force: true });
fs.rmSync(HOME_DIR, { recursive: true, force: true });

if (problems.length) {
  console.error('');
  for (const p of problems) console.error(CI ? `::error::${p}` : `  ERROR: ${p}`);
  console.error(`\n${problems.length} smoke failure(s); refusing to publish.`);
  process.exit(1);
}
console.log('\nsmoke test passed');
