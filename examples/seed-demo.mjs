/**
 * Build the profile the demo runs against.
 *
 * The demo needs a machine that has been used for a while, because the whole
 * point of LeastGrant is the difference between what it does on day one and
 * what it does on day thirty. Run against a cold profile it asks about
 * everything, which is correct and tells you nothing.
 *
 * So this writes a scratch profile into a temporary directory: forty days of
 * ordinary work on one project, approved by a human the way it would have been
 * in real use. Nothing here is special-cased — it goes through `analyze()` and
 * `observe()`, the same functions the live hook calls, and the demo then asks
 * the same engine for a verdict. What you see is what this history really
 * produces.
 *
 * Usage: node examples/seed-demo.mjs <state-dir> <project-dir>
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

const [, , stateDir, projectDir] = process.argv;
if (!stateDir || !projectDir) {
  console.error('usage: node examples/seed-demo.mjs <state-dir> <project-dir>');
  process.exit(2);
}
process.env.LEASTGRANT_HOME = stateDir;

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const dist = path.join(here, '..', 'dist', 'src');
const { analyze } = await import(new URL('core/classify.js', 'file://' + dist.split(path.sep).join('/') + '/'));
const { newEnvelope, observe } = await import(new URL('core/envelope.js', 'file://' + dist.split(path.sep).join('/') + '/'));
const { saveEnvelope } = await import(new URL('store/index.js', 'file://' + dist.split(path.sep).join('/') + '/'));
const { findProjectRoot, projectKey } = await import(new URL('core/paths.js', 'file://' + dist.split(path.sep).join('/') + '/'));

fs.mkdirSync(path.join(projectDir, '.git'), { recursive: true });
fs.mkdirSync(path.join(projectDir, 'src'), { recursive: true });

/** A week's worth of ordinary work, repeated across forty days. */
const ROUTINE = [
  'git status',
  'git diff --stat',
  'git add -A',
  'git log --oneline -20',
  'npm test',
  'npm run build',
  'ls -la',
  'cat README.md',
  'grep -rn TODO src',
  'mkdir -p build',
  'cp src/a.ts src/b.ts',
];

const DAY = 86_400_000;
const now = Date.now();
const key = projectKey(findProjectRoot(projectDir));
const env = newEnvelope('project', key);

for (let day = 0; day < 40; day++) {
  for (const command of ROUTINE) {
    const at = now - (40 - day) * DAY;
    const a = analyze(
      { agent: 'claude-code', tool: 'Bash', input: { command }, cwd: projectDir, sessionId: `s${day}`, at },
      { roots: [projectDir], secretPatterns: [] },
    );
    for (const action of a.actions) {
      observe(env, {
        signature: action.signature,
        capability: action.capability,
        blast: action.blast,
        // What the human actually did: they were prompted and they said yes.
        evidence: 'confirmed',
        at,
        sessionId: `s${day}`,
        display: action.display,
      });
    }
  }
}
saveEnvelope(env);
console.log(`seeded ${Object.keys(env.signatures).length} signatures from ${40 * ROUTINE.length} approvals`);
