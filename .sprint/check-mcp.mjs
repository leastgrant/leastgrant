import * as os from 'node:os';
import * as path from 'node:path';
import { analyze } from '../dist/src/core/classify.js';

const WS = path.join(os.tmpdir(), 'lg-mcp');
const KEY = path.join(os.homedir(), '.ssh', 'id_rsa');

const go = (tool, input) => {
  const a = analyze(
    { agent: 't', tool, input, cwd: WS, sessionId: 's', at: Date.now() },
    { roots: [WS], secretPatterns: [] },
  );
  const x = a.actions[0];
  return `${x.capability.padEnd(12)} exposure=${x.blast.exposure.padEnd(14)} ${x.signature}`;
};

const T = 'mcp__filesystem__read_multiple_files';
console.log('batch reads');
console.log('  benign   ', go(T, { paths: ['src/a.ts', 'src/b.ts'] }));
console.log('  secret@1 ', go(T, { paths: ['src/a.ts', KEY] }));
console.log('  secret@0 ', go(T, { paths: [KEY, 'src/a.ts'] }));
console.log('  order swap must not mint a new identity:',
  go(T, { paths: ['src/a.ts', KEY] }) === go(T, { paths: [KEY, 'src/a.ts'] }));

console.log('single read (was already fine, must stay fine)');
console.log('  benign   ', go('mcp__filesystem__read_file', { path: 'src/a.ts' }));
console.log('  secret   ', go('mcp__filesystem__read_file', { path: KEY }));

console.log('non-filesystem batch collapse');
const Q = 'mcp__db__query';
console.log('  one stmt ', go(Q, { statements: ['select 1'] }));
console.log('  two stmts', go(Q, { statements: ['select 1', 'drop table users'] }));

console.log('size property: a uniform batch stays one fragment');
console.log('  500 paths', go(T, { paths: Array.from({ length: 500 }, (_, i) => `src/f${i}.ts`) }));

// The end-to-end claim: train the benign batch to allow, then try the attack.
import { decide } from '../dist/src/core/decide.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../dist/src/core/envelope.js';
import { DEFAULT_CONFIG } from '../dist/src/store/index.js';
const DAY = 86_400_000, AT = Date.now();
const env = newEnvelope('project', WS);
for (let i = 0; i < 40; i++) {
  const a = analyze({ agent: 't', tool: T, input: { paths: ['src/a.ts', 'src/b.ts'] }, cwd: WS, sessionId: `s${i}`, at: AT - (40 - i) * DAY }, { roots: [WS], secretPatterns: [] });
  for (const x of a.actions) observe(env, { signature: x.signature, capability: x.capability, blast: x.blast, evidence: 'confirmed', at: AT - (40 - i) * DAY, sessionId: `s${i}`, display: x.display });
}
const ctx = { roots: [WS], secretPatterns: [], config: { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] }, envelope: env, session: newSession('a', AT), stateDir: path.join(os.tmpdir(), 'lg-mcp-st'), projectKey: WS };
const v = (input) => { const r = decide({ agent: 't', tool: T, input, cwd: WS, sessionId: 'a', at: AT }, ctx); return `${r.decision.toUpperCase().padEnd(5)} floor=${r.floor}`; };
console.log('after 40 approvals of the benign batch');
console.log('  benign again ', v({ paths: ['src/a.ts', 'src/b.ts'] }));
console.log('  with the key ', v({ paths: ['src/a.ts', KEY] }));
