// Re-derives every number the README asserts, from the real history on this
// machine. Run it before changing a claim in the README.
import { transcriptFiles, readTranscript, evidenceFor, mine } from '../dist/src/adapters/claude-code/mine.js';
import { replay } from '../dist/src/replay.js';
import { proposeBundles, coverageOf } from '../dist/src/core/bundles.js';
import { DEFAULT_CONFIG } from '../dist/src/store/index.js';
import { DEFAULT_THRESHOLDS, observe } from '../dist/src/core/envelope.js';

const events = [];
for (const f of transcriptFiles()) for (const ev of readTranscript(f)) {
  if (!ev.cwd) continue;
  events.push({ at: ev.at, sessionId: ev.sessionId, cwd: ev.cwd, tool: ev.tool,
    input: ev.input, agentMode: ev.permissionMode, denied: ev.denied, evidence: evidenceFor(ev) });
}
const summary = mine();
const cfg = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

const before = replay(events, { config: cfg });
const envs = [...before.envelopes.values()];
const bundles = proposeBundles(envs);
const recommended = bundles.filter(b => b.recommended);
const now = 1788000000000;
for (const b of recommended) for (const env of envs) for (const sig of b.signatures) {
  const st = env.signatures[sig]; if (!st) continue;
  observe(env, { signature: sig, capability: st.capability, blast: st.worstBlast,
    evidence: 'granted', at: now, sessionId: 'setup', display: sig }, cfg.thresholds);
}
const pct = n => Math.round(n * 100);
// Measured before the second replay: `replay` clones its seed, but the grants
// above already bumped totalSeen once each, and the denominator should be the
// history, not the history plus our own bookkeeping.
const totalActions = envs.reduce(
  (n, e) => n + Object.values(e.signatures).reduce((m, s) => m + s.totalSeen, 0), 0);

const seeded = new Map(envs.map(e => [e.key, e]));
const after = replay(events, { config: cfg, seed: seeded });

console.log('README claim                          value');
console.log('------------------------------------  -----------------------------');
console.log('sessions / projects / actions        ', `${summary.sessions} / ${summary.byProject.size} / ${before.total.toLocaleString('en-US')}`);
console.log('share that ran unattended            ', pct(summary.observed / summary.events) + '%');
console.log('refusals on record                   ', summary.denied);
console.log('allow rate BEFORE starter grants     ', pct(before.allowed / before.total) + '%');
console.log('allow rate AFTER starter grants      ', pct(after.allowed / after.total) + '%');
console.log('regrets after grants (must be 0)     ', after.regrets.length);
console.log('bundle coverage of all actions       ', Math.min(100, pct(coverageOf(recommended) / totalActions)) + '%');
