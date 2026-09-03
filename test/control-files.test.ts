/**
 * The file that switches LeastGrant off is always worth a person.
 *
 * Every agent reads one file to decide whether the hook runs. That file is the
 * single highest-value write on the machine for anything trying to get out from
 * under a permission layer: change it once and every later call is unguarded,
 * with no verdict to notice because there is no longer anything asking.
 *
 * So the requirement is not "the list in guards.ts looks complete". It is: for
 * every `configPath` in `compatibility/*.json` — the same records `doctor`, the
 * README and the website read — a write there must be FLOORED by
 * `guard.agent-config`, and not merely produce an `ask` for some other reason.
 *
 * That distinction is the whole test. When this was written, three of the six
 * config paths did produce an `ask`, and none of the three was floored:
 *
 *   ~/.codex/hooks.json           asked because it is outside the project
 *   ~/.gemini/config/hooks.json   asked because it is outside the project
 *   <repo>/.agents/hooks.json     asked because it was unfamiliar
 *
 * Neither reason holds up. Outside-home writes share one signature, so
 * approving any of them approves the class; unfamiliarity is precisely what
 * promotion exists to retire. Both roads end at a silent allow on the off
 * switch. The list in guards.ts had `.codex/config.toml` and
 * `.gemini/settings.json` in it — which is why reading it did not find this,
 * and why probing every recorded config path through the engine did.
 *
 * Deriving the paths from the compatibility records rather than restating them
 * means the next adapter cannot ship its config path unfloored: adding the
 * record is what adds the requirement.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';
import { loadCompatibility } from '../src/core/compatibility.js';

const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-controlfiles-ws-'));
fs.mkdirSync(path.join(WS, '.git'), { recursive: true });
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-controlfiles-home-'));
const STATE = path.join(os.tmpdir(), 'lg-controlfiles-state');
const AT = 1_760_000_000_000;

/**
 * The config paths a record names, as absolute paths.
 *
 * `configPath` is prose meant for a human — "~/.gemini/config/hooks.json
 * (global) or <repo>/.agents/hooks.json (workspace)" — so the file-shaped parts
 * are pulled out of it rather than assuming one path per agent. An agent with
 * two config locations has two ways to be switched off, and Antigravity is one.
 */
function configPaths(text: string | undefined): string[] {
  if (!text) return [];
  const out: string[] = [];
  for (const m of text.matchAll(/(~|<repo>)([\\/][\w.\-/\\]+)/g)) {
    const rel = m[2]!.replace(/^[\\/]/, '');
    out.push(path.join(m[1] === '~' ? HOME : WS, rel));
  }
  return out;
}

function write(file: string) {
  return decide(
    { agent: 't', tool: 'Write', input: { file_path: file, content: '{}' }, cwd: WS, sessionId: 's', at: AT },
    {
      roots: [WS],
      secretPatterns: [],
      config: { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] },
      envelope: newEnvelope('project', WS),
      session: newSession('s', AT),
      stateDir: STATE,
      projectKey: WS,
    },
  );
}

/** A recorded control path, placed under a fake home or repo. */
function place(p: string): string {
  const rel =
    p.startsWith('~/') ? p.slice(2)
    : p.startsWith('<repo>/') ? p.slice(7)
    : p;
  const base = p.startsWith('~/') ? HOME : WS;
  const abs = path.join(base, rel);
  // A directory entry stands for everything under it, so probe a file inside.
  return /\.(json|jsonc|toml|md|ya?ml)$/.test(abs) ? abs : path.join(abs, 'probe.json');
}

describe('everything that decides what an agent may do later', () => {
  const agents = loadCompatibility();

  test('every agent records the paths that control it', () => {
    // An adapter with no recorded control paths is an adapter whose off switch
    // nobody has looked for. The list is not allowed to be empty and it is not
    // allowed to be only the install path — Antigravity has ten, and the two
    // that matter most are the host's own grant store and its MCP wiring,
    // neither of which is where LeastGrant installs itself.
    for (const a of agents) {
      const cps = a.controlPaths ?? [];
      assert.ok(cps.length > 0, `${a.id}: records no controlPaths`);
      for (const cp of cps) {
        assert.ok(cp.path && cp.what && cp.why, `${a.id}: incomplete control path ${JSON.stringify(cp)}`);
        assert.ok(
          cp.what.length > 20,
          `${a.id}: "${cp.path}" does not say what it decides — a reader cannot judge a path from its name`,
        );
      }
    }
  });

  test('every recorded control path is floored by guard.agent-config', () => {
    // Derived from the records rather than restated, so adding an adapter adds
    // the requirement. Checked against `flooredGuards` and not against the
    // decision: `~/.gemini/config/config.json` produced an `ask` before this
    // existed, from `guard.write-outside` plus a lucky filename match on the
    // credentials heuristic. Outside-home writes share one signature, so
    // approving any of them approves the class — and that file holds the
    // host's own standing-grant list.
    for (const a of agents) {
      for (const cp of a.controlPaths ?? []) {
        const v = write(place(cp.path));
        assert.ok(
          v.flooredGuards.includes('guard.agent-config'),
          `${a.id}: writing ${cp.path} gave ${v.decision} with floors ` +
            `[${v.flooredGuards.join(', ') || 'none'}] — it decides ${cp.what}`,
        );
      }
    }
  });

  test('a grant store is never left to the credentials heuristic', () => {
    // The narrow version of the above, kept separate because it is the one
    // whose absence was worst. A file that can hand an agent standing approval
    // must be floored for BEING that, not because its name looked like a
    // secret — rename it and the accident stops working.
    for (const a of agents) {
      for (const cp of (a.controlPaths ?? []).filter((c) => c.why === 'grant' || c.why === 'mcp')) {
        const v = write(place(cp.path));
        assert.ok(
          v.flooredGuards.includes('guard.agent-config'),
          `${a.id}: ${cp.path} is a ${cp.why} store floored only by [${v.flooredGuards.join(', ')}]`,
        );
      }
    }
  });

  test('the four Antigravity workspace roots are all floored, not just the documented one', () => {
    // 2.11.0 loads workspace hooks from `.agents`, `_agents`, `.agent` and
    // `_agent`, and from `plugins/<name>/hooks.json` besides. Only the first
    // was covered; the other four were ordinary project files. A write to any
    // of them installs a handler that runs on every later tool call, and one
    // returning `auto_approve` switches enforcement off while LeastGrant still
    // reports itself installed.
    for (const rel of [
      '.agents/hooks.json',
      '_agents/hooks.json',
      '.agent/hooks.json',
      '_agent/hooks.json',
      'plugins/anything/hooks.json',
      '_agents/mcp_config.json',
    ]) {
      const v = write(path.join(WS, rel));
      assert.ok(
        v.flooredGuards.includes('guard.agent-config'),
        `${rel} can install a hook and is floored by [${v.flooredGuards.join(', ') || 'nothing'}]`,
      );
    }
    // The control: a source file whose path merely contains the word hooks.
    const ok = write(path.join(WS, 'src', 'hooks', 'index.ts'));
    assert.ok(
      !ok.flooredGuards.includes('guard.agent-config'),
      'an ordinary source file under src/hooks/ is being treated as agent configuration',
    );
  });

  test('a customization root is one where the runtime looks, not anywhere', () => {
    // Antigravity's discovery walks UP from the workspace and never down, so
    // `.agents` and its three siblings are customization roots at the workspace
    // root and at its ancestors — and ordinary directory names everywhere else.
    // They were floored at any depth, and on that agent a floored ask becomes
    // `force_ask`: an unsuppressible prompt on `crates/_agent/Cargo.toml` and
    // `src/_agents/pool.py`, which are common names in Rust and ML repos.
    //
    // Coverage is unchanged where it matters, because a `hooks.json` inside one
    // is still floored by filename from anywhere. The danger is the file that
    // installs a handler, not the directory it sits in.
    for (const rel of ['.agents/plugins.json', '_agents/hooks.json', '_agent/mcp_config.json', '.agent/skills.json']) {
      const v = write(path.join(WS, rel));
      assert.ok(v.flooredGuards.includes('guard.agent-config'), `${rel} at the workspace root is not floored`);
    }
    for (const rel of [
      'crates/_agent/Cargo.toml',
      'src/_agents/pool.py',
      'node_modules/pkg/_agent/index.js',
      'vendor/.agents/README.md',
    ]) {
      const v = write(path.join(WS, rel));
      assert.ok(
        !v.flooredGuards.includes('guard.agent-config'),
        `${rel} is nested, not a customization root, and is being floored`,
      );
    }
    // But a hooks.json down there is still the file that installs a handler.
    const nested = write(path.join(WS, 'vendor', '_agents', 'hooks.json'));
    assert.ok(
      nested.flooredGuards.includes('guard.agent-config'),
      'a nested hooks.json lost its floor — the filename rule is what carries this',
    );
  });

  test('every agent in the compatibility data names where its config lives', () => {
    // A record without one cannot be checked, which would make the guard below
    // silently vacuous for that agent — the failure mode where a test protects
    // five things and reports six.
    for (const a of agents) {
      assert.ok(
        configPaths(a.configPath).length > 0,
        `${a.id}: no parseable config path in "${a.configPath ?? ''}" — the floor below cannot be checked for it`,
      );
    }
  });

  test('a write to any of them is floored, not merely asked about', () => {
    for (const a of agents) {
      for (const file of configPaths(a.configPath)) {
        const v = write(file);
        assert.ok(
          v.flooredGuards.includes('guard.agent-config'),
          `${a.id}: writing ${file} gave ${v.decision} with floors [${v.flooredGuards.join(', ') || 'none'}]. ` +
            `An ask for another reason is not the same thing: outside-home writes share one ` +
            `signature and unfamiliarity is retired by promotion, so both end at a silent allow ` +
            `on the off switch.`,
        );
      }
    }
  });

  test('an ordinary project file is not floored, so the check above means something', () => {
    // Without this, a guard that floored every write would pass the test above
    // and destroy the product.
    const v = write(path.join(WS, 'src', 'index.ts'));
    assert.ok(
      !v.flooredGuards.includes('guard.agent-config'),
      `an ordinary source edit is being treated as an agent-config change: ${v.headline}`,
    );
  });

  test('the floor does not depend on where the file sits', () => {
    // The Antigravity miss was workspace-local and the Codex miss was in the
    // home directory. A list that catches one location and not the other looks
    // right in whichever place you happen to test, which is how both survived.
    for (const rel of ['.agents/hooks.json', '.codex/hooks.json', '.gemini/config/hooks.json']) {
      for (const [where, base] of [['home', HOME], ['the repo', WS]] as const) {
        const v = write(path.join(base, rel));
        assert.ok(
          v.flooredGuards.includes('guard.agent-config'),
          `${rel} under ${where} is not floored: ${v.decision}, [${v.flooredGuards.join(', ') || 'none'}]`,
        );
      }
    }
  });
});
