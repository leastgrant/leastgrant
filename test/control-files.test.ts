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

describe('the file that turns LeastGrant off', () => {
  const agents = loadCompatibility();

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
