/**
 * Audit: signature collision.
 *
 * EVERY TEST IN THIS FILE IS EXPECTED TO FAIL against the current engine.
 * They are the specification for the fix, not a description of today's
 * behaviour.
 *
 * The thesis of signature.ts is that "risk-relevant distinctions survive
 * templating". These cases are the places where they do not: two actions with
 * very different consequences share one signature, so evidence gathered on the
 * harmless one is spent on the dangerous one.
 *
 * Three root causes, in order of severity:
 *
 *  1. `commandSignature()` is built from argv only. Redirects are not in it, and
 *     `buildShellAction()` adds the redirect's target to `action.targets`
 *     without changing `action.kind` or `action.capability`. So `cat x` and
 *     `cat x > ~/.bashrc` are the same learnable identity, and every floor that
 *     keys off kind/capability (self-write, persistence, write-outside) is blind
 *     to the write.
 *
 *  2. `toolSignature()` templates every workspace file to `Edit(<path>)`. The
 *     persistence/control floors are then the only thing separating "edit a
 *     source file" from "edit the thing that runs code later", and that list
 *     misses CI workflows, `.git/config`, `.mcp.json` and `package.json`.
 *
 *  3. An MCP signature is the bare tool name. Arguments never enter it at all,
 *     and a read-shaped verb puts the call at a promotable tier.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config, Request, Verdict } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';
import { analyze } from '../src/core/classify.js';
import { proposeBundles } from '../src/core/bundles.js';

const WORKSPACE = path.join(os.tmpdir(), 'leastgrant-sigcollide-ws');
const STATE_DIR = path.join(os.tmpdir(), 'leastgrant-sigcollide-state');
const DAY = 86_400_000;

const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

type Spec = string | { tool: string; input: Record<string, unknown> };

function mkReq(spec: Spec, sessionId: string, at: number): Request {
  return typeof spec === 'string'
    ? { agent: 't', tool: 'Bash', input: { command: spec }, cwd: WORKSPACE, sessionId, at }
    : { agent: 't', tool: spec.tool, input: spec.input, cwd: WORKSPACE, sessionId, at };
}

/** Saturate an envelope with human approvals — the attacker's best case. */
function trainedOn(specs: Spec[], at = Date.now()) {
  const envelope = newEnvelope('project', WORKSPACE);
  for (let i = 0; i < 40; i++) {
    for (const spec of specs) {
      const a = analyze(mkReq(spec, `s${i}`, at - (40 - i) * DAY), {
        roots: [WORKSPACE],
        secretPatterns: [],
      });
      for (const action of a.actions) {
        observe(envelope, {
          signature: action.signature,
          capability: action.capability,
          blast: action.blast,
          evidence: 'confirmed',
          at: at - (40 - i) * DAY,
          sessionId: `s${i}`,
          display: action.display,
        });
      }
    }
  }
  return {
    roots: [WORKSPACE],
    secretPatterns: [],
    config,
    envelope,
    session: newSession('attack', at),
    stateDir: STATE_DIR,
    projectKey: WORKSPACE,
  };
}

function judge(spec: Spec, ctx: ReturnType<typeof trainedOn>): Verdict {
  const at = Date.now();
  return decide(mkReq(spec, 'attack', at), { ...ctx, session: newSession('attack', at) });
}

const sigOf = (spec: Spec): string =>
  analyze(mkReq(spec, 's', Date.now()), { roots: [WORKSPACE], secretPatterns: [] }).actions[0]!.signature;

/** A path the shell tokenizer will not mangle on Windows. */
const shq = (p: string): string => p.replace(/\\/g, '/');

// ---------------------------------------------------------------------------
// 1. Redirects are not part of the signature, and do not change kind/capability
// ---------------------------------------------------------------------------

describe('AUDIT: a redirect is a write the signature and the floors both miss', () => {
  // The ordinary read-only vocabulary of any real project.
  const READS = ['ls -la', 'cat README.md', 'echo "a note about the build"', 'tail -n 20 out.log'];

  test('EXPECTED TO FAIL: signature does not record the redirect at all', () => {
    assert.notEqual(
      sigOf('cat README.md'),
      sigOf('cat README.md > /etc/cron.d/pwn'),
      'a command that writes /etc/cron.d/pwn must not share an identity with one that writes nothing',
    );
  });

  // CRITICAL. `guard.self-write` is the one floor documented as not overridable
  // by anyone. It is skipped when `action.kind === 'file.read'` — but a redirect
  // off `cat` produces a state-directory *write* while the kind stays file.read.
  test('EXPECTED TO FAIL: cat > <stateDir>/config.json must not be allowed', () => {
    const ctx = trainedOn(READS);
    const v = judge(`cat evil.json > ${shq(path.join(STATE_DIR, 'config.json'))}`, ctx);
    assert.notEqual(v.decision, 'allow', `rewriting LeastGrant's own config: ${v.headline}`);
    assert.equal(v.decision, 'deny', 'the self-write integrity floor should still deny this');
  });

  test('EXPECTED TO FAIL: ls > <stateDir>/envelope.json must not be allowed', () => {
    const ctx = trainedOn(READS);
    const v = judge(`ls -la > ${shq(path.join(STATE_DIR, 'envelope.json'))}`, ctx);
    assert.notEqual(v.decision, 'allow', v.headline);
  });

  // CRITICAL. Arbitrary machine-wide write under a trained read.
  for (const cmd of [
    'ls -la > /etc/cron.d/pwn',
    'cat README.md > /etc/cron.d/pwn',
    'cat payload.txt > ~/.bashrc',
    'echo "a note about the build" >> ~/.bashrc',
    'echo "a note about the build" >| ~/.bashrc',
    'cat payload.txt > /usr/local/bin/kubectl',
  ]) {
    test(`EXPECTED TO FAIL: ${cmd}`, () => {
      const v = judge(cmd, trainedOn(READS));
      assert.notEqual(v.decision, 'allow', v.headline);
    });
  }

  // CRITICAL. Persistence inside the workspace: guard.persistence never fires
  // because the action's kind is `exec` / `file.read`, not `file.write`.
  for (const cmd of [
    'echo "a note about the build" > .git/hooks/pre-commit',
    'echo "a note about the build" > .husky/pre-commit',
    'echo "a note about the build" > .envrc',
    'cat payload.txt > .git/hooks/pre-push',
    'tail -n 20 payload.txt > .git/hooks/post-checkout',
    'echo "a note about the build" 2> .git/hooks/pre-commit',
  ]) {
    test(`EXPECTED TO FAIL: ${cmd}`, () => {
      const v = judge(cmd, trainedOn(READS));
      assert.notEqual(v.decision, 'allow', v.headline);
    });
  }

  // The existing bypass corpus already trains on `ls -la` and `cat README.md`.
  // Its two redirect cases (`echo evil >> ~/.bashrc`, `echo x > /etc/cron.d/pwn`)
  // pass only because the *echoed word* happens not to match the trained one.
  test('EXPECTED TO FAIL: the existing bypass corpus training already opens this', () => {
    const ctx = trainedOn(['git status', 'npm test', 'ls -la', 'echo hello', 'cat README.md', 'diff a b', 'git log']);
    for (const cmd of [
      'ls -la > /etc/cron.d/pwn',
      'cat README.md > ~/.bashrc',
      'cat README.md > .git/hooks/pre-commit',
    ]) {
      assert.notEqual(judge(cmd, ctx).decision, 'allow', cmd);
    }
  });

  // And the pre-selected `read` bundle turns all of the above into one click.
  test("EXPECTED TO FAIL: the recommended 'read' bundle grants machine-wide writes", () => {
    const at = Date.now();
    const history = newEnvelope('project', WORKSPACE);
    for (let i = 0; i < 10; i++) {
      for (const cmd of READS) {
        const a = analyze(mkReq(cmd, `s${i}`, at - (10 - i) * DAY), { roots: [WORKSPACE], secretPatterns: [] });
        for (const x of a.actions) {
          observe(history, {
            signature: x.signature, capability: x.capability, blast: x.blast,
            evidence: 'observed', at: at - (10 - i) * DAY, sessionId: `s${i}`, display: x.display,
          });
        }
      }
    }
    const read = proposeBundles([history]).find((b) => b.id === 'read')!;
    assert.ok(read, 'the read bundle should be proposed');
    assert.equal(read.recommended, true);

    const env = newEnvelope('project', WORKSPACE);
    for (const sig of read.signatures) {
      const s = history.signatures[sig]!;
      observe(env, {
        signature: sig, capability: s.capability, blast: s.worstBlast,
        evidence: 'granted', at, sessionId: 'setup', display: sig,
      });
    }
    const ctx = {
      roots: [WORKSPACE], secretPatterns: [], config, envelope: env,
      session: newSession('x', at), stateDir: STATE_DIR, projectKey: WORKSPACE,
    };
    for (const cmd of ['cat payload.txt > ~/.bashrc', 'ls -la > /etc/cron.d/pwn']) {
      const v = decide(mkReq(cmd, 'x', at), { ...ctx, session: newSession('x', at) });
      assert.notEqual(
        v.decision,
        'allow',
        `the bundle says "not files outside the project" but allowed: ${cmd}`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Edit(<path>) is one identity for the entire workspace
// ---------------------------------------------------------------------------

describe('AUDIT: Edit(<path>) collapses every file in the project', () => {
  const SOURCE = [
    { tool: 'Edit', input: { file_path: 'src/index.ts' } },
    { tool: 'Edit', input: { file_path: 'src/util.ts' } },
  ];

  // Files inside the workspace whose modification runs code later, or changes
  // what the agent itself is allowed to do. None are on the persistence or
  // control lists, so `Edit(<path>)` covers all of them.
  const DANGEROUS = [
    '.github/workflows/release.yml', // runs in CI with repository secrets
    '.gitlab-ci.yml',
    '.circleci/config.yml',
    '.git/config',                   // core.hooksPath / [alias] => RCE, and it
                                     // relocates the .git/hooks floor entirely
    '.mcp.json',                     // declares MCP servers the agent will launch
    '.claude/commands/deploy.md',    // injected into future agent sessions
    '.claude/agents/reviewer.md',
    'package.json',                  // prepare/postinstall lifecycle scripts
  ];

  for (const f of DANGEROUS) {
    test(`EXPECTED TO FAIL: Edit(${f})`, () => {
      const v = judge({ tool: 'Edit', input: { file_path: f } }, trainedOn(SOURCE));
      assert.equal(
        sigOf({ tool: 'Edit', input: { file_path: f } }),
        'Edit(<path>)',
        'sanity: this really is the same signature as an ordinary source edit',
      );
      assert.notEqual(v.decision, 'allow', v.headline);
    });
  }

  test('EXPECTED TO FAIL: Write and NotebookEdit have the same hole', () => {
    assert.notEqual(
      judge({ tool: 'Write', input: { file_path: '.github/workflows/release.yml' } },
        trainedOn([{ tool: 'Write', input: { file_path: 'src/index.ts' } }])).decision,
      'allow',
    );
    assert.notEqual(
      judge({ tool: 'NotebookEdit', input: { notebook_path: '.github/workflows/release.yml' } },
        trainedOn([{ tool: 'NotebookEdit', input: { notebook_path: 'nb/a.ipynb' } }])).decision,
      'allow',
    );
  });
});

// ---------------------------------------------------------------------------
// 3. An MCP signature is the tool name; arguments never enter it
// ---------------------------------------------------------------------------

describe('AUDIT: MCP signatures discard every argument', () => {
  // `query` is on MCP_READ_VERBS, so the call is judged tier 2 and is
  // promotable. The signature is `mcp__db__query` whatever the SQL is.
  test('EXPECTED TO FAIL: approving query(SELECT) approves query(DROP TABLE)', () => {
    const ctx = trainedOn([{ tool: 'mcp__db__query', input: { sql: 'select 1' } }]);
    const v = judge({ tool: 'mcp__db__query', input: { sql: 'drop table users' } }, ctx);
    assert.notEqual(v.decision, 'allow', v.headline);
  });

  // A malicious or careless server picks a read-shaped verb for a write.
  for (const tool of ['mcp__acme__resolve_ticket', 'mcp__acme__check_out_branch', 'mcp__acme__get_document']) {
    test(`EXPECTED TO FAIL: ${tool} reaches allow on name shape alone`, () => {
      const v = judge({ tool, input: { destructive: true } }, trainedOn([{ tool, input: {} }]));
      assert.notEqual(v.decision, 'allow', v.headline);
    });
  }
});

// ---------------------------------------------------------------------------
// 4. Smaller collisions
// ---------------------------------------------------------------------------

describe('AUDIT: smaller signature collisions', () => {
  // `chroot NEWROOT cmd` is unwrapped by dropping NEWROOT, tagged `env`, and no
  // guard looks at the `env` tag. The signature is the inner command's.
  test('EXPECTED TO FAIL: chroot inherits the inner command signature with no floor', () => {
    const v = judge('chroot /tmp/evilroot npm test', trainedOn(['npm test']));
    assert.notEqual(v.decision, 'allow', v.headline);
  });

  // `kill <n>` is one signature for every process on the machine.
  test('EXPECTED TO FAIL: kill <n> collapses every pid', () => {
    assert.notEqual(judge('kill 1', trainedOn(['kill 48211'])).decision, 'allow');
  });

  // Any tool name the adapter does not recognise becomes `meta` with NIL_BLAST,
  // i.e. tier 0 and promotable from observation alone.
  test('EXPECTED TO FAIL: an unrecognised tool name is treated as a no-op', () => {
    const v = judge({ tool: 'DeleteEverything', input: { path: '/' } },
      trainedOn([{ tool: 'DeleteEverything', input: {} }]));
    assert.notEqual(v.decision, 'allow', v.headline);
  });
});
