/**
 * The real Antigravity payloads, driven through the real binary.
 *
 * `test/fixtures/antigravity-live.json` is not a fixture in the usual sense.
 * Every entry was captured off the wire from a signed-in Antigravity Desktop
 * 2.11.0 session by a wrapper that passed stdin, stdout and the exit code
 * through untouched. The paths are redacted; nothing else is edited.
 *
 * It exists because this adapter shipped broken twice on hand-written payloads.
 * The first version routed on `hook_event_name`, which does not exist on the
 * wire, so the adapter never ran — and eleven tests were green because they all
 * synthesised the field. The second believed only PreToolUse carries
 * `toolCall`; both do. In each case the tests agreed with the author and the
 * runtime did not.
 *
 * So these tests assert against what the host actually sent. If a future change
 * makes the adapter disagree with a recorded payload, the recorded payload is
 * right.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

/**
 * The repo root, found by walking up for package.json.
 *
 * This file runs from `dist/test`, so a fixed `..` lands in `dist` and the
 * fixture is not there — tsc does not copy JSON. Walking up is the version
 * that works from both the source tree and the build output.
 */
function repoRoot(from = import.meta.dirname): string {
  let dir = from;
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error(`could not find the repo root from ${from}`);
}

const ROOT = repoRoot();
const CLI = path.join(ROOT, 'bin', 'leastgrant.js');
const FIXTURES = path.join(ROOT, 'test', 'fixtures', 'antigravity-live.json');

interface Capture {
  event: 'pre' | 'post';
  tool: string;
  payload: Record<string, unknown>;
}

let captures: Capture[] = [];
let HOME = '';
let STATE = '';

before(() => {
  captures = JSON.parse(fs.readFileSync(FIXTURES, 'utf8')) as Capture[];
  HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-aglive-'));
  STATE = path.join(HOME, '.leastgrant');
});

after(() => {
  fs.rmSync(HOME, { recursive: true, force: true });
});

/** Drive the shipped binary the way Antigravity does. */
function hook(event: 'pre' | 'post', payload: unknown, extraArgs: string[] = []) {
  const r = spawnSync(
    process.execPath,
    [CLI, 'hook', '--agent', 'antigravity', '--event', event, ...extraArgs],
    {
      input: typeof payload === 'string' ? payload : JSON.stringify(payload),
      encoding: 'utf8',
      env: { ...process.env, LEASTGRANT_HOME: STATE, HOME, USERPROFILE: HOME },
      timeout: 30_000,
    },
  );
  const out = (r.stdout ?? '').trim();
  let json: Record<string, unknown> | null = null;
  try {
    json = out ? (JSON.parse(out) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { out, json, exit: r.status, decision: json?.['decision'] as string | undefined };
}

describe('the payloads Antigravity actually sends', () => {
  test('the corpus holds both events and the tools that were exercised', () => {
    // Guards against the file being emptied or trimmed to nothing, which would
    // make every test below vacuous.
    assert.ok(captures.length >= 6, `only ${captures.length} captured payloads`);
    const tools = new Set(captures.map((c) => c.tool));
    for (const t of ['run_command', 'view_file', 'write_to_file', 'list_dir', 'find_by_name']) {
      assert.ok(tools.has(t), `no captured payload for ${t}`);
    }
    assert.ok(captures.some((c) => c.event === 'pre'), 'no PreToolUse captures');
    assert.ok(captures.some((c) => c.event === 'post'), 'no PostToolUse captures');
  });

  test('no captured payload carries an event name, so nothing may route on one', () => {
    // The first release's mistake, pinned. If a future Antigravity adds the
    // field this test starts failing and somebody looks — which is the right
    // outcome, because the adapter would then have a better discriminator.
    for (const c of captures) {
      assert.ok(!('hook_event_name' in c.payload), `${c.tool}: payload has hook_event_name`);
      assert.ok(!('hookEventName' in c.payload), `${c.tool}: payload has hookEventName`);
    }
  });

  test('both events carry toolCall, which is why the label exists', () => {
    // The second release's mistake, pinned. A shape test on `toolCall` cannot
    // tell these apart, and this asserts that is still true rather than
    // trusting the comment that says so.
    for (const ev of ['pre', 'post'] as const) {
      const sample = captures.find((c) => c.event === ev);
      assert.ok(sample, `no ${ev} capture`);
      assert.ok(sample.payload['toolCall'], `${ev} payload has no toolCall`);
    }
  });

  test('every PreToolUse gets an explicit decision, never silence', () => {
    // Silence with exit 0 is the one path the host treats as "no hook result"
    // and lets through — measured live. So an abstain here is an allow, and
    // this adapter is not allowed to abstain.
    for (const c of captures.filter((x) => x.event === 'pre')) {
      const r = hook('pre', c.payload);
      assert.equal(r.exit, 0, `${c.tool}: exited ${r.exit} — a non-zero exit blocks the call`);
      assert.ok(r.out.length > 0, `${c.tool}: printed nothing, which the host reads as allow`);
      assert.ok(
        ['allow', 'ask', 'force_ask', 'deny'].includes(r.decision ?? ''),
        `${c.tool}: decision was ${JSON.stringify(r.decision)}`,
      );
    }
  });

  test('every PostToolUse answers with exactly {} and no decision', () => {
    // A decision here is answering a question that was not asked, and it means
    // the action was judged a second time after it already ran.
    for (const c of captures.filter((x) => x.event === 'post')) {
      const r = hook('post', c.payload);
      assert.equal(r.exit, 0, `${c.tool}: exited ${r.exit}`);
      assert.equal(r.out, '{}', `${c.tool}: PostToolUse answered ${r.out}`);
    }
  });

  test('a PostToolUse payload sent without a label is still not judged', () => {
    // The fallback for installs written before the label existed. `error` and
    // `result` belong to PostToolUse alone, and the captured post payloads
    // carry `error` even on success.
    for (const c of captures.filter((x) => x.event === 'post')) {
      const r = spawnSync(process.execPath, [CLI, 'hook', '--agent', 'antigravity'], {
        input: JSON.stringify(c.payload),
        encoding: 'utf8',
        env: { ...process.env, LEASTGRANT_HOME: STATE, HOME, USERPROFILE: HOME },
        timeout: 30_000,
      });
      assert.equal(
        (r.stdout ?? '').trim(),
        '{}',
        `${c.tool}: an unlabelled PostToolUse was judged as a PreToolUse`,
      );
    }
  });

  test('a credential read in the real payload shape is floored to force_ask', () => {
    // The distinction the whole adapter exists for, driven through the binary
    // with the tool name and argument key the host really uses. `ask` would be
    // wrong here: measured live, an ordinary ask is auto-executed under the
    // host's eager auto-execution policy.
    const base = captures.find((c) => c.event === 'pre' && c.tool === 'view_file');
    assert.ok(base, 'no captured view_file payload to build on');

    const secret = {
      ...base.payload,
      workspacePaths: ['D:/proj'],
      toolCall: { name: 'view_file', args: { AbsolutePath: 'D:/proj/.env', toolAction: 'x', toolSummary: 'x' } },
    };
    const r = hook('pre', secret);
    assert.equal(r.decision, 'force_ask', `a credential read came back as ${r.decision}: ${r.out}`);

    // The control. Same payload, same tool, an ordinary source file — it must
    // NOT be force_ask, or the test above would pass for the wrong reason.
    const ordinary = {
      ...base.payload,
      workspacePaths: ['D:/proj'],
      toolCall: { name: 'view_file', args: { AbsolutePath: 'D:/proj/src/index.ts', toolAction: 'x', toolSummary: 'x' } },
    };
    const c2 = hook('pre', ordinary);
    assert.notEqual(
      c2.decision,
      'force_ask',
      'an ordinary source read is also force_ask, so the credential result proves nothing',
    );
  });

  test('a payload LeastGrant cannot read is answered, not passed over in silence', () => {
    // Measured live: on Antigravity an empty stdout with exit 0 is treated as
    // "no hook result" and the call PROCEEDS. So the abstain that is correct on
    // every other agent is an allow here, and the generic parse-failure path
    // was taking it — any truncated, malformed or non-object payload arriving
    // with --agent antigravity was a silent allow.
    //
    // Not a hypothetical shape: a truncated pipe, invalid UTF-8 or an
    // oversized payload all land here.
    for (const bad of ['{"toolCall":', 'not json at all', '', '[]', 'null', '"a string"', '42']) {
      const r = hook('pre', bad);
      assert.ok(
        r.out.length > 0,
        `${JSON.stringify(bad)} produced silence, which this host reads as allow`,
      );
      assert.equal(
        r.decision,
        'force_ask',
        `${JSON.stringify(bad)} came back ${r.decision} — an unreadable call must reach a person, ` +
          `and must not be satisfiable by a cached grant`,
      );
      assert.equal(r.exit, 0, `${JSON.stringify(bad)} exited ${r.exit}; a non-zero exit blocks everything`);
    }
  });

  test('the same garbage on Claude Code still abstains, because there silence is honest', () => {
    // The control for the test above. Claude Code, Codex, Copilot and Cursor
    // read an empty response as "no opinion" and fall back to their own
    // permission flow. Answering `force_ask` there would be inventing a verdict
    // out of our own parse failure, and it would make every one of those agents
    // prompt whenever LeastGrant hiccuped.
    const r = spawnSync(process.execPath, [CLI, 'hook', '--agent', 'claude-code'], {
      input: 'not json at all',
      encoding: 'utf8',
      env: { ...process.env, LEASTGRANT_HOME: STATE, HOME, USERPROFILE: HOME },
      timeout: 30_000,
    });
    assert.equal((r.stdout ?? '').trim(), '', 'Claude Code should abstain on an unreadable payload');
    assert.equal(r.status, 0);
  });

  test('the real argument keys are the ones the adapter translates', () => {
    // Captured from the wire: run_command carries IsDaemon, not Blocking, and
    // write_to_file carries Description and Overwrite. Recorded so that a
    // future rename upstream is caught here rather than in the field.
    const byTool = (t: string) => captures.find((c) => c.event === 'pre' && c.tool === t)?.payload as
      | { toolCall: { args: Record<string, unknown> } }
      | undefined;

    const expected: Record<string, string[]> = {
      run_command: ['CommandLine', 'Cwd', 'IsDaemon', 'WaitMsBeforeAsync'],
      write_to_file: ['TargetFile', 'CodeContent', 'Description', 'Overwrite'],
      view_file: ['AbsolutePath'],
      list_dir: ['DirectoryPath'],
      find_by_name: ['SearchDirectory', 'Pattern', 'MaxDepth'],
    };
    for (const [tool, keys] of Object.entries(expected)) {
      const p = byTool(tool);
      assert.ok(p, `no captured ${tool} payload`);
      for (const k of keys) {
        assert.ok(k in p.toolCall.args, `${tool}: captured payload has no ${k}`);
      }
      // Every tool also carries these two, and they are not arguments.
      assert.ok('toolAction' in p.toolCall.args, `${tool}: no toolAction`);
    }
  });
});
