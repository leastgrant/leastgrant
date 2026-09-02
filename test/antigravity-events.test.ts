/**
 * Telling Antigravity's two hook events apart.
 *
 * This is the third time this adapter has got event dispatch wrong, and each
 * mistake was invisible from the outside:
 *
 *   1. It routed on `hook_event_name`. That field does not exist on the wire —
 *      zero occurrences in the 153 MB runtime — so the adapter never ran at all
 *      and every tool call went unenforced. The suite was green because all
 *      eleven fixtures synthesised the field.
 *
 *   2. It routed on the presence of `toolCall`, believing only PreToolUse
 *      carries one. Symbolising the runtime says otherwise:
 *
 *        PreToolHookArgs   tool_call(1)  step_idx(2)
 *        PostToolHookArgs  step_idx(1)   tool_call(2)  error(3)  result(4)
 *
 *      Both carry both. So every PostToolUse was read as a PreToolUse.
 *
 *   3. (What this file exists to prevent.) The consequences of (2) were not
 *      obvious: the action is judged a second time after it already ran,
 *      `{"decision":…}` is returned where the contract wants `{}`, and
 *      `recordPost` never runs — so no evidence is ever recorded on this agent
 *      and nothing ever becomes familiar. A permission layer that never learns
 *      looks careful rather than broken, which is why it would have survived.
 *
 * The fix is that LeastGrant labels its own handlers. These tests assert the
 * label wins, that the fallback is conservative where the label is missing, and
 * that the installer actually writes the label.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isPreToolUse, eventFlag } from '../src/adapters/antigravity/hook.js';

/** A PreToolUse payload in the shape the runtime actually sends: flat, camelCase. */
const pre = (over: Record<string, unknown> = {}) => ({
  conversationId: 'c1',
  workspacePaths: ['D:\\ws'],
  transcriptPath: 'D:\\ws\\t.jsonl',
  artifactDirectoryPath: 'D:\\ws\\a',
  modelName: 'gemini-3-pro',
  toolCall: { name: 'run_command', args: { CommandLine: 'git status', Cwd: 'D:\\ws' } },
  stepIdx: 7,
  ...over,
});

/**
 * A PostToolUse payload, with the two fields the descriptor says it adds. This
 * is the fixture the old code could not have distinguished from the one above.
 */
const post = (over: Record<string, unknown> = {}) => ({
  ...pre(),
  stepIdx: 7,
  result: { ExitCode: 0, Output: 'nothing to commit' },
  ...over,
});

describe('which Antigravity event this is', () => {
  test('the label decides, whatever the payload looks like', () => {
    // Both directions, and deliberately against the payload's own shape, so a
    // future "improvement" to the fallback cannot quietly outrank the label.
    assert.equal(isPreToolUse(post(), 'pre'), true, 'an explicit --event pre must win');
    assert.equal(isPreToolUse(pre(), 'post'), false, 'an explicit --event post must win');
  });

  test('an unlabelled PostToolUse is not mistaken for a PreToolUse', () => {
    // The regression itself. Without the label, `result` and `error` are the
    // only fields that belong to PostToolUse alone.
    assert.equal(isPreToolUse(post()), false, 'a payload carrying `result` is a PostToolUse');
    assert.equal(
      isPreToolUse({ ...pre(), error: 'command failed' }),
      false,
      'a payload carrying `error` is a PostToolUse',
    );
  });

  test('an unlabelled PreToolUse still works, so old installs keep enforcing', () => {
    // The fallback has to stay usable: an install written before the label
    // existed must not stop gating tool calls the moment it is upgraded.
    assert.equal(isPreToolUse(pre()), true);
  });

  test('nothing recognisable is not a PreToolUse', () => {
    for (const junk of [null, undefined, 0, '', 'pre', [], { stepIdx: 3 }, { toolCall: 'run_command' }]) {
      assert.equal(isPreToolUse(junk), false, `${JSON.stringify(junk)} was read as a PreToolUse`);
    }
  });

  test('the flag is read in both spellings', () => {
    // `--agent` was got wrong exactly here once already, and the failure sent a
    // Codex payload to the Claude renderer.
    assert.equal(eventFlag(['node', 'x', '--event', 'post']), 'post');
    assert.equal(eventFlag(['node', 'x', '--event=post']), 'post');
    assert.equal(eventFlag(['node', 'x', '--event', 'POST']), 'post');
    assert.equal(eventFlag(['node', 'x', '--agent', 'antigravity']), undefined);
    // A bare token that happens to say "post" is not a flag.
    assert.equal(eventFlag(['node', 'x', 'post']), undefined);
  });
});
