/**
 * The README's agent-support block must match what the generator produces.
 *
 * A hand-written support table decays silently. By the time the second audit
 * read this one, six of its claims were contradicted by the repository's own
 * compatibility data — "an ask reaches you in every mode" on Claude Code, which
 * is false under `claude -p`; "a real ask" for Codex modes where nothing
 * prompts; a credential read on Cursor described as blocked when the file has
 * already been read by the time the hook sees it. Every one of those was true
 * when it was written, and every one of them read fluently, which is exactly
 * why nobody caught them.
 *
 * So the block is generated from `compatibility/*.json`, the same file
 * `leastgrant doctor` and the website render, and this test is what makes the
 * generator load-bearing rather than a suggestion. Without it a well-meaning
 * edit to the README wins silently, which is the state that produced the six.
 *
 * If this fails: run `npm run gen:readme`. If the generated text is wrong, the
 * data is wrong — fix `compatibility/<agent>.json`, which also fixes doctor and
 * the website in the same commit.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { repoRoot } from './helpers/repo-root.js';

const README = path.join(repoRoot(), 'README.md');

describe('the README agent table is generated, not written', () => {
  test('the committed block matches the generator', () => {
    // Run as a subprocess rather than imported: the generator is .mjs, this
    // suite is typed, and `--check` is the same command CI uses.
    const r = spawnSync(process.execPath, [path.join(repoRoot(), 'scripts', 'gen-readme.mjs'), '--check'], {
      encoding: 'utf8',
      timeout: 60_000,
    });
    assert.equal(
      r.status,
      0,
      `${(r.stderr || r.stdout || '').trim()}
(the data is the source: fix compatibility/<agent>.json, then run npm run gen:readme)`,
    );
  });

  test('every agent with a compatibility file appears in it', () => {
    // Guards the quiet failure where the generator silently stops emitting an
    // agent: the table would still be "generated" and still be wrong.
    const readme = fs.readFileSync(README, 'utf8');
    const names = fs
      .readdirSync(path.join(repoRoot(), 'compatibility'))
      .filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(repoRoot(), 'compatibility', f), 'utf8')) as { name: string })
      .map((a) => a.name);

    assert.ok(names.length >= 4, `only ${names.length} compatibility records found`);
    for (const name of names) {
      assert.ok(readme.includes(name), `${name} has a compatibility file but does not appear in the README`);
    }
  });
});
