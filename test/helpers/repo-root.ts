/**
 * Where the repository is, from inside a test.
 *
 * Tests that read files which are *not* compiled — the corpus, the workflow
 * YAML, package.json — cannot use a fixed relative depth, because the same
 * file runs from `dist/test/` after a build and from `test/` if invoked
 * directly. Walking up to the nearest package.json works from both.
 *
 * This lives in one place because it had already been written twice with the
 * same comment attached, and a third copy was about to be written for the
 * bypass corpus. Path-resolution logic duplicated across files is how two
 * callers end up disagreeing about where the repository is.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

export function repoRoot(from: string = fileURLToPath(import.meta.url)): string {
  let dir = path.dirname(from);
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  throw new Error(`could not locate the repository root from ${from}`);
}
