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
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { analyze } from '../src/core/classify.js';
import { redact } from '../src/core/secrets.js';

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

describe('a bare credential variable name is redacted', () => {
  // The rule required a prefix before the credential word — `[A-Za-z_]` had to
  // consume a character first — so `DB_PASSWORD=` was caught and `PASSWORD=`
  // could never match at all. Those bare spellings are the commonest there are,
  // and the value went into ledger.jsonl, the envelope, and denials.jsonl,
  // which is append-only and by design never pruned, so it outlived every
  // other copy.
  const BARE = ['PASSWORD', 'TOKEN', 'SECRET', 'API_KEY', 'APIKEY', 'AUTH', 'CREDENTIALS', 'PASSWD'];
  for (const name of BARE) {
    test(`${name}=`, () => {
      const out = redact(`${name}=s3cr3tvalue ./deploy.sh`);
      assert.ok(!out.includes('s3cr3tvalue'), out);
    });
  }

  test('the prefixed spellings still work', () => {
    for (const s of ['DB_PASSWORD=hunter2', 'MY_TOKEN=abc123', 'GITHUB_TOKEN=xyz']) {
      assert.ok(!redact(s).includes('hunter2') || !s.includes('hunter2'), redact(s));
      assert.match(redact(s), /«redacted/);
    }
  });

  test('an ordinary variable is left alone', () => {
    // The cost of a broader rule. These appear on nearly every command line and
    // redacting them would make the ledger unreadable, which is the failure the
    // module header warns about.
    for (const s of ['NODE_ENV=test', 'PATH=/usr/bin', 'CI=true', 'PORT=3000', 'LANG=en_US']) {
      assert.equal(redact(s), s);
    }
  });

  test('a more specific rule keeps its label', () => {
    // This rule is broad and runs after the specific ones, so without a guard
    // it re-redacts what they produced and the human loses the label telling
    // them which kind of credential it was.
    assert.match(redact('TOKEN=xoxb-1234567890-abcdef'), /slack-token/);
    assert.match(redact('curl --password=hunter2 https://x'), /flag-value/);
    assert.match(redact('AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE'), /aws-key-id/);
  });
});

describe('an unreadable config is not a quiet reset to the defaults', () => {
  // "There is no config yet" and "your config is unreadable" used to get the
  // same answer. A first run has no file and the defaults are right for it. A
  // file that exists and will not parse is different: the human's deny rules
  // and posture are still on disk and cannot be read, and returning the
  // defaults discarded them and landed on `assist`, which auto-approves
  // familiar work — quite possibly more permissive than what they configured,
  // arrived at by an error nobody was told about.
  const withStateDir = async (write: ((dir: string) => void) | null) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leastgrant-cfg-'));
    if (write) write(dir);
    const prev = process.env['LEASTGRANT_HOME'];
    process.env['LEASTGRANT_HOME'] = dir;
    try {
      const { loadConfig } = await import('../src/store/index.js');
      return loadConfig();
    } finally {
      if (prev === undefined) delete process.env['LEASTGRANT_HOME'];
      else process.env['LEASTGRANT_HOME'] = prev;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  test('a missing config is a first run, and the defaults are right', async () => {
    const cfg = await withStateDir(null);
    assert.equal(cfg.posture, 'assist');
  });

  test('a corrupt config falls towards asking, not towards allowing', async () => {
    const cfg = await withStateDir((d) => fs.writeFileSync(path.join(d, 'config.json'), '{ not json'));
    assert.equal(
      cfg.posture,
      'strict',
      'an unreadable config silently became the permissive default and dropped every rule',
    );
    assert.deepEqual(cfg.rules, []);
  });
});

describe('forgetting learned evidence actually removes it', () => {
  // `saveEnvelope` re-reads the file and merges before writing, so two hook
  // processes racing cannot lose each other's evidence. That merge starts from
  // what is on disk and only ever adds — right for concurrency, and exactly
  // wrong for a person typing `leastgrant forget --learned`, which deleted the
  // signature from the in-memory envelope and had it restored on the way out.
  // The command reported success and forgot nothing.
  const withStore = async <T>(fn: (api: typeof import('../src/store/index.js')) => Promise<T> | T): Promise<T> => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leastgrant-forget-'));
    const prev = process.env['LEASTGRANT_HOME'];
    process.env['LEASTGRANT_HOME'] = dir;
    try {
      return await fn(await import('../src/store/index.js'));
    } finally {
      if (prev === undefined) delete process.env['LEASTGRANT_HOME'];
      else process.env['LEASTGRANT_HOME'] = prev;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  const NIL = { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'single' } as const;

  test('a deleted signature stays deleted when it is named', async () => {
    await withStore(async ({ saveEnvelope, loadEnvelope }) => {
      const { newEnvelope, observe } = await import('../src/core/envelope.js');
      const seed = newEnvelope('project', 'proj');
      for (const sig of ['npm test', 'git status']) {
        observe(seed, {
          signature: sig, capability: 'exec.test', blast: NIL,
          evidence: 'confirmed', at: 1_760_000_000_000, sessionId: 's', display: sig,
        });
      }
      saveEnvelope(seed);

      const before = loadEnvelope('project', 'proj');
      delete before.signatures['npm test'];
      saveEnvelope(before, { forget: ['npm test'] });

      const after = loadEnvelope('project', 'proj');
      assert.deepEqual(Object.keys(after.signatures), ['git status']);
    });
  });

  test('and comes back when it is not, which is the concurrency guarantee', async () => {
    // Asserted so the merge is not quietly removed later: an unnamed deletion
    // must still lose to what is on disk, or a hook writing concurrently with a
    // forget could have its evidence dropped.
    await withStore(async ({ saveEnvelope, loadEnvelope }) => {
      const { newEnvelope, observe } = await import('../src/core/envelope.js');
      const seed = newEnvelope('project', 'proj2');
      observe(seed, {
        signature: 'npm test', capability: 'exec.test', blast: NIL,
        evidence: 'confirmed', at: 1_760_000_000_000, sessionId: 's', display: 'npm test',
      });
      saveEnvelope(seed);

      const before = loadEnvelope('project', 'proj2');
      delete before.signatures['npm test'];
      saveEnvelope(before);

      assert.deepEqual(Object.keys(loadEnvelope('project', 'proj2').signatures), ['npm test']);
    });
  });
});
