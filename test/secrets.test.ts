/**
 * Credential-path detection and the ledger redactor.
 *
 * Both halves of `src/core/secrets.ts` fail in opposite directions, and both
 * failures are expensive:
 *
 *   - Miss a credential path and LeastGrant quietly auto-approves reading your
 *     SSH key, because nothing told it that file was different.
 *   - Match too much and it cries wolf. Treating the whole of `~/.claude` as
 *     credentials — which the code used to do — meant reading an ordinary
 *     project note was reported as a credential access. A tool that does that
 *     gets uninstalled, and then it protects nothing at all.
 *
 * The redactor has the same shape. It has to strip a token out of a command
 * line, and it has to leave the rest of the command line readable, because a
 * ledger full of `«redacted»` where the file paths should be is a ledger nobody
 * reads. So the negatives below are asserted just as hard as the positives —
 * every rule that fires on a credential is paired with the ordinary lookalike
 * it must keep its hands off.
 *
 * Determinism: nothing in secrets.ts reads the clock, the network, or file
 * contents, so there is no `at` to pass and nothing to stub. It does read
 * `os.homedir()` once at import, which the `~/.ssh`-style rules are anchored
 * to. Rather than build strings from whatever home directory this machine
 * happens to have, the setup below points `$HOME`/`%USERPROFILE%` at a
 * throwaway directory *before* importing the module, so the home-anchored
 * rules are exercised against a home we own. Every path in this file is rooted
 * in that temp directory, and the temp directory is removed on the way out.
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** A real directory we own, so no assertion depends on this machine's files. */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'leastgrant-secrets-'));

/**
 * A fake home and a workspace that is deliberately *not* inside it. Keeping
 * them siblings is what lets "caught outside $HOME too" mean anything — on
 * Windows the real temp directory lives under the real profile, so a workspace
 * rooted at the real `os.tmpdir()` is inside `$HOME` and that test proved
 * nothing.
 */
const HOME_DIR = path.join(TMP, 'home');
const WORK_DIR = path.join(TMP, 'work');
fs.mkdirSync(HOME_DIR, { recursive: true });
fs.mkdirSync(WORK_DIR, { recursive: true });

const PREV_HOME = process.env['HOME'];
const PREV_USERPROFILE = process.env['USERPROFILE'];
process.env['HOME'] = HOME_DIR;
process.env['USERPROFILE'] = HOME_DIR;

// Imported *after* the environment is pointed at the fake home, because
// secrets.ts resolves os.homedir() once at module load.
const {
  classifySecretPath,
  containsSecretLike,
  credentialTreeRoot,
  globMatch,
  nameRules,
  redact,
  shannon,
} = await import('../src/core/secrets.js');

after(() => {
  if (PREV_HOME === undefined) delete process.env['HOME'];
  else process.env['HOME'] = PREV_HOME;
  if (PREV_USERPROFILE === undefined) delete process.env['USERPROFILE'];
  else process.env['USERPROFILE'] = PREV_USERPROFILE;
  fs.rmSync(TMP, { recursive: true, force: true });
});

/** Sanity: if the override silently failed, every home-anchored case below is a lie. */
assert.equal(
  os.homedir().split('\\').join('/'),
  HOME_DIR.split('\\').join('/'),
  'the fake home did not take effect — home-anchored tests would be testing the real machine',
);

const slash = (p: string) => p.split('\\').join('/');

/** A path inside the throwaway workspace, in the forward-slash form the code normalises to. */
const ws = (...parts: string[]) => [slash(WORK_DIR), ...parts].join('/');

/** A path under the throwaway home directory. */
const home = (...parts: string[]) => [slash(HOME_DIR), ...parts].join('/');

/** The marker `redact` leaves behind. Kept in sync with secrets.ts by eye. */
const mark = (label: string) => `«redacted:${label}»`;

// ---------------------------------------------------------------------------
// classifySecretPath — the things that must be caught
// ---------------------------------------------------------------------------

describe('classifySecretPath catches credential files', () => {
  const SECRET: { name: string; abs: string; tag: string }[] = [
    // environment files
    { name: '.env', abs: ws('.env'), tag: 'dotenv' },
    { name: '.env.local', abs: ws('.env.local'), tag: 'dotenv' },
    { name: '.env.production', abs: ws('.env.production'), tag: 'dotenv' },
    { name: 'a nested .env', abs: ws('services', 'api', '.env'), tag: 'dotenv' },

    // ssh
    { name: 'id_rsa', abs: ws('id_rsa'), tag: 'ssh' },
    { name: 'id_ed25519', abs: ws('id_ed25519'), tag: 'ssh' },
    { name: 'id_rsa in ~/.ssh', abs: home('.ssh', 'id_rsa'), tag: 'ssh' },
    { name: 'anything in ~/.ssh', abs: home('.ssh', 'config'), tag: 'ssh' },
    { name: '~/.ssh itself', abs: home('.ssh'), tag: 'ssh' },

    // cloud and cluster credential directories
    // NOTE on the tag: the filename rules run before the directory rules, so
    // `credentials` is tagged for its *name* rather than for living under
    // `.aws`. Pinned rather than waved through, so a reshuffle of the rule
    // order shows up here instead of surprising a downstream rule.
    { name: '~/.aws/credentials', abs: home('.aws', 'credentials'), tag: 'generic' },
    { name: '~/.aws/config', abs: home('.aws', 'config'), tag: 'aws' },
    { name: '~/.gnupg', abs: home('.gnupg', 'pubring.kbx'), tag: 'gpg' },
    { name: '~/.kube/config', abs: home('.kube', 'config'), tag: 'kube' },
    { name: '~/.config/gcloud', abs: home('.config', 'gcloud', 'credentials.db'), tag: 'gcloud' },

    // package and network credentials
    { name: '.npmrc', abs: ws('.npmrc'), tag: 'npm' },
    { name: '.pypirc', abs: ws('.pypirc'), tag: 'pypi' },
    { name: '.netrc', abs: ws('.netrc'), tag: 'netrc' },
    { name: '.git-credentials', abs: ws('.git-credentials'), tag: 'git' },

    // infrastructure
    { name: 'terraform.tfstate', abs: ws('infra', 'terraform.tfstate'), tag: 'terraform' },
    { name: 'service-account.json', abs: ws('service-account.json'), tag: 'gcp' },
    { name: 'service_account_key.json', abs: ws('service_account_key.json'), tag: 'gcp' },

    // key material by extension
    { name: '*.pem', abs: ws('certs', 'server.pem'), tag: 'key' },
    { name: '*.key', abs: ws('certs', 'server.key'), tag: 'key' },
    { name: '*.p12', abs: ws('certs', 'client.p12'), tag: 'key' },
    { name: '*.pfx', abs: ws('certs', 'client.pfx'), tag: 'key' },

    // shell history: where pasted secrets go to live forever
    { name: '.bash_history', abs: home('.bash_history'), tag: 'history' },
    { name: '.zsh_history', abs: home('.zsh_history'), tag: 'history' },
    { name: '.psql_history', abs: home('.psql_history'), tag: 'history' },

    // agent settings hold API keys in their env blocks
    { name: '~/.claude/settings.json', abs: home('.claude', 'settings.json'), tag: 'agent' },
    { name: '~/.claude/settings.local.json', abs: home('.claude', 'settings.local.json'), tag: 'agent' },
    { name: '~/.codex/config.toml', abs: home('.codex', 'config.toml'), tag: 'agent' },
  ];

  for (const c of SECRET) {
    test(`${c.name} is a credential path`, () => {
      const r = classifySecretPath(c.abs);
      assert.equal(r.secret, true, `missed a credential path: ${c.abs}`);
      assert.ok(r.why.length > 0, 'a secret match must explain itself in plain English');
      assert.equal(r.tag, c.tag);
    });
  }

  test('a vendored credential directory is caught outside $HOME too', () => {
    // Containers and monorepos mount these in odd places. WORK_DIR is a
    // sibling of the fake home, so these really are outside it.
    assert.ok(!ws().startsWith(home()), 'the workspace must not be inside the fake home');
    assert.equal(classifySecretPath(ws('vendor', '.aws', 'credentials')).secret, true);
    assert.equal(classifySecretPath(ws('fixtures', '.ssh', 'id_rsa')).secret, true);
  });

  test('backslash paths are normalised before matching', () => {
    assert.equal(classifySecretPath('C:\\work\\proj\\.env').secret, true);
    assert.equal(classifySecretPath('C:\\Users\\dev\\.ssh\\id_rsa').secret, true);
  });
});

// ---------------------------------------------------------------------------
// classifySecretPath — the things that must NOT be caught
// ---------------------------------------------------------------------------

describe('classifySecretPath leaves ordinary files alone', () => {
  const ORDINARY: { name: string; abs: string; why: string }[] = [
    { name: 'src/index.ts', abs: ws('src', 'index.ts'), why: 'source code' },
    { name: 'package.json', abs: ws('package.json'), why: 'a manifest' },
    { name: 'README.md', abs: ws('README.md'), why: 'documentation' },
    { name: 'src/core/keys.ts', abs: ws('src', 'core', 'keys.ts'), why: 'named for keys, is a module' },
    {
      name: 'src/core/secrets.ts',
      abs: ws('src', 'core', 'secrets.ts'),
      why: 'the module under test is named for secrets and is still just code',
    },
    {
      name: 'public/key.png',
      abs: ws('public', 'key.png'),
      why: 'a picture of a key is not a key — the extension rule, not the stem, decides',
    },
    { name: 'credentials.md', abs: ws('docs', 'credentials.md'), why: 'prose about credentials' },
    {
      name: '.vscode/settings.json',
      abs: ws('.vscode', 'settings.json'),
      why: '.vscode is not an agent directory — this is the over-matching regression',
    },
    {
      name: '.claudette/settings.json',
      abs: ws('.claudette', 'settings.json'),
      why: 'an agent-directory prefix match must not spill into a longer name',
    },
    {
      name: '.aws-sam/template.yaml',
      abs: ws('.aws-sam', 'template.yaml'),
      why: 'a credential-directory prefix match must not spill into a longer name',
    },
    { name: '.awsconfig', abs: ws('.awsconfig'), why: 'the same, as a file' },
    {
      name: '~/.claude/projects/**/transcript.jsonl',
      abs: home('.claude', 'projects', 'foo', 'transcript.jsonl'),
      why: 'a transcript, not a credential',
    },
    {
      name: '~/.claude/plugins/x/SKILL.md',
      abs: home('.claude', 'plugins', 'x', 'SKILL.md'),
      why: 'plugin content, read constantly',
    },
    { name: '~/.claude/CLAUDE.md', abs: home('.claude', 'CLAUDE.md'), why: 'your own notes' },
    { name: '~/.cursor/rules/style.md', abs: home('.cursor', 'rules', 'style.md'), why: 'the same for cursor' },
    {
      name: '.env.example',
      abs: ws('.env.example'),
      why: 'a committed template — placeholders, not secrets',
    },
    { name: '.env.sample', abs: ws('.env.sample'), why: 'the same template under another name' },
    { name: '.env.template', abs: ws('config', '.env.template'), why: 'and another' },
    { name: 'the empty string', abs: '', why: 'nothing to classify' },
  ];

  for (const c of ORDINARY) {
    test(`${c.name} is not a credential path (${c.why})`, () => {
      const r = classifySecretPath(c.abs);
      assert.equal(r.secret, false, `false positive on ${c.abs}: ${r.why}`);
      assert.equal(r.why, '');
      assert.equal(r.tag, '');
    });
  }

  test('the .vscode exemption is not a blanket exemption for settings.json', () => {
    // The point of the regression fix was precision, not silence: the agent
    // directories still match.
    assert.equal(classifySecretPath(ws('.vscode', 'settings.json')).secret, false);
    assert.equal(classifySecretPath(ws('.claude', 'settings.json')).secret, true);
    assert.equal(classifySecretPath(ws('.cursor', 'mcp.json')).secret, true);
  });

  test('an agent directory only surrenders its credential-bearing files', () => {
    // The counterpart to the .vscode case: inside a directory that *is* an
    // agent directory, ordinary content still has to come back clean.
    assert.equal(classifySecretPath(home('.claude', 'settings.json')).secret, true);
    assert.equal(classifySecretPath(home('.claude', 'README.md')).secret, false);
    assert.equal(classifySecretPath(home('.claude', 'commands', 'review.md')).secret, false);
  });

  test('a template suffix does not exempt a file inside a credential directory', () => {
    // `.env.example` is safe because of where it is, not just what it is called.
    assert.equal(classifySecretPath(home('.ssh', 'id_rsa.example')).secret, true);
    assert.equal(classifySecretPath(home('.aws', 'credentials.sample')).secret, true);
  });
});

// ---------------------------------------------------------------------------
// classifySecretPath — spelling, and the one rule that forgot to fold case
// ---------------------------------------------------------------------------

describe('name rules do not depend on how the caller typed the file', () => {
  // The audit found `/^SAM$|^SECURITY$/` — the Windows registry hives — was the
  // only entry in SECRET_FILES without the `i` flag, so `…/config/sam` read as
  // an ordinary file outside the project while `…/config/SAM` was floored.
  //
  // This asserts the property rather than the instance. A test that spells out
  // `sam` and `SAM` proves nothing about the next entry somebody adds; this one
  // fails the moment a case-sensitive name rule appears in the file at all.
  test('every name and extension rule carries the i flag', () => {
    const bare = nameRules().filter((rx) => !rx.flags.includes('i'));
    assert.deepEqual(
      bare.map((rx) => String(rx)),
      [],
      'a basename rule that does not fold case is a rule the lower-case spelling walks past',
    );
  });

  test('the registry hives are credentials in either spelling', () => {
    for (const dir of ['C:/Windows/System32/config', 'c:/windows/system32/config', 'D:/Windows/Sysnative/config']) {
      for (const name of ['SAM', 'sam', 'SECURITY', 'security', 'SYSTEM', 'system', 'SOFTWARE']) {
        const r = classifySecretPath(`${dir}/${name}`);
        assert.equal(r.secret, true, `${dir}/${name} did not read as a credential hive`);
        assert.equal(r.tag, 'system');
      }
    }
  });

  test('a hive dumped somewhere else is still a hive', () => {
    // The live files are kernel-locked, so the copy is what actually gets
    // exfiltrated: `reg save HKLM\\SAM sam`, a VSS snapshot, a backup.
    for (const p of [ws('loot', 'sam'), ws('loot', 'SAM'), ws('ntds.dit'), ws('security.sav'), ws('system.hiv')]) {
      assert.equal(classifySecretPath(p).secret, true, `${p} did not read as a credential hive`);
    }
  });

  test('but an ordinary directory named after an English word is not a hive', () => {
    // The reason `SECURITY`, `SYSTEM` and `SOFTWARE` are scoped to the registry
    // directory instead of matched by basename anywhere. Flagging `linux/
    // security/` would put an unlearnable prompt on every recursive read of a
    // kernel tree, which is the crying-wolf failure this module exists to
    // avoid.
    for (const p of [ws('security'), ws('src', 'security'), ws('system'), ws('src', 'system'),
      ws('software'), ws('config', 'default'), ws('SECURITY.md')]) {
      assert.equal(classifySecretPath(p).secret, false, `${p} was wrongly read as a credential`);
    }
  });
});

// ---------------------------------------------------------------------------
// credentialTreeRoot — what a recursive read would sweep up
// ---------------------------------------------------------------------------

describe('credentialTreeRoot names the directories a recursive read must not sweep', () => {
  test('a directory above a credential store is one', () => {
    for (const p of [slash(HOME_DIR), slash(path.dirname(HOME_DIR)), '/', '/home', '/home/bob',
      '/Users', '/Users/alice', '/etc', '/private/etc', '/root', 'C:/', 'C:/Users',
      // Not only the obvious ones: `~/.config` is above `~/.config/gcloud`,
      // `~/.config/gh` and the 1Password CLI's state.
      home('.config'), home('.local'), home('.local', 'share')]) {
      assert.equal(credentialTreeRoot(p).secret, true, `${p} should be a credential tree root`);
    }
  });

  test('an ordinary directory, however far outside the project, is not', () => {
    // The control. Answering true everywhere would satisfy the assertion above
    // and turn every recursive search on the machine into an unlearnable ask.
    for (const p of [home('Documents'), home('code'), home('.cache'), home('.config', 'nvim'),
      ws(), ws('src'),
      '/etc/nginx', '/root/scratch', '/home/bob/code', '/usr', '/usr/share', '/var/log',
      '/tmp', '/opt/app', 'C:/Program Files']) {
      assert.equal(credentialTreeRoot(p).secret, false, `${p} should not be a credential tree root`);
    }
  });

  test('the home directory itself is a tree root, its children are not', () => {
    // The exact asymmetry the audit turned into an ALLOW: `~` and `~/Documents`
    // were the same thing to the engine, so approvals of the second paid for
    // the first.
    assert.equal(credentialTreeRoot(home()).secret, true);
    assert.equal(credentialTreeRoot(home('Documents')).secret, false);
  });
});

// ---------------------------------------------------------------------------
// classifySecretPath — user-supplied patterns
// ---------------------------------------------------------------------------

describe('classifySecretPath honours patterns you add yourself', () => {
  test('a ** pattern marks a whole subtree', () => {
    const r = classifySecretPath(ws('vault', 'prod.txt'), ['**/vault/**']);
    assert.equal(r.secret, true);
    assert.equal(r.tag, 'custom');
    // The wording is the UI's business, not this suite's; that it explains
    // itself at all is the contract.
    assert.ok(r.why.length > 0, 'a custom match must still explain itself');
  });

  test('a pattern that does not match changes nothing', () => {
    assert.equal(classifySecretPath(ws('notes.md'), ['**/vault/**']).secret, false);
  });

  test('a single * does not cross a directory boundary', () => {
    assert.equal(globMatch('/a/*/c', '/a/b/c'), true);
    assert.equal(globMatch('/a/*/c', '/a/b/x/c'), false);
    assert.equal(globMatch('/a/**/c', '/a/b/x/c'), true);
  });

  test('? matches exactly one non-separator character', () => {
    assert.equal(globMatch('/a/?.ts', '/a/b.ts'), true);
    assert.equal(globMatch('/a/?.ts', '/a/bc.ts'), false);
    assert.equal(globMatch('/a?c', '/a/c'), false);
  });

  test('regex metacharacters in a pattern are literal, not syntax', () => {
    // This is the negative half of the glob contract: a user writing a
    // character class gets a literal one, and a pattern that would be an
    // invalid regex comes back false instead of throwing.
    assert.equal(globMatch('[abc]', 'a'), false);
    assert.equal(globMatch('[abc]', '[abc]'), true);
    assert.equal(globMatch('a.c', 'abc'), false);
    assert.equal(globMatch('[unclosed', 'anything'), false);
    assert.doesNotThrow(() => classifySecretPath(ws('notes.md'), ['[unclosed', 'a(b', '+++']));
    assert.equal(classifySecretPath(ws('notes.md'), ['[unclosed']).secret, false);
  });
});

// ---------------------------------------------------------------------------
// redact — what must be removed
// ---------------------------------------------------------------------------

/**
 * Assert the secret is gone, the marker is there, and running redaction again
 * changes nothing. Idempotence is checked on every positive rather than once,
 * because the way it breaks is one rule chewing on another rule's marker.
 */
function assertRedacted(input: string, secret: string, label?: string) {
  const out = redact(input);
  assert.ok(!out.includes(secret), `the secret survived redaction:\n  in:  ${input}\n  out: ${out}`);
  assert.notEqual(out, input);
  assert.equal(containsSecretLike(input), true, 'containsSecretLike disagreed with redact');
  if (label) {
    assert.ok(out.includes(mark(label)), `expected ${mark(label)}, got:\n  ${out}`);
  }
  assert.equal(redact(out), out, `redaction is not idempotent:\n  once:  ${out}\n  twice: ${redact(out)}`);
}

const AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const GHP = 'ghp_0123456789abcdefABCDEFghijkl';
const GH_PAT = 'github_pat_11ABCDEFG0abcdefghijklm_ABCDEFGHIJKLMNOPqrstuvwxyz1234567890AB';
const SK_ANT = 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
const SK = 'sk-AbCdEfGhIjKlMnOpQrStUvWx1234';
// Deliberately not shaped like a real Slack token. The previous fixture used
// plausible numeric team and user ids, which is precisely what GitHub's secret
// scanner looks for — it blocked the push of this repository. A fixture for a
// redaction test only has to match *our* pattern (`xox[baprs]-` followed by ten
// or more word characters), so it may as well say what it is.
const XOXB = 'xoxb-EXAMPLE-NOT-A-REAL-SLACK-TOKEN';
const AIZA = 'AIzaSyD1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P';
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const PEM = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEowIBAAKCAQEAx7Bn3kQpVvL2mJ4tR8sD1fG6hK9nP0qW3eY5uI7oA2bC4dE6',
  'fG8hJ0kL2mN4pQ6rS8tU0vW2xY4zA6bC8dE0fG2hJ4kL6mN8pQ0rS2tU4vW6xY8z',
  '-----END RSA PRIVATE KEY-----',
].join('\n');
const HIGH_ENTROPY = 'aB3xQ9zL2mN7pR4tV6wY8kJ1hG5d';

describe('redact removes credentials', () => {
  test('an AWS access key id', () => {
    assertRedacted(`aws configure set aws_access_key_id ${AWS_KEY_ID}`, AWS_KEY_ID, 'aws-key-id');
  });

  test('a temporary AWS key id', () => {
    const asia = 'ASIAY34FZKBOKMUTVV7A';
    assertRedacted(`echo ${asia}`, asia, 'aws-key-id');
  });

  test('a GitHub classic token', () => {
    assertRedacted(`export GITHUB=${GHP}`, GHP, 'github-token');
  });

  test('a GitHub fine-grained token', () => {
    assertRedacted(`curl -H "X-Auth: ${GH_PAT}"`, GH_PAT, 'github-token');
  });

  test('a GitHub token hidden in a clone URL', () => {
    // The token and the URL-password rules both want this line. The output has
    // to be one clean marker, not a marker nested inside a marker.
    const line = `git remote add origin https://${GHP}@github.com/acme/app.git`;
    assertRedacted(line, GHP, 'github-token');
    assert.ok(redact(line).includes('@github.com/acme/app.git'), 'the rest of the URL should still be readable');
  });

  test('an Anthropic key', () => {
    assertRedacted(`echo ${SK_ANT}`, SK_ANT, 'anthropic-key');
  });

  test('a generic sk- key', () => {
    assertRedacted(`curl -H "X-Key: ${SK}"`, SK, 'api-key');
  });

  test('a Slack token', () => {
    assertRedacted(`curl -d token=${XOXB} https://slack.com/api/x`, XOXB, 'slack-token');
  });

  test('a Google API key', () => {
    assertRedacted(`curl "https://maps.googleapis.com/maps/api/js?key=${AIZA}"`, AIZA, 'google-key');
  });

  test('a JWT', () => {
    assertRedacted(`curl -H "Cookie: session=${JWT}"`, JWT, 'jwt');
  });

  test('a PEM private key block', () => {
    const out = redact(`cat <<EOF > k.pem\n${PEM}\nEOF`);
    assert.ok(!out.includes('MIIEowIBAAKCAQEA'), 'the key body survived');
    assert.ok(out.includes(mark('private-key')));
    assert.equal(out, `cat <<EOF > k.pem\n${mark('private-key')}\nEOF`, 'the surrounding heredoc should be intact');
    assert.equal(redact(out), out);
  });

  test('a password inside a URL', () => {
    assertRedacted('git clone https://alice:hunter2@github.com/acme/app.git', 'hunter2', 'url-password');
  });

  test('a URL password containing an @', () => {
    // Stopping at the first @ leaves the tail of the password in the ledger.
    assertRedacted('psql "postgres://app:s3cr3tP@ss@db.internal:5432/app"', 's3cr3tP@ss', 'url-password');
    assert.ok(redact('psql "postgres://app:s3cr3tP@ss@db.internal:5432/app"').includes('@db.internal:5432/app'));
  });

  test('an Authorization: Bearer header', () => {
    assertRedacted('curl -H "Authorization: Bearer abc123def456ghi789" https://api.example.com', 'abc123def456ghi789');
  });

  test('an Authorization: Basic header', () => {
    assertRedacted('curl -H "Authorization: Basic dXNlcjpwYXNzd29yZA==" https://x', 'dXNlcjpwYXNzd29yZA==', 'auth-header');
  });

  test('--password=hunter2', () => {
    assertRedacted('mysqldump --password=hunter2 app > dump.sql', 'hunter2', 'flag-value');
  });

  test('--token X', () => {
    const out = redact('gh auth login --token X');
    assert.equal(out, `gh auth login --token ${mark('flag-value')}`);
    assert.equal(redact(out), out);
  });

  test('a quoted flag value', () => {
    assertRedacted('deploy --secret "correct horse battery staple"', 'correct horse battery staple', 'flag-value');
  });

  test('mysql -pSECRET with no space', () => {
    assertRedacted('mysql -h db -u root -phunter2sekrit app', 'hunter2sekrit', 'mysql-password');
    // The rest of the invocation has to survive, or the ledger entry stops
    // telling you which database was dumped.
    assert.equal(
      redact('mysql -h db -u root -phunter2sekrit app'),
      `mysql -h db -u root -p${mark('mysql-password')} app`,
    );
  });

  test('the -p form is recognised for the rest of the mysql family', () => {
    assertRedacted('mysqldump -u root -psecretpw app > dump.sql', 'secretpw', 'mysql-password');
    assertRedacted('mariadb -u root -psecretpw app', 'secretpw', 'mysql-password');
    assertRedacted('mysqladmin -u root -psecretpw flush-hosts', 'secretpw', 'mysql-password');
  });

  test('DATABASE_PASSWORD=x', () => {
    const out = redact('DATABASE_PASSWORD=x npm run migrate');
    assert.equal(out, `DATABASE_PASSWORD=${mark('env-secret')} npm run migrate`);
    assert.equal(redact(out), out);
  });

  test('other credential-shaped variable names', () => {
    for (const name of ['MY_TOKEN', 'STRIPE_SECRET', 'AWS_ACCESS_KEY', 'GCP_CREDENTIALS', 'X_API_KEY', 'BASIC_AUTH']) {
      const out = redact(`${name}=zzz9zzz`);
      assert.equal(out, `${name}=${mark('env-secret')}`, `${name} should have been redacted`);
    }
  });

  test('a long high-entropy mixed-case token with no vendor prefix', () => {
    assertRedacted(`echo ${HIGH_ENTROPY}`, HIGH_ENTROPY, 'high-entropy');
  });

  test('an AWS secret access key, which contains slashes', () => {
    // The slash-containing case matters: it is what the path exemption below
    // has to be careful not to swallow.
    assertRedacted(`aws configure set aws_secret_access_key ${AWS_SECRET}`, AWS_SECRET, 'high-entropy');
  });

  test('several secrets on one line are all removed', () => {
    const line = `env ${AWS_KEY_ID} ${GHP} ${SK_ANT} deploy`;
    const out = redact(line);
    for (const s of [AWS_KEY_ID, GHP, SK_ANT]) assert.ok(!out.includes(s), `${s} survived`);
    assert.equal(redact(out), out);
  });
});

// ---------------------------------------------------------------------------
// redact — what must survive intact
// ---------------------------------------------------------------------------

function assertUntouched(input: string, why: string) {
  const out = redact(input);
  assert.equal(out, input, `redaction damaged ${why}:\n  in:  ${input}\n  out: ${out}`);
  assert.equal(containsSecretLike(input), false, `containsSecretLike disagreed with redact on ${why}`);
}

describe('redact leaves ordinary text alone', () => {
  const SAFE: { name: string; text: string }[] = [
    { name: 'a git SHA', text: 'git checkout 9c1f2a4b8d3e5f60718293a4b5c6d7e8f9012345' },
    { name: 'a short git SHA', text: 'reverting a1b2c3d' },
    { name: 'a UUID', text: 'session 3f2504e0-4f89-11d3-9a0c-0305e82c3301 started' },
    {
      name: 'a sha256 digest',
      text: 'digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    {
      name: 'an npm integrity hash',
      text: '"integrity": "sha512-Vg1G6t0oiFbEZFPWWzuXKGP2K5H0kfN2SB5uxTqx4tvKuTNSmDXtLQZ8dCkDnQOF3n0hqTvMzQ=="',
    },
    {
      name: 'an md5 integrity hash',
      text: '"integrity": "md5-0123456789abcdef0123456789abcdefABCD01"',
    },
    { name: 'a plain sentence', text: 'The user does not want to proceed with this tool use.' },
    { name: 'a long ordinary word', text: 'antidisestablishmentarianism is a long word' },
    { name: 'a short file path', text: 'cat src/core/secrets.ts' },
    { name: 'a Windows file path', text: 'node D:/LeastGrant/dist/src/adapters/claude-code/hook.js' },
    {
      name: 'a long mixed-case file path',
      text: 'cat /home/alice/projects/MyApp2/src/components/Button.tsx',
    },
    {
      name: 'a monorepo path with digits',
      text: 'node packages/web3-utils/lib/commonjs/Web3Utils.js',
    },
    {
      name: 'a deep Java package path',
      text: 'javac app/src/main/java/com/example/MyApp2/MainActivity.java',
    },
    { name: 'a versioned bin path', text: '/opt/homebrew/Cellar/node/22.11.0/bin/node --version' },
    { name: 'a version number', text: 'installed typescript@5.6.3 alongside node v20.10.0' },
    { name: 'an all-lowercase hex blob', text: 'blob 0123456789abcdef0123456789abcdef01234567' },
    { name: 'mkdir -p', text: 'mkdir -p dist/src/core' },
    { name: 'docker port mapping', text: 'docker run -p 8080:8080 -it alpine sh' },
    { name: 'ssh on a nonstandard port', text: 'ssh -p 2222 deploy@host' },
    { name: 'grep for the word password', text: 'grep -rn "password" src/' },
    { name: 'an npm install line', text: 'npm install --save-dev typescript@^5.6.0' },
    { name: 'a git log format string', text: 'git log --pretty=format:%H --since=2024-01-01' },
    { name: 'a plain https URL', text: 'curl https://api.example.com/v1/models' },
    { name: 'an ssh remote', text: 'git remote add origin git@github.com:acme/app.git' },
    { name: 'a docker image digest', text: 'docker pull alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b' },

    // ---- `-p` lookalikes -------------------------------------------------
    // `-pSECRET` is a mysql idiom and nothing else. Every other program on the
    // box uses `-p` for something ordinary, and the space-separated forms above
    // never proved that, because the rule only fires when the value is jammed
    // up against the flag. These are the forms that actually collide.
    { name: 'docker publishing a port, no space', text: 'docker run -p8080:80 -v /data:/data nginx' },
    { name: 'docker publishing a bound port', text: 'docker run -p127.0.0.1:8080:8080 alpine' },
    { name: 'ssh on a nonstandard port, no space', text: 'ssh -p2222 deploy@host' },
    { name: 'gcc -pthread', text: 'gcc -pthread -O2 main.c -o main' },
    { name: 'rsync -progress', text: 'rsync -progress src/ dst/' },
    { name: 'tar preserving permissions', text: 'tar -pxzvf archive.tar.gz' },
    { name: 'find with -prune and -print', text: 'find . -path ./node_modules -prune -o -name "*.ts" -print' },
    { name: 'curl -position-ish long flag', text: 'curl -parallel https://api.example.com' },

    // ---- vendor-prefix lookalikes ---------------------------------------
    { name: 'the letters AKIA in prose', text: 'grep -rn "AKIA" src/ # find hardcoded keys' },
    { name: 'an AWS region, not an ASIA key', text: 'aws --region ap-southeast-1 s3 ls' },
    { name: 'a URL with no credentials', text: 'psql postgres://app@db.internal:5432/app' },
    { name: 'an ssh:// remote with a user', text: 'git remote add o ssh://git@github.com/acme/app.git' },
  ];

  for (const c of SAFE) {
    test(c.name, () => assertUntouched(c.text, c.name));
  }

  test('the empty string is returned unchanged', () => {
    assert.equal(redact(''), '');
    assert.equal(containsSecretLike(''), false);
  });
});

// ---------------------------------------------------------------------------
// redact — the properties, not the cases
// ---------------------------------------------------------------------------

describe('redact holds up as a whole', () => {
  test('redacting twice changes nothing further', () => {
    const kitchenSink = [
      `aws_access_key_id = ${AWS_KEY_ID}`,
      `github: ${GHP}`,
      `anthropic: ${SK_ANT}`,
      `slack: ${XOXB}`,
      `google: ${AIZA}`,
      `jwt: ${JWT}`,
      `db: postgres://app:hunter2@db.internal:5432/app`,
      `curl -H "Authorization: Bearer abc123def456ghi789"`,
      `mysqldump --password=hunter2 app`,
      `mysql -u root -phunter2 app`,
      `DATABASE_PASSWORD=hunter2`,
      `blob ${HIGH_ENTROPY}`,
      PEM,
    ].join('\n');

    const once = redact(kitchenSink);
    assert.ok(!once.includes('hunter2'), `a password survived the kitchen sink:\n${once}`);
    const twice = redact(once);
    assert.equal(twice, once, 'a second pass must be a no-op');
    const thrice = redact(twice);
    assert.equal(thrice, twice);
  });

  test('containsSecretLike agrees with redact in both directions', () => {
    const corpus = [
      '',
      'git status',
      'npm test',
      'cat src/core/secrets.ts',
      'docker run -p8080:80 nginx',
      `echo ${AWS_KEY_ID}`,
      `echo ${GHP}`,
      'ssh -i ~/.ssh/id_rsa deploy@host',
      'The user does not want to proceed with this tool use.',
      'DATABASE_PASSWORD=hunter2',
      'mysql -u root -phunter2 app',
    ];
    for (const s of corpus) {
      assert.equal(containsSecretLike(s), redact(s) !== s, `disagreement on ${JSON.stringify(s)}`);
    }
  });

  test('a 100 KB input neither throws nor hangs', () => {
    const body = 'git commit -m "wip" && echo ok && ls -la src/core\n'.repeat(2100);
    const big = `${body}\nAWS ${AWS_KEY_ID}\n${body}`;
    assert.ok(big.length > 100_000, `wanted >100 KB, built ${big.length}`);
    const out = redact(big);
    assert.ok(out.includes(mark('aws-key-id')), 'the needle in the haystack should still be found');
    assert.ok(!out.includes(AWS_KEY_ID));
    assert.equal(redact(out), out);
  });

  test('a long run of nothing but separators is handled', () => {
    const junk = '-'.repeat(50_000);
    assert.equal(redact(junk), junk);
  });

  test('an unterminated PEM header does not eat the rest of the file', () => {
    // Asserting only that the BEGIN line survives would pass even if every
    // byte after it were swallowed, which is the exact failure mode. Assert on
    // the whole string instead.
    const text = `-----BEGIN RSA PRIVATE KEY-----\n${'abc\n'.repeat(5000)}`;
    assert.equal(redact(text), text, 'there is nothing to redact without an END marker');
    assert.equal(containsSecretLike(text), false);
  });
});

// ---------------------------------------------------------------------------
// shannon
// ---------------------------------------------------------------------------

describe('shannon', () => {
  test('a single repeated character carries no information', () => {
    assert.equal(shannon('aaaaaaaa'), 0);
  });

  test('two equally frequent characters carry one bit each', () => {
    assert.equal(shannon('abab'), 1);
  });

  test('all-distinct characters hit the log2(n) ceiling', () => {
    assert.ok(Math.abs(shannon('abcd') - 2) < 1e-12);
    assert.ok(Math.abs(shannon(HIGH_ENTROPY) - Math.log2(HIGH_ENTROPY.length)) < 1e-12);
  });

  test('a random-looking token scores above an English phrase', () => {
    assert.ok(shannon(HIGH_ENTROPY) > shannon('the quick brown fox'));
  });

  test('an English phrase sits below the redaction threshold', () => {
    // 3.6 bits is the cutoff redactHighEntropy uses; if prose drifted above it
    // the ledger would start eating sentences.
    assert.ok(shannon('antidisestablishmentarianism') < 3.6);
    assert.ok(shannon('the user does not want to proceed') < 3.6);
  });
});
