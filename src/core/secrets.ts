/**
 * Two related jobs:
 *
 *   1. Recognising files that hold credentials, so reading them is never
 *      quietly auto-approved.
 *   2. Redacting anything that looks like a credential *before* it reaches
 *      LeastGrant's own ledger.
 *
 * The second job matters more than it looks. A tool that records every command
 * your agent runs, in order to protect your secrets, has just built an
 * excellent place to accidentally store your secrets. The ledger is plain text
 * on disk. Everything written to it goes through {@link redact} first.
 */

import * as path from 'node:path';
import * as os from 'node:os';

export interface SecretMatch {
  secret: boolean;
  /** Plain-English reason, e.g. `SSH private keys live here`. */
  why: string;
  /** Machine tag for tests and rules. */
  tag: string;
}

const NOT_SECRET: SecretMatch = { secret: false, why: '', tag: '' };

/**
 * Directories whose contents are credentials almost by definition.
 * Matched against the canonical path, so symlinks into them are caught too.
 */
const SECRET_DIRS: { rel: string; why: string; tag: string }[] = [
  { rel: '.config/op', why: '1Password CLI state lives here', tag: '1password' },
  { rel: '.local/share/keyrings', why: 'the desktop keyring lives here', tag: 'keyring' },
  { rel: '.ansible', why: 'Ansible vault passwords live here', tag: 'ansible' },
  { rel: '.m2', why: 'Maven repository credentials live here', tag: 'maven' },
  { rel: '.mozilla', why: 'browser passwords and cookies live here', tag: 'browser' },
  { rel: '.ssh', why: 'SSH private keys live here', tag: 'ssh' },
  { rel: '.aws', why: 'AWS credentials live here', tag: 'aws' },
  { rel: '.gnupg', why: 'GPG private keys live here', tag: 'gpg' },
  { rel: '.config/gcloud', why: 'Google Cloud credentials live here', tag: 'gcloud' },
  { rel: '.kube', why: 'Kubernetes cluster credentials live here', tag: 'kube' },
  { rel: '.docker', why: 'Docker registry credentials live here', tag: 'docker' },
  { rel: '.azure', why: 'Azure credentials live here', tag: 'azure' },
  { rel: '.config/gh', why: 'GitHub CLI auth tokens live here', tag: 'gh' },
  { rel: '.config/hub', why: 'GitHub tokens live here', tag: 'gh' },
  { rel: '.password-store', why: 'this is a password store', tag: 'pass' },
  { rel: '.gem', why: 'RubyGems credentials live here', tag: 'gem' },
  { rel: '.cargo', why: 'crates.io tokens live here', tag: 'cargo' },
  { rel: '.terraform.d', why: 'Terraform Cloud tokens live here', tag: 'terraform' },
  // NOTE: agent config directories are deliberately NOT listed wholesale.
  // `~/.claude` also holds session transcripts, plugin code and skill files —
  // thousands of ordinary reads. Treating the whole tree as credentials made
  // LeastGrant flag reading its own notes as a secret access, which is the kind
  // of crying-wolf that gets a security tool uninstalled. The specific
  // credential-bearing files inside them are matched by SECRET_FILES below.
  { rel: 'AppData/Roaming/gcloud', why: 'Google Cloud credentials live here', tag: 'gcloud' },
  { rel: 'AppData/Local/Google/Chrome/User Data', why: 'browser cookies and saved logins live here', tag: 'browser' },
  { rel: 'AppData/Roaming/Mozilla/Firefox/Profiles', why: 'browser cookies and saved logins live here', tag: 'browser' },
  { rel: 'Library/Application Support/Google/Chrome', why: 'browser cookies and saved logins live here', tag: 'browser' },
  { rel: 'Library/Keychains', why: 'this is the macOS keychain', tag: 'keychain' },
  { rel: 'AppData/Roaming/Microsoft/Crypto', why: 'Windows DPAPI master keys live here', tag: 'dpapi' },
  { rel: 'AppData/Local/Microsoft/Credentials', why: 'Windows stored credentials live here', tag: 'wincred' },
];

/**
 * Force the `i` flag onto a name pattern.
 *
 * Every rule below is matched against a basename, and NTFS and APFS are
 * case-insensitive, so `sam` and `SAM` are the same file. One entry
 * (`/^SAM$|^SECURITY$/`, the Windows registry hives) was written without the
 * flag, and that single missing character was the whole difference between
 * "credential hive, floored" and "ordinary file outside the project,
 * learnable" — the lower-case spelling of a locked hive is exactly what
 * `reg save` writes.
 *
 * Adding `i` to that one entry would have fixed the instance. Folding the flag
 * on structurally fixes the class: it is no longer *possible* to add a
 * case-sensitive name rule to this file by forgetting a character.
 */
const ci = (rx: RegExp): RegExp => (rx.flags.includes('i') ? rx : new RegExp(rx.source, rx.flags + 'i'));

/** Exact filenames, matched anywhere. Case-insensitive, always — see {@link ci}. */
const SECRET_FILES: { name: RegExp; why: string; tag: string }[] = ([
  // Credential stores found by the audit. Each of these was an auto-approvable
  // read of somebody's password store.
  { name: /^\.vault-token$/i, why: 'this is a HashiCorp Vault token', tag: 'vault' },
  { name: /^\.claude\.json$/i, why: 'this holds agent configuration, including MCP server environments', tag: 'agent' },
  { name: /^settings\.xml$/i, why: 'Maven repository passwords live here', tag: 'maven' },
  { name: /^gradle\.properties$/i, why: 'Gradle signing and publishing credentials live here', tag: 'gradle' },
  { name: /^logins\.json$/i, why: 'these are saved browser passwords', tag: 'browser' },
  { name: /^key[0-9]?\.db$/i, why: 'this is the browser password key store', tag: 'browser' },
  { name: /^.*\.keyring$/i, why: 'this is a desktop keyring', tag: 'keyring' },
  { name: /^vault_pass(\.txt)?$/i, why: 'this is an Ansible vault password', tag: 'ansible' },
  { name: /^npmrc$/i, why: 'npm auth tokens live here', tag: 'npm' },
  { name: /^hosts\.yml$/i, why: 'GitHub CLI auth tokens live here', tag: 'gh' },
  // POSIX system credential stores. These were missing entirely, so
  // `dd if=/etc/shadow` read as an ordinary file.
  { name: /^shadow$/i, why: 'this holds system password hashes', tag: 'system' },
  { name: /^gshadow$/i, why: 'this holds group password hashes', tag: 'system' },
  { name: /^sudoers$/i, why: 'this decides who can act as root', tag: 'system' },
  { name: /^master\.passwd$/i, why: 'this holds system password hashes', tag: 'system' },
  // Windows credential hives, in the spellings that are not also ordinary
  // words. `SAM` is the account database and `NTDS.dit` is its domain
  // equivalent; neither is a plausible name for a source directory. A copy
  // saved out of the registry keeps the hive name and gains an extension.
  //
  // `SECURITY`, `SYSTEM` and `SOFTWARE` are hives too, and they deliberately
  // are NOT here: matched by basename anywhere and folded case-insensitive,
  // they would classify `linux/security/`, `src/system/` and every other
  // directory named after an English word as a credential store. Those are
  // recognised by {@link HIVE_DIR} instead, where they really are the hives.
  { name: /^sam$/i, why: 'this is a Windows registry credential hive', tag: 'system' },
  { name: /^ntds\.dit$/i, why: 'this is the Active Directory credential database', tag: 'system' },
  {
    name: /^(?:sam|security|system|software|default)\.(?:sav|bak|old|hiv|hive|save|dmp)$/i,
    why: 'this is a saved copy of a Windows registry credential hive',
    tag: 'system',
  },
  { name: /^\.env(\..*)?$/i, why: 'environment files usually hold secrets', tag: 'dotenv' },
  { name: /^\.npmrc$/i, why: 'npm auth tokens live here', tag: 'npm' },
  { name: /^\.yarnrc\.yml$/i, why: 'yarn auth tokens can live here', tag: 'yarn' },
  { name: /^\.pypirc$/i, why: 'PyPI credentials live here', tag: 'pypi' },
  { name: /^\.netrc$/i, why: 'this file holds login credentials', tag: 'netrc' },
  { name: /^_netrc$/i, why: 'this file holds login credentials', tag: 'netrc' },
  { name: /^\.git-credentials$/i, why: 'git remote passwords live here', tag: 'git' },
  { name: /^credentials(\.json)?$/i, why: 'this file is named for credentials', tag: 'generic' },
  { name: /^secrets?\.(json|ya?ml|toml|ini)$/i, why: 'this file is named for secrets', tag: 'generic' },
  { name: /^id_(rsa|dsa|ecdsa|ed25519|xmss)$/i, why: 'this is an SSH private key', tag: 'ssh' },
  { name: /^known_hosts$/i, why: 'this maps your SSH trust relationships', tag: 'ssh' },
  { name: /^service[-_]?account.*\.json$/i, why: 'this is a cloud service-account key', tag: 'gcp' },
  { name: /^kubeconfig$/i, why: 'Kubernetes cluster credentials', tag: 'kube' },
  { name: /^terraform\.tfstate(\.backup)?$/i, why: 'Terraform state often contains plaintext secrets', tag: 'terraform' },
  { name: /^\.terraformrc$/i, why: 'Terraform credentials live here', tag: 'terraform' },
  { name: /^\.pgpass$/i, why: 'PostgreSQL passwords live here', tag: 'postgres' },
  { name: /^\.my\.cnf$/i, why: 'MySQL passwords live here', tag: 'mysql' },
  { name: /^\.htpasswd$/i, why: 'this file holds password hashes', tag: 'htpasswd' },
  { name: /^\.dockercfg$/i, why: 'Docker registry credentials', tag: 'docker' },
  { name: /^\.boto$/i, why: 'cloud storage credentials live here', tag: 'gcp' },
  { name: /^\.s3cfg$/i, why: 'S3 credentials live here', tag: 'aws' },
  { name: /^\.rclone\.conf$/i, why: 'rclone stores remote credentials here', tag: 'rclone' },
  { name: /^Cookies$/i, why: 'browser cookies include session tokens', tag: 'browser' },
  { name: /^Login Data$/i, why: 'this holds saved browser passwords', tag: 'browser' },
  { name: /^auth\.json$/i, why: 'this file is named for authentication data', tag: 'generic' },
  { name: /^\.credentials\.json$/i, why: 'this holds your agent login token', tag: 'agent' },
  // Shell history is a well-known place for secrets to end up by accident.
  { name: /^\.(bash|zsh|psql|mysql|node_repl|python)_history$/i, why: 'shell history often contains pasted secrets', tag: 'history' },
  { name: /^\.dbeaver-data-sources\.xml$/i, why: 'database credentials live here', tag: 'db' },
] as { name: RegExp; why: string; tag: string }[]).map((f) => ({ ...f, name: ci(f.name) }));

/**
 * The registry's own directory, where the hive files really are the hives.
 *
 * Scoping the generic hive names to this directory is what lets `SECURITY`,
 * `SYSTEM` and `SOFTWARE` be recognised case-insensitively without turning
 * every repository's `security/` folder into a credential store.
 */
const HIVE_DIR = /\/(?:system32|sysnative|winnt\/system32)\/(?:config|repair)\//i;
const HIVE_NAME = /^(?:sam|security|system|software|default|components)(?:\.(?:sav|bak|old|log\d*))?$/i;

/**
 * Names that *look* credential-shaped but are deliberately committed templates.
 * `.env.example` is in almost every repo, is meant to be read, and holds
 * placeholder values — flagging it is the same crying-wolf failure as treating
 * the whole of `~/.claude` as credentials.
 *
 * This suppresses the name and extension rules only. A file called
 * `id_rsa.example` sitting inside `~/.ssh` is still caught by the directory
 * rules further down.
 */
const TEMPLATE_NAME = ci(/\.(example|sample|template|dist|defaults?|tpl)$/i);

/** Extensions that are private keys or credential bundles. Case-insensitive, always. */
const SECRET_EXTS: { ext: RegExp; why: string; tag: string }[] = ([
  { ext: /\.(pem|key|p12|pfx|jks|keystore|asc|gpg|ppk)$/i, why: 'this is a key or certificate file', tag: 'key' },
  { ext: /\.kdbx?$/i, why: 'this is a password database', tag: 'passwords' },
] as { ext: RegExp; why: string; tag: string }[]).map((e) => ({ ...e, ext: ci(e.ext) }));

const HOME = (() => {
  try {
    return os.homedir();
  } catch {
    return '';
  }
})();

const norm = (p: string) => p.replace(/\\/g, '/');
const lower = (p: string) => (process.platform === 'win32' || process.platform === 'darwin' ? p.toLowerCase() : p);

/**
 * Does this canonical absolute path point at something credential-shaped?
 *
 * `extra` lets a project add its own patterns (glob-ish, `*` only).
 */
export function classifySecretPath(abs: string, extra: string[] = []): SecretMatch {
  if (!abs) return NOT_SECRET;
  const p = norm(abs);
  const base = path.posix.basename(p);

  if (!TEMPLATE_NAME.test(base)) {
    for (const f of SECRET_FILES) {
      if (f.name.test(base)) return { secret: true, why: f.why, tag: f.tag };
    }
    for (const e of SECRET_EXTS) {
      if (e.ext.test(base)) return { secret: true, why: e.why, tag: e.tag };
    }
    if (HIVE_DIR.test(p) && HIVE_NAME.test(base)) {
      return { secret: true, why: 'this is a Windows registry credential hive', tag: 'system' };
    }
  }

  if (HOME) {
    const h = lower(norm(HOME)).replace(/\/$/, '');
    const lp = lower(p);
    for (const d of SECRET_DIRS) {
      const full = `${h}/${lower(d.rel)}`;
      if (lp === full || lp.startsWith(full + '/')) {
        return { secret: true, why: d.why, tag: d.tag };
      }
    }
  }

  // Match secret dirs anywhere, not just under $HOME — a repo can contain a
  // vendored `.aws/credentials`, and containers mount them in odd places.
  const lp = lower(p);
  for (const d of SECRET_DIRS) {
    if (!d.rel.startsWith('.')) continue;
    const seg = `/${lower(d.rel)}/`;
    if (lp.includes(seg)) return { secret: true, why: d.why, tag: d.tag };
  }

  // Agent configuration: only the files that actually carry credentials, not
  // the whole directory. `~/.claude/settings.json` routinely holds an API key
  // in its `env` block; `~/.claude/projects/**` is just transcripts.
  const agentDir = AGENT_DIRS.find((d) => lp.includes(`/${d}/`) || lp.endsWith(`/${d}`));
  if (agentDir && AGENT_CREDENTIAL_FILES.some((rx) => rx.test(base))) {
    return { secret: true, why: 'agent settings here can contain API keys', tag: 'agent' };
  }

  for (const pat of extra) {
    if (globMatch(lower(pat), lp)) {
      return { secret: true, why: 'you marked this path as sensitive', tag: 'custom' };
    }
  }

  return NOT_SECRET;
}

/**
 * The absolute directories that hold credentials, as places rather than as
 * names — every `SECRET_DIRS` entry resolved against `$HOME`, plus the system
 * stores that hold the files `SECRET_FILES` names.
 *
 * Used only by {@link credentialTreeRoot}. Computed once, because `HOME` is
 * read once (see the note on `HOME` above).
 */
const CREDENTIAL_ANCHORS: string[] = (() => {
  const out: string[] = [];
  const h = HOME ? norm(HOME).replace(/\/+$/, '').toLowerCase() : '';
  if (h) for (const d of SECRET_DIRS) out.push(`${h}/${d.rel.toLowerCase()}`);
  // POSIX system credential stores: /etc holds shadow, gshadow and sudoers;
  // root's home holds root's keys.
  out.push('/etc', '/private/etc', '/root', '/var/root');
  // The Windows registry hives, on whichever drive the user lives.
  const drive = /^([a-z]:)\//.exec(h)?.[1] ?? 'c:';
  out.push(`${drive}/windows/system32/config`);
  return out;
})();

/**
 * Directories that *contain* other users' credential stores. A recursive read
 * of any of these, or of any one home inside them, sweeps up `~/.ssh` for
 * whoever lives there.
 */
const HOME_CONTAINERS: string[] = ['/home', '/users', 'c:/users'];
// Containers only, and only the three whose children are homes by definition.
//
// `/root` is a home, not a container of homes — listing it would make every
// `/root/<subdir>` read as somebody's home. It is an anchor above instead.
//
// This deliberately does not include whatever `dirname($HOME)` happens to be.
// That directory is already a sweep root, because it is a strict ancestor of
// `$HOME/.ssh` and the anchor check catches it; adding it here would go
// further and declare all of its *children* to be homes, which is only true
// when it really is a user-profile directory.

/**
 * Is a *recursive* read rooted here certain to descend into credentials?
 *
 * `grep -r "BEGIN OPENSSH PRIVATE KEY" ~/.ssh` was floored and
 * `grep -r "BEGIN OPENSSH PRIVATE KEY" ~` was not — the strictly wider search
 * was the safer one, because the judgement looked only at the single path on
 * the command line and `~` is not itself a credential store. Naming the parent
 * directory was enough to evade the floor, and `~` collapses onto the same
 * `<path:outside:home>` token as `~/Documents`, so approvals of an ordinary
 * scoped search paid for the whole-home one.
 *
 * This answers the question the path alone cannot: does walking down from here
 * reach `~/.ssh`, `~/.aws`, `/etc/shadow`, the registry hives? It is
 * deliberately about *certainty*, not possibility — any directory might have a
 * `.env` buried in it, and a rule that fired on that would flag every recursive
 * search in the world. It fires only for the ancestors of stores that exist by
 * platform convention: `~`, `/home`, `/Users`, another user's home, `/etc`, a
 * drive root, `/`.
 *
 * Reads that are already secret by path are not this function's business;
 * `classifySecretPath` answers those.
 */
export function credentialTreeRoot(abs: string): SecretMatch {
  if (!abs) return NOT_SECRET;
  const p = norm(abs).replace(/\/+$/, '').toLowerCase() || '/';
  const prefix = p === '/' ? '/' : p + '/';
  for (const a of CREDENTIAL_ANCHORS) {
    if (a === p || a.startsWith(prefix)) {
      return { secret: true, why: 'everything under here includes credential stores', tag: 'tree' };
    }
  }
  if (HOME_CONTAINERS.includes(p) || HOME_CONTAINERS.includes(path.posix.dirname(p))) {
    return { secret: true, why: 'this is a home directory, and home directories hold credentials', tag: 'tree' };
  }
  return NOT_SECRET;
}

const AGENT_DIRS = ['.claude', '.codex', '.cursor', '.gemini', '.continue', '.aider', '.copilot'];

const AGENT_CREDENTIAL_FILES = [
  /^settings(\.local)?\.json$/i,
  /^config\.(toml|json|ya?ml)$/i,
  /^auth\.json$/i,
  /^\.credentials\.json$/i,
  /^mcp\.json$/i,
].map(ci);

/**
 * The patterns this module matches against a basename, exposed so a test can
 * assert the property rather than the instances: every one of them folds case.
 *
 * A test that spells out `sam` and `SAM` proves nothing about the next entry
 * somebody adds. This lets the suite check the invariant itself.
 */
export function nameRules(): RegExp[] {
  return [
    ...SECRET_FILES.map((f) => f.name),
    ...SECRET_EXTS.map((e) => e.ext),
    ...AGENT_CREDENTIAL_FILES,
    TEMPLATE_NAME,
    HIVE_DIR,
    HIVE_NAME,
  ];
}

/** Minimal glob: `*` matches within a segment, `**` matches across segments. */
export function globMatch(pattern: string, value: string): boolean {
  const rx = pattern
    .split('')
    .map((c, i, a) => {
      if (c === '*') {
        if (a[i + 1] === '*') return '';
        if (a[i - 1] === '*') return '.*';
        return '[^/]*';
      }
      if (c === '?') return '[^/]';
      return /[.+^${}()|[\]\\]/.test(c) ? '\\' + c : c;
    })
    .join('');
  try {
    return new RegExp(`^${rx}$`).test(value);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

interface RedactRule {
  rx: RegExp;
  label: string;
}

/**
 * Ordered most-specific first. Each rule replaces the *secret* portion, keeping
 * enough context that the ledger entry is still readable:
 * `curl -H "Authorization: Bearer <redacted:bearer>"`.
 */
const RULES: RedactRule[] = [
  { rx: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, label: 'private-key' },
  { rx: /\bgithub_pat_[A-Za-z0-9_]{20,}/g, label: 'github-token' },
  { rx: /\bgh[pousr]_[A-Za-z0-9]{16,}/g, label: 'github-token' },
  { rx: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, label: 'anthropic-key' },
  { rx: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, label: 'api-key' },
  { rx: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}/g, label: 'stripe-key' },
  { rx: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, label: 'slack-token' },
  { rx: /\bAKIA[0-9A-Z]{16}\b/g, label: 'aws-key-id' },
  { rx: /\bASIA[0-9A-Z]{16}\b/g, label: 'aws-key-id' },
  { rx: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: 'google-key' },
  { rx: /\bglpat-[A-Za-z0-9_-]{16,}/g, label: 'gitlab-token' },
  { rx: /\bnpm_[A-Za-z0-9]{30,}/g, label: 'npm-token' },
  { rx: /\bdop_v1_[a-f0-9]{64}\b/g, label: 'digitalocean-token' },
  { rx: /\bhf_[A-Za-z0-9]{30,}/g, label: 'huggingface-token' },
  { rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, label: 'jwt' },
  // Credentials embedded in URLs: https://user:pass@host
  // The `«»` exclusions keep this from re-matching a marker a rule above
  // already left behind — `https://ghp_…@github.com` would otherwise come out
  // as the nonsense `https://«redacted:«redacted:url-password»@github.com`.
  // The password half is greedy up to the *last* `@` before the path, because
  // passwords contain `@` and stopping at the first one leaves the tail of the
  // secret in the ledger.
  { rx: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@«»]+):([^\s/«»]+)@/gi, label: 'url-password' },
  // Authorization headers of any scheme.
  { rx: /((?:Authorization|Proxy-Authorization)\s*:\s*)(?:Bearer|Basic|Token|ApiKey)\s+[A-Za-z0-9._~+/=-]{8,}/gi, label: 'auth-header' },
  // Common CLI password flags.
  { rx: /(--?(?:password|passwd|pwd|token|api[-_]?key|secret|auth)[= ])(?!\s)("[^"]*"|'[^']*'|\S+)/gi, label: 'flag-value' },
  // mysql -pSECRET (no space).
  //
  // `-p` glued to its value means "password" in the mysql/mariadb clients and
  // essentially nowhere else. Matching a bare `\s-p\S{4,}` anywhere was far too
  // eager: `docker run -p8080:80`, `ssh -p2222 host`, `gcc -pthread`,
  // `tar -pxzvf`, `rsync -progress` and `find … -prune -o … -print` all came
  // out of the ledger with a «redacted» where the operator needed to read the
  // port or the flag. That is the crying-wolf failure this module exists to
  // avoid, so the rule is anchored to a mysql-family command instead.
  //
  // The gap excludes `;&|` so the match cannot jump a command separator and
  // steal the `-p` belonging to some later program in the same line.
  { rx: /((?:^|[\s;&|(])(?:mysql|mariadb)[\w-]*[^\n;&|]*?\s-p)(?!\s)([^\s'"]{4,})/gi, label: 'mysql-password' },
  // `mysql -p hunter2` - the same flag with a space. Anchored to the same
  // command family for the same reason, and the value must not look like a
  // port number, because `-p 3306` is the other thing that spelling means.
  //
  // Found by an audit that grepped the real bytes on disk rather than reading
  // the rules: the spaced form was reaching `denials.jsonl`, which is
  // append-only and never pruned, so it outlived every other copy.
  {
    rx: /((?:^|[\s;&|(])(?:mysql|mariadb)[\w-]*[^\n;&|]*?\s-p\s+)(?!\d+(?:\s|$))([^\s'"]{4,})/gi,
    label: 'mysql-password',
  },
  // `curl -u user:password`. The user half is kept: it is not the secret, and
  // losing it would make two different accounts against one host look like
  // the same action.
  { rx: /((?:^|\s)(?:-u|--user)\s+[^\s:'"]+:)([^\s'"]+)/g, label: 'basic-auth' },
  // NAME=VALUE where NAME smells like a credential.
  //
  // The value must not already be a marker. This rule is broad by design and
  // runs after the specific ones, so without that guard it re-redacts what they
  // produced: `TOKEN=xoxb-…` becomes `«redacted:slack-token»` and then
  // `«redacted:env-secret»`, losing the label that told the human which kind of
  // credential it was. `--password=…` lost `flag-value` the same way.
  //
  // The prefix is optional, and it used to be mandatory: `[A-Za-z_]` had to
  // consume a character before the credential word could start matching, so
  // `DB_PASSWORD=` and `MY_TOKEN=` were caught while the bare spellings —
  // `PASSWORD=`, `TOKEN=`, `SECRET=`, `API_KEY=` — could never match at all.
  // Those are the most common forms there are, and the value went into
  // ledger.jsonl, the envelope, and denials.jsonl, which is append-only and by
  // design never pruned, so it outlived every other copy.
  {
    rx: /\b((?:[A-Za-z_][A-Za-z0-9_]*)?(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?|AUTH)[A-Za-z0-9_]*)=(?![\u00ab<])("[^"]*"|'[^']*'|\S+)/gi,
    label: 'env-secret',
  },
];

/** Replacement marker. Distinctive so tests and humans can spot it. */
const mark = (label: string) => `«redacted:${label}»`;

/**
 * Remove credential-shaped substrings from text destined for disk or display.
 *
 * This is best-effort by nature. It is not a guarantee, and LeastGrant does not
 * claim otherwise — which is exactly why the ledger also never stores file
 * contents, only command lines and paths.
 */
export function redact(text: string): string {
  if (!text) return text;
  let out = text;

  for (const r of RULES) {
    out = out.replace(r.rx, (_match, ...rest) => {
      const groups = rest.slice(0, -2).filter((g) => typeof g === 'string') as string[];
      switch (r.label) {
        case 'url-password':
          return `${groups[0]}:${mark('url-password')}@`;
        case 'auth-header':
          return `${groups[0]}${mark('auth-header')}`;
        case 'flag-value':
          return `${groups[0]}${mark('flag-value')}`;
        case 'mysql-password':
          return `${groups[0]}${mark('mysql-password')}`;
        case 'basic-auth':
          return `${groups[0]}${mark('basic-auth')}`;
        case 'env-secret':
          return `${groups[0]}=${mark('env-secret')}`;
        default:
          return mark(r.label);
      }
    });
  }

  out = redactHighEntropy(out);
  return out;
}

/**
 * Catch credentials that match no known vendor pattern.
 *
 * Only fires on long, high-entropy, alphabet-mixed tokens, and skips things
 * that are legitimately random-looking and harmless: git SHAs, UUIDs, hashes
 * in lockfiles, base64 of small data. False positives here cost readability;
 * false negatives cost a leaked secret, so the bias is deliberate but bounded.
 */
function redactHighEntropy(text: string): string {
  return text.replace(/[A-Za-z0-9_\-+/=]{28,}/g, (tok) => {
    if (/^[0-9a-f]{7,40}$/i.test(tok)) return tok; // git sha / md5 / sha1
    if (/^[0-9a-f]{64}$/i.test(tok)) return tok; // sha256 digest
    if (/^[0-9a-fA-F-]{36}$/.test(tok)) return tok; // uuid
    if (/^[0-9]+$/.test(tok)) return tok;
    if (/^(sha\d+|md5)-/i.test(tok)) return tok; // subresource integrity
    if (!/[A-Z]/.test(tok) || !/[a-z]/.test(tok) || !/[0-9]/.test(tok)) return tok;
    // Slashes are in the token alphabet because base64 uses them, which means a
    // long file path arrives here as one token. `/home/alice/projects/MyApp2/
    // src/components/Button` is mixed-case, has a digit and scores 4.05 bits —
    // enough to be redacted on the rules above, and a ledger full of
    // «redacted» where the paths should be is a ledger nobody can read.
    // A path is short words joined by slashes; a credential that happens to
    // contain a slash still has one long random run in it. Judge on that.
    if (tok.includes('/') && !tok.split('/').some((run) => run.length >= 12 && shannon(run) >= 3.5)) {
      return tok;
    }
    if (shannon(tok) < 3.6) return tok;
    return mark('high-entropy');
  });
}

/** Shannon entropy in bits per character. */
export function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * The credential-shaped substrings inside `text`, as literals.
 *
 * `redact()` works on adjacency: it recognises `-p hunter2` because the flag
 * and the value sit next to each other. A *signature* has been reassembled —
 * flags sorted, positionals separated — so by the time the value reaches it,
 * `hunter2` is a lone token and no rule matches it any more. The secret was
 * scrubbed from the display and survived in the signature, which is the half
 * that gets written to `denials.jsonl` and never pruned.
 *
 * So the secret is identified in the original text, where the context still
 * exists, and the caller removes those exact strings from wherever they ended
 * up. Returned longest-first so that a value containing another value cannot
 * be half-replaced.
 */
export function secretSubstrings(text: string): string[] {
  if (!text) return [];
  const found = new Set<string>();
  for (const r of RULES) {
    const rx = new RegExp(r.rx.source, r.rx.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(text)) !== null) {
      // The last capture group is the value in every rule; earlier groups are
      // the context that identified it and must be kept.
      const value = m[m.length - 1];
      if (typeof value === 'string' && value.length >= 4) found.add(value);
      if (m.index === rx.lastIndex) rx.lastIndex++;
    }
  }
  return [...found].sort((a, b) => b.length - a.length);
}

/** True if redaction changed anything — used to warn the user once. */
export function containsSecretLike(text: string): boolean {
  return redact(text) !== text;
}
