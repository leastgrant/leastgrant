/**
 * Action signatures: the identity under which we learn.
 *
 * `git commit -m "fix login bug"` and `git commit -m "bump deps"` are the same
 * habit and should count together. `git push` and `git push --force` are not.
 * Getting that line right is most of what makes the learning feel intelligent
 * rather than either forgetful or reckless.
 *
 * Two rules keep generalization safe:
 *
 *  1. **Normalize the parsed argv, never the raw string.** Regexes over a
 *     command line are how `git checkout <SHA>-e29b-...-<SHA>` happens, and
 *     worse, how two commands with different meanings collapse into one
 *     signature. We template per token, after parsing.
 *
 *  2. **Risk-relevant distinctions survive templating.** A path argument does
 *     not become `<path>`; it becomes `<path>`, `<path:outside>` or
 *     `<path:secret>` depending on where it points. A URL keeps its hostname.
 *     So no amount of learning about `cat <path>` can ever quietly cover
 *     `cat ~/.ssh/id_rsa` — they are different signatures, and the second also
 *     trips a floor.
 */

import { UNRESOLVED } from './shell/tokenize.js';
import { credentialTreeRoot } from './secrets.js';
import { isUnplaceable } from './paths.js';

export interface SignatureCtx {
  resolve(arg: string): string;
  inWorkspace(abs: string): boolean;
  isSecret(abs: string): boolean;
  looksLikePath(arg: string): boolean;
}

const SHA = /^[0-9a-f]{7,40}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUM = /^[+-]?\d+(\.\d+)?$/;
const VERSION = /^v?\d+\.\d+(\.\d+)?([-+][\w.]+)?$/;
const PORT = /^:\d{2,5}$/;
const URLISH = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Normalize a single argument into a placeholder, or return it unchanged.
 *
 * Order matters: UUID must be tested before SHA, or a UUID's hex runs get
 * eaten piecemeal by the SHA rule.
 */
export function normalizeArg(arg: string, ctx: SignatureCtx): string {
  if (!arg) return arg;
  if (arg.includes(UNRESOLVED)) return '<dynamic>';

  if (URLISH.test(arg)) {
    const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/:?#\s]+)/i.exec(arg);
    return m ? `<url:${m[1]!.toLowerCase()}>` : '<url>';
  }

  if (UUID.test(arg)) return '<uuid>';
  if (SHA.test(arg) && arg.length >= 7 && /\d/.test(arg) && /[a-f]/i.test(arg)) return '<sha>';
  if (VERSION.test(arg)) return '<version>';
  if (NUM.test(arg)) return '<n>';
  if (PORT.test(arg)) return '<port>';

  // `user@host:path` — an scp-style remote.
  if (/^[\w.-]+@[\w.-]+:/.test(arg)) return '<remote>';

  if (ctx.looksLikePath(arg)) {
    const abs = ctx.resolve(arg);
    if (!abs) return '<path:unresolved>';
    // A credential is a credential under every spelling. This is tested before
    // the unplaceable branch on purpose: `cat <marked ~/.ssh/id_rsa>` names the
    // same key as `cat ~/.ssh/id_rsa` and must share its identity, which is
    // floored forever, rather than getting a token of its own.
    if (ctx.isSecret(abs)) return '<path:secret>';
    // Anything else we could not place gets one token that no resolvable path
    // ever shares. `outsideZone` below reads a *region* out of the path text,
    // and the text of an unplaceable path is exactly as readable as any other —
    // so `cat C:\pagefile.sys\..\..\Users\me\.ssh\id_rsa` came out as
    // `cat <path:outside:home>`, byte-identical to `cat ~/Documents/notes.txt`.
    // Twenty approvals of the notes file then bought the key.
    //
    // The token is safe to share across every unplaceable path because it is
    // never promotable: an action holding one is not understood, and
    // `guard.not-understood` returns from `decideOne` before any evidence is
    // weighed.
    if (isUnplaceable(abs)) return '<path:unresolved>';
    if (!ctx.inWorkspace(abs)) return '<path:outside:' + outsideZone(abs) + '>';
    return '<path>';
  }

  // Free text: a commit message, a search pattern, a SQL string. Anything with
  // whitespace or that is long is not an identifier worth learning verbatim —
  // except that a SQL statement's verb is exactly the part that matters.
  if (/\s/.test(arg) || arg.length > 48) return sqlShape(arg) ?? '<text>';

  return arg;
}

/**
 * Build a signature for a shell command.
 *
 * Flags are kept (they change behaviour) and sorted (their order does not).
 * Flag *values* are normalized like positional arguments, so
 * `--output=/tmp/x` becomes `--output=<path:outside>`.
 */
/**
 * A signature fragment for leading environment assignments.
 *
 * `PATH=./tools:$PATH git status` and `git status` used to be the same learned
 * thing, so approving the second taught LeastGrant to allow the first. Values
 * are normalized like any other argument; the names are what matter.
 */
export function assignmentSignature(
  assignments: { name: string; value: string }[],
  ctx: SignatureCtx,
): string {
  if (!assignments.length) return '';
  return (
    assignments
      .map((a) => a.name + '=' + normalizeArg(a.value, ctx))
      .sort()
      .join(' ') + ' '
  );
}

/**
 * A coarse label for where outside the project a path lives.
 *
 * Every outside path used to normalize to the single token `<path:outside>`,
 * which meant approving one read of one file outside the project taught
 * LeastGrant to allow reading *any* file outside the project. Splitting the
 * token by region keeps the learning useful — a build that reads
 * `/usr/share/...` every time still settles — without letting that approval
 * spread to a home directory or a system config.
 *
 * Deliberately coarse: a per-directory token would never accumulate enough
 * evidence to settle, which is its own failure mode.
 */
export function outsideZone(abs: string): string {
  const p = abs.replace(/\\/g, '/').toLowerCase();
  // A directory that *contains* credential stores is its own zone, tested
  // first because it is a property of the exact path and the rules below are
  // prefix rules: `/etc/nginx` is `etc`, but `/etc` itself, `~`, `/home`,
  // `/Users/someone` and `C:\` each sit above somebody's keys.
  //
  // Without this, `~` and `~/Documents` were one learned thing, so twenty
  // approvals of `grep -r <phrase> ~/Documents` auto-approved
  // `grep -r "BEGIN OPENSSH PRIVATE KEY" ~`. Splitting the token is the half of
  // that fix which does not depend on recognising the recursion: even a walker
  // LeastGrant does not know is recursive can no longer spend a scoped
  // search's trust on the whole home directory.
  if (credentialTreeRoot(abs).secret) return 'credential-tree';
  if (/^([a-z]:)?\/(etc|private\/etc)\b/.test(p)) return 'etc';
  if (/^([a-z]:)?\/(usr|opt|bin|sbin|lib)\b/.test(p)) return 'system';
  if (/^([a-z]:)?\/(var|proc|sys|dev)\b/.test(p)) return 'runtime';
  if (/\/(tmp|temp)\//.test(p) || /^([a-z]:)?\/tmp\b/.test(p)) return 'temp';
  if (/^[a-z]:\/(windows|program files)/.test(p)) return 'system';
  if (/\/(users|home)\//.test(p)) return 'home';
  return 'other';
}

/**
 * SQL statements keep their verb.
 *
 * `psql -c "SELECT 1"` and `psql -c "DROP TABLE users"` are both long strings
 * with spaces, so both normalised to `<text>` and shared one identity —
 * approving a select taught LeastGrant to allow a drop. The verb is the entire
 * difference in risk, so it survives templating; the rest of the statement does
 * not, which is what keeps `SELECT a` and `SELECT b` together.
 */
const SQL_VERB = /^\s*(?:\/\*.*?\*\/\s*)?(--[^\n]*\n\s*)*(select|insert|update|delete|drop|truncate|alter|create|grant|revoke|copy|call|do|merge|vacuum|reindex|attach|pragma)\b/i;

export function sqlShape(arg: string): string | undefined {
  const m = SQL_VERB.exec(arg);
  if (!m?.[2]) return undefined;
  const verb = m[2].toLowerCase();

  // A statement that carries more statements is not the verb it starts with.
  //
  // `select 1; drop table users` matched `select` and templated as
  // `<sql:select>` — identical to `select 1`, so approvals of an ordinary read
  // covered a table drop. Stacked statements are the SQL spelling of the shell
  // `;` that `shell-composition` cases already cover, and the same rule applies:
  // the leading token is not the action when there is a second one behind it.
  //
  // Not an attempt to parse SQL. It only has to answer "is there more than one
  // statement here", conservatively — a trailing semicolon is just punctuation,
  // and a semicolon inside a quoted string is not a separator. Anything it
  // cannot be sure about is treated as stacked, which is the safe direction:
  // the worst outcome is a distinct signature for a statement that did not need
  // one, which costs approvals rather than safety.
  return hasStackedStatement(arg) ? `<sql:${verb}+more>` : `<sql:${verb}>`;
}

/** Is there a second statement after the first semicolon that is not inside a string? */
function hasStackedStatement(sql: string): boolean {
  let quote: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i]!;
    if (quote) {
      // Doubled quote is an escaped quote in SQL, not a terminator.
      if (ch === quote) {
        if (sql[i + 1] === quote) i++;
        else quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === ';') return sql.slice(i + 1).trim().length > 0;
  }
  return false;
}

/**
 * Shell builtins whose arguments are variable assignments rather than operands.
 *
 * These need the same treatment `assignmentSignature` already gives to a
 * leading `NAME=value` prefix, and for the same reason: the name is the whole
 * meaning. Without this, `export LD_PRELOAD=/tmp/evil.so` normalized to
 * `export <path>` — the identical signature to `export CACHE_DIR=/tmp/build` —
 * so forty ordinary build steps taught LeastGrant to auto-approve an
 * environment hijack. Reproduced end to end before this was written: allow,
 * floor false, on LD_PRELOAD, BASH_ENV, NODE_OPTIONS and PYTHONSTARTUP, from
 * training on the cache directory alone.
 *
 * The inline form `LD_PRELOAD=x git status` was never affected, because it goes
 * through assignmentSignature, whose comment has said "the names are what
 * matter" since it was written. This is that rule reaching the other spelling.
 */
const ASSIGNMENT_BUILTINS = new Set(['export', 'set', 'setenv', 'declare', 'typeset', 'local', 'readonly', 'alias']);

export function commandSignature(argv: string[], ctx: SignatureCtx): string {
  if (!argv.length) return '(empty)';
  const program = argv[0]!;
  const assigns = ASSIGNMENT_BUILTINS.has(program);
  const flags: string[] = [];
  const positional: string[] = [];

  let sawDashDash = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--' && !sawDashDash) {
      sawDashDash = true;
      continue;
    }
    if (!sawDashDash && a.startsWith('-') && a !== '-') {
      const eq = a.indexOf('=');
      if (eq > 0) {
        flags.push(`${a.slice(0, eq)}=${normalizeArg(a.slice(eq + 1), ctx)}`);
      } else {
        flags.push(a);
      }
      continue;
    }
    // Keep the name, normalize the value. `alias` is in the same set and wants
    // the same shape: `alias ls=<dynamic>` must not be learnable as `alias
    // <dynamic>`, because what is being redefined is the point.
    const eq = assigns ? a.indexOf('=') : -1;
    positional.push(eq > 0 ? `${a.slice(0, eq)}=${normalizeArg(a.slice(eq + 1), ctx)}` : normalizeArg(a, ctx));
  }

  flags.sort();
  return [program, ...positional, ...flags].join(' ');
}

/** Signature for a structured (non-shell) tool call. */
export function toolSignature(tool: string, parts: string[]): string {
  return parts.length ? `${tool}(${parts.join(', ')})` : tool;
}

/** Key names whose value must never be reproduced in a signature. */
const SECRETISH_KEY =
  /(?:token|secret|password|passwd|credential|api[_-]?key|^key$|auth|cookie|session[_-]?id|private|^value$|^val$|^data$|^payload$|^content$|^body$|^arg$|^args$|^input$)/i;

/**
 * MCP tools whose *name* says the arguments are sensitive, whatever the keys
 * are called. `mcp__vault__get_secret({name, value})` has no credential-shaped
 * key at all, and `value` held the secret.
 */
const SECRETISH_TOOL = /(?:secret|credential|password|token|vault|keychain|keyring|auth)/i;

/**
 * Values kept verbatim in an MCP signature.
 *
 * The tension here is real and does not have a clean answer. Keeping a short
 * string means `mode=read` and `mode=write` are different learned things,
 * which matters — collapsing them would let an approved read cover a write.
 * But a short string can also be a password, and a signature is written to
 * disk and never pruned from `denials.jsonl`.
 *
 * The compromise: keep only values shaped like an enum, meaning a single token
 * that is entirely lower-case or entirely upper-case and no longer than
 * sixteen characters. `write`, `read`, `DELETE`, `main`, `prod-db` survive.
 * `mcpPLAINVALUE` and anything with a digit do not — mixed case and digits are
 * what identifiers and secrets look like, and enums almost never do. Longer or
 * higher-entropy values were already handled by `redact()` downstream.
 *
 * It is a heuristic, and `docs/privacy.md` says so rather than implying the
 * signature is guaranteed clean.
 */
const ENUMISH = /^(?:[a-z][a-z_-]{0,15}|[A-Z][A-Z_]{1,15})$/;

/**
 * Key names that carry prose.
 *
 * Only ever consulted for a value that would otherwise be kept verbatim, so a
 * `query` holding SQL still gets its verb and a `path` still gets its zone.
 * Without this, `create_pr(title: "Another")` became a signature containing the
 * word "Another" — a new learned identity per pull request, and a fragment of
 * the user's content written into a file we ask them to read.
 */
const FREETEXT_KEY = /^(?:title|body|message|msg|description|desc|content|text|comment|summary|prompt|note|notes|reason|label|caption|question|answer)$/i;

/**
 * The argument shape of an MCP call.
 *
 * An MCP tool is a black box: LeastGrant cannot see the server's code, so the
 * only things it has are the tool's name and the arguments the agent passed.
 * For a long time the signature was the *name alone*, and that turned out to be
 * the single widest collision in the system — `mcp__db__query` was one learned
 * identity, so eleven approved `SELECT`s auto-approved a `DROP TABLE`, and
 * `mcp__acme__get_document({})` auto-approved
 * `mcp__acme__get_document({destructive: true})`.
 *
 * What goes in is the *shape*, not the data: sorted key names, each with a
 * coarse description of its value. That keeps the identity stable across calls
 * that differ only in which record they touch, while making a call that adds a
 * parameter, or changes a SQL verb, or points at a different host, a different
 * thing that has to earn its own approval.
 *
 * The one MCP-specific rule on top of `normalizeArg`: an identifier containing
 * a digit collapses to `<id>`. Shell arguments keep such tokens verbatim, but
 * MCP calls are overwhelmingly "do this to record ABC-123", and fragmenting per
 * record id would mean a prompt for every ticket the agent ever opens. Words
 * without digits — `write`, `force`, `DELETE`, `main` — are kept, because those
 * are the enum-shaped arguments that actually change what the call does.
 */
export function mcpArgSignature(input: Record<string, unknown>, ctx: SignatureCtx, tool = ''): string {
  const parts = shapeObject(input, ctx, 0, SECRETISH_TOOL.test(tool));
  return parts.length ? `(${parts.join(', ')})` : '()';
}

function shapeObject(o: Record<string, unknown>, ctx: SignatureCtx, depth: number, allSecret = false): string[] {
  const keys = Object.keys(o).sort();
  const shown = keys.slice(0, 16);
  const parts = shown.map(
    (k) => `${k}=${shapeValue(o[k], ctx, depth, allSecret || SECRETISH_KEY.test(k), FREETEXT_KEY.test(k))}`,
  );
  if (keys.length > shown.length) parts.push(`+${keys.length - shown.length} more`);
  return parts;
}

function shapeValue(v: unknown, ctx: SignatureCtx, depth: number, secretish: boolean, freetext = false): string {
  if (v === null) return '<null>';
  switch (typeof v) {
    case 'undefined':
      return '<null>';
    case 'boolean':
      // Kept verbatim: two possible values, and `force`/`destructive`/`dryRun`
      // are exactly the arguments that decide what a call does.
      return v ? '<true>' : '<false>';
    case 'number':
    case 'bigint':
      return '<n>';
    case 'function':
    case 'symbol':
      return '<opaque>';
    case 'string': {
      if (secretish) return '<redacted>';
      const n = normalizeArg(v, ctx);
      // `normalizeArg` returns the argument unchanged when it is a short
      // identifier. For MCP that is usually a record id or, worse, a secret
      // under an innocuous key — so only enum-shaped values survive.
      if (n === v && freetext) return '<text>';
      if (n === v && /\d/.test(v)) return '<id>';
      if (n === v && !ENUMISH.test(v)) return '<text>';
      return n;
    }
    default:
      break;
  }
  if (Array.isArray(v)) {
    if (!v.length) return '<list>';
    if (depth >= 2) return '<list>';
    // The DISTINCT element shapes, not the first one.
    //
    // It used to be `shapeValue(v[0], …)`, on the reasoning that a 500-item
    // batch must not produce a 500-fragment signature. That reasoning is right
    // and the implementation threw away the security content of the list:
    // everything after index zero was invisible. So
    //
    //   read_multiple_files({paths: ['src/a.ts', '~/.ssh/id_rsa']})
    //
    // signed byte-identically to a read of two project files, and a dozen
    // approvals of the ordinary batch promoted the one with the key in it. A
    // secret in position ZERO did change the signature, which is the tell: the
    // distinction was always meant to survive templating and simply stopped at
    // the first element.
    //
    // Distinct shapes keep the size property that motivated the original —
    // a uniform batch of any length is still one fragment, because every
    // element reduces to the same string — while a batch that mixes an
    // ordinary path with a credential can no longer wear the ordinary one's
    // identity. Sorted so element order cannot mint a second identity for the
    // same set, and capped so a deliberately heterogeneous list cannot grow the
    // signature without bound.
    const shapes = new Set<string>();
    for (const el of v) {
      shapes.add(shapeValue(el, ctx, depth + 1, secretish, freetext));
      if (shapes.size > 4) {
        shapes.add('<mixed>');
        break;
      }
    }
    return `<list of ${[...shapes].sort().join('|')}>`;
  }
  if (depth >= 2) return '<obj>';
  const inner = shapeObject(v as Record<string, unknown>, ctx, depth + 1);
  return inner.length ? `{${inner.join(', ')}}` : '{}';
}

/**
 * A coarser family key, used to answer "we have not seen this exact command,
 * but we have seen a lot like it".
 *
 * `npm run build:prod` -> family `npm run`. Only ever used to *explain* a
 * decision or to order suggestions — never to grant permission, because a
 * family is exactly the kind of generalization an attacker would aim at.
 */
export function familyOf(signature: string): string {
  const parts = signature.split(' ').filter((p) => !p.startsWith('-'));
  if (parts.length <= 1) return parts[0] ?? signature;
  const head = parts.slice(0, 2);
  // Keep a third token when the second is a common dispatch word, so that
  // `git remote add` does not collapse into `git remote`.
  if (parts.length > 2 && /^(run|remote|config|stash|submodule|worktree|branch|tag|kv|state|secret)$/.test(parts[1]!)) {
    head.push(parts[2]!);
  }
  return head.join(' ');
}
