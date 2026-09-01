# Threat model

This document is the part of LeastGrant you should read before trusting it. It says
what the code actually does, and — at greater length — what it does not do. If you
only read one section, read [What it does not defend against](#3-what-it-does-not-defend-against).

Everything here is checkable against the source. Where a claim rests on a constant,
the constant is quoted and the file is named.

---

## 1. What LeastGrant is

LeastGrant is a decision layer. Your coding agent asks it a question before a tool
call — "may I run this?" — and it answers allow, ask, or deny. It does not confine a
process, intercept a syscall, or contain anything that has already started running.

It is a hook, not a sandbox. It sits at one specific seam: the permission check the
agent performs on itself, voluntarily, before it acts. Everything LeastGrant can do
follows from that, and so does everything it cannot.

If you want confinement, you want a container, a VM, a seccomp profile, or Claude
Code's own sandboxing. LeastGrant is complementary to those and a poor substitute
for any of them.

---

## 2. What it actually defends against

Everything in this section describes the default posture, `assist`. Three of the four
postures change some of these answers, and one of them switches LeastGrant off
entirely. See [Posture changes what a "floor" means](#posture-changes-what-a-floor-means)
in section 3 before relying on anything below.

### A prompt-injected or confused agent taking a destructive action

**Mechanism.** `src/core/decide.ts` runs every tool call through a fixed precedence
order: integrity floors, then your explicit deny rules, then your explicit allow
rules, then ask floors, then learned promotion, then ask. A command is decomposed
into separate actions and *the worst one drives the verdict* — `npm test && git push
--force` is judged as a force-push, not as a test run (`decide()`, the `rank`
comparator).

The floors in `src/core/guards.ts` are the part that learning does not move. They cover
credential reads, anything that can send data off the machine, writes outside the
project, files that run automatically later (`PERSISTENCE_FILES`,
`PERSISTENCE_DIRS`), privilege escalation, piping downloaded content into a shell,
one-step fetch-and-run wrappers like `npx` (`guard.fetch-run`), publishing,
production reach, irreversible actions that reach past the workspace
(`guard.irreversible` is conditioned on `reach !== 'workspace'`), and anything the
parser could not fully account for.

**The bound.** This only works for actions the agent has to ask permission for. See
section 3.

### Credential reads

**Mechanism.** `checkGuards()` raises `guard.secret-read` whenever an action's blast
radius has `exposure: 'reads-secrets'` or its capability is `secret.read`. Separately,
`blastTier()` in `src/core/types.ts` scores `reads-secrets` at 3 and `can-exfiltrate`
at 4, and `DEFAULT_THRESHOLDS.maxTier` is `2`. `canPromote()` checks the tier
*before* it looks at any statistics, so evidence for a tier-3 action is never even
examined. The test `a thousand approvals of a secret read still asks` in
`test/bypass.test.ts` asserts this.

Signatures also keep the distinction. `normalizeArg()` in `src/core/signature.ts`
templates a path to `<path>`, `<path:outside:…>` or `<path:secret>` depending on where
it resolves, so learning `cat <path>` can never spend itself on `cat <path:secret>` —
they are different keys.

**Two honest qualifications.** `guard.secret-read` produces `ask`, not `deny`. And an
explicit allow rule that you write yourself sits *above* the ask floors in the
precedence order (`decideOne()` steps 3 and 4), so a rule of yours does override it
(verified: with a `match: "*"` allow rule in the config, `cat ~/.ssh/id_rsa` returns
`allow`, with `guard.secret-read` listed in the reasons as satisfied by the rule).
That is deliberate — a floor exists to get a human answer, and a rule is a human
answer given in advance — but it means "nothing unlocks a credential read" would be
false. Learning cannot unlock it. You can.

There is also a real gap in which commands trip this floor at all. See section 3.

### Command-allowlist evasion

**Mechanism.** Classification runs on a parsed argv, not on a string prefix. Three
files do this work:

- `src/core/shell/tokenize.ts` — a POSIX-aware tokenizer. Handles single, double and
  ANSI-C (`$'\x2f'`) quoting, escapes, here-docs, fd-prefixed redirects, command and
  process substitution, and arithmetic expansion. Only `HOME`, `USERPROFILE`, `PWD`,
  `TMPDIR`, `TEMP`, `TMP` and `HOMEPATH` are resolved (`RESOLVABLE`); everything else
  becomes an unresolved marker rather than a guess.
- `src/core/shell/parse.ts` — flattens the token stream into an inventory of every
  program that will run, recursing into `$(...)`, backticks and `<(...)`. So
  `echo $(rm -rf /)` reports `rm` as a command that runs.
- `src/core/shell/unwrap.ts` — peels wrappers until it reaches something nameable, and
  records what it peeled. `sudo`, `doas`, `su`, `pkexec`, `gosu`, `env`, `chroot`,
  `unshare`, `timeout`, `nice`, `watch`, `nohup`, `xargs`, `find -exec`, `ssh`,
  `docker exec`, `kubectl exec`, `make`, `npx`, `eval`, `source`, `sh -c`, `trap`, and
  `git -c`. Assignments that make another program run code (`LD_PRELOAD`, `BASH_ENV`,
  `NODE_OPTIONS`, `GIT_SSH_COMMAND`, and the rest of that list) mark the command
  opaque — and an assignment written as `env FOO=x cmd` is moved into the command's
  own assignment list before that check runs, so the two spellings are one thing.

The specific evasions this closes. The first four groups are in the corpus in
`test/bypass.test.ts`; the path forms are asserted in `test/paths.test.ts`, and only
the two traversal cases also appear in the bypass corpus:

- **Separators.** `git status; rm -rf /`, `&&`, `||`, `&`, newline. Each becomes its
  own action.
- **Substitution.** `git status $(cat ~/.ssh/id_rsa)`, backticks, nested `$(...)`,
  process substitution.
- **Wrappers.** `sudo`, `env FOO=bar`, `sh -c`, `nohup`, `xargs`, `find -exec`,
  `timeout 5`, `ssh box "..."`, `git -c core.pager='!sh -c ...'`, `LD_PRELOAD=`,
  `BASH_ENV=`.

  **Two of those were holes, and are worth spelling out because the fix is the
  interesting part.** `env FOO=x cmd` had its assignments stripped from argv without
  ever being checked — the opacity check reads `current.assignments`, which is where
  the parser puts a *prefix* assignment, while `env`'s are argv tokens. So
  `LD_PRELOAD=/tmp/evil.so npm test` correctly asked and
  `env LD_PRELOAD=/tmp/evil.so npm test` was allowed, with a signature byte-identical
  to plain `npm test`, inheriting every approval the honest command had earned.
  `unwrap.ts` now moves them into `current.assignments` rather than special-casing
  them, so both spellings flow through the same opacity check and the same
  `assignmentSignature()`. Verified: both forms now sign as
  `LD_PRELOAD=<path:outside:temp> npm test`, and both ask after thirty approvals of
  `npm test` — and after thirty approvals of themselves.

  `git -c key=value` was the same class of mistake with a worse blast radius: the
  pair was stripped from argv in *every* case, so
  `git -c core.hooksPath=/tmp/evil commit` was learned as `git commit` and spent that
  command's approvals. The key now stays in the signature — values dropped, keys
  lower-cased and sorted, so `core.hooksPath=/a` and `core.hooksPath=/b` are one
  thing. That is the primary defence, because it does not require anyone to have
  heard of the key: `git -c totally.made.up=/tmp/evil status` signs as
  `git totally.made.up=<value> status -c`, which is a different learned identity from
  `git status` and asks even after thirty approvals of the honest command. The second
  layer is `GIT_CONFIG_EXECUTES`, a denylist of the keys that make git run a program
  (`core.pager`, `core.hooksPath`, `gpg.program`, `diff.external`,
  `credential.helper`, `init.templateDir`, `alias.*`, and the rest); those
  additionally force opacity, so no number of approvals promotes them —
  `git -c core.hooksPath=… commit` still asks after thirty approvals of *itself*. The
  denylist is second on purpose, because a config system with hundreds of keys will
  always have one nobody listed. The honest limit of that arrangement: an
  unlisted key that does turn out to be dangerous is only unfamiliar, not
  unapprovable. `git -c totally.made.up=… status` is tier 1, so five deliberate
  approvals across two days and two sessions will settle it. What the signature
  guarantees is that those five have to be given to *that* command, and cannot be
  borrowed from a plain `git status`.
- **Encoding and quoting.** `cat $'\x2f\x65\x74\x63...'`, `c""at`, `c\at`.
- **Path forms.** Traversal (`../../../.ssh/id_rsa`), symlinks out of the workspace,
  Windows `\\?\` and `\\.\` prefixes, NTFS alternate data streams (`file::$DATA`),
  trailing dots and spaces, and case-insensitive filesystems — all in
  `src/core/paths.ts`. Containment is decided by `isInside()`, which compares path
  *components* under an ASCII-only case fold (`pathComponents` and `foldCase`), not
  by a string prefix and not by `path.relative`. Three things follow: `/proj-evil` is
  not inside `/proj`; `..hidden` is an ordinary directory name and not a climb out;
  and U+212A (KELVIN SIGN) does not fold onto ASCII `k` the way `toLowerCase()` would,
  so a filename NTFS considers distinct cannot be matched against a root inside the
  project. `path.relative` defeated the last two on win32, because it does its own
  `toLowerCase()` fold and silently resolves a relative input against
  `process.cwd()`. A path that cannot be resolved comes back `unknown` with an empty
  `abs`, and `isInside('')` is false — an unplaceable path never reads as contained.

  **`..` after a symlink.** This was the last known hole in that group and it is
  closed. `canonicalize()` called `path.resolve` before `realpath`, which collapses
  `..` in the string before anything is followed, so with `<workspace>/link-out`
  pointing elsewhere, `<workspace>/link-out/../id_rsa` read as inside the workspace
  while a POSIX kernel serves `<target-parent>/id_rsa` from outside it.

  What makes this awkward is that there is no single correct answer to substitute.
  POSIX resolves `..` physically — the symlink is followed first and `..` is the
  parent of the *target* (POSIX.1 §4.13; `path_resolution(7)`). Win32 resolves it
  lexically: `GetFullPathName` strips `..` from the string before the object manager
  ever sees the reparse point. Both were verified by reading a real file through the
  construction. Worse, the split is not merely per-platform: on POSIX, `bash`'s `cd`
  defaults to `-L` and keeps a logical `$PWD`, and Python's `os.path.abspath` collapses
  lexically, so a script that calls `abspath` and then `open` touches a *different
  file* from the one the shell would — on the same machine, from the same string.

  So `canonicalize()` computes both. `resolvePhysical()` walks the path one component
  at a time, following each symlink as it is met and taking `..` against the prefix
  already resolved — which is correct precisely because that prefix contains no
  symlinks. The lexical answer is computed as before. When they differ, `abs` holds
  whichever the host OS would give and `alt` holds the other; `candidatesOf()` returns
  both. Containment then requires *every* candidate to be inside, and credential
  status is granted to *any* candidate that is one, so the ambiguous case fails
  towards asking. `riskiest()` in `src/core/classify.ts` applies that ordering once —
  secret beats outside beats inside — so the dozen knowledge modules downstream keep
  receiving a single path and cannot each forget the rule.

  The walk is skipped unless the input actually contains a `..`, because without one
  the two rules agree by construction; the hook's hot path is unchanged, and a path
  with a `..` costs about 0.14 ms more to resolve when it is not already cached.
  A symlink loop or a chain past 40 hops returns exhausted, which yields no
  candidates rather than a plausible-looking literal path. Measured on 11,100 real
  actions, the dual resolution itself costs nothing — no path in that history is
  ambiguous. The auto-approve rate moved from 42% to 41%, and all of that came from
  a second fix found while testing this one: input redirects (`cmd < file`) were
  being dropped before resolution entirely, so `grep -n TODO < ~/.ssh/id_rsa` was
  judged as an ordinary project-local read with the signature `grep TODO -n`. Those
  reads are now seen, which is why there are slightly more of them.

  Two residual limits, both narrow. On Linux, `..` at a *mount* root traverses to the
  parent of the mountpoint in the current mount namespace, so with bind mounts the
  physical answer is namespace-relative and LeastGrant computes it from the inode
  tree instead. And the walk reads the filesystem as it is at decision time; a link
  swapped between the check and the command running is the time-of-check race that
  §3 already declines to defend against.

Where a wrapper hides the payload rather than revealing it — a script file, a
Makefile target, `eval`, `docker exec` — the result is marked opaque, and
`src/core/types.ts` rule 1 makes an opaque action unapprovable by construction.
Obfuscation cannot be a way to look boring. (In `autopilot` posture the *parse-level*
`guard.not-understood` floor is waived for actions that stay inside the project. An
opaque action itself is still unapprovable: either it classifies as `exec.unknown`,
whose reach is `machine`, or — when the opacity came from a wrapper that *injects*
execution rather than merely hiding a project file — `INJECTS_EXECUTION` in
`src/core/classify.ts` widens its reach to `machine` anyway. See
[Posture changes what a "floor" means](#posture-changes-what-a-floor-means).)

**Anti-claim, in two numbers that measure different things.** Across 6,075 real Bash
tool calls from this machine's Claude Code transcripts, the shell parser accounted
for 6,072 of them, with 0 crashes and 0.04 ms average parse time. That is a statement
about *parsing*. Only 44.5% of the same corpus comes out `understood: true` — inline
code (`python -c`), programs with no knowledge module, script files, and interpreters
fed from stdin are all not-understood, and all of them ask, every time.

Those two numbers are not interchangeable, and conflating them is how the figure that
used to sit here — "98.4% of 5,452 real agent commands fully accounted for" — read as
a claim about coverage when it was a claim about the tokenizer. The parser is good.
The knowledge is partial. The gap between the two is where the asking happens, and on
a repository built around shell scripts it is most of the traffic.

### Slow escalation

**Mechanism.** Learning can only reduce friction *within* a blast tier. It cannot move
an action between tiers, because the tier is computed from the action itself
(`blastTier()`) and compared against a fixed ceiling before any evidence is consulted:

```
DEFAULT_THRESHOLDS.maxTier = 2        // src/core/envelope.ts
CONFIDENCE_BY_TIER = { 0: 0.6, 1: 0.6, 2: 0.8 }
```

Tier 3 and 4 have no entry, deliberately. `git push --force origin main` scores tier
4, `npm publish` tier 4, `terraform apply` tier 4, `cat ~/.ssh/id_rsa` tier 3. No
number of approvals reaches them.

Within a tier the schedule is a Wilson score lower bound with a one-sided
`Z = 1.645`. For a clean record it reduces to `n / (n + z²)`, so you can check it with
a calculator: 5 approvals buys 0.6488, 11 buys 0.8026, 25 buys 0.9023. Tier 2 requires
0.8, which is 11 approvals, and also `minDays: 2` and `minSessions: 2` — a burst
inside one sitting does not count as a habit.

The floors are strictly one-directional. `GuardHit.decision` is typed
`Extract<Decision, 'ask' | 'deny'>`, so a guard cannot express "allow", and
`decideOne()` only ever consumes hits to force a verdict downward — step 1 turns a
`deny` hit into `deny`, step 4 turns any remaining hit into `ask`. There is no path
through `checkGuards()` that makes anything more permitted. (`guards.ts` also exports
a `guardDecision()` helper that summarises a hit list, but nothing calls it; the
enforcement lives in `decideOne()`.)

### Baseline poisoning

**Mechanism.** Evidence is typed by how it was obtained (`EvidenceKind` in
`src/core/types.ts`). `confirmed` means a human answered a prompt. `observed` means
it merely ran, possibly in `bypassPermissions` while nobody was watching. `granted`
means you wrote a rule.

`postToolUse()` in the hook decides which: reaching PostToolUse means the call ran,
and if LeastGrant said `ask` and the mode was attended, something approved it. The
`UNATTENDED` set is `bypassPermissions`, `acceptEdits`, `dontAsk`, `auto`. The miner
applies the same rule plus one more — `AUTO_ALLOWED` in
`src/adapters/claude-code/mine.ts` marks `Read`, `Glob`, `Grep`, `TodoWrite`,
`NotebookRead`, `WebSearch` and `Task` as observation regardless of mode, because
Claude Code does not prompt for them.

Observation alone can only promote actions that are harmless by construction. The
predicate in `canPromote()` is stated in terms of consequences, not a tier number:

```ts
const harmless =
  (blast.reach === 'workspace' || blast.reach === 'none') &&
  blast.reversibility === 'trivial' &&
  blast.exposure === 'none' &&
  blast.scale !== 'sweeping';
```

and it still needs `minObserved: 8` sightings across `minSessions: 2` distinct
sessions. The counter is `fam.observed + fam.confirmed`, so approvals count as
sightings too. In `autopilot` posture this predicate is relaxed — see
[Posture changes what a "floor" means](#posture-changes-what-a-floor-means).

**`minObserved: 8` means nine in practice, and every "eight" below should be read
that way.** The number is compared against a *decayed* count. Each fold ages what is
already stored to meet the newer event's timestamp, and `familiarity()` ages the
total again on read, so eight real sightings arrive as slightly less than eight:
7.988 for eight an hour apart, 7.9999999968 for eight a millisecond apart. Neither
clears `seen >= th.minObserved`. Nine does. Exactly 8.0 requires all eight events to
carry a byte-identical timestamp, which happens in a test and not on a machine. This
is not a bug so much as an off-by-a-fraction nobody would predict from reading the
constant, which is why it is written down here rather than left for you to find.

Denials never decay. `familiarity()` decays `confirmed` and `observed` by a 90-day
half-life and leaves `denied` alone (`const denied = s.denied; // never decays`), and
`canPromote()` returns `previously-denied` before it looks at any evidence. One "no"
keeps asking forever; only a rule you write undoes it. The test `a single denial is
permanent` trains 200 approvals on top of a 400-day-old denial and asserts it still
asks.

### An agent disabling LeastGrant

**Mechanism.** `guard.self-write` denies any non-read action whose target resolves
inside the state directory. It is the only guard that produces `deny`, and it sits at
step 1 of `decideOne()`, above your own rules — a wildcard allow rule of yours does
not override it (verified: a `match: "*"` allow rule still yields `deny`). The state
directory is canonicalized before comparison, because comparing a resolved path
against an unresolved boundary silently answers "no".

`guard.agent-config` raises `ask` for writes to `CONTROL_FILES`. The summary that used
to sit here listed only the agent settings files and "friends", which undersold the
list badly. The real categories:

- **Agent configuration** — `.claude/settings.json`, `.claude/settings.local.json`,
  `.claude/hooks`, `.cursor/hooks.json`, `.cursor/cli.json`, `.codex/config.toml`,
  `.gemini/settings.json`, `.copilot/hooks`, `.aider.conf.yml`,
  `.leastgrant/config.json`, `managed-settings.json`.
- **CI configuration** — `.github/workflows`, `.gitlab-ci.yml`,
  `.circleci/config.yml`, `azure-pipelines.yml`, `.github/hooks`. An edit here runs
  later, on someone else's machine, under someone else's credentials.
- **Editor task and launch configuration** — `.vscode/tasks.json`,
  `.vscode/launch.json`, `.devcontainer/devcontainer.json`.
- **`.git/config`**, which decides what `git` itself runs.
- **`.mcp.json`**, which decides which MCP servers the agent is wired to.
- **`package.json`**, because it holds the scripts that a later, already-approved
  `npm test` will execute.
- **Agent prompt directories** — `.claude/commands`, `.claude/agents`,
  `.claude/skills`. These are not settings, they are instructions a future session
  will follow as if you had typed them.
- **`AGENTS.md`, `CLAUDE.md`, `.cursorrules`**, for the same reason.

Ask, not deny, because these are files you edit by hand all the time. `package.json`
is the entry that costs real friction: on a JavaScript project the agent touches it
often, and every touch prompts. That is a deliberate trade — the scripts in it are
the payload of every `npm run` you have already trained — and it is the one you are
most likely to disagree with.

`AGENTS.md` and `CLAUDE.md` were dead entries until recently. `isControlFile()`
lower-cases the path before comparing, and those two were listed capitalised, so they
could never match anything — the instruction files that steer every future agent
session were the only control files not actually guarded. Fixed, and verified: a
`Write` to either now raises `guard.agent-config`, as does `echo x > CLAUDE.md`.

Both behaviours are asserted in `test/bypass.test.ts` under
`LeastGrant defends its own configuration`.

---

## 3. What it does not defend against

### Posture changes what a "floor" means

`Config.posture` has four values (`src/core/types.ts`), and the default is `assist`
(`DEFAULT_CONFIG` in `src/store/index.ts`). Two of the other three weaken guarantees
stated in section 2, so they belong here rather than in a settings table.

**`observe` turns everything off.** `preToolUse()` computes the verdict, writes the
ledger entry, updates session taint — and then `if (config.posture === 'observe')
process.exit(0)` *before* `emit()`. Nothing is sent to the agent. In observe posture
even `guard.self-write`, the one guard that produces `deny`, blocks nothing. It is a
recorder, not a gate.

**`strict` only strengthens.** `decideOne()` returns `ask` at step 5 before consulting
any evidence, so nothing runs freely except what an explicit allow rule covers.

**`autopilot` makes two concessions, and one of them is a hole in a section-2 claim.**
Both are bounded by `containedInProject()` in `decide.ts` — reach `workspace` or
`none`, exposure `none`, and no target that is secret or outside the workspace.

1. `guard.not-understood` is filtered out of the floors for such actions. Section 2
   says an action the parser could not fully account for always asks; in autopilot
   that is not true. Verified: `npm run build "unclosed` — a command whose tokenizer
   run fails, so `analysis.understood` is `false` — is auto-approved in autopilot
   after nine observations across two sessions. In `assist` the same command asks
   even after twelve human approvals.

   **The bound, stated precisely.** Autopilot waives this floor for code LeastGrant
   has not *read* that stays inside the project. It never waives it for code being
   *injected*.

   The not-read side was always covered, and the earlier wording was right about it:
   anything whose `action.understood` is `false` because the payload is hidden —
   `./run.sh`, `sh ./x.sh`, `frobnicate`, `./node_modules/.bin/foo` — classifies as
   `exec.unknown`, whose default reach is `machine`, so `containedInProject()` is
   false and the floor stands. Checked on all four, and on `make release`,
   `bash deploy.sh`, `source ./env.sh`, `docker exec c sh` and `npx cowsay hi`.

   The injection side was a hole, and the earlier wording missed it because it
   reasoned about programs rather than about wrappers. `bash --rcfile /tmp/evil -c
   ls`, `env -C /etc npm test`, `env BASH_ENV=/tmp/evil.sh npm test` and
   `git -c core.hooksPath=/tmp/evil commit` are opaque because something of the
   caller's choosing runs *as well as* the command we could read — but they kept
   classifying as whatever the inner command was (`fs.read.workspace`, `exec.test`),
   which is project-contained, so `containedInProject()` said yes and autopilot
   waived the floor. `INJECTS_EXECUTION` in `src/core/classify.ts` now widens reach
   to `machine` whenever the opacity came from an injecting wrapper — `shell-eval`,
   `env`, `git-config`, `privilege`, `deferred`, `dynamic`. Correcting the reach
   rather than the waiver is the right shape of fix: the reach was simply wrong, and
   the tier, the floors and the waiver should all be working from the corrected
   value. Verified in autopilot with the observation gate cleared: all four of those
   ask, while `npm run build "unclosed` still allows.

2. Observation alone may promote `easy`-reversible in-project actions, not just
   `trivial` ones. Section 2's `harmless` predicate is the `assist` rule. Verified:
   a `Write` to a file inside the project, seen nine times across two sessions with
   zero human approvals, is `ask` in `assist` and `allow` in autopilot.

Every other floor — credentials, exfiltration, writes outside the project,
persistence, privilege, pipe-to-shell, publish, production, irreversible, and the
integrity floors — still stands in autopilot, and the blast ceiling of
`maxTier: 2` is untouched. Autopilot is aimed at someone who would otherwise run with
permissions switched off, and it is strictly more protection than that. It is not the
posture the rest of this document describes.

### It fails open

If the hook crashes, times out, or exits with any code other than 2, Claude Code
records a non-blocking error and **the tool call continues through the normal
permission flow**. The documentation is explicit about it: "don't count on a stalled
hook to act as a gate." The installer sets `timeout: 10` seconds
(`src/cli/commands/install.ts`). The hook contract this section relies on is pinned in
the header of `src/adapters/claude-code/hook.ts` as verified against Claude Code
v2.1.240; if that contract changes, this section is the first thing to recheck.

What "continues through the normal permission flow" means depends on your settings.
If you are running in `default` mode with no matching allow rule, you get the usual
permission prompt and nothing is lost. If you are in `bypassPermissions`, or the call
matches an allow rule in your own `settings.json`, it runs with no prompt at all and
LeastGrant never had a say.

The code leans into this rather than fighting it. `runHook()` wraps everything and
exits 0 on any error; `appendLedger()` and `saveSession()` swallow their own failures
because a full disk must not stop you working. The worst case is "no opinion", never
"agent wedged".

**With one deliberate exception.** A crash inside `decide()` is not treated as
infrastructure failure. `judgePre()` catches it separately and returns `ask` with the
reason code `engine.error`, because an input that reliably crashed the classifier
would otherwise be a complete bypass: in `bypassPermissions` nothing else is
checking, so silence means the call simply runs. Verified against a stubbed `decide()`
that throws: `judgePre()` returns `{ decision: 'ask', reasons: ['engine.error'] }` and
logs the stack, and every posture but `observe` emits that as a prompt. Failures
anywhere outside the judging path — unreadable stdin, an unknown event name, a
config file it cannot load, a failed ledger write — still exit 0 with no opinion,
which is what the paragraph above describes.

**Why fail-closed was not available.** For a `command` hook installed into
`settings.json` — which is how LeastGrant ships, because that is what works with the
CLI you already have — exit code 2 is the only code that blocks. Exit 1 does not.
A timeout does not. There is no "if I do not answer, refuse" setting. The one route
that does fail closed is an Agent SDK callback hook, where a timeout blocks the tool
call, and that requires the SDK rather than the plain CLI. LeastGrant is a reliable
veto and a best-effort grant, and it is designed around that asymmetry.

A hook `deny` is absolute — it beats allow rules and `bypassPermissions`. A hook
`allow` is not — your own deny and ask rules still override it. Both directions are
the agent's contract, not our choice.

### Anything the agent does without asking

LeastGrant answers a question. If nobody asks the question, it has nothing to say.
This covers:

- A tool you have already allowed outright in `settings.json`. LeastGrant still sees
  the `PreToolUse` event, still writes the ledger, and a LeastGrant `deny` still
  blocks — but a LeastGrant `allow` adds nothing, and a LeastGrant `ask` is silently
  satisfied by your rule without you seeing a prompt. That last case is not neutral:
  it is recorded as `confirmed` evidence. See
  [Evidence inflation through your own allow rules](#evidence-inflation-through-your-own-allow-rules).
- An MCP server acting on its own between calls. LeastGrant sees `mcp__server__tool`
  and the name of the tool; it does not see what the server does afterwards.
- Code inside a script that was approved to run. Also see the next item.
- Anything outside the agent tool-call path entirely: your editor's own AI, a daemon,
  a CI job, you.

### Once a command is approved, LeastGrant has no further say

Approving `npm test` approves whatever the test script does, including
`postinstall`-style behaviour you have never read. `unwrap.ts` says as much when it
tags a `pkg-script` wrapper: "runs the `test` script from package.json, whose contents
are not analysed here."

The same is true within a single call. LeastGrant inspects a file path at decision
time; nothing stops that path from pointing somewhere else by the time the tool
opens it. `canonicalize()` resolves symlinks and memoizes the result for the lifetime
of the process (bounded at `CANON_CACHE_MAX = 4096` entries, flushed wholesale when
full), which is a few milliseconds for a hook invocation and much longer for a
replay — but even a zero-length window is a window. There is no atomicity here and
there cannot be, because LeastGrant does not hold the file.

### It cannot read code it has not been given

LeastGrant sees the tool call. It does not see the contents of anything the tool call
names. So it can tell you that code will run, and never what that code does:

| What it sees | What it cannot see | Marked opaque? |
| --- | --- | --- |
| `bash deploy.sh` | the contents of `deploy.sh` | yes, `unwrap.ts` (`script-file`) |
| `source ./env.sh` | the file it loads into the shell | yes, `unwrap.ts` (`script-file`) |
| `make release` | the recipe for `release` | yes, `unwrap.ts` (`make`) |
| `docker exec c sh` | anything inside the container | yes, `unwrap.ts` (`container`) |
| `python -c "..."` | what the inline program does — "runs code written straight into the command line, which could do anything" | yes, but by `src/core/knowledge/runtime.ts`, not by `unwrap.ts` |
| `npm run build` | the `build` script | **no** |

The first five all land on `understood: false`, and `src/core/types.ts` rule 1 makes an
action with `understood: false` unapprovable, so they ask every time. That is the
honest answer, and it is also the reason LeastGrant asks about more than you might
like on a repository built around shell scripts.

**`npm run` is the exception, and it is a real one.** `unwrap.ts` tags the
`pkg-script` wrapper and says in as many words that the script contents "are not
analysed here" — but it deliberately does *not* mark the action opaque, because
"`npm run test` is a meaningful, learnable unit". The package module then classifies
the action from the *name* of the script. `npm run build` comes out `exec.build`,
`understood: true`, blast tier 1, and after five approvals across two days and two
sessions LeastGrant stops asking about it — while still never having read a line of
the script. Verified: twelve approvals of `npm run build` yields `allow`. A script
whose name LeastGrant does not recognise falls back to `exec.unknown` at tier 3 and
keeps asking (`npm run deploy` does), so the exposure is bounded by the naming
convention and by nothing else.

### The classification knowledge base is opinion

`src/core/knowledge/` is 10,545 lines across seven files at time of writing —
judgements about what programs do: that `terraform apply` changes state outside this
machine and cannot be undone, that `aws s3 rm` cannot be undone, that `curl -d` can
exfiltrate. `src/core/knowledge/types.ts` says so in its header: "This is the part of
LeastGrant that is opinion rather than mechanism."

Those judgements are argv-sensitive in ways the summary above flattens. `terraform
apply` scores `reach: 'external'`; it only scores `reach: 'production'` when something
in the argv names production, as in `terraform apply -var env=prod`. Both land at
tier 4, so nothing turns on the difference here — but do not read a `reach` value out
of this document when you can read it out of `leastgrant check`.

It can be wrong. It can be out of date. A flag added to a tool last month may change
what that tool does without changing what LeastGrant thinks it does. A program with no
module falls through to `exec.unknown`, which is tier 3 and always asks — that is the
safe direction — but a program that *is* covered and covered wrongly is judged
wrongly, with no warning.

**A specific instance, found while writing this document, since fixed.** The floor for
credential reads fired on `blast.exposure` or `capability`, but not on whether the
action had a target the path classifier had already flagged as secret. Five commands
therefore read a credential file with no floor and no exposure, and were promotable
by ordinary learning:

```
tar -czf out.tgz ~/.ssh          exposure=none   tier=1   -> allow after training
zip -r out.zip ~/.aws            exposure=none   tier=1   -> allow after training
rsync -a ~/.aws/ ./b/            exposure=none   tier=1   -> allow after training
sort ~/.aws/credentials          exposure=none   tier=1   -> allow after training
openssl base64 -in ~/.ssh/id_rsa exposure=none   tier=1   -> allow after training
```

`cat`, `grep`, `tail`, `od`, `strings`, `xxd` and `cp` always handled it. The
difference was per-module, which is exactly the failure mode a knowledge base
produces.

`classify.ts` now overrides the module's answer from the resolved targets: any target
the secret classifier recognises forces `exposure: 'reads-secrets'`, and any target
outside the workspace forces `reach: 'machine'` and turns a workspace read or write
into an outside one. Targets are ground truth about where an action lands; a module
reasoning from a program's name and its flags often cannot see that. Re-measured, all
five now report `exposure=reads-secrets` at tier 3 or 4, trip `guard.secret-read`, and
still ask after thirty clean approvals.

Note what the fix does and does not reach. A target scan corrects a module that was
wrong about *where* an action lands. It cannot correct one that is wrong about *what
the program does* — a flag whose meaning changed, a subcommand nobody classified, an
argument that names a remote resource rather than a file. Nothing in the resolved
targets would show any of those, so the paragraph above this one still stands in full.

### Redaction is best-effort pattern matching

`redact()` in `src/core/secrets.ts` strips private-key blocks, GitHub, Anthropic,
OpenAI, Stripe, Slack, AWS, Google, GitLab, npm, DigitalOcean and Hugging Face token
shapes, JWTs, credentials embedded in URLs, `Authorization` headers, common password
flags, `NAME=VALUE` where the name smells like a credential, and — as a backstop —
any run of 28+ characters that mixes upper, lower and digits and scores Shannon
entropy of 3.6 or more.

The backstop has deliberate carve-outs, and they are holes as well as features:
`redactHighEntropy()` skips hex runs that look like git SHAs, MD5/SHA-1/SHA-256
digests, UUIDs, all-digit runs, subresource-integrity prefixes, and any token
containing `/` unless one slash-free run inside it is 12+ characters scoring 3.5+.
That last one exists so a ledger full of long file paths stays readable; it also
means a credential shaped like a path is not redacted.

It is pattern matching. A credential that matches none of those patterns and has low
entropy (a passphrase, a short internal token, a base64 blob of structured data) goes
into the ledger verbatim. The mitigation that actually holds is structural: the ledger
stores command lines, paths and reason codes, and never file contents. That bounds
the damage; it does not eliminate it.

`~/.leastgrant/ledger.jsonl` is plain text with your filesystem's permissions on it
and nothing else. Treat it as approximately as sensitive as your shell history.

### A local attacker who can write to your state directory has already won

If something can write to `~/.leastgrant`, it can add an allow rule, rewrite the
envelope, or set `posture: "observe"` and silence LeastGrant entirely. If it can write
to `~/.claude/settings.json`, it can remove the hook, or set `LEASTGRANT_HOME` in the
`env` block and point LeastGrant at an empty state directory — `stateDir()` reads that
variable, and the `guard.self-write` boundary moves with it.

`guard.self-write` and `guard.agent-config` exist to stop *the agent* doing these
things through a tool call, which is a real and common path. They do nothing against a
process that already has your uid and is not going through the hook. There is no
signing, no integrity check, and no attempt at one.

### The ledger is not tamper-evident

There is no hash chain, deliberately. `appendLedger()` writes one line with a single
`appendFileSync`, which is atomic enough on POSIX (`O_APPEND`) and Windows for
concurrent sessions. A hash chain needs a single writer and a lock, and a lock that
can wedge an agent mid-session is a worse failure than a log you cannot prove is
complete.

So: you can read the ledger, and you can tell that an entry says what it says. You
cannot tell whether an entry was removed. Do not build an audit process on it that
assumes otherwise.

Related: envelopes are read-modify-write, not append-only. `postToolUse()` does
`loadEnvelope` → `observe` → `saveEnvelope` with no lock, so two concurrent sessions
in the same project, or the miner running while a session is live, still race.

What that used to mean was last-writer-wins, and the dangerous half of it was that a
denial learned by the miner could be clobbered by a concurrent hook write — denials
being the one thing that is supposed to be permanent. Two changes closed that half.
`saveEnvelope()` re-reads the file immediately before writing and merges monotonically
in the direction of caution: denials, grants and counts all take the maximum of the
two sides. And every denial is journalled to `~/.leastgrant/denials.jsonl` on the way
out and replayed over the envelope on every load, so a refusal outlives the envelope
that recorded it.

What remains is a lost *count*. Two writers starting from a base of one approval and
each adding one produce two, not three — measured. That is in the safe direction: less
evidence means more asking. Neither writer can lose a no, and the test for it is
blunt: record a denial, delete the envelope file outright, then have a second writer
save thirty clean approvals on top. `canPromote()` still returns `previously-denied`.

### A malicious MCP server, dependency, or anything off the tool-call path

An MCP server's *tier* is decided by the shape of its tool name and nothing else.
`analyze()` splits `mcp__server__tool` and looks at the leading verb. `get`, `list`,
`read`, `search`, `query`, `status`, `describe` and friends score
`network / trivial / none / single`, which is tier 2. `exec`, `run`, `eval`, `invoke`,
`spawn`, `build` and friends score `machine / hard`, tier 3. Every name on neither
list is treated as a write at `external / hard`, also tier 3 — so a verb nobody
anticipated is judged a write, not a read. That is a naming
convention, not a capability check. A server whose `get_status` tool deletes your
database is judged as a read, and being wrong there is bounded only by the fact that
tier 2 still needs a human approval before it stops asking.

What the *arguments* buy is a narrower learned identity, not a better tier.
`mcpArgSignature()` in `src/core/signature.ts` puts a coarse shape of the input into
the signature: key names sorted, each value reduced to a placeholder. The signature
used to be the tool name alone, which was the widest collision in the system —
eleven approved `SELECT`s auto-approved a `DROP TABLE`, and
`get_document({})` auto-approved `get_document({destructive: true})`. Verified now:
`mcp__db__query(sql=<sql:select>)` and `mcp__db__query(sql=<sql:drop>)` are different
things, even though `query` is a read verb and both sit at tier 2. Booleans survive
verbatim, because `force` and `destructive` are exactly the arguments that decide what
a call does; a URL keeps its host, a path keeps its zone, a credential-shaped key
becomes `<redacted>`, and an identifier containing a digit collapses to `<id>` so that
one prompt per ticket does not happen. Adding a parameter is enough to make a call
new: eleven approvals of `query(sql=<sql:select>)` do not cover
`query(force=<true>, sql=<sql:select>)`.

None of that tells you what the server does when you call it. It only stops one
approved call from standing in for a different one.

A malicious npm or PyPI dependency runs inside a process LeastGrant already approved
and never appears as a tool call. Neither does a compromised VS Code extension, a
malicious git hook that fires during an approved `git commit`, or a build plugin.
LeastGrant is not in the path.

---

## 4. The adversarial model for the learning itself

The learning is the interesting attack surface, because it is the part that changes
what LeastGrant will permit. Five attacks, the structural countermeasure for each, and
the limit of that countermeasure.

### Boiling frog: escalate one small step at a time

**Countermeasure.** Structural, not statistical. `canPromote()` checks
`blastTier(blast) > th.maxTier` and returns `blast-too-high` before it reads a single
statistic. There is no sequence of tier-1 approvals whose sum is a tier-3 permission,
because tier is a property of the action being judged and not of its history. The
`Reach`, `Reversibility` and `Exposure` tables in `src/core/types.ts` are a `max`, not
an average — "an action that is trivially reversible but reads your SSH key is not
medium risk, it is a secret read." `Scale` is the one dimension that is additive
rather than a max: `SCALE_BUMP` adds 0/1/2 on top of that maximum, capped at 4, and
only when the base is already amplifiable (reach at `machine` or beyond, or hard/
irreversible, or any exposure). It only ever pushes a tier up.

**Limit.** The tier is only as good as the classification that produced it. Everything
in "the knowledge base is opinion" applies here in full: an action mis-scored as
tier 1 is promotable at tier 1, and the boiling-frog defence has nothing to say about
it. The `tar -czf out.tgz ~/.ssh` case above was exactly that — a boiling-frog attack
that worked, through a classification gap rather than a threshold gap. It is fixed.
Read it as an illustration of the shape of the problem rather than as evidence that
none of the shape is left.

### Burst poisoning during an unattended session

**Countermeasure.** Three layers. First, `hook.ts` classifies everything in
`bypassPermissions`, `acceptEdits`, `dontAsk` and `auto` as `observed`, never
`confirmed` — the mode approved it, not you. Second, the observation route in
`canPromote()` only accepts the `harmless` predicate quoted above: inside the project,
trivially reversible, no credential exposure, not sweeping. Third, both routes require
`minSessions: 2`, and the human route additionally requires `minDays: 2`, so a burst
inside one sitting teaches nothing.

**Limit.** Three of them.

The second layer is posture-dependent. In `autopilot` the observation route also
accepts `easy`-reversible actions inside the project, so nine observations across two
sessions are enough to stop LeastGrant asking about writes to project files that
nobody ever approved. See
[Posture changes what a "floor" means](#posture-changes-what-a-floor-means).

The session gate counts distinct session ids, and an agent that can spawn
`claude -p --permission-mode bypassPermissions` twice can manufacture two distinct
sessions and nine observations of whatever it likes. The bound on the damage is that
only `harmless` actions are reachable that way, and that spawning `claude` is itself
an unrecognised program at tier 3 which always asks — but the path exists.

Separately, the distinct-session set is capped: `observe()` keeps the last 16 session
ids per signature and shifts the oldest off (`if (recent.length > 16) recent.shift()`).
The list holds 16, so an id is evicted once 16 newer distinct ids have been recorded,
and recurs as a "new" session after that. Inflating `sessions` past 2 is not much of a
prize, but the count is not exact.

### Decomposing a bad action into benign parts

**Countermeasure.** Within one tool call, `decide()` judges every action separately and
the worst one wins. Across tool calls, `src/core/envelope.ts` keeps session taint:

```ts
export const TAINT_BY_CAPABILITY: Partial<Record<Capability, Taint>> = {
  'secret.read':      'read-secrets',
  'fs.read.outside':  'read-outside',
  'net.fetch':        'network-egress',
  'net.send':         'network-egress',
  'exec.pkg':         'fetched-code',
};
```

`taintConcern()` then raises three specific sequences: read-a-secret then send data
off the machine, read-a-secret then push to a remote, download-packages then run code
we cannot inspect. A concern turns an `allow` into an `ask` in `decide()`.

**Limit.** Three hard-coded pairs is a small vocabulary, and it only covers sequences
where the first step was classified with a tainting capability.

Concretely: `cp ~/.aws/credentials ./notes.txt` has `exposure: 'reads-secrets'` and
does trip `guard.secret-read`, so you are asked about it. But its *capability* is
`fs.write.outside`, and `applyTaint()` keys on capability alone — so approving that
copy leaves the session untainted, and a later `git push` gets no taint warning. The
guard and the taint disagree about what counts as reading a secret. Anything that
launders a credential into an ordinary-looking file in one step defeats this.

Taint also lives in a per-session file under `~/.leastgrant/sessions/`, pruned after
24 hours, and does not cross sessions. Split the read and the send across two
conversations and there is no link at all.

### Normalization collisions

**Countermeasure.** `normalizeArg()` templates the parsed argv, never the raw string,
and preserves the distinctions that matter for risk: a path becomes `<path>`,
`<path:outside:…>` or `<path:secret>`, a URL keeps its hostname. Flags are kept because
they change behaviour, and sorted because their order does not.
`familyOf()` produces a coarser key for explanations and is documented as never
granting permission, "because a family is exactly the kind of generalization an
attacker would aim at."

**Limit.** This is the sharpest limit in the document, so here it is with the receipts.

`<path:outside>` used to be a single equivalence class: every path outside the
workspace not recognised as a secret collapsed into one token, so approving a single
out-of-project read taught LeastGrant to allow any of them. `outsideZone()` in
`src/core/signature.ts` now splits it by region — `etc`, `system`, `runtime`, `temp`,
`home`, `other`. Actual output:

```
train:  cat /etc/hosts   x11 human approvals, 2+ days, 2+ sessions
        signature learned: "cat <path:outside:etc>"

then:   cat /etc/hosts            -> allow
        cat /etc/passwd           -> allow   (same signature)
        cat /etc/resolv.conf      -> allow   (same signature)
        cat /var/log/auth.log     -> ask     (<path:outside:runtime>)
        cat /usr/share/dict/words -> ask     (<path:outside:system>)
        cat /tmp/x.txt            -> ask     (<path:outside:temp>)
        cat ~/notes.txt           -> ask     (<path:outside:home>)
        cat /etc/shadow           -> ask     (<path:secret>)
```

The same holds for the structured tools: eleven approvals of `Read /etc/hosts`
promotes `Read(<path:outside:etc>)`, which covers `Read /etc/resolv.conf` and not
`Read /var/log/auth.log`. URLs are not split at all: `curl <url:api.github.com>`
covers every path on that host, so approving `curl https://api.github.com/user`
approves `curl https://api.github.com/anything`.

So the class is narrower than it was, and it is still a class. Everything under `/etc`
that the secret classifier does not recognise is one learned thing, and approving
`cat /etc/hosts` really does cover `cat /etc/passwd`. The zones are deliberately
coarse — a per-directory token would never accumulate enough evidence to settle, which
is its own failure mode — so this is a smaller version of the same trade, not the
removal of it.

What holds the line inside a zone is the secret classifier in `src/core/secrets.ts` —
its `SECRET_DIRS`, `SECRET_FILES` and `SECRET_EXTS` lists are what keep `/etc/shadow`
and `~/.ssh/id_rsa` in a different bucket from `/etc/hosts`. Any credential-bearing
file those lists do not recognise is inside the same equivalence class as the one you
approved. You can extend the lists with `secretPatterns` in your config.

Templating per-file would mean learning nothing, and a tool that learns nothing gets
uninstalled. But you should know what you are agreeing to when you approve an
out-of-workspace read: you are approving a region, not a file.

### Waiting for a denial to decay

**Countermeasure.** Denials do not decay. `observe()` applies the 90-day decay factor
to `confirmed` and `observed` and skips `denied` entirely. `familiarity()` does the
same on read: `const denied = s.denied; // never decays`. And `canPromote()` returns
`previously-denied` before it evaluates any evidence at all. Only a rule you write
removes it.

**Limit.** The permanence no longer depends on the envelope file surviving: denials
are journalled to `denials.jsonl` and replayed on every load, and `saveEnvelope()`
merges rather than overwrites, so the race described in section 3 can lose a count
but not a no. Verified by deleting the envelope and checking the denial still binds.

What remains is a delay. Denials are only ever *learned* from mined transcripts:
`isDenial()` in `mine.ts` recognises `toolDenialKind: "user-rejected"` (and the two
prose forms Claude Code feeds back to the model), and `evidenceFor()` turns that into
`denied` — the one kind of evidence mining still produces besides `observed`. The live
hook cannot record one, because a rejected tool call never fires `PostToolUse`. So a
refusal you make today is not in the envelope until the next time you mine.

### Evidence inflation through your own allow rules

Worth stating separately, because it undercuts "only human-attested evidence promotes".

`postToolUse()` records `confirmed` when LeastGrant said `ask` and the mode was
attended. But Claude Code's own `permissions.allow` rules approve a call in `default`
mode without prompting you. So if your `settings.json` already contains
`Bash(curl:*)`, every `curl` LeastGrant asks about is silently approved by that rule
and recorded as though you had clicked yes. Eleven of those and LeastGrant stops
asking on its own account too.

A defensible reading is that you did write the rule, so a human did author something.
But it is a weaker form of attestation than the name `confirmed` suggests, and it
applies to exactly the tools most likely to be allowlisted.

The mining half of this effect used to be worse and is now gone. `evidenceFor()` in
`mine.ts` no longer returns `confirmed` at all; mining yields `observed` and `denied`
and nothing else. The allow-rule ambiguity was the small reason. The large one is that
transcripts are files, and files can be written: an agent talked into writing to
`~/.claude/projects/` can fabricate months of plausible history, and `leastgrant init`
read it as hundreds of human approvals. Measured, that forgery promoted an outbound
`curl` to an attacker-chosen host on the strength of nothing at all. Mining is now
demoted to what it can honestly claim — this is what *typically* happens here — and
the attestation is the human accepting or rejecting what setup offers on the strength
of it.

The cost was measured on 10,800 real actions before the change: the auto-approve rate
after setup is identical at 42%, the same starter bundles are proposed with the same
coverage, and the only number that moves is the rate *before* the user has agreed to
anything, which falls from 9% to 5%. Denials are still mined, because the worst a
forged denial can do is make LeastGrant ask about something it would otherwise have
allowed, and an explicit rule undoes it.

So the inflation described at the top of this section is the hook's, and only the
hook's.

---

## 5. Trust boundaries

Five things LeastGrant trusts. If any of them is compromised, the guarantees above do
not hold.

1. **The agent.** LeastGrant trusts that Claude Code sends a faithful `PreToolUse`
   event before every tool call and honours a `deny`. A modified agent, or a tool call
   the agent does not hook, is invisible.
2. **The hook process.** It runs as you, with your environment, reading
   `LEASTGRANT_HOME` from it. Anything that can influence that environment or replace
   `bin/leastgrant.js` controls the decision.
3. **The state directory** (`~/.leastgrant`, or `$LEASTGRANT_HOME`). Config, rules,
   envelopes, session taint and the ledger. Filesystem permissions are the only
   protection; there is no signing and no integrity check.
4. **The transcripts it mines** (`~/.claude/projects/**/*.jsonl`, or
   `$CLAUDE_CONFIG_DIR`). `leastgrant init` reads these to build a starting profile.
   They are written by the agent, and this boundary is deliberately weaker than it
   was: nothing mined counts as human approval in any permission mode, because a file
   that can be written can be forged. What someone who can write these files still
   gets is influence over what setup *offers* you, and the ability to plant a denial.
   The permission mode recorded in them now only feeds the summary `leastgrant init`
   prints about your own history; it no longer decides what evidence is worth. Note
   that transcripts record refusals distinguishably but *approvals* not at all — an
   auto-approval and a click look identical, which is the fact that forced that
   demotion.
5. **The knowledge base** (`src/core/knowledge/`). Compiled in, so it is trusted at
   build time rather than run time — a supply-chain compromise of LeastGrant itself is
   a compromise of every judgement it makes. `classify.ts` also exports
   `registerKnowledge()`, where later registrations override built-ins; it has no
   callers anywhere in the repository today, not even in the tests, but if a plugin
   loader is ever added, that becomes a live boundary and this list gains a sixth
   entry.

---

## 6. What the v0.1.0 audit found, and what it left standing

Before the first release this document was treated as a set of claims to be broken
rather than a description to be trusted. Independent passes reproduced the assertions
above against the shipped binary, a differential fuzzer compared the shell parser
against bash itself, and hostile inputs were driven at the hook over real stdin. That
turned up nine classes of genuine bypass, all now fixed and all with regression tests.
They are listed here rather than buried in a commit log, because a threat model whose
history is invisible is asking to be taken on faith.

**Fixed during the audit.** Each of these produced a real `allow` for something that
should have asked:

1. **Wrappers that swallowed a token.** `env LD_PRELOAD=… npm test` had a signature
   byte-identical to `npm test`, because `env`'s assignments were stripped without
   being checked. So did `git -c core.hooksPath=… commit` versus `git commit`, and
   `BASH_ENV=… sh -c ls` versus `ls`. Each inherited every approval the honest command
   had earned. The rule now is that a wrapper may not silently discard a token: it
   either changes the judgement or marks the command opaque.
2. **Wrapper flags that inject code.** `bash --rcfile /tmp/evil -c ls` sources a file
   before it runs anything, and `env -C /etc npm test` moves every relative path in the
   command. Both were treated as cosmetic.
3. **Autopilot laundering injected code.** The concession autopilot makes — unreadable
   code that stays inside the project — was keyed on the classified action's reach, and
   an injecting wrapper left the inner command looking modest. Injected execution now
   widens reach to `machine`, so the concession no longer covers it.
4. **A crash was a bypass.** A `tool_input` of `{command: {toString: 'curl'}}` made the
   classifier throw. The hook fails open by design, so the call ran with LeastGrant
   silent — and in `bypassPermissions` nothing else was checking. Judging is now
   wrapped separately from the infrastructure around it and emits `ask` on error.
5. **Forged history.** `leastgrant init` mines `~/.claude/projects/*.jsonl`, and an
   agent that can write files can write those. Sixty days of fabricated approvals
   promoted an outbound `curl` to an attacker-chosen host. Mining no longer produces
   human-grade evidence at all.
6. **Credentials in signatures.** A signature is the half that gets stored, and it was
   not being redacted: `--password=`, `AWS_SECRET_ACCESS_KEY=`, `mysql -p hunter2`,
   `curl -u user:pass` and an MCP argument under a key called `value` all reached disk
   in clear, including `denials.jsonl`, which is never pruned.
7. **`..` after a symlink read as inside the project.** `path.resolve` collapsed
   `..` in the string before any link was followed, so a path that climbed out
   through a symlinked directory — including onto a credential file — was reported
   as contained. Resolution is now done per component, both the physical and lexical
   readings are kept, and containment requires all of them. See §2 for why there is
   no single correct answer to have picked instead.

   Attacking that fix turned up three more holes of the same shape — a path that
   never reaches the resolver is never checked, however good the resolver is.
   **Input redirects** (`grep -n TODO < ~/.ssh/id_rsa`) were filtered out by a test
   for `>`, so the target was dropped: no containment check, no credential check, no
   target recorded, and a signature identical to the same command in a pipeline. It
   was the most exploitable thing found in the whole audit, because every
   stdin-reading filter was a vehicle and the training needed was entirely ordinary.
   **Attached short-flag values** admitted `/`, `~` and `.` but not a drive letter,
   so `unzip a.zip -dC:/Windows/Temp` read as a project-local write while the
   detached spelling read as outside. And **`Glob`'s `pattern`** was never resolved
   at all, so `Glob {pattern: "~/.ssh/*"}` was an ordinary project read while
   `Glob {path: "~/.ssh"}` was a credential read. One more was found in the fix
   itself: `~` expansion used `path.join`, which collapses `..`, so a tilde-spelled
   traversal skipped the new walk entirely and got the old answer.
8. **Lost evidence and lost taint under parallel calls.** Agents issue tool calls in
   parallel, and each hook process rewrote one shared session file. Measured on forty
   concurrent calls, thirty-six recorded nothing — and the same file holds the taint
   set that connects a credential read to a later outbound call.

**What is still true, and is not going to be fixed by v0.1.0.** These are the ones to
weigh before trusting this:

- **Not a sandbox.** Everything here is a decision layer. Once a call is approved,
  LeastGrant has no further say, and it cannot see what a program does after it starts.
- **Fails open outside the judging path.** An unreadable stdin, a full disk, a config
  that will not parse: the hook exits 0 with no opinion and the agent proceeds. This is
  deliberate — a permission tool that wedges the agent gets uninstalled — but it means
  LeastGrant is not a control you can rely on being present.
- **44.5% of real commands are marked not-understood.** Inline code (`python -c`), script
  files, package runners and unknown binaries cannot be reasoned about, so they always
  ask. That is the honest answer and it is also the single largest source of prompts.
- **Forged history can still promote harmless work.** Mining now yields observation
  only, and observation only promotes trivially-reversible project-local reads. A forged
  transcript can therefore still buy silent reads of project files — not nothing, but a
  long way from where it was.
- **MCP tiering rests on the tool's name.** `get_*` reads as a read. A server whose
  `get_status` deletes your database is judged wrongly, and eleven human approvals will
  settle it. Arguments now form part of the identity, which bounds the damage to that
  exact call shape, but the name still drives the tier.
- **Redaction is best-effort and always will be.** It recognises shapes. A low-entropy
  secret under an unremarkable flag will pass through into a stored signature. The
  `«redacted»` markers tell you where it caught something; nothing tells you where it
  did not.
- **The Cursor adapter has never run inside Cursor.** It is written against the
  published hook contract and unit-tested both ways, including a test that it agrees
  with the Claude adapter — but nobody has confirmed that Cursor invokes it. Cursor's
  `beforeReadFile` also has no "ask", so an unfamiliar read there is allowed rather than
  blocked; a credential read is denied.
- **Concurrent calls still lose ordering.** Pending records and taint are now merged
  rather than overwritten, but `lastCapability` — which drives the "unusual transition"
  signal — is last-writer-wins across parallel calls. That weakens a heuristic; it does
  not weaken a floor.
- **Approvals are per-signature, and a signature is a generalisation.** `<path>` is one
  identity for every file in the project; `<path:outside:home>` is one for everything
  under a home directory. Approving one member of an equivalence class approves the
  class. The classes are drawn where the risk changes, but they are classes.
- **The calibration numbers come from one machine.** 59 sessions, 20 projects, one
  developer's command mix. `scripts/verify-claims.mjs` exists so you can replace them
  with yours rather than believing these.
- **A symlink swapped after the check still wins.** Resolution reads the filesystem
  at decision time. Nothing stops a link being repointed between the verdict and the
  command running — the time-of-check-to-time-of-use race that §3 declines to defend
  against, because defending it needs a sandbox and this is not one.

---

## 7. What the multi-agent audit found

Adding the Codex and Copilot adapters widened the attack surface in a way the v0.1.0
audit could not have covered: three more agents, each with its own wire format, its own
permission modes, and its own idea of what to do when a hook misbehaves. The same
treatment was applied — independent adversarial passes with every reported finding
reproduced or refuted against the shipped binary — and it found more than the first
audit did, in a smaller amount of new code.

Two of these were reachable in the field, not in theory, and both are the same shape:
LeastGrant returning a confident answer about something it had not actually judged.

**A floor on any part of a compound command was erased.** `decide()` picks a "worst"
action by decision rank and then by blast tier, and the verdict's `floor` flag was read
off that one action's guards. In `rm -rf ./build && cat ~/.ssh/id_rsa` the delete has the
larger blast tier and fires no guard at all, so it won the sort — and the credential
read's `guard.secret-read` vanished from both the reasons and the floor. Under Claude
Code this only cost a sentence of explanation, because the decision was still `ask`. It
became a hole the moment an adapter used `floor` to decide something, which is exactly
what the Codex adapter does when it cannot express `ask`: floor false means "merely
unfamiliar", so it stood aside and the credential read ran. `floor` and the reasons now
aggregate across every action.

**An untranslatable call was reported as a clean one.** The Codex adapter normalised an
unrecognised `tool_input` to `{}`, and `{}` is not "unknown" — it is "a call with no
arguments". The engine judged that as a fully understood, floorless no-op. So a shell
command sent as a bare string or as Codex's argv array, and a patch whose target path the
adapter could not find, all came back clean. An adapter that cannot faithfully translate
a call must not produce a verdict about it; it now says so and fails strict.

**Also fixed.** A hook command that quoted the path to `node.exe` never ran at all under
PowerShell, which is the shell Codex and Copilot both use on Windows — Codex then failed
open and enforced nothing, Copilot failed closed and blocked everything. `--agent=codex`
in its equals form defeated the routing check, sending Codex a response shape it rejects
and then ignores. `dontAsk` was used as proof-of-Codex when it is also a Claude Code
mode, pulling Claude Code traffic into an adapter that cannot ask. An absent
`permission_mode` — which Copilot never sends — was read as "a human approved this", so
completed calls were banked as `confirmed` evidence, the one kind that promotes a
signature. The installer's marker was the bare substring `leastgrant`, so it overwrote
and deleted third-party hooks that merely mentioned the word, in direct contradiction of
its own stated contract. A settings file containing a JSON array was reported as
successfully installed while nothing was written.

**What this says about the design.** Every one of these lives at a boundary — between an
agent's vocabulary and LeastGrant's, or between "I judged this" and "I could not". None
of them is a flaw in the decision engine's reasoning; all of them are places where an
adapter answered a question it had not asked. That is the failure mode to look for in the
next adapter, and the reason each of them now fails strict rather than quiet.

**Still standing.** In an unattended Codex mode, a command LeastGrant cannot read — the
`python -c '<anything>'` class, which is roughly half of real traffic — is left ungated
rather than denied. That is a deliberate trade explained in the README: denying it would
block most of an unattended run, and a gate that blocks most of your work is a gate people
remove. It is the same hole you already have by running unattended at all, so LeastGrant
does not make it worse; it also does not close it.

---

## 8. Reporting

See [SECURITY.md](SECURITY.md) for how to report a vulnerability privately, and for the
project's definition of one: any input that causes LeastGrant to return `allow` for an
action that should have been asked about or denied.

Two things are worth more than anything else:

- **A bypass.** A command that LeastGrant auto-approves and should not. If you have
  one, the best possible form for it is a new entry in the corpus in
  `test/bypass.test.ts` — one line, a name and a command. That file is the project's
  real specification.
- **A claim in this document that the code does not support.** A threat model that
  overstates is worse than no threat model, and the value of this one is entirely in
  its accuracy.
