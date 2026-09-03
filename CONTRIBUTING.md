# Contributing to LeastGrant

LeastGrant sits between a coding agent and the machine and decides, per tool call, whether to
allow, ask, or deny. That position sets the rules for everything below. Code on this path runs
before every single tool call your agent makes, so it has to be fast, it has to be readable in
an afternoon, and when it is unsure it has to stop rather than guess.

## Build and test

You need Node 20.10 or newer (`engines.node` in `package.json` is `>=20.10.0`).

```
npm install
npm run build
npm test
```

- `npm run build` runs `tsc -p tsconfig.json`. Output lands in `dist/`, mirroring the source
  tree, so `src/core/decide.ts` becomes `dist/src/core/decide.js` and `test/bypass.test.ts`
  becomes `dist/test/bypass.test.js`.
- `npm test` builds first, then runs `node --test --test-reporter=spec "dist/test/**/*.test.js"`.
  If the build fails, the tests do not run.
- `npm run test:fast` skips the build and runs whatever is already in `dist/`. Use it in a loop
  next to `npm run watch`.
- `npm run typecheck` is `tsc -p tsconfig.json --noEmit` when you only want the errors.

To try the CLI without installing it globally:

```
node bin/leastgrant.js check "git push --force origin main"
```

Point `LEASTGRANT_HOME` at a scratch directory when you are experimenting, so you do not write
into your real `~/.leastgrant`:

```
LEASTGRANT_HOME=/tmp/lg-scratch node bin/leastgrant.js check "npm test"
```

## Zero runtime dependencies

`package.json` has an empty `dependencies` block, and it stays empty.

The only devDependencies are TypeScript and the Node type definitions. Tests use `node:test`
and `node:assert/strict`. Argument parsing, terminal rendering, glob matching, and the shell
parser are all hand-written in this repository — not because writing them was fun, but because
of where this code runs.

A dependency here is not a dependency in a web app. It is code that executes inside the process
that decides whether your agent may read `~/.ssh/id_rsa`, on every tool call, forever. Three
consequences:

- **Supply chain.** A compromised transitive package would be running in the one process
  specifically designed to catch that class of problem. There is nothing clever we could do
  about it from inside.
- **Auditability.** The pitch is that you can read this tool and decide whether to trust it. That
  stops being true the moment "read it" means reading a lockfile with four hundred entries.
- **Speed.** The hook is a fresh Node process before every tool call, so the round trip is
  dominated by process creation and Node boot — neither of which we control. Module load is the
  part we do control, and every import adds to it. This is why `src/main.ts` dispatches to
  commands with dynamic `import()` and checks the `hook` case first, and why the hook path in
  `src/adapters/claude-code/hook.ts` never touches the CLI renderer or the transcript miner.
  If you want a number, measure it on your own machine; this repository does not currently
  record a benchmark, and the figures vary by an order of magnitude across platforms.

If you find yourself wanting a package, the answer is usually a smaller feature. If it really is
not, open an issue before the pull request.

## What is most useful to contribute

In order.

### 1. A knowledge module, or a correction to one

`src/core/knowledge/` is where the opinions live. Everything else is mechanism: the tokenizer
either parses `sed -i` or it does not, and it is testable in one line. But whether `sed -i`
should be a workspace write or a machine write, and whether `git gc --prune=now` deserves to be
called irreversible, are judgement calls. They are also the calls most likely to be wrong,
because there is no way to be right about `terraform` by reading the `terraform` help text
alone — you have to have been burned by it.

So a correction is worth as much as a new module. If LeastGrant asks you about something
harmless forty times a day, that is a bug in the knowledge base and it is worth reporting with
the same seriousness as a missed danger. A permission tool that cries wolf gets uninstalled, and
then it protects nobody.

### 2. A bypass case for `test/bypass.test.ts`

That file is the corpus of ways people have historically defeated command allowlists. Its test
harness first trains LeastGrant with forty sessions of human approvals for `git status`,
`npm test` and friends, and then checks that a dangerous variant wearing the same shape is still
not auto-approved.

If you can think of a shape that is not in there, add it. You do not need to fix it in the same
pull request — a failing case with a name is a contribution on its own, and it tells us
something we did not know.

The cases live in
[`corpus/bypasses.json`](https://github.com/leastgrant/leastgrant/blob/main/corpus/bypasses.json),
not in the test. The corpus is not in the published package — it is a repository artifact — which
is why that link leaves the tarball. Add an object to
`cases` with an `id` of the form `class/short-name`, the `class` it belongs to (one of the keys in
`classes`), the literal `command`, an `expect` of `not-allow`, and a one-line `note` saying what the
shape is. `test/bypass.test.ts` iterates the file, so a case needs no test code of its own.

`expect: "not-allow"` rather than a specific verdict, because the claim being tested is "this is
never waved through", not "this produces exactly this verdict".

### 3. An adapter for another agent

`src/adapters/claude-code/` has two pieces: the hook (`hook.ts`) and the transcript miner
(`mine.ts`). An adapter's whole job is to translate an agent's native event shape into the
`Request` interface in `src/core/types.ts` and translate a `Verdict` back into whatever the agent
expects on stdout. The decision engine is agent-agnostic and should stay that way.

Before you start, find out four things about the target agent and write them down in the
adapter's header comment, the way `hook.ts` does:

- What happens when the hook crashes, times out, or exits non-zero. Per the contract recorded in
  `hook.ts` (verified against Claude Code v2.1.240), every exit code *other than 2* is a
  non-blocking error and Claude Code **proceeds with the tool call**. Exit 2 is the one code that
  blocks. On Claude Code and Codex CLI, LeastGrant therefore fails open: `runHook` catches
  everything and `emit()` always exits 0. Cursor, Copilot and Antigravity block the call
  instead — `failure.onCrash` in [`compatibility/`](compatibility/) records which is which.
- Whether a hook `deny` is absolute, and by which mechanism. This is the claim most easily
  overstated, and it took live probes on all five shipped agents to earn it: every one of them
  now records `verdicts.deny` as `honoured` with `evidence: probe`, Claude Code in its most
  permissive mode and Codex under `--dangerously-bypass-approvals-and-sandbox`. Read the notes in
  [`compatibility/`](compatibility/) rather than assuming it transfers — the mechanism differs.
  Claude Code documents **exit 2** as the unconditional block, and LeastGrant does not use exit 2:
  `emit()` writes `hookSpecificOutput.permissionDecision` and exits 0. That the JSON path has the
  same reach was established by running it, not by reading the contract. If you are writing a new
  adapter, find out which mechanism your agent honours, probe it, and write down which one you
  used and what you saw.
- What a hook `allow` is worth. In Claude Code it is not absolute: the user's own deny and ask
  rules still override it. LeastGrant aims to be a reliable veto and a best-effort grant, and
  the product is built around that asymmetry.
- Whether there is a post-execution event. Without one, the tool still protects you but it never
  learns, because a PostToolUse event is the only way to tell "the human approved this" from
  "the mode approved this".

`src/cli/commands/install.ts` already has partial wiring for Cursor and the GitHub Copilot CLI.
Both are less complete than the Claude Code path. The Cursor installer says so in the note it
prints ("Cursor support is newer than the Claude Code integration and covers shell, MCP and
file reads only"); the Copilot installer sets no note at all, which it should.

## Adding a knowledge module

A knowledge module answers one question for a family of programs: given this argv, what
capability is being used and how far can it reach? Copy `src/core/knowledge/coreutils.ts` — it is
the model, and it covers most of the shapes you will need.

### The interface

From `src/core/knowledge/types.ts`:

```ts
export interface ProgramKnowledge {
  /** Base program names handled, lowercased, no extension. */
  names: string[];
  /** One-line description. */
  describe: string;
  classify: Classifier;
}

export type Classifier = (argv: string[], ctx: KnowledgeCtx) => Judgement | null;
```

`argv[0]` is the base program name, already unwrapped: by the time your classifier runs,
`sudo`, `env FOO=bar`, `nohup`, `timeout 5`, `ssh host` and friends have been peeled off by
`src/core/shell/unwrap.ts`, and the wrapper tags are applied on top of your judgement by
`src/core/classify.ts`. You are looking at the inner command.

`ctx` gives you five things and no more: `cwd`, the workspace `roots`, and the three predicates
`resolve(arg)`, `inWorkspace(abs)` and `isSecret(abs)`. Resolve before you judge — a path
argument is only "outside the project" after canonicalization.

A `Judgement` is deliberately sparse. State only what differs from the capability's default:

```ts
export interface Judgement {
  capability: Capability;
  reach?: Reach;
  reversibility?: Reversibility;
  exposure?: Exposure;
  scale?: Scale;
  note?: string;
  pathArgs?: number[] | 'auto' | 'none';
  targets?: Target[];
  opaque?: boolean;
}
```

The defaults come from the `CAPABILITY_DEFAULTS` table in `src/core/knowledge/types.ts`, just
below the interfaces above. Read that table before you start overriding fields — most
invocations need nothing but a `capability` and a `note`. Keeping judgements sparse is what stops
the knowledge base from turning into thousands of copy-pasted risk tuples that nobody can audit.

Shared helpers, also from `types.ts`, so you do not hand-roll flag parsing: `firstNonFlag`,
`nonFlags`, `hasFlag`, `flagValue`, `hostOf`.

### Conservative by default

Returning `null` declines the argv. The next module gets a turn, and if nobody claims it,
`src/core/classify.ts` produces `exec.unknown` with `opaque: true`. That makes the action
`understood: false`, which trips `guard.not-understood`, which means LeastGrant asks.

Be precise about how strong that is, because two nearby comments in the tree overstate it. The
doc comment on `Action.understood` in `src/core/types.ts` says a false there "makes
auto-approval impossible, by construction", and that is not what `decide.ts` does. In autopilot
posture `decideOne` explicitly filters `guard.not-understood` out of the effective floors when
`containedInProject(action)` holds, and the code comment above that filter says so in as many
words: unreadable code that stays inside the project is allowed to be learned. What actually
stops such an action today is the *tier ceiling*, not the floor — `exec.unknown` defaults to
`reversibility: 'hard'`, which is blast tier 3, and `th.maxTier` is 2, so `canPromote` refuses
before it looks at any evidence. Verified by running the engine: in autopilot a saturated
`mvn foo:bar` (workspace reach, `understood: false`) loses the floor and is then held by
`gap.blast`.

So the accurate statement is: in `assist` and `strict` the not-understood floor always holds; in
`autopilot` it does not, and containment plus the tier ceiling is what is holding the line. If
you give an opaque judgement a `reach` inside the workspace *and* a reversibility of `easy` or
`trivial`, you will have made an unreadable action auto-approvable in autopilot. Do not.

Declining is safe in every posture, because the `exec.unknown` fallback keeps the machine-reach
default. Narrowing an opaque judgement is the risky move.

The same applies inside a module. Three rules:

- **If you cannot see the effect in the argv, set `opaque: true`.** A script name, a Makefile
  target, an interpreter's `-c` payload, `git rebase --exec`, `tar --to-command`. You know the
  program runs *something*; you do not know what. Say so rather than guessing.
- **Widen, do not narrow, when unsure.** `coreutils.ts` treats `dd` with an `of=` pointing at
  `/dev/sd*` as machine reach and irreversible, because being wrong in the other direction is
  unrecoverable.
- **A flag that changes the verb changes the judgement.** `sed` is a text filter until `-i`, at
  which point it is a write. `find` is a search until `-delete`. `sort` is a filter until `-o`.
  `git push` is different from `git push --force`. Those pairs are the interesting part of every
  module; the boring majority is easy.

Do not add a floor from inside a knowledge module. Floors live in `src/core/guards.ts` and are a
separate, deliberately short, deliberately boring file. A module's job is to describe the action
accurately; the guards decide what *learning* can never auto-approve.

Note the exact strength of a floor, from the precedence list at the top of `src/core/decide.ts`.
A guard hit with `decision: 'deny'` — today only `guard.self-write` — is checked first and
nothing overrides it. A guard hit with `decision: 'ask'` sits at step 4, *below* explicit rules
at steps 2 and 3, so a user's own `leastgrant allow` rule satisfies an ask floor. That is
deliberate and the header comment explains why: a floor exists to get a human answer, and a rule
is a human answer given in advance. "Floor" means learning cannot unlock it, not that nothing
can.

### The note

`note` is a plain-English clause appended to the explanation the developer reads at 2am. It is
not a log line and not a label.

- Lowercase, no trailing period, reads as a continuation.
- Say what happens, not what category it is in. `overwrites history on the remote, discarding
  commits anyone else may have already pulled` (the real note on a force push, in `vcs.ts`)
  beats `high-risk VCS operation`.
- No scores, no severities, no CVSS, no colours-as-nouns.
- Address the reader as "you" where a subject is needed.

Good notes already in the tree: `deletes every matching file`, `writes directly to a device`,
`tar --to-command runs a program for each entry`, `runs whatever the download returned, as a sh
script`.

### Register it

One import and one array entry in `src/core/classify.ts`:

```ts
const MODULES: ProgramKnowledge[] = [coreutils, vcs, packages, cloud, runtime, network];
```

Order matters only where two modules claim the same program name: later entries win, which is
why the specialised modules are listed after `coreutils`. Nothing else in the codebase needs to
know your module exists.

There is also `registerKnowledge(mod)` exported from the same file, for tests and plugins. It
appends to `MODULES` and invalidates the lookup index, so a registration made at test time
overrides a built-in.

### Add tests

At minimum, for each program you claim:

- The common invocation, asserting the capability and that it is not over-graded. The point of a
  module is to make routine work quiet.
- The dangerous variant that looks almost the same, asserting it is not auto-approvable.
- Anything you marked `opaque`, asserting `understood === false`.

Use `analyze()` from `src/core/classify.ts` when you want to assert on the action, and `decide()`
from `src/core/decide.ts` when you want to assert on the verdict. `test/bypass.test.ts` shows
both, including how to build a saturated envelope with `observe()` so that "even after heavy
training" is part of the assertion rather than an assumption.

## House style

Match the comments already in the source; they are the style guide.

**Comments explain why, not what.** The code says what. A comment earns its place by recording
the reasoning that is not recoverable from reading it — the measurement that motivated a
threshold, the attack a check exists to stop, the thing that was tried first and did not work.
The comment inside `blastTier` in `src/core/types.ts`, above the `amplifiable` check, explaining
why scale only amplifies where there is something to amplify, is the shape to aim for.

**No risk scores in user-facing text.** Blast radius is a set of independent dimensions — reach,
reversibility, exposure, scale — not a number. `blastTier()` collapses them into 0..4, and that
ordinal exists only for threshold comparisons; it must never be printed. `0.7314` is not an
explanation. `reach: network` is.

**Plain English, addressed to the developer.** Say "you", not "the user". No marketing, no
hedging, no security jargon. Never claim a guarantee the code does not provide — where something
is a heuristic, the code already says so out loud (see the MCP verb heuristic in `classify.ts`
and the redactor comment in `secrets.ts`), and so should you.

**Fail closed when uncertain.** Every place where LeastGrant does not know something, the answer
is to ask, never to assume. An unparseable command is `understood: false`. An unrecognised
program is `exec.unknown`. A corrupt envelope degrades to "I know nothing", never to "everything
is allowed". If you add a code path with an "or else" branch, make sure the else branch is the
cautious one.

Two exceptions worth knowing, both deliberate and both in the code today:

- The hook itself fails *open*, because Claude Code proceeds when a hook errors and there is
  nothing we can do about that from inside. That is a property of the integration, not a licence
  to be relaxed anywhere in the engine.
- `autopilot` posture makes two named concessions in `decideOne`, each with a comment arguing
  for it: it drops the `guard.not-understood` floor for actions contained in the project, and it
  lets observation alone promote reversible work inside the project rather than only read-only
  work. Neither applies in `assist` or `strict`. If you are reasoning about what LeastGrant
  guarantees, say which posture you mean.

Neither exception is a licence to add a third.

## Before you open the pull request

Run `leastgrant check` on anything your change affects, and paste the before and after into the
description. This is the fastest way for a reviewer to see what actually moved, and it catches
the case where a knowledge change is correct in isolation and wrong once the guards and the
learning are layered on top.

```
git stash
npm run build
node bin/leastgrant.js check "your command here" > /tmp/before.txt
git stash pop
npm run build
node bin/leastgrant.js check "your command here" > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt
```

The output looks like this, and pasting it verbatim is fine. Long fields wrap to your terminal
width, so your copy may break lines differently:

```
  ? ask  git push --force origin main

  what it does   overwrites history on the remote, discarding commits anyone else may have already pulled
  blast radius   reach production │ undo irreversible │ scale many
  touches        origin

  why
    • this affects something other people depend on
    • this cannot be undone
    • LeastGrant never auto-approves this kind of action, however often it happens

  ╰ this always asks. To pre-answer it, run: leastgrant allow "git push origin main --force"
```

Add `--json` after the command if you want the full verdict, including every action a chained
command decomposes into:

```
node bin/leastgrant.js check "npm test && git push" --json
```

Set `LEASTGRANT_HOME` to a scratch directory for both runs so your own learned history does not
change the answer between them.

Also:

- `npm test` passes.
- No new entries under `dependencies`.
- If you changed a threshold, a default, or a capability's blast radius, say in the description
  what you measured. Several of the numbers in `src/core/envelope.ts` carry their reasoning next
  to them — `Z`, `CONFIDENCE_BY_TIER`, `requiredConfidence`, and the session gate on the
  observation route — and new ones should too. Every field of `Thresholds` is read by something,
  and `test/audit-learning.test.ts` asserts that each one demonstrably changes a decision; a knob
  that appears in the config file and does nothing is a lie the user cannot detect.

## Reporting a security problem

Do not open a normal issue. See [SECURITY.md](SECURITY.md).

## Releasing

Maintainers only, and there is nothing to do by hand: pushing a `vX.Y.Z` tag runs the whole
verification suite and then publishes. See [RELEASING.md](RELEASING.md) — in particular before
renaming `.github/workflows/release.yml`, which npm's trusted publisher is bound to by name.
