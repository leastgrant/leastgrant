# Security policy

## Reporting a vulnerability

Open a private security advisory on the repository:

<https://github.com/leastgrant/leastgrant/security/advisories/new>

There is no email address for this, on purpose. An address nobody monitors is worse than no
address at all, and an advisory gets to the same place with a record attached.

> **If that link does not resolve for you:** open a normal issue saying only that you have a
> security report, with no details in it, and a private channel will be opened from there. Do not
> put the finding in a public issue. A tool whose entire job is to return the right answer cannot
> have a reporting route that dead-ends, so the fallback stays documented rather than assumed.

Please include:

- The exact input. For a shell command, the literal string, not a description of it.
- The output of `leastgrant check "<that input>"`, and what you expected instead.
- Your `posture` from `~/.leastgrant/config.json` and, if it matters, any rules you had set. The
  answer differs between `assist`, `autopilot` and `strict`, and a report that does not say which
  one is hard to reproduce.
- Your platform. Path handling and the secret-path table differ across Windows, macOS and Linux.

If the finding is that LeastGrant is *too* cautious, that is a normal issue, not an advisory.
Please file it as one — it is a real bug and we want it, it just does not need to be private.

## What counts as a vulnerability here

This is unusual enough to spell out.

**A vulnerability is any input that causes LeastGrant to return `allow` for an action that should
have been asked about or denied.**

That is the whole definition. It does not matter how the input got there or how contrived it
looks. Concretely, all of these qualify:

- A command that reaches a credential file without tripping the secret-read floor. Path
  traversal, symlinks, environment expansion, an encoding the tokenizer resolves differently
  from the shell.
- A wrapper, quoting trick, or substitution that hides the real program from
  `src/core/shell/unwrap.ts`, so a dangerous inner command inherits a harmless outer signature.
- Two different actions that collapse to the same signature in `src/core/signature.ts`, so
  approvals earned by the safe one are spent on the dangerous one.
- Anything that promotes an action above the blast ceiling in `src/core/envelope.ts`, or that
  gets a previously-denied signature auto-approved again.
- Anything that lets an agent write to `~/.leastgrant`, or edit the hook configuration, without
  the corresponding guard firing.
- Learning poisoning: a way for an agent's own unattended activity to be recorded as `confirmed`
  evidence rather than `observed`. Approvals promote; observations mostly do not. Blurring that
  line is a bypass even though no single decision looks wrong.

**A crash is lower severity, and how much lower depends on which agent you are running.**

When the hook crashes, times out, or exits non-zero, what happens next belongs to the host, not to
LeastGrant. Claude Code and Codex CLI treat it as a non-blocking error and proceed with the tool
call. Cursor, GitHub Copilot CLI and Google Antigravity block the call instead. The per-agent
answer is in [`compatibility/`](compatibility/) and `leastgrant doctor` prints it for the agent you
are actually running; please say which one your report is against, because it changes the severity.

On the agents that proceed, a crash is a denial of protection rather than a denial of service —
your agent keeps working, it is just unsupervised for that call. It is bounded, and it is loud in
`~/.leastgrant/leastgrant.log`. On the agents that block, the same crash costs you the call
instead: annoying, occasionally very annoying, but not a hole.

That asymmetry is why an `allow` bypass is the serious case everywhere. Where the host proceeds
there is no safe fallback state to land in, so the only thing between a tool call and the machine
is the engine returning the right answer; and where the host blocks, a wrong `allow` is the one
answer that still gets through. A wrong `allow` is not a degraded mode. It is the tool actively
telling the agent to go ahead.

A crash becomes high severity if you can make it happen *selectively* — that is, if the same input
that crashes the hook is the input you wanted allowed. On a fail-open agent, a parser panic
reachable only by the command you were trying to sneak through is an `allow` bypass with extra
steps, and should be reported as one. On a fail-closed agent the same trick refuses the call rather
than permitting it, so report it as a normal bug — unless you can pair it with something that gets
the call retried without the hook, in which case it is back to being an advisory.

## What is out of scope

**Things LeastGrant never sees.** It is a decision layer, not a sandbox. It cannot judge a tool
call that does not go through the hook: an agent running without the hook installed, a process
the agent already started, code executing inside a program LeastGrant approved, or anything on a
machine where the agent has a shell by another route. "I disabled the hook and then it did not
stop me" is not a finding.

**Over-cautious classification.** A knowledge module labelling something more dangerous than it
is, or asking about a command that is obviously fine, is a bug worth fixing — see
[CONTRIBUTING.md](CONTRIBUTING.md), the knowledge base is where the opinions live and corrections
are welcome — but it is not a security issue. Report it publicly.

**Anything that requires local write access to `~/.leastgrant`.** Somebody who can edit
`config.json` can set `posture: observe` and turn the whole thing off, or write themselves an
allow rule. That is not a bypass, it is the owner of the machine changing their own settings. The
directory is protected against the *agent* editing it — that is what `guard.self-write` is for,
and a way around that guard **is** in scope — but it is not protected against you, and it was
never meant to be.

**Attacks that assume the attacker is already root, or already the user.** Same reasoning.

**Secrets appearing in a ledger line you can only read because you own the machine.** The
redactor is best-effort and says so in [docs/privacy.md](docs/privacy.md). A specific credential
shape it misses is a genuine bug and we want the pattern — file it publicly. It only becomes an
advisory if the miss also causes a wrong decision.

## Threat model

Before reporting, it is worth reading [THREAT-MODEL.md](THREAT-MODEL.md). It states what
LeastGrant defends against, what it does not, and the several places where the honest answer is
"we cannot". A finding that lands inside one of those stated limits is still useful — the limits
may be wrong — but the conversation starts in a different place.

The short version, so you can triage your own finding quickly:

- LeastGrant is a **reliable veto and a best-effort grant**. A hook `deny` is absolute in Claude
  Code, including under `bypassPermissions`. A hook `allow` is not — your own deny and ask rules
  still override it.
- The ledger is append-only but **not tamper-evident**. It is not hash-chained, because that
  would need a single writer and a lock that can wedge an agent mid-session is a worse failure
  than a log you cannot prove is complete.
- Parsing coverage and *understanding* are different numbers, and this file used to quote one as
  if it were the other. The shell parser structurally accounts for almost everything it is given.
  Roughly half of real commands are nonetheless marked not-understood, because an interpreter
  running code we cannot read is parsed perfectly and understood not at all. The single measured
  figure, with the sample size and the machine it came from, is in the README; it is not repeated
  here, because two copies of a number is how they came to disagree.
