# What LeastGrant stores

Short version: everything is a plain text file in one directory on your machine, nothing is sent
anywhere, and you can read all of it with `cat`.

The longer version is below, because "we take your privacy seriously" is not a design document
and you should be able to check this yourself.

## Where

Everything lives in `~/.leastgrant`. On Windows that is `C:\Users\<you>\.leastgrant`.

You can move it by setting `LEASTGRANT_HOME`. It does not have to be absolute: `stateDir()` runs
`path.resolve()` on it, so a relative value is resolved against the current working directory —
which, for a hook, is whatever directory your agent happened to launch it from. Give it an absolute
path unless you want that. It is the only override, and it is read fresh on every run (`stateDir()`
in `src/store/index.ts`).

```
~/.leastgrant/
  config.json          what you told LeastGrant to do
  ledger.jsonl         one line per decision, append-only
  denials.jsonl        one line per refusal, append-only and never pruned
  envelopes/*.json     what it has learned, one file per project
  sessions/*.json      scratch state for conversations still in progress
  leastgrant.log       diagnostics, usually empty
```

Every agent writes into the same directory. Claude Code and Cursor share one decision path and one
state directory; the ledger's `agent` field is what tells their entries apart.

Nothing is written outside that directory, with one exception: `leastgrant install` edits your
agent's settings file to add the hook, and takes a copy alongside it first — for Claude Code
that is `~/.claude/settings.json` and `~/.claude/settings.json.leastgrant-backup`, for Cursor
`~/.cursor/hooks.json` and its `.leastgrant-backup`.

## Each file, honestly

### `config.json`

Your settings. Posture, thresholds, the allow and deny rules you wrote, extra workspace roots,
extra secret path patterns, and the `telemetry.ledger` switch. Written by `leastgrant init`,
`leastgrant allow`, `leastgrant deny` and `leastgrant forget`. Pretty-printed, two-space indent,
meant to be hand-edited.

The only personal data in here is whatever is in your own rules — a rule's `match` is a signature
glob you chose, and its `note` is a sentence you wrote. The glob goes through the redactor on the
way in (`addRule()` in `src/store/index.ts`), so a credential pasted into a pattern is stored as a
marker. The `note` does not.

### `ledger.jsonl`

One JSON object per line, one line per decision, appended and never rewritten in place. Written
only by the hook, and only when `telemetry.ledger` is true.

A real line looks like this:

```json
{"v":1,"at":1788172475478,"agent":"claude-code","sessionId":"s1","project":"d:\\tmp",
 "tool":"Bash","display":"mysql --password=«redacted:flag-value» -e \"select 1\"",
 "signature":"mysql <sql:select> --password=«redacted:flag-value» -e","capability":"exec.db",
 "blast":{"reach":"external","reversibility":"trivial","exposure":"reads-secrets","scale":"single"},
 "understood":true,"decision":"ask","reasons":["guard.secret-read","floor.explain"],
 "agentMode":"default","ms":7}
```

**This file contains command lines and file paths.** That is not incidental, it is the point —
it is simultaneously the audit trail, the training data, and the thing `leastgrant why` reads
when you ask what happened. A security tool whose data you cannot read is a worse security tool.
But it does mean that if your commands mention project names, client names, internal hostnames or
directory layouts, those are on disk here in the clear.

What each field is:

- `display` — the command, rendered for humans, **passed through the redactor**.
- `signature` — the normalized identity used for learning, with volatile parts templated out
  (`<path>`, `<path:secret>`, `<text>`, `<sql:verb>`, `<sha>`, `<url:host>`). Also passed through
  the redactor: `scrub()` in `src/core/classify.ts` runs both `display` and `signature` through it
  at the `analyze()` boundary. See the known gap below for what the redactor does not catch.
- `project` — the project root path, or a hash of it in the per-project envelope filenames.
- `reasons` — reason codes only. The prose is regenerated at read time, so no sentences are
  stored.
- `blast`, `capability`, `understood`, `decision`, `agentMode`, `ms` — the judgement and how long
  it took.

`leastgrant trail` and `leastgrant why` read this file. `leastgrant doctor` reads it to look for
over-broad access.

### `denials.jsonl`

The record of what was refused. One line per refused signature, written by `recordDenial()` in
`src/store/index.ts`:

```json
{"v":1,"scope":"project","key":"d:\\tmp","signature":"git push origin main --force","at":1788169471290}
```

Three things about it are worth stating plainly.

**It is append-only and is never pruned or decayed.** Nothing trims it by age, and no command
deletes from it. That is deliberate: it is what makes "a no does not expire" true even if the
envelope is deleted, corrupted, or lost to a concurrent write — `applyDenials()` replays this file
over every envelope it loads. Every `saveEnvelope()` re-appends a line for each still-denied
signature in that project, and a `saveEnvelope()` happens on every completed tool call, so a single
denial accumulates copies as you work. Expect duplicates and expect the file to grow.

**It contains the project path in the clear.** The `key` field is the canonical root path, not the
hash used for envelope filenames. So unlike `envelopes/`, this file's contents disclose which
projects you work in.

**It is written regardless of `telemetry.ledger`.** Turning the ledger off does not turn this off.

Only one thing produces a denial: `leastgrant init` mining a refusal out of a Claude Code
transcript. The live hook never records one — it only knows that a call ran. `leastgrant deny
<pattern>` does not write here either; that writes a rule to `config.json`.

### `envelopes/*.json`

What LeastGrant has learned, one file per project. The filename is the first 16 hex characters of
the SHA-256 of the project's canonical root path, so the directory listing does not disclose
which projects you work on — but the `key` field *inside* each file is the plain path.

Per signature, the file holds decayed evidence counts (`confirmed`, `denied`, `observed`), a
lifetime total, first and last seen timestamps, counts of distinct sessions and days, the worst
blast radius ever seen, and up to three sample display strings. It also holds three bookkeeping
fields the counters need: `_byTier`, the same counts split by blast tier; `_recentDays`, up to 32
day numbers; and **`_recentSessions`, up to 16 raw agent session ids** — the ids as the agent
issued them, not hashed. If your agent derives session ids from anything you would rather not have
on disk, that is where they are.

At the top level the file also holds `capabilities`, a count per capability, and `transitions`, a
count per `from>to` capability pair.

Samples and signatures both go through the redactor, at the `analyze()` boundary. There is no
conversation content in here, and no file contents. It is counters and command shapes.

`global.json` sits alongside `envelopes/` in the code as a cross-project envelope. Nothing
currently writes it.

### `sessions/*.json`

Scratch state for a conversation that is still going. The hook runs as a separate process for
every tool call, so anything that has to survive between calls — which capability came last, what
the session has already touched, the decision waiting on its PostToolUse — lives in a small file
named after the session id.

```json
{"sessionId":"s1","taints":[],"count":1,"startedAt":1788172475478,
 "lastCapability":"exec.db","previousCapability":"exec.db",
 "pendingById":{"toolu_01":{"signature":"mysql <sql:select> --password=«redacted:flag-value» -e",
  "capability":"exec.db","blast":{"reach":"external","reversibility":"trivial",
  "exposure":"reads-secrets","scale":"single"},"decision":"ask",
  "display":"mysql --password=«redacted:flag-value» -e \"select 1\"","toolUseId":"toolu_01",
  "at":1788172475478,"attended":true,"project":"d:\\tmp"}}}
```

**`pendingById` means signatures land here too**, not only in the ledger, the envelope and
`denials.jsonl`. It holds up to 64 in-flight calls — one per tool call that has had a PreToolUse
but not yet a PostToolUse — and each carries the signature, capability, blast radius, decision,
redacted display and the plain project path. An interrupted call leaves its entry behind until the
file is pruned.

These are pruned automatically: anything untouched for 24 hours is deleted the next time a
session file is written. Deleting the whole directory at any time is safe; the worst that happens
is LeastGrant forgets what the current conversation has been doing so far.

### `leastgrant.log`

Timestamped diagnostic lines, written when the hook hits an error it cannot report any other way,
and also when it is handed a hook event name it does not recognise — which is not an error, just
an agent asking about something LeastGrant has no handler for. Usually empty. Lines are passed
through the redactor.

## What is not stored

None of these ever touch disk, because none of them are ever read:

- **File contents.** LeastGrant judges a `Write` by its path, not its payload. The `content` field
  of a tool call is never recorded.
- **Tool output.** There is no PostToolUse capture of what a command printed. The post-execution
  hook records only that the call ran.
- **Your prompts, or the model's replies.** LeastGrant does not see them. The hook is handed a
  tool name and tool input, and nothing else.
- **Conversation text of any kind.**

`leastgrant init` and `leastgrant simulate` *read* your Claude Code transcripts from
`~/.claude/projects/` to learn from history you already have. They read tool calls and permission
modes out of them, and nothing else — no prompts, no replies, no tool output. What lands in
`~/.leastgrant` is what the live hook would have written for the same call: a signature, a
redacted sample, and the transcript's session id in `_recentSessions`. So the commands are copied,
in normalized form; the conversation around them is not.

## The redactor

Everything written to `display` fields and `signature` fields, envelope samples, rule patterns and
the diagnostic log goes through `redact()` in `src/core/secrets.ts` first. A tool that records every
command your agent runs, in order to protect your secrets, has just built an excellent place to
accidentally store your secrets.

It catches, by pattern: PEM private key blocks, GitHub tokens (`ghp_`, `github_pat_`), Anthropic
and OpenAI-style keys (`sk-ant-`, `sk-`, `sk-proj-`), Stripe keys, Slack tokens, AWS access key
ids (`AKIA`, `ASIA`), Google API keys (`AIza`), GitLab PATs, npm tokens, DigitalOcean tokens,
Hugging Face tokens, JWTs, credentials embedded in URLs (`https://user:pass@host`),
`Authorization:` headers of any scheme, `--password` / `--token` / `--api-key` style flag values,
`mysql -pSECRET`, and `NAME=VALUE` where the name contains TOKEN, SECRET, PASSWORD, APIKEY,
ACCESS_KEY, PRIVATE_KEY, CREDENTIALS or AUTH.

There is also a catch-all for long, high-entropy, mixed-alphabet strings, which deliberately
skips git SHAs, UUIDs, sha256 digests and lockfile integrity hashes so the ledger stays readable.

**It is best-effort and it is a heuristic.** It is a list of patterns, and a credential shape
nobody has thought of yet will go straight through. That is exactly why the ledger never stores
file contents or tool output — the redactor is the second line of defence, not the first. If you
find a shape it misses, please report the pattern; see [../SECURITY.md](../SECURITY.md).

Replacements are marked distinctively so you can see them working:

```
mysql --password=«redacted:flag-value» -e "select 1"
```

You do not have to take this on faith. Read the file:

```
cat ~/.leastgrant/ledger.jsonl
grep -c 'redacted' ~/.leastgrant/ledger.jsonl
```

### Known gap: what the redactor does not recognise reaches five files

Signatures used to be exempt. They are not any more: `scrub()` runs `display` and `signature`
through `redact()` at the `analyze()` boundary, and `addRule()` does the same to a rule's pattern.
So there is no longer a shape that comes out redacted in one field and verbatim in another.

What is left is the redactor's own coverage, and the consequence of a miss is wider than one file.
A credential shape `redact()` does not recognise is written verbatim to the ledger line, to the
envelope (as the signature key *and* as a sample), to the session file, to `config.json` if you
put it in a rule, and to `denials.jsonl` if the action was ever refused — and that last one is
never pruned, so it outlives every other copy.

Three misses are known, and they are all the same shape: a short, human-chosen value in a position
the pattern list does not cover.

- `mysql -p hunter2` — the space-separated form. The `-p` rule is deliberately anchored to a glued
  value (`-phunter2`) so it does not redact `docker run -p 8080:80` and `ssh -p 2222 host`.
- `curl -u user:pass`, and `--user user:pass`. Not recognised at all.
- An MCP argument under a key whose *name* does not look credential-shaped. Values under `token`,
  `secret`, `password`, `apiKey`, `auth`, `cookie` and similar become `<redacted>`; a secret passed
  as, say, `value` does not.

A long random value in any of those positions is still caught, by the high-entropy catch-all. It is
the short, low-entropy, typed-by-a-human ones that get through.

You can check this on your own machine. The redactor's markers are distinctive, so anything left
over is what escaped:

```
grep -rhoiaE '(-p|-u|--user) [^ ",]+|(password|passwd|secret|token|api[-_]?key)=[^ ",]+' \
  ~/.leastgrant | grep -v redacted | sort -u
```

Deleting `~/.leastgrant` clears all of it.

## Nothing leaves the machine

- No telemetry. No usage reporting, no crash reporting, no counters phoned home.
- No network calls. LeastGrant does not open a socket. There is no HTTP client in the codebase.
  The complete list of modules the shipped code imports is `node:fs`, `node:path`, `node:os`,
  `node:crypto`, `node:url` and `node:readline/promises` — all Node builtins, none of them
  networking. (`node:test` and `node:assert/strict` appear in the test suite, which is not
  shipped.) You can check that yourself with
  `grep -rhoa "from 'node:[a-z/]*'" src/ | sort -u`. The `-a` is not optional: `src/core/paths.ts`
  contains a NUL byte in a sentinel string, so without it grep calls the file binary, prints
  `Binary file src/core/paths.ts matches`, and skips its imports.
- No account, no login, no license check, no update ping.
- Nothing is uploaded when you run `leastgrant init`, even though that is the command that reads
  the most.

The package has **zero runtime dependencies**. The `dependencies` block in `package.json` is
empty, and it is a project rule that it stays empty. So there is no third-party code in the
permission path at all: nothing that could make a request, and nothing whose next version could
start making one. TypeScript and the Node type definitions are devDependencies and are not
shipped or executed at runtime.

You can verify all of this in the way that actually proves it, by watching the process rather
than reading this page.

## Turning the ledger off

Set it in `~/.leastgrant/config.json`:

```json
{
  "telemetry": { "ledger": false }
}
```

The hook checks this before every append. It suppresses `ledger.jsonl`, and only that. Every other
file is still written: envelopes still record signatures, blast radii and evidence counts, session
files still record the signature and decision of each in-flight call, `denials.jsonl` still records
every refusal, and the log still records diagnostics. What you lose is the per-decision history,
not the recording of decisions.

What stops working:

- **`leastgrant trail`** — there is nothing to show. This is the command that tells you what your
  agents have been doing.
- **`leastgrant why`** — it explains a decision by looking it up in the ledger, so it has nothing
  to explain.
- **`leastgrant doctor`** — the checks that look for over-broad access across your history go
  quiet. The setup checks still work.

What keeps working, which may not be what you expect:

- **Learning.** Evidence is folded into the per-project envelope by the PostToolUse hook, which
  does not consult this switch. LeastGrant still gets quieter over time with the ledger off. What
  you lose is the ability to audit *why* it got quieter.
- **`leastgrant simulate`.** Replay reads your Claude Code transcripts from `~/.claude/projects/`,
  not the ledger, so counterfactual replay is unaffected.
- **`leastgrant status`.** It reads envelopes.

If you want LeastGrant to watch but never act, that is a different switch: `"posture": "observe"`
in the same file. In observe posture the hook makes a decision, records it, and then says nothing
to the agent.

## Deleting everything

To remove the hook from your agent's settings:

```
leastgrant uninstall
```

That edits the agent settings file and removes only the hook entries LeastGrant added. It does
**not** touch `~/.leastgrant`. Add `--project` for a project-scoped install, or name an agent
(`leastgrant uninstall cursor`, `leastgrant uninstall copilot`).

To delete every byte LeastGrant has stored:

```
rm -rf ~/.leastgrant
```

That is all of it — config, ledger, denials, envelopes, sessions, log. There is no registry key, no
cache elsewhere, no shadow copy. If you set `LEASTGRANT_HOME`, delete that directory instead.

Doing both, in either order, returns your machine to the state it was in before you installed
anything. If you want to start over rather than leave, delete the directory and keep the hook —
the next session begins with an empty history.
