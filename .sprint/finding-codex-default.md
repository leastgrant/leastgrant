# Codex `permission_mode: "default"` is not a human

Found by `test/conformance.test.ts` (branch `sprint/conformance`) deriving its
expectations from `compatibility/codex.json` rather than from a hand-written
per-agent branch. Not in `.sprint/audit-findings.json` — nobody was looking for
it, the data was.

## Severity

High. It is an unsafe-allow in the DEFAULT mode of a supported, "enforcing"
agent, and it is not the argv-array bug (finding #2) — it reproduces with the
plain string wire form too.

## Reproduction

```bash
cd D:/LeastGrant && npm run build
for mode in default dontAsk bypassPermissions; do
  printf '%-18s ' "$mode"
  echo "{\"session_id\":\"c\",\"turn_id\":\"t\",\"cwd\":\"$PWD\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"shell\",\"tool_input\":{\"command\":\"cat ~/.ssh/id_rsa\"},\"tool_use_id\":\"c1\",\"permission_mode\":\"$mode\"}" \
    | node bin/leastgrant.js hook --agent codex | head -c 90; echo
done
```

Observed:

```
default              (nothing — LeastGrant stands aside)
dontAsk              {"hookSpecificOutput":{...,"permissionDecision":"deny",...
bypassPermissions    {"hookSpecificOutput":{...,"permissionDecision":"deny",...
```

## Why standing aside is wrong here

`src/adapters/codex/hook.ts:77` has `PROMPTS_A_HUMAN` containing `'default'`, so
`resolve()` returns abstain, on the reasoning that Codex's own prompt will reach
the developer. Upstream evidence says it will not, reliably:

- `hook_permission_mode()` maps `AskForApproval::{UnlessTrusted, OnRequest,
  Granular(_)} -> "default"` and only `Never -> "bypassPermissions"`.
  (codex-rs/core/src/hook_runtime.rs:1009-1017)
- Under `-a on-request`, which is the default, **the model** decides when to ask.
  Most tool calls under on-request with a workspace-write sandbox never reach an
  approval prompt at all.
- `AskForApproval::Granular` with all fields false **auto-rejects** approval
  requests rather than showing them, and still reports `"default"`.
  (codex-rs/protocol/src/protocol.rs:965-988)

`compatibility/codex.json` already records the consequence — `modes.askSurvives`
is `[]`, with the note "`default` does not imply a human will be asked" — so the
published data and the adapter currently disagree with each other.

Codex additionally has no ASK verdict in any mode: `permissionDecision:"ask"` is
parsed, rejected, and the call runs anyway. So abstain and ask are both
unavailable, and deny is the only thing left that means anything.

## The fix

`'default'` comes out of `PROMPTS_A_HUMAN`. A floored action in any Codex mode
becomes a deny, which is what already happens in `dontAsk` and
`bypassPermissions`.

Deliberately NOT fixed by me: the codex-wire cluster is rewriting that file
right now and its brief already covers this constant ("PROMPTS_A_HUMAN at
hook.ts:77 lists 'ask' and '', which are not Codex permission_mode values").
Two people editing one constant from two directions produces a merge conflict
and possibly two contradictory fixes.

## Cost of the fix, stated honestly

More denies on Codex in interactive `-a on-request` sessions, and a deny there
cannot be overridden in the moment — the developer has to add a rule or approve
via `leastgrant`. That is worse UX than a prompt.

It is still the right trade, because the alternative is not "a prompt". The
alternative is the command running. Codex cannot be made to prompt by a hook; a
hook can only preserve a prompt Codex was already going to show.

## What must happen to `test/conformance.test.ts`

It is on branch `sprint/conformance` and is RED on main today: 10 failures, all
Codex, all this bug plus the argv-array one. It was not landed red and it was
not weakened to make it pass. Merge it once the codex-wire cluster lands and it
becomes the regression test for both.
