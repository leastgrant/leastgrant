# Compatibility data

One file per agent. **This directory is the source.** The support table in the
README, `leastgrant doctor`, and the website's compatibility page are all
generated from these files, so there is one place to change when an agent
changes and no way for the four of them to drift apart.

That mattered as soon as it existed: the README claimed an `ask` from LeastGrant
"reaches you in every mode" on Claude Code. Probing the installed binary showed
a hook `ask` becomes a **deny** under `claude -p`. Four hand-maintained copies of
that sentence would have meant four places to be wrong.

## The rule about evidence

Every claim carries how it was established, and the grades are not
interchangeable:

| grade | meaning |
|---|---|
| `probe` | Someone ran the real agent and watched this happen. |
| `source` | Someone read the shipped binary or bundle. Strong, but not behaviour. |
| `docs` | The vendor says so. Weakest — vendor docs are routinely ahead of, or behind, what ships. |
| `unknown` | Nobody has established it. Degrades conservatively; never rendered as a tick. |

`docs` alone never justifies the word "verified" anywhere in the UI. Cursor's own
documentation states its hooks are "fail-open by default"; reading the shipped
3.18.25 bundle shows that depends on the failure kind. That is why `source` and
`probe` outrank it.

## Honesty rules these files exist to enforce

- An upstream limitation is never rendered as a green tick. If reads are
  observed rather than gated, the field says observed.
- `unknown` is a real value and must survive to the UI as "unknown", not as a
  blank that reads like "fine".
- `lastVerified` is the date a human or agent actually checked, not the date the
  file was edited.
- `supported` describes what LeastGrant *ships*, and is independent of how good
  the upstream contract is. An agent can have an excellent hook API and no
  adapter here yet.

## Adding an agent

Copy the closest existing file, fill in every field, and set `evidence` honestly.
A field you did not check is `unknown`. The test suite fails on a missing field
and on an evidence grade the file cannot justify; it does not fail on `unknown`,
because "we have not checked" is a legitimate and useful thing to publish.
