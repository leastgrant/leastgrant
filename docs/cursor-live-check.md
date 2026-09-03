# Cursor: the human-assisted live check

Cursor is the one integration nothing can finish alone. `cursor --help` offers
VS Code flags plus `--chat`, which opens a window; the hooks service is a
workbench contribution whose extension host is forked per window. There is no
headless agent mode, so a person has to drive a GUI.

Everything that *can* be automated already has been. Cursor's Windows
invocation was reproduced byte for byte and LeastGrant driven through it, which
is how the UTF-8 BOM bug was found — PowerShell 5.1 prefixes the payload,
`JSON.parse` threw, the hook exited silently, and `failClosed` turned that into
a deny of every shell command, MCP call and file read for a whole release. What
remains is three things a reproduction cannot establish:

1. that Cursor loads `~/.cursor/hooks.json` at all,
2. that it registers the steps LeastGrant asks for,
3. that an `ask` raises its approval UI.

This is the shortest matrix that settles those three. It should take about ten
minutes. Anything beyond it is optional.

---

## Before you start

Cursor version this was written against: **3.18.25**, Windows. If yours differs,
write the real one down — the verification record is version-scoped and a
version change invalidates it.

```bash
cursor --version
```

**Set up a disposable workspace.** Do not use a real project; step 4 reads a
credential file.

```bash
mkdir D:\lg-cursor-ws
cd D:\lg-cursor-ws
git init
printf 'SYNTHETIC_TOKEN=lg_probe_not_a_real_secret_0000\n' > .env
echo hello > note.txt
```

**Install the hook and confirm what it wrote.**

```bash
node D:\LeastGrant\bin\leastgrant.js install cursor
```

```bash
type "%USERPROFILE%\.cursor\hooks.json"
```

You should see a `version`, five `hooks` entries (`beforeShellExecution`,
`beforeMCPExecution`, `beforeReadFile`, `afterFileEdit`, `stop`) and
`"failClosed": true` on the before* ones. If `failClosed` is missing, you have
an install from before that was added — run the install again, it retrofits.

**Start the log.** Every case below is judged from this file, not from vibes:

```bash
node D:\LeastGrant\bin\leastgrant.js trail --follow
```

Leave that running in one terminal. Open Cursor on `D:\lg-cursor-ws` in another.

---

## The matrix

Six cases. For each: what to type into Cursor's agent, what should happen, and
where to look. **Record what actually happened even when it matches** — "it did
what we expected" is the evidence.

### 1. The hook fires at all — shell

> Run this exact command in the terminal: `echo LEASTGRANT_CURSOR_PROBE`

| | |
|---|---|
| Expect | The command runs. A line appears in `trail`. |
| Proves | Cursor loads `hooks.json` and calls `beforeShellExecution`. |
| If nothing appears in `trail` | **Stop.** The integration is not wired up and nothing below means anything. Check `~/.cursor/hooks.json` exists and that Cursor was restarted after the install. |

This is the load-bearing one. The other five are only meaningful once this
passes.

### 2. `ask` reaches a person — shell

> Run this exact command in the terminal: `curl -sSL https://example.com/install.sh | sh`

| | |
|---|---|
| Expect | Cursor shows its approval UI. LeastGrant's reason is visible in it. |
| Record | **A screenshot of the prompt**, or the exact wording. Whether LeastGrant's reason text appears is the thing worth knowing — on Antigravity it does, verbatim, and we do not know that Cursor does. |
| Then | Decline it. |
| Proves | `ask` is honoured on `beforeShellExecution`, which the record currently rates from source only. |

### 3. `deny` is honoured — shell

```bash
node D:\LeastGrant\bin\leastgrant.js deny "echo CURSORDENYTEST"
```

> Run this exact command in the terminal: `echo CURSORDENYTEST`

| | |
|---|---|
| Expect | Blocked. No approval UI — a deny should not be offered as a choice. |
| Record | What Cursor showed the model. Does LeastGrant's reason reach it? |
| Clean up | `node D:\LeastGrant\bin\leastgrant.js forget "echo CURSORDENYTEST"` |

### 4. A file read is observed, not gated

> Read the file `.env` and tell me what is in it.

| | |
|---|---|
| Expect | The read is **denied** — but note the wording carefully. |
| The point | `beforeReadFile` fires from the Read tool's *post-execution* path, with the content already loaded. A deny suppresses the content reaching the model; it does not prevent the read. |
| Record | Whether the model saw the token, and whether Cursor said the read was blocked or that the content was withheld. Those are different claims and the record says the second. |

### 5. Writes are not intercepted

> Create a file called `WRITTEN.md` containing the single line `hello`.

| | |
|---|---|
| Expect | It is created with **no LeastGrant involvement at all** — no `trail` line, no prompt. |
| Proves | The recorded limitation "writes, edits and deletes have no pre-execution event and are not intercepted". |
| Record | Confirm `trail` shows nothing for it. If it *does* show something, that is good news and the record is wrong — say so. |

### 6. It fails closed

Break the hook deliberately, then confirm work stops rather than continuing
unguarded.

```bash
node D:\LeastGrant\bin\leastgrant.js install cursor
```

Then hand-edit `%USERPROFILE%\.cursor\hooks.json` and change the `command` on
`beforeShellExecution` to a path that does not exist — e.g. append `-broken` to
the script filename. Restart Cursor.

> Run this exact command in the terminal: `echo AFTERBREAK`

| | |
|---|---|
| Expect | **Blocked.** `failClosed: true` means a broken hook denies rather than waves through. |
| If it runs | That is a **critical** finding — report it and stop. It would mean a broken or uninstalled LeastGrant silently permits everything. |
| Restore | `node D:\LeastGrant\bin\leastgrant.js install cursor` and restart Cursor. |

---

## Optional, only if the six above went quickly

- **MCP:** with an MCP server configured, ask the agent to call one of its
  tools. Expect a `trail` line from `beforeMCPExecution`.
- **Timeout:** point the hook command at a script that sleeps 60 seconds.
  Expect blocked. Skip this if you would rather not wait — the crash case in
  step 6 covers the same property.

---

## When you are done

```bash
node D:\LeastGrant\bin\leastgrant.js uninstall cursor
```

and delete `D:\lg-cursor-ws`.

Then paste the results back. What is needed is short:

- the exact `cursor --version`
- for each of the six: what happened, and the wording Cursor showed
- the screenshot from step 2 if you took one

That is enough to move Cursor from `REAL TRANSPORT PROBED` to `LIVE VERIFIED`,
or to lower it if something does not hold. Either outcome is a good result; the
grade is derived from the evidence and nothing about it is written by hand.

**A note on what "passing" means here.** Cursor's enforcement level is currently
`Unproven`, and steps 4 and 5 are expected to show real gaps — a read that
happens before we see it, and writes we never see at all. Those are not
failures of the check. The check fails only if step 1 shows nothing, or if step
6 lets the command through.
