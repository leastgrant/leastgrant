# LeastGrant — working notes for Claude

A permission layer that sits in front of coding agents. It learns what your agents normally do,
lets routine work through, and stops on the rest. Zero runtime dependencies, fully local.

This file is the handoff. It records what the repository does not: current state, the conventions
that are not obvious from the code, the mistakes already paid for, and what is still open.

---

## Current state

| | |
|---|---|
| Version | **0.5.0**, published to npm, `latest` |
| Tip commit | `b7ac6c0` on `main` (verify with `git log --oneline -1`) |
| Released from | `396760c`, tag `v0.5.0` |
| Published artifact | shasum `43a54cc5f80b2b50bbc255ff1d8093adeb59175f`, 233 files, reproducible |
| Provenance | SLSA v1, GitHub-hosted builder, OIDC Trusted Publishing — no token fallback |
| Site | <https://leastgrant.xyz>, live and matching the records |

Tests, all green at the tip: **1798 core** (1794 pass, 4 skipped), **224 site**, of which
**132** are the bypass corpus and **53** are conformance. CI is **17 jobs** — Windows, Linux and
macOS × Node 20/22/24, plus package, fuzz, dependencies, bypass, and agent-claims jobs.

### Agent support — canonical, do not retype

| Agent | Enforcement | Verification | On hook crash | Version tested |
|---|---|---|---|---|
| Claude Code | Partial | LIVE VERIFIED | **open** — runs anyway | 2.1.240 |
| Codex CLI | Veto only | LIVE VERIFIED | **open** — runs anyway | 0.152.0 |
| Cursor | Partial | LIVE VERIFIED | **closed** — blocks | 3.18.25 |
| GitHub Copilot CLI | Partial | LIVE VERIFIED | **closed** — blocks | 1.0.82 |
| Google Antigravity | Partial | LIVE VERIFIED | **closed** — blocks | 2.11.0 |
| OpenCode | Not yet | UNVERIFIED | open | 1.18.26 — **ships no adapter, deferred** |

Regenerate rather than edit: `node -e` over `dist/src/core/compatibility.js`, or read
`compatibility/*.json`. The README table is generated (`npm run gen:readme`) and the site derives
from the same records; if they disagree, the build fails.

---

## Commands

```bash
npm ci                  # install (2 dev deps, 0 runtime deps)
npm run build           # tsc -> dist/
npm test                # build + full suite (~4 min on Windows)
npm run test:fast       # suite only, dot reporter
npm run typecheck
npm run site:build      # -> site/dist (not tracked; CI and the origin both rebuild it)
npm run site:test       # 224 tests, includes the agent-docs guard
npm run verify:agents   # every adapter has a record, every record within its evidence
npm run gen:readme      # regenerate the README's generated blocks
npm run release:check   # 13-section release rehearsal; run before ever tagging
node scripts/run-tests.mjs <substring>   # one test file
```

`site/serve.mjs` on `127.0.0.1:8787` serves `site/dist`; `.claude/launch.json` already configures
it for the preview tools.

---

## Architecture

```
src/core/          the engine every adapter shares — a hole here is a hole in all five
  decide.ts        composes the verdict
  guards.ts        the floors: mandatory refusals that must never be silently downgraded
  classify.ts      tool name -> internal kind; unmapped becomes "unknown"
  paths.ts         workspace containment and path canonicalisation
  secrets.ts       credential recognition
  signature.ts     action identity — decides what "the same action" means for learning
  envelope.ts      session state, taint, blast ceiling, promotion counters
  shell/           tokenize (POSIX rules), unwrap (peels wrappers), parse
  knowledge/       the opinions: what commands mean. Deliberately readable and arguable.
  compatibility.ts assess() -> enforcement level, deriveVerification() -> grade
src/adapters/      claude-code (also serves copilot), codex, cursor, antigravity
src/cli/commands/  install, doctor, check, status, trail, why, rules, init, simulate, benchmark
compatibility/*.json   canonical per-agent capability records — the source of truth
corpus/bypasses.json   88 attack cases, all expected `not-allow`
site/lib/facts.mjs     everything the site states as fact, read out of the repository
```

**Two axes, never conflated.** *Enforcement* (`assess()` → Enforcing / Partial / Veto only /
Unproven / Not yet) is what the agent lets us stop. *Verification* (`deriveVerification()` → LIVE
VERIFIED / REAL TRANSPORT PROBED / CONTRACT / BINARY VERIFIED / CONFORMANCE TESTED / UNVERIFIED)
is how well we know. Both are **derived from the records, never declared**.

---

## Rules that matter

**Never upgrade a verification grade without evidence.** A transport reproduction is not a live
test. A conformance pass is not a live test. LIVE VERIFIED means something ran inside the real
agent.

**Never weaken a security guarantee to get a greener badge.** OpenCode is deferred for exactly
this reason — its pre-tool hook is unraceable, but `POST /session/{id}/shell`, command-template
interpolation and `GET /file/content` all go around it. A badge there would describe a door.

**Floors are mandatory.** `flooredGuards` means the refusal cannot be downgraded. Where a host has
no interactive ask (Cursor's generic `preToolUse`), a non-floored ask degrades to allow and a
floored one degrades to **deny**, never to allow. Any *undocumented* downgrade path is critical.

**Records are canonical.** README, `doctor`, the site and the docs all derive from
`compatibility/*.json`. Write a claim into prose and it will rot — see the fail-open story below.

**Never touch the user's real agent config** (`~/.claude`, `~/.cursor`, `~/.codex`, `~/.copilot`,
`~/.gemini`) when testing. Use a throwaway HOME:

```bash
HOME=$T USERPROFILE=$T LEASTGRANT_HOME=$T/.leastgrant node bin/leastgrant.js ...
```

Synthetic secrets only. Never print, copy or log real credentials, tokens or keyring contents.

---

## Mistakes already paid for — do not repeat

**Backslash mangling.** `node -e` and bash/python one-liners with Windows paths eat backslashes.
This produced broken `hooks.json`, broken regexes and broken test literals, repeatedly. **Write a
`.mjs` file to disk with the Write tool instead.** Use `String.raw` for Windows path literals.

**CRLF.** Python's `io.open(..., 'w')` reintroduces CRLF on Windows and the release guard rejects
it. Everything shipped must be LF. Check with
`require('fs').readFileSync(f,'utf8').includes('\r\n')`.

**The release guard rejects absolute paths in comments.** An illustrative `C:\Users\First Last\…`
in a source comment is indistinguishable from a leaked build-machine path and blocks the release.
Describe the shape in words instead.

**Windows-shaped path literals in tests.** `C:/Users/...` is absolute on Windows and *relative*
on POSIX, so every "outside the project" assertion inverts on Linux and macOS. Use
`path.join(os.tmpdir(), …)`. Where the test really is about Windows resolution, gate it with
`{ skip: !WINDOWS && 'reason' }` and write the reason down.

**CI paths have no spaces; real Windows paths do.** The installer writes the 8.3 short form
(`LEASTG~1.JS`) when the install path contains a space, and recognition only knew the long
spelling — so a second install duplicated every handler and uninstall reported success while
removing none. Fixed in `isOurCommand` / `MARKER` by resolving through `fs.realpathSync.native`.
`test/spaced-install-path.test.ts` stages a real copy under a real spaced directory. **Shape is
not identity** — `leastgrant-notify.js` also gets `LEASTG~1.JS`, and this module promises never to
remove a hook it did not add.

**Vacuous tests.** A refusal that comes from `guard.not-understood` or "path outside the project"
rather than the guard being claimed is worthless — it survives deleting the feature. Always run
the benign control twin. Two of these were found and fixed.

**Pinning prose in tests.** `assert.match(sec, /fails open/i)` held a false sentence in place and
made correcting it break the build. Pin the *shape* a claim must have, checked against the
records — not a particular wording.

---

## Release process

Tag-driven, OIDC Trusted Publishing. **Never `npm publish` by hand**, and never add a token
fallback — npm generates provenance automatically for public repos using Trusted Publishing, and a
fallback would bypass that.

```bash
npm run release:check        # rehearse first; it refuses on anything the guard dislikes
git tag -a v0.x.0 -F- <<'MSG' ... MSG
git push origin v0.x.0
```

The Release workflow reruns the whole Verify matrix and **skips publish if anything is red** —
this is proven: the first `v0.5.0` tag failed on Linux/macOS and published nothing. If that
happens: delete the tag locally and remotely, fix, re-cut.

Post-publish, verify independently: registry propagation with bounded retry, `dist.integrity`
against the rehearsed artifact, provenance attestation (`npm audit signatures`), a fresh install
smoke test, the GitHub Release, and the production pages.

**Site deploy is not the Site workflow.** That workflow only builds and uploads an artifact. The
origin VPS polls `main` and rebuilds **within ten minutes** (`site/DEPLOY.md` §3.2). So production
lags a push — do not conclude a deploy failed until ten minutes have passed. Cloudflare tunnel,
`cf-cache-status: DYNAMIC`, `max-age=0`, so it is not a caching problem.

---

## Conventions

Commit messages are prose, not bullet lists: say what was wrong, why it mattered, and what
changed. Explain the reasoning a future reader would otherwise have to reconstruct. End with:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

Comments explain *why*, and frequently record the bug that motivated the code. Match that density
— it is the house style, not decoration.

---

## Open work

A large hardening sprint (Tracks A–J: cross-agent hostile audit, permission-semantics
differential, Cursor precedence, Antigravity grants, install torture matrix, corpus
productization, claim audit, supply-chain review, launch assets, researcher experience) was
**started and cancelled** after the first attack wave. Nothing from it is committed. Its
surviving hypotheses:

**S3 — Cursor's degraded allow contradicts itself.** `preToolUse` has no interactive ask, so a
non-floored ask becomes `allow` — documented. But the payload still says
`agent_message: "LeastGrant paused this: …"` alongside `permission: "allow"`. The model is told it
was stopped while the tool runs. Possibly not a hole, but it is a wrong statement to the model,
and a model that believes it was blocked may retry or work around it.

**S4 — there is no `leastgrant report-bypass` command.** `src/cli/commands/` has none. Either
build one with redaction as the primary constraint (it must never auto-upload private data, and a
researcher must be able to file a useful report without pasting credentials or a whole
transcript), or decide the `SECURITY.md` template is enough and say why.

**S5 — the corpus has no per-case metadata.** Cases carry `id`, `class`, `command`, `expect`,
`note`. A public evidence page would want expected security property, affected platforms/adapters,
historical status, and a regression-test reference — four fields that do not exist, so the page
cannot be generated without inventing them.

S1 (SECURITY.md generalising Claude Code's fail-open) and S2 (the stale pre-release caveat) were
**fixed** in `50b7b95` and `b7ac6c0`.

### Known limitation, stated not hidden

Copilot's `failure.onTimeout` is `unknown`. Do not round it up to match its crash behaviour —
`site/lib/facts.mjs` deliberately splits on `onCrash` for this reason.

---

## What does not transfer between machines

`.sprint/` is gitignored and holds **55 helper scripts** from the v0.5.0 hardening sprint.
`.sprint2/` holds scratch from the cancelled sprint. Neither is in git, so a fresh clone will not
have them. Five are load-bearing for the release process and would need rebuilding or promoting
into `scripts/`:

| script | what it proves |
|---|---|
| `freeze-assertions.mjs` | every release condition holds; records == doctor == README == site |
| `install-roundtrip.mjs` | all five agents install and uninstall byte-identically, other vendors intact |
| `vacuity-check.mjs` | each security claim is carried by the guard it names, with a control |
| `spaced-path-roundtrip.mjs` | install/reinstall/uninstall from a path containing a space |
| `spaced-checkout.mjs` | stages a runnable package copy under a spaced directory |

Everything else — source, tests, records, corpus, site, CI, release pipeline — is committed and
travels with the clone.
