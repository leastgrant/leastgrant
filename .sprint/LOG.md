# 48-hour sprint log

Survives context compaction. Update after every merged change.

Started: 2026-09-02, repo at 18772b0, version 0.2.0, 1076 core + 200 site tests green.

## HAZARD LEARNED THE HARD WAY
Do NOT junction node_modules into a git worktree. `git worktree remove --force`
follows the junction and deletes the contents of the REAL node_modules. It
happened once here; recovered with `npm ci` (3 packages, 1s, so cheap). Use
`npm ci --ignore-scripts` inside worktrees instead. Agents in the fix campaign
were told to junction, so expect this to recur when their worktrees are cleaned
up - just re-run npm ci.

## Orchestration budget
12 CPUs -> each Workflow caps at 10 concurrent agents. Max 3 concurrent
workflows = the 30-agent ceiling. Never launch a 4th while 3 are live.

## Ground truth established solo (before any agent ran)
- `decide.ts:152` floor aggregation ALREADY FIXED in a prior session
  (`judged.some(j => j.hits.length > 0)`).
- Version comes from package.json, site auto-deploys from main via a systemd
  timer on the VPS. Live at v0.2.0.

## Confirmed bugs found solo (feed these to attackers as seeds, already proven)
1. **decide.ts:137 taint evaluated only on the winning action.**
   `taintConcern(ctx.session, worst.action.capability, worst.action.blast)`.
   In a compound command the escalation on a losing action is dropped.
2. **claude-code/hook.ts:308 session taint recorded only for the winning action.**
   `applyTaint(session, verdict.action.capability)` vs `replay.ts:244` which
   loops over every action. So `rm -rf ./build && cat ~/.ssh/id_rsa` taints the
   session with `fs.delete` and NOT `secret.read` -> a later `curl` in the same
   session gets no taint concern. Production and `leastgrant simulate` disagree.

Both are the same root class as the already-fixed floor bug: **per-action
security metadata is dropped when one action is chosen to represent the set.**

3. **"Is a human watching?" is encoded three times, three different ways.**
   - `claude-code/hook.ts:67` ATTENDED allowlist {default,plan,ask}, lowercased.
   - `doctor.ts:71` UNATTENDED *blocklist* {bypassPermissions,acceptEdits,
     dontAsk,auto}, CASE-SENSITIVE. The comment admits the duplication.
   - `codex/hook.ts:77` PROMPTS_A_HUMAN allowlist {default,acceptedits,plan,
     ask,''} - includes acceptEdits, contradicting the other two.
   Consequences: an unknown mode ("yolo") is unattended to the hook (safe) but
   ATTENDED to doctor, which therefore under-reports unattended activity. A
   differently-cased mode string diverges too. This is the exact motivation for
   the AgentCapabilities contract - one place, capability-derived, not three
   hand-maintained sets. Severity: reporting integrity, not an enforcement hole.

## CRITICAL found solo (2026-09-02, via the adapter fuzzer's control case)

**Learned trust in a benign `export` transfers to an environment hijack.**

    signature of `export CACHE_DIR=/tmp/build`   -> "export <path>"
    signature of `export LD_PRELOAD=/tmp/evil.so` -> "export <path>"   SAME

The templater erases the variable NAME, which is the entire security content of
an export. Train on the first (an ordinary build step) and the second is
auto-approved, along with BASH_ENV, NODE_OPTIONS and PYTHONSTARTUP. Reproduced:
all four return `allow`, `floor=false`, from 40 sessions of the benign one only.

Violates the claim bypass.test.ts states in its own header: "no amount of
learned trust in a shape can be spent on a different action wearing that shape."

Secondary, same area:
- `export <anything>` is capability `meta`, blast tier 0, reach `none`. An
  export is not inert: it changes what every later command in that shell does.
  The inline form `LD_PRELOAD=x git status` IS caught (floor=true); only the
  standalone/`&&` form escapes, so the corpus case for this class is evaded by
  splitting it in two.
- Because floor=false, the Codex adapter stands aside in unattended modes,
  so this is an unsafe-allow there even before learning is involved.
- `cd` IS correctly tracked in compound commands - `cd /etc && echo > passwd`
  resolves outside the workspace. Not a bug; verified while investigating.

Nearly shipped a change making this worse: TodoWrite/ExitPlanMode ask forever
(tier 0, genuinely inert) and the obvious fix is "auto-allow tier 0". That would
have made `export LD_PRELOAD=...` instantly auto-approved. Any tier-0 fast path
must come AFTER exports stop being tier 0.

## LANDED ON MAIN (pushed)
- f72fcde corpus/bypasses.json is the source; bypass.test.ts reads it
- 8ebb51d `leastgrant benchmark` (core decision p95 585us idle, budget 10ms)
- ad5208f **env-hijack fix** (my critical, above). 1298 tests green.

## AUDIT RESULT wf_6ea7b04c-360: 16 confirmed, 12 refuted, 0 unverified
Full detail in `.sprint/audit-findings.json`. Clusters by root cause:
- shell-unwrap (unwrap.ts): #4 assignment-only dropped, #5 nested -c, #6 env -S,
  #13 find -exec, #14 pipedFromNetwork top-level only. ALL reach ALLOW.
- paths-floor (paths.ts/classify.ts): #3 unresolvable path disables every
  path-keyed floor incl. the non-overridable self-write DENY, #10 device
  namespace, #11 credential signature laundering.
- session-race (hook.ts:582): #1 CRITICAL lock-free read-modify-write loses the
  taint set; 4/25 trials at 5 concurrent. Verifier notes writeAtomic alone is
  NOT enough - needs mutual exclusion or append-only taints.
- codex-wire (codex/hook.ts): #2 argv-array command never translated (the
  NORMAL shape), #9 workdir dropped.
- guards-secrets: #12 `grep -r ~`, #15 SAM regex missing /i, #16 CONTROL_FILES.
- aggregation (decide.ts:97): #7 sort tie-break is input order.

## AGGREGATION SPEC wf_9114bfdc-82a -> `.sprint/aggregation-spec.md` (72k)
Confirmed additionally: `rm -rf ./build && curl <url>` = ALLOW while the curl
alone = ASK. An allow-rule can make Codex HARD-DENY an unrelated command.
Production learns 1 action, replay learns all. blastTier is NOT a lattice
homomorphism (per-dimension join invents tier 3 for `npm test && curl`), which
rules out the naive join. taintConcern's `blast` param is dead code.

## UPSTREAM CONTRACTS wf_d4921637-641 -> `.sprint/upstream-contracts.json`
**Cursor 3.18.25, Antigravity 2.11.0, OpenCode 1.18.26 are ALL INSTALLED here.**
Claims in our docs that upstream evidence contradicts (must fix before release):
- README ~432 "an ask reaches you in every mode" on Claude Code is FALSE -
  probed: ask becomes DENY under `claude -p` in bypass/manual/acceptEdits/dontAsk.
- Codex: only DENY is enforced on PreToolUse, not ALLOW. codexCaveat says both.
- Codex PostToolUse fires only on success -> learning never sees failures.
- Codex `"async": true` handler = silent total bypass.
- Codex trust hash covers commandWindows only on Windows (per-OS hash drift).
- Cursor beforeReadFile may be POST-execution with content already loaded.
- Cursor does not intercept writes/edits/deletes at all.
- Cursor preToolUse `ask` REJECTS the call with an error, not a prompt.
- test/cursor.test.ts:56 asserts `afterReadFile`, which may not exist.
- Cursor workspace_roots are VS Code URIs ('/d:/LeastGrant'), not fs paths.
- Cursor has `failClosed: true`; our installer writes bare {command} = fails open.
- Cursor ingests .claude/settings.json too - possible double-install.
- ATTENDED contains 'ask', not a real Claude Code mode.
- install.ts registers only PreToolUse/PostToolUse; failures fire
  PostToolUseFailure -> pendingById leaks.
- mine.ts AUTO_ALLOWED has 'Task'; live payload names it 'Agent'.

## LANDED SINCE (all pushed)
- 4d5ac05 compatibility/*.json + test/compatibility.test.ts (the source of truth)
- 454c12a untrack agent worktrees, gitignore .claude/worktrees/
- 8433b20 doctor "what actually gets enforced, per agent", src/core/compatibility.ts
- 9775261 website /compatibility page + site tests; facts.mjs now reads the corpus
1365 core + 205 site tests green at 9775261.

## LANDED (quota-reset session)
- dec7fe7 merge guards-secrets fix (findings 12/15/16). I re-verified all three
  myself: `grep -r ~` now secret.read+sweeping, scoped searches unaffected,
  SECURITY.md is NOT a credential, ~/Documents is NOT a credential tree,
  agent-instruction files guarded with no false positives on src/README/Makefile.
- 3b7f86c /Users/alice -> /Users/you (the site's own leak check refused to
  publish a page containing what looks like a real home directory).
- **AGGREGATION FOLD** - taint per action + floor from `floored` not `hits` +
  total election order + new `Verdict.flooredGuards`. Closes the two bugs the
  invariant workflow confirmed. 1456 tests, both folds mutation-tested.
  NOTE FOR CODEX WORK: codex/hook.ts still classifies floors by scanning reason
  codes for a `guard.` prefix. It should read `flooredGuards` instead. The data
  is there now; the adapter migration was left to the in-flight cluster.

## IN FLIGHT
- wf_de8f9282-668 **criticals campaign** (relaunched after the quota reset
  killed the first attempt): shell-unwrap, paths-floor, session-race,
  codex-wire, each in a worktree, each with an independent verifier.
  These hold 5 of the 6 criticals. guards-secrets already landed.

## DEAD / SUPERSEDED
- wf_5dea6e16-9ef: 4 of 5 clusters died on the 429 budget wall. Only
  guards-secrets finished; landed as dec7fe7. Relaunched as wf_de8f9282-668.
- wf_900d6002-1ad Cursor: 4/6 agents finished, findings captured in
  .sprint/upstream-contracts.json. The fix+verify agents died. Cursor claim
  corrections are STILL TO DO.
- wf_524764a6-4c9 Antigravity: died before assessing. Antigravity 2.11.0 IS
  installed and has force_ask; spike not yet done.
- wf_8525a5f1-588 attack wave 2: all 8 agents died on budget. Not re-run.

## DECIDED
- OpenCode: DEFER, well-evidenced. permission.ask is in the types and never
  fired by the binary (live probe). Recorded in compatibility/opencode.json.
- Antigravity: strongest ask semantics of any agent (non-suppressible
  force_ask). Spike running.

## UNKNOWN-RATE MEASUREMENT (§17) - DONE, and the answer is "do not chase it"
`node scripts/measure-unknowns.mjs`, 7,399 real Bash commands from 120 local
transcripts. Raw JSON in `.sprint/unknown-rate.json`.

    understood                    43.4%   (README says 44.5% - consistent)
    not understood                56.6%
      of those unknowns:
        an interpreter running code we cannot read      78.0%
        a family a known-tool fix could plausibly reach  5.2%  (2.9% of all)

So the prompt budget is dominated by `python x.py`, `python -c`, `node -e` and
script files - exactly the class where guessing would be unsafe and where
"opaque stays opaque" is the correct answer, not a gap. Covering EVERY package
runner, npm script, build tool, make, test runner and docker invocation
perfectly would move the understood rate by under 3 points.

**Conclusion: there is no large safe win in the unknown rate.** Effort should go
to correctness, not coverage. Revisit only if a cheap, sound signal appears for
interpreter invocations (e.g. hashing a script body so learned evidence dies
when the body changes) - and that is a much smaller idea than it first looks.

Caveat recorded rather than acted on: this script reports 1.6 ms average, the
README 0.03 ms. They are not the same measurement (this runs full `analyze()`
including path canonicalisation; the README figure is the shell parser) and the
machine had nine agents on it. Not a regression claim - re-measure idle.

## STILL TO DO
- capability contract in code (.sprint/capability-contract.md, 41k) - blocked on
  the adapter fixes landing, since it rewrites all adapters.
- aggregation invariant (.sprint/aggregation-spec.md, 72k) - blocked likewise.
- adapter conformance suite (§8)
- README support table generated from compatibility/ (deferred: cursor+codex
  fixers are both editing README right now)
- /security/corpus website page
- unknown-rate measurement (§17) before any tier-0 fast path
- release

## Status
- [x] Phase 0 recon
- [~] Phase 1 core aggregation audit RUNNING wf_6ea7b04c-360
- [~] Phase 2 capability contract: upstream wf_d4921637-641, invariant wf_9114bfdc-82a
- [ ] Phase 3 conformance suite
- [ ] Phase 4 doctor
- [ ] Phase 5 compatibility data
- [ ] Phase 6 live tests
- [ ] Phase 7 release

## Worktrees in flight
- `../lg-corpus` branch `sprint/corpus` @ f72fcde - corpus/bypasses.json is now
  the source, bypass.test.ts reads it, test/helpers/repo-root.ts extracted.
  1084 tests green. NOT yet merged to main (waiting for the audit to finish so
  attackers are not building against a moving tree).
  node_modules there is a junction to the main repo's.

## Workflow runs
(append runId + outcome)
