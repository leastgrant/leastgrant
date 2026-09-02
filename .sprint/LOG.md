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
