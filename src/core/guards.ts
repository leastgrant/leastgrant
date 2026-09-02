/**
 * Hard floors.
 *
 * These are the rules learning can never unlock. Every other part of
 * LeastGrant is a heuristic that gets better as it watches you; this file is
 * the part that does not move. It exists so there is something we can describe
 * to a user without hedging.
 *
 * Floors are strictly one-directional: they can turn an `allow` into an `ask`,
 * or an `ask` into a `deny`. Nothing here can make an action *more* permitted.
 * That asymmetry is what makes slow-escalation attacks structurally impossible
 * rather than statistically unlikely — there is no amount of patient, boring,
 * approved behaviour that adds up to permission to read `~/.ssh/id_rsa`.
 *
 * Keep this file boring, short, and readable. If you cannot explain a guard to
 * a working developer in one sentence, it does not belong here.
 */

import * as path from 'node:path';
import type { Action, Decision } from './types.js';
import { canonicalDir, isInside } from './paths.js';

export interface GuardCtx {
  /** Canonical workspace roots. */
  roots: string[];
  /** Directory holding LeastGrant's own state. */
  stateDir: string;
  /** True when the tool call could not be fully parsed. */
  understood: boolean;
  /** Wrapper tags collected while unwrapping, e.g. `privilege`, `shell-eval`. */
  wrapperTags: string[];
  /** Whether the previous commands in this pipeline fetched something. */
  pipedFromNetwork: boolean;
}

export interface GuardHit {
  id: string;
  decision: Extract<Decision, 'ask' | 'deny'>;
  /** One sentence, addressed to the developer. */
  text: string;
}

/**
 * Files that cause code to run later, outside any agent session.
 *
 * Writing one of these is how a mistake becomes permanent and how a compromise
 * survives closing the terminal. Individually they are ordinary files a
 * developer edits by hand; the point is only that an *agent* should not edit
 * them without being noticed.
 */
const PERSISTENCE_FILES = [
  '.bashrc', '.bash_profile', '.bash_login', '.bash_logout', '.profile',
  '.zshrc', '.zprofile', '.zshenv', '.zlogin',
  '.envrc', '.direnvrc',
  '.gitconfig', '.gitmodules',
  '.npmrc', '.yarnrc', '.yarnrc.yml', '.pnpmfile.cjs', '.pnp.cjs', 'bunfig.toml',
  '.pre-commit-config.yaml', '.bazelrc',
  'crontab',
];

const PERSISTENCE_DIRS = [
  '.git/hooks',
  '.husky',
  '.vscode',
  '.idea',
  '.devcontainer',
  '.config/systemd',
  '.config/autostart',
  'library/launchagents',
  'library/launchdaemons',
  '/etc/systemd/system',
  '/etc/cron.d',
  '/etc/init.d',
  'appdata/roaming/microsoft/windows/start menu/programs/startup',
];

/**
 * Configuration that decides whether LeastGrant runs at all, or what any agent
 * is allowed to do. An agent editing these is editing its own restraints.
 */
const CONTROL_FILES = [
  // Files that steer an agent, a CI run, or the toolchain. Editing one of these
  // arranges for something else to run later, under someone else's authority —
  // the same reason `.bashrc` is floored, one level up.
  '.github/workflows',
  '.gitlab-ci.yml',
  '.circleci/config.yml',
  'azure-pipelines.yml',
  '.git/config',
  '.mcp.json',
  '.vscode/tasks.json',
  '.vscode/launch.json',
  '.devcontainer/devcontainer.json',
  // Lower-case, like every other entry: `isControlFile` folds the path before
  // comparing, so a capitalised entry here can never match anything. These two
  // were dead for exactly that reason — the instruction files that steer every
  // future agent session were the only control files not actually guarded.
  //
  // The rest of this family is matched by shape rather than spelled out, in
  // AGENT_INSTRUCTION below; see the note there for why.
  'agents.md',
  'agent.md',
  'claude.md',
  'claude.local.md',
  'gemini.md',
  // Slash commands and subagent definitions are prompts an agent will later
  // execute as instructions — editing one steers every future session.
  '.claude/commands',
  '.claude/agents',
  '.claude/skills',
  // Antigravity's equivalents, found by looking at what the installed 2.11.0
  // runtime actually keeps rather than by analogy: `builtin/skills` is the same
  // thing as `.claude/skills`, and `brain` and `implicit` are the persisted
  // memory a later session is handed as context. All three are instructions a
  // future run follows without anybody re-reading them.
  '.gemini/antigravity/builtin',
  '.gemini/antigravity/brain',
  '.gemini/antigravity/implicit',
  '.gemini/antigravity/knowledge',
  // package.json carries the scripts that `npm test` and friends run, so an
  // edit here is an edit to what a later approved command will execute.
  'package.json',
  // The same rule, applied consistently. The test that decides membership here
  // is not "does this file run code" — plenty do — but "is there an approved
  // command that will run it". `npm test`, `cargo build`, `cargo test` and
  // `pytest` are all understood, so all four are learnable, so all four can
  // cash in an edit to the file they execute.
  //
  // THREAT-MODEL.md used to list build.rs and conftest.py under "deliberately
  // not on the list", on the grounds that their runners stay understood:false
  // and can never be approved. That is true of `make`, `just`, `task`, `nox`
  // and `python setup.py`, which is where the reasoning came from, and it is
  // false of cargo and pytest — measured, not assumed. So a poisoned build.rs
  // was cashable end to end through an already-approved `cargo build`.
  'build.rs',
  'conftest.py',
  '.aider.conf.yml',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.claude/hooks',
  '.cursor/hooks.json',
  '.cursor/cli.json',
  '.codex/config.toml',
  '.gemini/settings.json',
  '.copilot/hooks',
  '.github/hooks',
  '.leastgrant/config.json',
  'managed-settings.json',
  // The file each agent reads to decide whether LeastGrant runs at all.
  //
  // Three of these were missing, found by probing every `configPath` in
  // `compatibility/*.json` through the real binary rather than by reading this
  // list. The list looked complete — `.codex/config.toml` and
  // `.gemini/settings.json` are both here — and the actual hook configuration
  // for those two agents lives somewhere else entirely.
  //
  // They were not silently allowed. `~/.codex/hooks.json` and
  // `~/.gemini/config/hooks.json` asked because they are outside the project,
  // and `<repo>/.agents/hooks.json` asked because it was unfamiliar. Neither is
  // a floor. Outside-home writes share the `<path:outside:home>` signature, so
  // approving one approves the class; unfamiliarity is what the promotion
  // machinery exists to retire. Both roads end at a silent allow on the file
  // that switches the enforcement off, which is the one edit that must always
  // reach a person.
  //
  // `test/control-files.test.ts` derives this requirement from the
  // compatibility records, so the next adapter cannot ship its config path
  // unfloored.
  '.codex/hooks.json',
  '.gemini/config/hooks.json',
  // Any file called `hooks.json`, wherever it sits.
  //
  // Named rather than enumerated by directory, because enumerating is what
  // kept failing. Antigravity 2.11.0 loads hooks from FOUR workspace roots —
  // `.agents`, `_agents`, `.agent`, `_agent` — and from `plugins/<name>/`
  // besides; `.agents/hooks.json` was floored and the other four were ordinary
  // project files. A write to any of them installs a handler that runs on every
  // subsequent tool call, and one returning `auto_approve` switches enforcement
  // off while LeastGrant still reports itself installed.
  //
  // The false positive is a project that keeps unrelated git-hook config under
  // this name and eats one prompt for it. The false negative is the next vendor
  // to pick a fifth directory.
  'hooks.json',
  // The customization roots themselves, so `mcp_config.json`, plugin
  // definitions and anything else the runtime learns to read there are covered
  // without waiting for the next drift report.
  '.agents',
  '_agents',
  '.agent',
  '_agent',
  // Antigravity's whole config directory, because that is what the runtime
  // itself calls it: `language_server.exe --config_dir="config"`, resolved
  // relative to the Gemini dir. Naming the individual files was the mistake
  // that left the first three above uncovered, and this directory holds worse
  // than a hook path.
  //
  // `config.json` in here carries `userSettings.globalPermissionGrants.allow`
  // — the host's OWN "Always allow" list, entries like
  // `mcp(playwright/browser_evaluate)` and `read_url(raw.githubusercontent.com)`.
  // An agent that appends one line to it grants itself standing approval from
  // the host, which is strictly worse than disabling LeastGrant: it is invisible
  // in LeastGrant's own state and it survives uninstalling us. It was reaching
  // only `guard.write-outside` plus a lucky filename match on the credentials
  // heuristic, and neither is a floor on the thing that matters.
  //
  // `mcp_config.json` decides which MCP servers the agent is wired to, which is
  // already why `.mcp.json` is floored; this is the same file under another
  // vendor's name.
  '.gemini/config',
  // The project registry, which maps a folder to the project whose settings and
  // resources the runtime will apply to it.
  '.gemini/projects.json',
  // OpenCode's, which no adapter reads yet. Guarding it is not an integration
  // claim — a poisoned permission config is worth a prompt whether or not
  // LeastGrant is the thing being disabled.
  '.config/opencode',
  'opencode.json',
  'opencode.jsonc',
];

/**
 * Agent-instruction files, matched by shape rather than by vendor.
 *
 * The literal list above records the spellings that existed when it was
 * written. Vendors have since moved almost all of them: Cursor's `.cursorrules`
 * became `.cursor/rules/*.mdc`, Copilot's instructions are
 * `.github/copilot-instructions.md` and `.github/instructions/*.instructions.md`,
 * Claude Code grew `.claude/rules/` and `.claude/output-styles/`, and Windsurf,
 * Cline, Roo and Devin each ship their own `.x/rules/` directory. Every one of
 * those was silently ALLOWed, and — because an in-project write signs as the
 * same `Write(<path>)` as editing any source file — a handful of approvals of
 * ordinary source edits paid for them.
 *
 * Adding the current spellings to the list would fix today's names and be
 * stale again by the next rename. These three patterns are the shapes the
 * whole industry has converged on:
 *
 *  1. a dotfile whose name ends in `rules` (`.cursorrules`, `.windsurfrules`,
 *     `.clinerules`, `.roorules`, `.continuerules`, Zed's `.rules`) — as a file
 *     or, increasingly, as a directory of them;
 *  2. anything under a vendor dot-directory's instruction surface
 *     (`.cursor/rules`, `.claude/rules`, `.github/instructions`,
 *     `.devin/rules`, `.codex/prompts`, …);
 *  3. an instruction file recognised by its suffix (`*.instructions.md`,
 *     `*-instructions.md`, `*.prompt.md`, `*.chatmode.md`, `*.mdc`).
 *
 * Deliberately not here: `Makefile`, `justfile`, `Taskfile.yml`, `noxfile.py`,
 * `setup.py` and `build.rs`. They look like the same "an approved command runs
 * this later" case as `package.json`, but `make`, `just`, `task`, `nox` and
 * `setup.py` are opaque runners that never become approvable in the first
 * place, so poisoning their config buys an attacker nothing that is cashable —
 * and flooring them would put a prompt on an extremely common edit. Measured
 * before deciding; see the test named for it.
 */
const RULES_DOTFILE = /^\.[a-z0-9._-]*rules$/;
const AGENT_SURFACE_DIR =
  /(?:^|\/)\.[a-z0-9_-]+\/(?:rules?|commands?|agents?|subagents?|skills?|prompts?|instructions?|chatmodes?|modes?|output-styles?|workflows?|hooks?)(?:\/|$)/;
const AGENT_INSTRUCTION_SUFFIX = /(?:\.(?:instructions|prompt|chatmode)\.md|-instructions\.md|\.mdc)$/;

const isAgentInstruction = (p: string): boolean => {
  if (AGENT_SURFACE_DIR.test(p)) return true;
  if (AGENT_INSTRUCTION_SUFFIX.test(p)) return true;
  // As a file, or as any segment of the path when it is a directory of rules.
  return p.split('/').some((seg) => RULES_DOTFILE.test(seg));
};

const isControlFile = (abs: string): boolean => {
  const p = abs.replace(/\\/g, '/').toLowerCase();
  if (CONTROL_FILES.some((c) => p.endsWith('/' + c) || p.includes('/' + c + '/'))) return true;
  return isAgentInstruction(p);
};

const isPersistence = (abs: string): boolean => {
  const p = abs.replace(/\\/g, '/').toLowerCase();
  const base = path.posix.basename(p);
  if (PERSISTENCE_FILES.includes(base)) return true;
  return PERSISTENCE_DIRS.some((d) => p.includes('/' + d + '/') || p.endsWith('/' + d) || p.includes(d + '/'));
};

/**
 * Evaluate every floor against an action. Returns all hits, worst first, so the
 * explanation can mention more than one reason when more than one applies.
 */
export function checkGuards(action: Action, ctx: GuardCtx): GuardHit[] {
  const hits: GuardHit[] = [];
  const add = (id: string, decision: 'ask' | 'deny', text: string) => hits.push({ id, decision, text });

  // --- LeastGrant's own integrity -----------------------------------------
  // An agent in bypass mode can write anywhere, including to the hook config
  // that installs us. Removing the seatbelt must not itself be a quiet action.
  //
  // The state directory is canonicalized here because targets already are, and
  // comparing a resolved path against an unresolved boundary silently answers
  // "no" — which for this particular guard would mean an agent could edit
  // LeastGrant's own records unchallenged.
  const stateRoot = canonicalDir(ctx.stateDir);
  for (const t of action.targets) {
    if (t.type !== 'path' || !t.value) continue;
    if (isInside(t.value, stateRoot)) {
      if (action.kind !== 'file.read') {
        add(
          'guard.self-write',
          'deny',
          "this would modify LeastGrant's own records, which it does not allow — run leastgrant commands directly instead",
        );
      }
    } else if (isControlFile(t.value) && action.kind !== 'file.read') {
      add(
        'guard.agent-config',
        'ask',
        'this edits the configuration that decides what agents are allowed to do, including the hook that runs these checks',
      );
    }
  }

  // --- credentials ---------------------------------------------------------
  if (action.blast.exposure === 'reads-secrets' || action.capability === 'secret.read') {
    const which = action.targets.find((t) => t.secret);
    // "reads" is wrong for a write. `Write ~/.claude/settings.json` was
    // reported as "this reads … which holds credentials", which describes the
    // wrong action and undersells it: overwriting a credential file is worse
    // than reading one.
    const verb = action.capability.startsWith('fs.write') || action.kind === 'file.write' || action.kind === 'file.edit'
      ? 'writes to'
      : 'reads';
    add(
      'guard.secret-read',
      'ask',
      which
        ? `this ${verb} ${short(which.value)}, which holds credentials`
        : 'this reads something that holds credentials',
    );
  }
  if (action.blast.exposure === 'can-exfiltrate') {
    add(
      'guard.exfiltrate',
      'ask',
      'this sends data off the machine, so anything it can read it can also leak',
    );
  }

  // --- writing outside the workspace --------------------------------------
  //
  // Keyed on the target, not on the capability.
  //
  // Keying it on the capability meant the floor only fired for programs the
  // knowledge base had already labelled as writing outside — which is precisely
  // the judgement being checked. Anything that named its destination in a flag
  // slipped past: `curl -o /etc/cron.d/x`, `wget --save-cookies ~/.bashrc`,
  // `tar --directory /etc`, `git -C /elsewhere commit`, `find / -exec chmod`.
  //
  // Reads are excluded and stay learnable: fetching `/usr/share/dict/words`
  // every build is ordinary, and its region-scoped signature already keeps that
  // trust from spreading. Everything else that reaches outside the project asks.
  const READ_ONLY: ReadonlySet<string> = new Set([
    'fs.read.workspace',
    'fs.read.outside',
    'exec.inspect',
    'exec.vcs.read',
    'meta',
  ]);
  if (!READ_ONLY.has(action.capability)) {
    const outside = action.targets.filter((t) => t.type === 'path' && t.value && t.inWorkspace === false);
    if (outside.length) {
      add(
        'guard.write-outside',
        'ask',
        `this reaches ${short(outside[0]!.value)}, which is outside the project`,
      );
    }
  }

  // --- persistence ---------------------------------------------------------
  if (action.kind === 'file.write' || action.kind === 'file.edit' || action.capability === 'fs.write.workspace' || action.capability === 'fs.write.outside') {
    const p = action.targets.find((t) => t.type === 'path' && t.value && isPersistence(t.value));
    if (p) {
      add(
        'guard.persistence',
        'ask',
        `this edits ${short(p.value)}, which runs automatically later — outside any agent session`,
      );
    }
  }
  if (action.capability === 'exec.process' && /crontab|schtasks|systemctl|launchctl|\bat\b|reg\b/.test(action.display)) {
    if (/crontab|schtasks|launchctl (load|bootstrap)|systemctl (enable|--user enable)|reg (add|import)/.test(action.display)) {
      add(
        'guard.persistence',
        'ask',
        'this schedules something to run later, outside any agent session',
      );
    }
  }

  // --- privilege -----------------------------------------------------------
  if (ctx.wrapperTags.includes('privilege') || action.capability === 'exec.privilege') {
    add('guard.privilege', 'ask', 'this runs with elevated privileges');
  }

  // --- executing fetched content ------------------------------------------
  if (ctx.pipedFromNetwork) {
    add(
      'guard.pipe-to-shell',
      'ask',
      'this runs code that was just downloaded, so what it does depends on what the server sent back',
    );
  }
  if (ctx.wrapperTags.includes('pkg-fetch-run')) {
    add(
      'guard.fetch-run',
      'ask',
      'this can download a package and run it in one step',
    );
  }

  // --- irreversible and far-reaching --------------------------------------
  if (action.blast.reach === 'production') {
    // Reach 'production' covers both a resource literally named prod and a
    // shared branch everyone pulls from, so the wording has to fit both. The
    // specifics come from the knowledge module's own note, which is printed
    // directly above this line.
    add('guard.production', 'ask', 'this affects something other people depend on');
  }
  if (action.capability === 'exec.pkg.publish') {
    add('guard.publish', 'ask', 'publishing is public and cannot be taken back');
  }
  if (action.blast.reversibility === 'irreversible' && action.blast.reach !== 'workspace') {
    add('guard.irreversible', 'ask', 'this cannot be undone');
  }

  // --- we did not understand it -------------------------------------------
  if (!ctx.understood || !action.understood) {
    add(
      'guard.not-understood',
      'ask',
      'LeastGrant could not fully account for what this command does, and it only auto-approves things it understands',
    );
  }

  return hits.sort((a, b) => (a.decision === 'deny' ? -1 : 0) - (b.decision === 'deny' ? -1 : 0));
}

/** The strongest decision implied by a set of guard hits, if any. */
export function guardDecision(hits: GuardHit[]): Decision | null {
  if (hits.some((h) => h.decision === 'deny')) return 'deny';
  if (hits.length) return 'ask';
  return null;
}

function short(p: string): string {
  const norm = p.replace(/\\/g, '/');
  const parts = norm.split('/');
  return parts.length > 3 ? '…/' + parts.slice(-3).join('/') : norm;
}
