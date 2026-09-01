/**
 * Version control: git, gh, hg, svn, glab, jj.
 *
 * An agent runs `git` more than any other program, and almost all of it is
 * `status`, `diff`, `log`, `add`, `commit`. Those should be silent forever.
 * The value of this module is the small set of invocations that are nothing
 * like them, and the fact that they are spelled almost the same:
 *
 *   - `git checkout .`, `git restore .`, `git reset --hard`, `git clean -fdx`
 *     destroy uncommitted work. No commit, no reflog, no stash holds it. This
 *     is the most commonly missed danger in the whole tool, because everything
 *     else about git is famously recoverable.
 *   - `git push --force` rewrites history other people have already pulled.
 *     `--force-with-lease` refuses to when the remote moved, so it is a
 *     genuinely different action and is graded differently.
 *   - `git config --global` writes outside the project, and a handful of keys
 *     (`core.pager`, `alias.*`, `credential.helper`, the filter and textconv
 *     families) tell git to run a program later. Writing one of those is a way
 *     to arrange code execution that no later command will look suspicious.
 *   - `git gc --prune=now` and `git reflog expire` throw away the objects that
 *     every other "don't worry, git remembers" claim depends on.
 *
 * Where a subcommand takes a user-supplied command (`rebase --exec`,
 * `submodule foreach`, `bisect run`, `filter-branch`) the real effect is not in
 * the argv we can read, so those are marked opaque.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { nonFlags, hasFlag, flagValue, hostOf } from './types.js';

type Targets = NonNullable<Judgement['targets']>;

// --- shared helpers --------------------------------------------------------

/**
 * Short flags bundle: `git clean -fdx` is `-f -d -x`, and `hasFlag` only does
 * exact matches. Anything after `--` is a pathspec, not a flag.
 */
function shortFlag(argv: string[], letter: string, from = 1): boolean {
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') break;
    if (!a.startsWith('-') || a.startsWith('--') || a === '-') continue;
    if (a.slice(1).includes(letter)) return true;
  }
  return false;
}

/** Index of the first non-flag argument, so callers can read what follows it. */
function firstNonFlagIndex(argv: string[], from = 1): number {
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return i + 1 < argv.length ? i + 1 : -1;
    if (!a.startsWith('-')) return i;
  }
  return -1;
}

/** Hostname of a git remote, including the `git@host:org/repo` scp form. */
function gitHost(arg: string): string | undefined {
  const url = hostOf(arg);
  if (url) return url;
  const scp = /^(?:[^@/\s]+@)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::|\/)/i.exec(arg);
  return scp ? scp[1]!.toLowerCase() : undefined;
}

/** Name a remote (and its host, when the argument is a URL) as targets. */
function remoteTargets(arg: string | undefined): Targets {
  if (!arg || arg.startsWith('-')) return [];
  const out: Targets = [{ type: 'remote', value: arg }];
  const host = gitHost(arg);
  if (host) out.push({ type: 'host', value: host });
  return out;
}

/**
 * Does any argument name a credential file?
 *
 * Covers the `rev:path` form too, because `git show HEAD:.env` and
 * `git cat-file -p main:secrets.yml` print secrets without ever naming a path
 * the generic extractor would recognise.
 */
function touchesSecret(argv: string[], ctx: KnowledgeCtx, from: number): boolean {
  for (const a of nonFlags(argv, from)) {
    const colon = a.lastIndexOf(':');
    const candidates = colon > 0 ? [a, a.slice(colon + 1)] : [a];
    for (const c of candidates) {
      if (!c) continue;
      const abs = ctx.resolve(c);
      if (abs && ctx.isSecret(abs)) return true;
    }
  }
  return false;
}

/** Do any of these arguments land outside the workspace? */
function anyOutside(args: string[], ctx: KnowledgeCtx): boolean {
  return args.some((a) => {
    const abs = ctx.resolve(a);
    return abs !== '' && !ctx.inWorkspace(abs);
  });
}

/**
 * An argument that is far more likely to be a file than a branch name.
 * Branches are `feature/foo`; pathspecs are `.`, `src/`, `main.ts`, `*.json`.
 */
function looksLikePathspec(a: string): boolean {
  if (a === '.' || a === '..' || a === '*') return true;
  if (a.startsWith('./') || a.startsWith('../') || a.startsWith(':/') || a.startsWith(':!')) return true;
  if (a.endsWith('/') || a.endsWith('\\')) return true;
  if (a.includes('*') || a.includes('?')) return true;
  return /\.[A-Za-z0-9]{1,12}$/.test(a);
}

/**
 * git settings whose value is a program, or a place git looks for programs.
 * Writing one of these is arranging for code to run on some later, innocent
 * looking git command, so it is graded as a privilege change rather than a
 * config write.
 */
const CONFIG_EXECUTES =
  // `protocol.version` is exempt: it is the one key in the `protocol.` family
  // that selects a wire format rather than enabling a transport helper, and it
  // appears in ordinary CI invocations constantly.
  /^(alias\.|core\.(pager|editor|sshcommand|hookspath|fsmonitor|gitproxy|askpass|alternaterefscommand)|credential\.|diff\..*\.(textconv|command|external)|difftool\.|merge\..*\.driver|mergetool\.|filter\..*\.(clean|smudge|process)|trailer\..*\.command|url\..*\.insteadof|http\.(proxy|sslcainfo)|remote\..*\.(uploadpack|receivepack|proxy)|gpg\.|init\.templatedir|protocol\.(?!version\b)|sequence\.editor|pager\.|browser\.|help\.browser|guitool\.|man\..*\.cmd|instaweb\.|uploadpack\.|receive\.|safe\.directory|include\.|includeif)/i;

/** Config keys whose values are, or reveal, credentials. */
const CONFIG_CREDENTIAL = /credential|password|passwd|token|\bauth\b|secret|apikey|api[._-]?key/i;

/** Branches that other people, or a deployment, are relying on. */
const PROTECTED_REF = /^(refs\/heads\/)?(main|master|trunk|develop|development|prod|production|release|stable)$/i;

// --- git -------------------------------------------------------------------

/** Global git options that swallow the following argument. */
const GIT_GLOBAL_VALUE_FLAGS = new Set([
  '-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env', '--super-prefix',
]);

/** Find the subcommand, stepping over global options and their values. */
function gitSubcommand(argv: string[]): { name: string; at: number } | undefined {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith('-')) return { name: a.toLowerCase(), at: i };
    if (GIT_GLOBAL_VALUE_FLAGS.has(a)) i++;
  }
  return undefined;
}

/**
 * Every `key=value` handed to git as `-c`, `--config` or `--config-env`, from
 * index `from`. Set `stopAtNonFlag` to scan only git's own global options,
 * which sit before the subcommand; clear it to scan a subcommand's own
 * options, which is where `git clone -c ...` lives.
 */
function configPairs(argv: string[], from: number, stopAtNonFlag: boolean): string[] {
  const out: string[] = [];
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-c' || a === '--config' || a === '--config-env') {
      const v = argv[i + 1];
      if (v !== undefined) out.push(v);
      i++;
      continue;
    }
    if (a.startsWith('--config=')) { out.push(a.slice(9)); continue; }
    if (a.startsWith('--config-env=')) { out.push(a.slice(13)); continue; }
    // The glued `-ccore.pager=x` form is accepted by git just the same.
    if (a.startsWith('-c') && !a.startsWith('--') && a.length > 2) { out.push(a.slice(2)); continue; }
    if (stopAtNonFlag && !a.startsWith('-')) break;
    if (GIT_GLOBAL_VALUE_FLAGS.has(a)) i++;
  }
  return out;
}

/** Does any of those pairs name a setting that makes git run a program? */
function configExecutes(pairs: string[]): boolean {
  return pairs.some((kv) => CONFIG_EXECUTES.test(kv.split('=')[0] ?? ''));
}

/** Every value given to `flag`, in both `--flag value` and `--flag=value` form. */
function flagValues(argv: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === flag) {
      const v = argv[i + 1];
      if (v !== undefined) out.push(v);
      i++;
      continue;
    }
    if (a.startsWith(flag + '=')) out.push(a.slice(flag.length + 1));
  }
  return out;
}

/** Subcommands that only ever report. None of them can change a byte. */
const GIT_READ = new Set([
  'status', 'diff', 'diff-files', 'diff-index', 'diff-tree', 'log', 'shortlog', 'show', 'blame',
  'annotate', 'whatchanged', 'describe', 'rev-parse', 'rev-list', 'name-rev', 'merge-base',
  'ls-files', 'ls-tree', 'cat-file', 'check-ignore', 'check-attr', 'check-ref-format',
  'check-mailmap', 'count-objects', 'verify-commit', 'verify-tag', 'verify-pack', 'fsck',
  'var', 'grep', 'cherry', 'range-diff', 'show-branch', 'show-ref', 'for-each-ref',
  'for-each-repo', 'get-tar-commit-id', 'patch-id', 'request-pull', 'interpret-trailers',
  'stripspace', 'rerere',
]);

/**
 * Transport options that hand a command name to one end of the connection.
 * `ext::sh -c ...` as a URL, or `--upload-pack=`, is remote-code-execution
 * dressed up as a clone.
 */
function namesAProgram(argv: string[]): boolean {
  return argv.some((a, i) => {
    if (i === 0) return false;
    if (a.startsWith('ext::')) return true;
    if (a.startsWith('--upload-pack') || a.startsWith('--receive-pack')) return true;
    if (a === '--exec' || a.startsWith('--exec=')) return true;
    if (a === '--template' || a.startsWith('--template=')) return true;
    return false;
  });
}

function classifyGit(argv: string[], ctx: KnowledgeCtx): Judgement {
  const sub = gitSubcommand(argv);
  if (sub && GIT_CONTENT_CHOOSES_DESTINATION.has(sub.name)) {
    // The patch names the files it touches, and a patch can name
    // `../../etc/cron.d/x`. Nothing in argv reveals that, so this is the same
    // situation as archive extraction: judged from the command line, it is a
    // guess.
    return {
      capability: 'fs.write.workspace',
      reversibility: 'hard',
      scale: 'many',
      opaque: true,
      note: 'applies a patch, and the patch chooses which files it touches',
    };
  }
  if (!sub) {
    // Bare `git`, or only global flags: prints usage.
    return { capability: 'meta', note: 'prints git usage', pathArgs: 'none' };
  }
  const { name, at } = sub;
  const args = nonFlags(argv, at + 1);
  const arg0 = args[0];

  // A global `-c key=value` takes effect before the subcommand does, so
  // `git -c core.pager='sh -c ...' log` is arbitrary code execution wearing
  // the argv of a pure read. This outranks whatever the subcommand is,
  // including `help`, which pages its output too.
  if (configExecutes(configPairs(argv, 1, true))) {
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'hard',
      opaque: true,
      note: 'sets a git setting for this one command that makes git run a program of its own',
      pathArgs: 'none',
    };
  }
  // `--exec-path=<dir>` is where git looks for its own subcommands, and it is
  // prepended to PATH for everything git spawns.
  if (argv.some((a, i) => i > 0 && a.startsWith('--exec-path='))) {
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'hard',
      opaque: true,
      note: 'points git at another directory for the programs it runs',
      pathArgs: 'none',
    };
  }

  if (name === 'help' || name === 'version') {
    return { capability: 'meta', note: 'prints git documentation', pathArgs: 'none' };
  }

  // --- pure reads --------------------------------------------------------
  if (GIT_READ.has(name)) {
    if (touchesSecret(argv, ctx, at + 1)) {
      return { capability: 'secret.read', note: 'prints the contents of a credential file', pathArgs: 'none' };
    }
    // `--output=<file>` is a diff option, so `log`, `show` and `diff` all take
    // it, and it redirects to a file of your choosing instead of stdout. A
    // read command that writes anywhere on disk is not a read.
    const outFile = flagValue(argv, '--output');
    if (outFile !== undefined && outFile !== '') {
      const outside = anyOutside([outFile], ctx);
      return {
        capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
        reach: outside ? 'machine' : 'workspace',
        note: outside
          ? 'writes its output over a file outside the project instead of printing it'
          : 'writes its output over a file instead of printing it',
      };
    }
    // `git grep -O<cmd>` hands every matching file to a program you name.
    if (name === 'grep' && (hasFlag(argv, '--open-files-in-pager') || shortFlag(argv, 'O', at + 1))) {
      return { capability: 'exec.unknown', opaque: true, note: 'opens every matching file in a program of your choosing', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.read', pathArgs: 'none' };
  }

  // `difftool -x cmd` runs whatever you name, once per changed file.
  if (name === 'difftool') {
    if (hasFlag(argv, '-x', '--extcmd')) {
      return { capability: 'exec.unknown', opaque: true, note: 'runs a command of your choosing over each changed file', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.read', note: 'opens the configured diff viewer', pathArgs: 'none' };
  }
  if (name === 'mergetool') {
    // The tool itself comes from config, so what actually runs is not in argv.
    return { capability: 'exec.vcs.write', opaque: true, note: 'opens the configured merge tool and writes the resolved files', pathArgs: 'none' };
  }

  // --- network reads -----------------------------------------------------
  if (name === 'ls-remote') {
    return {
      capability: 'exec.vcs.read',
      reach: 'network',
      note: 'asks a remote repository which refs it has',
      pathArgs: 'none',
      targets: remoteTargets(arg0),
    };
  }
  if (name === 'fetch') {
    if (namesAProgram(argv)) {
      return { capability: 'exec.unknown', opaque: true, reach: 'network', note: 'names a program for the remote end to run', pathArgs: 'none' };
    }
    // An explicit refspec with a destination writes *local* refs, not just
    // remote-tracking ones: `git fetch origin +main:main` moves your own main
    // to whatever the remote says, fast-forward or not. That is the one shape
    // of fetch that can lose commits.
    const fetchDests = args.slice(1).filter((r) => r.includes(':'));
    if (fetchDests.length > 0) {
      const forced = fetchDests.some((r) => r.startsWith('+')) || hasFlag(argv, '--force', '-f') || shortFlag(argv, 'f', at + 1);
      return {
        capability: 'exec.vcs.write',
        reach: 'network',
        reversibility: forced ? 'hard' : 'easy',
        note: forced
          ? 'downloads from the remote and overwrites the named local branches with it, fast-forward or not'
          : 'downloads from the remote and updates the local branches named in the refspec',
        pathArgs: 'none',
        targets: remoteTargets(arg0),
      };
    }
    return {
      capability: 'exec.vcs.read',
      reach: 'network',
      // fetch writes objects and remote-tracking refs, but never touches the
      // working tree or any local branch, so nothing you have can be lost.
      note: hasFlag(argv, '--prune', '-p')
        ? 'downloads from the remote and drops remote-tracking branches that are gone'
        : 'downloads commits from the remote without changing your branches',
      pathArgs: 'none',
      targets: remoteTargets(arg0),
    };
  }

  // --- clone: network in, files out --------------------------------------
  if (name === 'clone') {
    if (namesAProgram(argv)) {
      return { capability: 'exec.unknown', opaque: true, reach: 'network', note: 'clones through a transport that runs a program', pathArgs: 'none' };
    }
    // `clone` spells this `-c` as well as `--config`, and accepts it more than
    // once, so every pair has to be checked rather than just the first.
    if (configExecutes(configPairs(argv, at + 1, false))) {
      return { capability: 'exec.privilege', reach: 'machine', reversibility: 'hard', opaque: true, note: 'clones with a setting that makes git run a program of its own', pathArgs: 'none' };
    }
    const dest = args[1];
    const outside = dest !== undefined && anyOutside([dest], ctx);
    return {
      capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
      reach: 'network',
      scale: 'many',
      note: outside
        ? 'downloads a repository from the network into a directory outside the project'
        : hasFlag(argv, '--recurse-submodules', '--recursive')
          ? 'downloads a repository and its submodules from the network'
          : 'downloads a repository from the network into a new directory',
      targets: remoteTargets(arg0),
    };
  }

  // --- pull: fetch plus a local history change ---------------------------
  if (name === 'pull') {
    const rebasing = hasFlag(argv, '--rebase', '-r');
    return {
      capability: 'exec.vcs.write',
      reach: 'network',
      reversibility: rebasing ? 'hard' : 'easy',
      scale: 'many',
      note: rebasing
        ? 'downloads from the remote and replays your commits on top, rewriting them'
        : 'downloads from the remote and merges it into the current branch',
      pathArgs: 'none',
      targets: remoteTargets(arg0),
    };
  }

  // --- push: the one that leaves the machine -----------------------------
  // `send-pack` is push in plumbing clothes, down to `--force` and `--mirror`;
  // left to the fallback it would read as a merely opaque local command.
  if (name === 'push' || name === 'send-pack') return classifyGitPush(argv, at);

  // --- staging and committing --------------------------------------------
  if (name === 'add' || name === 'stage') {
    // Staging a credential file is the first half of committing it, and the
    // commit itself will look completely routine.
    if (touchesSecret(argv, ctx, at + 1)) {
      return {
        capability: 'exec.vcs.write',
        exposure: 'reads-secrets',
        note: 'stages a credential file, which puts it in line to be committed',
      };
    }
    const sweeping = hasFlag(argv, '-A', '--all', '-u', '--update') || args.includes('.');
    return {
      capability: 'exec.vcs.write',
      reversibility: 'trivial',
      scale: sweeping ? 'many' : 'single',
      note: 'stages changes for the next commit',
    };
  }
  if (name === 'commit') {
    const amending = hasFlag(argv, '--amend');
    // `-n`/`--no-verify` skips pre-commit and commit-msg hooks, which is where
    // a project puts the checks it does not want bypassed.
    const skipsHooks = hasFlag(argv, '--no-verify', '-n');
    const base = amending
      ? 'replaces the most recent commit; the original stays in the reflog'
      : 'records a commit in this repository only';
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      note: skipsHooks ? `${base}, skipping the project's commit hooks` : base,
      pathArgs: 'none',
    };
  }
  if (name === 'mv') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'renames a tracked file' };
  }

  // --- git rm: removes files from disk, not just from the index ----------
  if (name === 'rm') {
    if (hasFlag(argv, '--cached')) {
      return { capability: 'exec.vcs.write', reversibility: 'trivial', note: 'stops tracking files but leaves them on disk' };
    }
    const recursive = shortFlag(argv, 'r', at + 1) || hasFlag(argv, '-r', '-R');
    return {
      capability: 'fs.delete',
      // Committed content comes back; uncommitted edits to those files do not.
      reversibility: 'hard',
      scale: recursive ? 'sweeping' : args.length > 1 ? 'many' : 'single',
      note: recursive ? 'deletes a directory of tracked files from disk' : 'deletes tracked files from disk',
    };
  }

  // --- the four that destroy uncommitted work ----------------------------
  if (name === 'checkout') return classifyGitCheckout(argv, at);
  if (name === 'switch') {
    const forcing = hasFlag(argv, '--force', '--discard-changes') || shortFlag(argv, 'f', at + 1);
    return {
      capability: 'exec.vcs.write',
      reversibility: forcing ? 'irreversible' : 'easy',
      note: forcing
        ? 'switches branch and throws away uncommitted changes, which nothing in git keeps'
        : 'switches to another branch, refusing if that would lose local changes',
      pathArgs: 'none',
    };
  }
  if (name === 'restore') {
    const staged = hasFlag(argv, '--staged', '-S');
    const worktree = hasFlag(argv, '--worktree', '-W');
    if (staged && !worktree) {
      return { capability: 'exec.vcs.write', reversibility: 'trivial', note: 'unstages files without touching them on disk' };
    }
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: args.includes('.') || args.length > 1 ? 'sweeping' : 'single',
      note: 'overwrites files with their committed contents, discarding uncommitted edits for good',
    };
  }
  if (name === 'reset') return classifyGitReset(argv, at);
  if (name === 'clean') {
    if (hasFlag(argv, '--dry-run') || shortFlag(argv, 'n', at + 1)) {
      return { capability: 'exec.vcs.read', note: 'lists the untracked files it would delete' };
    }
    const alsoIgnored = shortFlag(argv, 'x', at + 1) || shortFlag(argv, 'X', at + 1);
    return {
      capability: 'fs.delete',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note: alsoIgnored
        ? 'deletes untracked and ignored files, which is where local env files and build output live'
        : 'deletes untracked files, and git has no copy of those',
    };
  }

  // --- history editing ---------------------------------------------------
  if (name === 'merge') {
    if (hasFlag(argv, '--abort', '--quit')) {
      return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'stops a merge in progress', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', scale: 'many', note: 'merges another branch into this one', pathArgs: 'none' };
  }
  if (name === 'rebase') {
    if (hasFlag(argv, '--exec', '-x')) {
      return { capability: 'exec.unknown', opaque: true, note: 'runs a command you supplied once per commit', pathArgs: 'none' };
    }
    if (hasFlag(argv, '--abort', '--quit', '--skip', '--continue', '--edit-todo')) {
      return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'steps a rebase already in progress', pathArgs: 'none' };
    }
    return {
      capability: 'exec.vcs.write',
      reversibility: 'hard',
      scale: hasFlag(argv, '--root') ? 'sweeping' : 'many',
      note: 'rewrites local commits, so anyone who already has them will diverge',
      pathArgs: 'none',
    };
  }
  if (name === 'cherry-pick' || name === 'revert') {
    if (hasFlag(argv, '--abort', '--quit', '--skip', '--continue')) {
      return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'steps an operation already in progress', pathArgs: 'none' };
    }
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      note: name === 'revert' ? 'adds a commit undoing an earlier one' : 'copies commits onto the current branch',
      pathArgs: 'none',
    };
  }
  if (name === 'apply' || name === 'am') {
    if (name === 'apply' && hasFlag(argv, '--check', '--stat', '--summary', '--numstat')) {
      return { capability: 'exec.vcs.read', note: 'checks whether a patch would apply' };
    }
    // `--directory=../../etc` and `--directory=C:\...` escape just as well as
    // a leading slash, so ask the workspace rather than pattern-match the string.
    const applyDir = flagValue(argv, '--directory');
    const escapes = hasFlag(argv, '--unsafe-paths') || (applyDir !== undefined && applyDir !== '' && anyOutside([applyDir], ctx));
    return {
      capability: escapes ? 'fs.write.outside' : 'fs.write.workspace',
      reach: escapes ? 'machine' : 'workspace',
      scale: 'many',
      note: escapes
        ? 'applies a patch that is allowed to write outside the repository'
        : 'applies a patch, changing whichever files it names',
    };
  }
  if (name === 'stash') return classifyGitStash(argv, at);

  // --- refs --------------------------------------------------------------
  if (name === 'branch') {
    // `-d -f` is spelled `-D` by everyone who means it, but git accepts both,
    // so force has to be read before the delete flags rather than after.
    const forcing = hasFlag(argv, '--force') || shortFlag(argv, 'f', at + 1);
    const deleting = hasFlag(argv, '-d', '-D', '--delete') || shortFlag(argv, 'd', at + 1) || shortFlag(argv, 'D', at + 1);
    if (deleting && (forcing || hasFlag(argv, '-D') || shortFlag(argv, 'D', at + 1))) {
      return {
        capability: 'exec.vcs.write',
        reversibility: 'hard',
        note: 'deletes a branch even when its commits exist nowhere else, leaving only the reflog',
        pathArgs: 'none',
      };
    }
    if (deleting) {
      return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'deletes a branch that is already merged', pathArgs: 'none' };
    }
    if (hasFlag(argv, '-m', '-M', '--move', '-c', '-C', '--copy', '--set-upstream-to', '-u', '--unset-upstream', '--edit-description')) {
      // `-M` and `-C` overwrite an existing branch of that name, which drops
      // whatever it pointed at.
      const clobbers = forcing || hasFlag(argv, '-M', '-C');
      return {
        capability: 'exec.vcs.write',
        reversibility: clobbers ? 'hard' : 'easy',
        note: clobbers
          ? 'renames a branch over the top of an existing one, leaving what that pointed at only in the reflog'
          : 'renames a branch or changes what it tracks',
        pathArgs: 'none',
      };
    }
    if (arg0 === undefined) return { capability: 'exec.vcs.read', note: 'lists branches', pathArgs: 'none' };
    if (forcing) {
      // `git branch -f main origin/other` does not create anything: it moves an
      // existing branch, and the commits it left behind survive only in the reflog.
      return {
        capability: 'exec.vcs.write',
        reversibility: 'hard',
        note: 'moves an existing branch to another commit, leaving what it pointed at only in the reflog',
        pathArgs: 'none',
      };
    }
    return { capability: 'exec.vcs.write', reversibility: 'trivial', note: 'creates a branch', pathArgs: 'none' };
  }
  if (name === 'tag') {
    const forcing = hasFlag(argv, '-f', '--force') || shortFlag(argv, 'f', at + 1);
    if (hasFlag(argv, '-d', '--delete') || shortFlag(argv, 'd', at + 1)) {
      return { capability: 'exec.vcs.write', reversibility: 'hard', note: 'deletes a tag locally', pathArgs: 'none' };
    }
    if (arg0 === undefined || hasFlag(argv, '-l', '--list', '--contains', '--points-at', '--merged', '-n')) {
      return { capability: 'exec.vcs.read', note: 'lists tags', pathArgs: 'none' };
    }
    return {
      capability: 'exec.vcs.write',
      // Moving a tag is the one git operation that changes meaning under
      // people who already fetched it, since tags are not re-fetched by default.
      reversibility: forcing ? 'hard' : 'easy',
      note: forcing ? 'moves an existing tag to another commit' : 'creates a tag in this repository',
      pathArgs: 'none',
    };
  }
  if (name === 'update-ref') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'hard',
      note: hasFlag(argv, '-d') ? 'deletes a ref outright, without the safety checks the branch command does' : 'moves a ref by hand',
      pathArgs: 'none',
    };
  }
  if (name === 'symbolic-ref') {
    if (args.length >= 2) return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'points HEAD at another ref', pathArgs: 'none' };
    return { capability: 'exec.vcs.read', pathArgs: 'none' };
  }
  if (name === 'notes') {
    if (arg0 === 'show' || arg0 === 'list' || arg0 === undefined) {
      return { capability: 'exec.vcs.read', note: 'reads commit notes', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'changes commit notes', pathArgs: 'none' };
  }
  if (name === 'replace') {
    return { capability: 'exec.vcs.write', reversibility: 'hard', note: 'makes git substitute one object for another everywhere', pathArgs: 'none' };
  }

  // --- the index and the working tree, in plumbing form ------------------
  if (name === 'read-tree' || name === 'checkout-index') {
    const overwrites = hasFlag(argv, '-u', '--reset', '-f', '-a', '--all') || shortFlag(argv, 'u', at + 1) || shortFlag(argv, 'f', at + 1);
    return {
      capability: 'exec.vcs.write',
      reversibility: overwrites ? 'irreversible' : 'easy',
      scale: overwrites ? 'sweeping' : 'single',
      note: overwrites ? 'overwrites working tree files from the index, discarding uncommitted edits' : 'rewrites the index',
      pathArgs: 'none',
    };
  }
  if (name === 'update-index') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'changes the index by hand' };
  }
  if (name === 'hash-object') {
    return { capability: hasFlag(argv, '-w') ? 'exec.vcs.write' : 'exec.vcs.read', reversibility: 'trivial', note: 'stores a file as a git object' };
  }
  if (name === 'sparse-checkout') {
    if (arg0 === 'list') return { capability: 'exec.vcs.read', pathArgs: 'none' };
    return {
      capability: 'exec.vcs.write',
      reversibility: 'hard',
      scale: 'sweeping',
      note: 'changes which files exist in the working tree at all',
      pathArgs: 'none',
    };
  }

  // --- garbage collection: this is where undo goes to die ----------------
  if (name === 'gc' || name === 'prune' || name === 'prune-packed' || name === 'maintenance') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: 'many',
      note: 'permanently deletes unreachable objects, which is exactly what recovering a lost commit relies on',
      pathArgs: 'none',
    };
  }
  if (name === 'repack') {
    return {
      capability: 'exec.vcs.write',
      reversibility: hasFlag(argv, '-d') || shortFlag(argv, 'd', at + 1) ? 'irreversible' : 'easy',
      note: 'repacks the object store',
      pathArgs: 'none',
    };
  }
  if (name === 'reflog') {
    if (arg0 === 'expire' || arg0 === 'delete') {
      return {
        capability: 'exec.vcs.write',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'erases the record git uses to find commits you dropped',
        pathArgs: 'none',
      };
    }
    return { capability: 'exec.vcs.read', note: 'lists where the branch has pointed', pathArgs: 'none' };
  }
  if (name === 'filter-branch' || name === 'filter-repo') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: 'sweeping',
      // The filters are shell, and the rewrite touches every commit, so the
      // argv tells us the blast radius but not the actual edit.
      opaque: name === 'filter-branch',
      note: 'rewrites every commit in the repository, giving them all new identities',
      pathArgs: 'none',
    };
  }

  // --- configuration -----------------------------------------------------
  if (name === 'config') return classifyGitConfig(argv, at, ctx);
  if (name === 'credential' || name.startsWith('credential-')) {
    if (arg0 === 'fill' || name === 'credential-store' || name === 'credential-cache' || arg0 === undefined) {
      return { capability: 'secret.read', note: 'reads a stored git credential', pathArgs: 'none' };
    }
    return { capability: 'fs.write.outside', reach: 'machine', exposure: 'reads-secrets', note: 'changes a stored git credential', pathArgs: 'none' };
  }

  // --- remotes -----------------------------------------------------------
  if (name === 'remote') {
    const verb = arg0 ?? '';
    if (verb === '' || verb === 'show' || verb === 'get-url') {
      // `remote show` (without -n) queries the remote over the network.
      const online = verb === 'show' && !hasFlag(argv, '-n');
      return {
        capability: 'exec.vcs.read',
        reach: online ? 'network' : 'workspace',
        note: 'lists the configured remotes',
        pathArgs: 'none',
        targets: remoteTargets(args[1]),
      };
    }
    if (verb === 'update' || verb === 'prune') {
      return { capability: 'exec.vcs.read', reach: 'network', note: 'contacts the remotes to refresh tracking branches', pathArgs: 'none' };
    }
    // Adding or repointing a remote decides where future pushes go, so it is
    // the setup step for sending code somewhere unexpected.
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      note: 'changes where this repository pushes and pulls from',
      pathArgs: 'none',
      targets: remoteTargets(args[2] ?? args[1]),
    };
  }

  // --- submodules and worktrees ------------------------------------------
  if (name === 'submodule') {
    if (arg0 === 'foreach') {
      return { capability: 'exec.unknown', opaque: true, note: 'runs a command of your choosing inside every submodule', pathArgs: 'none' };
    }
    if (arg0 === 'status' || arg0 === 'summary' || arg0 === undefined) {
      return { capability: 'exec.vcs.read', note: 'reports submodule state', pathArgs: 'none' };
    }
    if (arg0 === 'deinit') {
      return { capability: 'fs.delete', reversibility: 'hard', scale: 'many', note: 'removes a submodule working tree from disk', pathArgs: 'none' };
    }
    return {
      capability: 'exec.vcs.write',
      reach: 'network',
      scale: 'many',
      // Checking out a submodule runs that repository's own hooks and filters.
      note: 'downloads submodule code from the network and checks it out, hooks and all',
      pathArgs: 'none',
    };
  }
  if (name === 'worktree') {
    if (arg0 === 'list' || arg0 === undefined) return { capability: 'exec.vcs.read', note: 'lists worktrees', pathArgs: 'none' };
    if (arg0 === 'add') {
      const dest = args[1];
      const outside = dest !== undefined && anyOutside([dest], ctx);
      return {
        capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
        reach: outside ? 'machine' : 'workspace',
        scale: 'many',
        note: outside ? 'checks out a second working tree outside the project' : 'checks out a second working tree',
      };
    }
    if (arg0 === 'remove') {
      return { capability: 'fs.delete', reversibility: 'hard', scale: 'many', note: 'deletes a worktree directory along with anything uncommitted in it' };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'adjusts worktree bookkeeping' };
  }

  // --- things whose real work is a command we cannot see -----------------
  if (name === 'bisect') {
    if (arg0 === 'run') {
      return { capability: 'exec.unknown', opaque: true, note: 'runs a command of your choosing over many commits', pathArgs: 'none' };
    }
    if (arg0 === 'log' || arg0 === 'view' || arg0 === 'visualize') {
      return { capability: 'exec.vcs.read', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'moves the working tree between commits while bisecting', pathArgs: 'none' };
  }
  if (name === 'hook') {
    return { capability: 'exec.unknown', opaque: true, note: 'runs a repository hook script', pathArgs: 'none' };
  }
  if (name === 'svn' || name === 'p4' || name === 'flow' || name === 'cvsimport') {
    return { capability: 'exec.vcs.publish', opaque: true, reach: 'external', note: 'bridges this repository to another version control server', pathArgs: 'none' };
  }

  // --- packaging and sending ---------------------------------------------
  if (name === 'archive') {
    if (hasFlag(argv, '--remote')) {
      return { capability: 'exec.vcs.read', reach: 'network', note: 'asks a remote for an archive', pathArgs: 'none' };
    }
    // `-o /etc/cron.d/x` is still just "writes an archive", but not here.
    const dest = flagValue(argv, '--output', '-o');
    const outside = dest !== undefined && dest !== '' && anyOutside([dest], ctx);
    return {
      capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
      reach: outside ? 'machine' : 'workspace',
      note: outside ? 'writes an archive of the tree outside the project' : 'writes an archive of the tree',
    };
  }
  if (name === 'format-patch' || name === 'bundle') {
    // format-patch takes the directory as `-o`; `bundle create <file>` takes it
    // as the first positional after the verb.
    const dest = flagValue(argv, '--output-directory', '--output', '-o');
    const outside =
      (dest !== undefined && dest !== '' && anyOutside([dest], ctx)) ||
      (name === 'bundle' && arg0 === 'create' && anyOutside(args.slice(1, 2), ctx));
    return {
      capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
      reach: outside ? 'machine' : 'workspace',
      scale: 'many',
      note: outside ? 'writes commits out as files outside the project' : 'writes commits out as files',
    };
  }
  if (name === 'send-email') {
    return {
      capability: 'net.send',
      reach: 'network',
      exposure: 'can-exfiltrate',
      reversibility: 'irreversible',
      note: 'emails patches, which sends repository content off this machine',
      pathArgs: 'none',
    };
  }
  if (name === 'daemon' || name === 'instaweb' || name === 'http-backend') {
    return {
      capability: 'net.send',
      reach: 'network',
      exposure: 'can-exfiltrate',
      note: 'serves this repository to anyone who can reach the machine',
      pathArgs: 'none',
    };
  }

  // --- lfs ---------------------------------------------------------------
  if (name === 'lfs') {
    if (arg0 === 'install' || arg0 === 'uninstall') {
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: 'installs git filters that run the lfs program on every later checkout',
        pathArgs: 'none',
      };
    }
    if (arg0 === 'push') {
      return { capability: 'exec.vcs.publish', reach: 'external', note: 'uploads large files to the lfs server', pathArgs: 'none' };
    }
    if (arg0 === 'fetch' || arg0 === 'pull' || arg0 === 'checkout' || arg0 === 'prune') {
      return { capability: 'exec.vcs.write', reach: 'network', note: 'moves large file content between the lfs server and the working tree', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.read', reach: 'network', note: 'inspects lfs state', pathArgs: 'none' };
  }

  // --- repository creation ------------------------------------------------
  if (name === 'init') {
    // `--template=<dir>` copies that directory's hooks into the new repository,
    // so the next perfectly ordinary commit in it runs the template author's code.
    if (namesAProgram(argv) || configExecutes(configPairs(argv, at + 1, false))) {
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        opaque: true,
        note: 'creates a repository preloaded with hooks or settings that run a program on later git commands',
        pathArgs: 'none',
      };
    }
    const outside = arg0 !== undefined && anyOutside([arg0], ctx);
    return {
      capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
      reach: outside ? 'machine' : 'workspace',
      reversibility: 'easy',
      note: 'creates a new repository',
    };
  }

  // An unrecognised subcommand is very often a user alias, and an alias
  // starting with `!` is an arbitrary shell command.
  return {
    capability: 'exec.unknown',
    opaque: true,
    note: 'runs a git subcommand or alias whose effect is not visible here',
    pathArgs: 'none',
  };
}

/** `git push` and its many ways of destroying someone else's work. */
function classifyGitPush(argv: string[], at: number): Judgement {
  const args = nonFlags(argv, at + 1);
  const remote = args[0];
  const refspecs = args.slice(1);
  const targets = remoteTargets(remote);

  if (hasFlag(argv, '--dry-run') || shortFlag(argv, 'n', at + 1)) {
    return { capability: 'exec.vcs.read', reach: 'network', note: 'reports what a push would do without doing it', pathArgs: 'none', targets };
  }
  if (namesAProgram(argv)) {
    return { capability: 'exec.unknown', opaque: true, reach: 'external', note: 'names a program for the receiving end to run', pathArgs: 'none', targets };
  }

  // A `+` in front of a refspec is `--force` for that ref alone.
  const plusForce = refspecs.some((r) => r.startsWith('+'));
  const force = hasFlag(argv, '--force', '-f') || shortFlag(argv, 'f', at + 1) || plusForce;
  const lease = hasFlag(argv, '--force-with-lease');
  const deleting = hasFlag(argv, '--delete', '-d') || refspecs.some((r) => r.startsWith(':'));
  const mirror = hasFlag(argv, '--mirror');
  // `--prune` removes every remote branch under the refspec that you do not
  // have locally. No `--force`, no `--delete`, and branches disappear for everyone.
  const pruning = hasFlag(argv, '--prune');

  // The destination side of `src:dst`; that is the ref that actually changes.
  const dests = refspecs.map((r) => {
    const bare = r.replace(/^[+:]/, '');
    const colon = bare.indexOf(':');
    return colon >= 0 ? bare.slice(colon + 1) : bare;
  });
  const hitsProtected = dests.some((d) => PROTECTED_REF.test(d));

  if (mirror) {
    return {
      capability: 'exec.vcs.publish',
      reach: hitsProtected ? 'production' : 'external',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note: 'replaces every branch and tag on the remote with the local ones, deleting anything the remote has and you do not',
      pathArgs: 'none',
      targets,
    };
  }
  if (deleting) {
    return {
      capability: 'exec.vcs.publish',
      reach: hitsProtected ? 'production' : 'external',
      reversibility: 'irreversible',
      note: 'deletes a branch on the remote for everyone',
      pathArgs: 'none',
      targets,
    };
  }
  if (pruning) {
    return {
      capability: 'exec.vcs.publish',
      reach: hitsProtected ? 'production' : 'external',
      reversibility: 'irreversible',
      scale: 'many',
      note: 'deletes every branch on the remote that you do not have locally',
      pathArgs: 'none',
      targets,
    };
  }
  if (force && !lease) {
    return {
      capability: 'exec.vcs.publish',
      reach: hitsProtected ? 'production' : 'external',
      reversibility: 'irreversible',
      // We cannot see which branch is checked out when no refspec is given,
      // so an unqualified force push is already treated at the top of the
      // scale rather than guessed at.
      note: 'overwrites history on the remote, discarding commits anyone else may have already pulled',
      pathArgs: 'none',
      targets,
    };
  }
  if (lease) {
    return {
      capability: 'exec.vcs.publish',
      reach: 'external',
      // The lease makes this fail rather than clobber when the remote moved
      // since your last fetch, which is the whole difference from --force.
      reversibility: 'hard',
      note: 'overwrites history on the remote, but refuses if the remote moved since you last fetched it',
      pathArgs: 'none',
      targets,
    };
  }
  const broad = hasFlag(argv, '--all', '--tags', '--follow-tags');
  const base = broad ? 'publishes commits and tags to the remote' : 'publishes commits to the remote';
  return {
    capability: 'exec.vcs.publish',
    // A fast-forward push only adds commits, so even onto main it stays
    // 'external'; 'production' is reserved for the ones that remove something.
    reach: 'external',
    reversibility: 'hard',
    scale: broad ? 'many' : 'single',
    // `--no-verify` skips the pre-push hook, which is where a project puts the
    // check it least wants skipped.
    note: hasFlag(argv, '--no-verify') ? `${base}, skipping the pre-push checks` : base,
    pathArgs: 'none',
    targets,
  };
}

/**
 * `git checkout` is three commands wearing one name: switch branch, create
 * branch, and overwrite files from a commit. Only the third destroys work, and
 * from argv alone `git checkout foo` could be either the first or the third.
 */
function classifyGitCheckout(argv: string[], at: number): Judgement {
  const args = nonFlags(argv, at + 1);
  const dashDash = argv.indexOf('--', at + 1);
  const creating = hasFlag(argv, '-b', '--orphan', '--track', '-t');
  // `-B` is not `-b`: on an existing branch it resets it to the start point,
  // which drops that branch's commits.
  const resetting = hasFlag(argv, '-B');
  const forcing = hasFlag(argv, '--force') || shortFlag(argv, 'f', at + 1);

  if (dashDash >= 0 || args.some(looksLikePathspec)) {
    const sweeping = args.includes('.') || args.length > 2;
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: sweeping ? 'sweeping' : 'single',
      note: 'overwrites files with their committed contents, and the uncommitted edits are in no commit, stash or reflog',
    };
  }
  if (resetting) {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'hard',
      note: 'creates a branch, or moves an existing one of that name and leaves its commits only in the reflog',
      pathArgs: 'none',
    };
  }
  if (creating) {
    return { capability: 'exec.vcs.write', reversibility: 'trivial', note: 'creates a branch and switches to it', pathArgs: 'none' };
  }
  if (forcing) {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      note: 'switches away and throws away uncommitted changes rather than refusing',
      pathArgs: 'none',
    };
  }
  if (args.length === 0) {
    return { capability: 'exec.vcs.read', note: 'reports the state of the working tree', pathArgs: 'none' };
  }
  // Ambiguous: a bare name is usually a branch, but if it happens to be a
  // tracked directory this silently reverts everything under it.
  return {
    capability: 'exec.vcs.write',
    reversibility: 'hard',
    note: 'switches to another branch, or throws away uncommitted changes if that name turns out to be a file',
    pathArgs: 'none',
  };
}

/** `git reset`: the mode flag is the whole story. */
function classifyGitReset(argv: string[], at: number): Judgement {
  if (hasFlag(argv, '--hard')) {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: 'sweeping',
      // The commits survive in the reflog; the edits in the working tree do
      // not exist anywhere else and are simply gone.
      note: 'throws away every uncommitted change in the working tree, and nothing in git holds a copy of them',
      pathArgs: 'none',
    };
  }
  if (hasFlag(argv, '--merge', '--keep')) {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'hard',
      note: 'moves the branch and may discard uncommitted changes along the way',
      pathArgs: 'none',
    };
  }
  const args = nonFlags(argv, at + 1);
  if (args.length > 0 && args.some(looksLikePathspec)) {
    return { capability: 'exec.vcs.write', reversibility: 'trivial', note: 'unstages files, leaving them untouched on disk' };
  }
  return {
    capability: 'exec.vcs.write',
    reversibility: 'easy',
    note: 'moves the branch pointer and unstages changes, leaving the files alone',
    pathArgs: 'none',
  };
}

/** `git stash`: mostly a safe parking spot, except for drop and clear. */
function classifyGitStash(argv: string[], at: number): Judgement {
  const verb = nonFlags(argv, at + 1)[0] ?? 'push';
  if (verb === 'list' || verb === 'show') {
    return { capability: 'exec.vcs.read', note: 'lists stashed changes', pathArgs: 'none' };
  }
  if (verb === 'clear') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note: 'discards every stashed change at once',
      pathArgs: 'none',
    };
  }
  if (verb === 'drop') {
    // A dropped stash becomes an unreachable object: findable with fsck until
    // the next gc, which is not a recovery path anyone should count on.
    return { capability: 'exec.vcs.write', reversibility: 'hard', note: 'discards a stashed change', pathArgs: 'none' };
  }
  if (verb === 'pop' || verb === 'apply' || verb === 'branch') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'puts stashed changes back into the working tree', pathArgs: 'none' };
  }
  return {
    capability: 'exec.vcs.write',
    reversibility: 'easy',
    note: 'moves uncommitted changes into the stash, taking them out of the working tree',
    pathArgs: 'none',
  };
}

/**
 * `git config`. Three questions: is it reading or writing, does it write
 * outside the project, and is the key one that makes git run a program.
 */
function classifyGitConfig(argv: string[], at: number, ctx: KnowledgeCtx): Judgement {
  const args = nonFlags(argv, at + 1);
  const sub = (args[0] ?? '').toLowerCase();
  const MODERN_SUBS = new Set([
    'get', 'set', 'unset', 'list', 'edit', 'rename-section', 'remove-section', 'replace-all', 'add', 'unset-all',
  ]);
  const modern = MODERN_SUBS.has(sub);
  const key = modern ? args[1] : args[0];
  const value = modern ? args[2] : args[1];

  const writing = modern
    ? ['set', 'unset', 'unset-all', 'edit', 'rename-section', 'remove-section', 'replace-all', 'add'].includes(sub)
    : value !== undefined ||
      hasFlag(argv, '--add', '--unset', '--unset-all', '--replace-all', '--edit', '-e', '--rename-section', '--remove-section');
  const listing = sub === 'list' || hasFlag(argv, '--list', '-l');

  const fileArg = flagValue(argv, '--file', '-f');
  const global = hasFlag(argv, '--global');
  const system = hasFlag(argv, '--system');
  const outside = global || system || (fileArg !== undefined && anyOutside([fileArg], ctx));

  if (!writing) {
    // `git config -f ~/.git-credentials --list` is a credential dump wearing
    // the argv of a config read; the key tells you nothing, the file does.
    const fileAbs = fileArg !== undefined && fileArg !== '' ? ctx.resolve(fileArg) : '';
    if (fileAbs !== '' && ctx.isSecret(fileAbs)) {
      return { capability: 'secret.read', note: 'reads settings straight out of a credential file', pathArgs: 'none' };
    }
    if (key !== undefined && CONFIG_CREDENTIAL.test(key)) {
      return { capability: 'secret.read', note: 'prints stored credential settings', pathArgs: 'none' };
    }
    if (listing) {
      // A full dump includes remote urls, and people do embed tokens in those.
      return {
        capability: 'exec.vcs.read',
        exposure: 'reads-secrets',
        note: 'prints every git setting, which can include a token embedded in a remote url',
        pathArgs: 'none',
      };
    }
    return { capability: 'exec.vcs.read', note: 'reads a git setting', pathArgs: 'none' };
  }

  if (key !== undefined && CONFIG_EXECUTES.test(key)) {
    return {
      capability: 'exec.privilege',
      reach: outside ? 'machine' : 'workspace',
      reversibility: 'hard',
      exposure: CONFIG_CREDENTIAL.test(key) ? 'reads-secrets' : 'none',
      note: system
        ? 'sets a git setting for every user on this machine that makes git run a program of its own on later commands'
        : global
          ? 'sets a git setting for your whole account that makes git run a program of its own on later commands'
          : 'sets a git setting that makes git run a program of its own on later commands',
      pathArgs: 'none',
    };
  }
  if (system) {
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'hard',
      note: 'changes git settings for every user on this machine',
      pathArgs: 'none',
    };
  }
  if (outside) {
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'changes git settings for your whole account, outside this project',
      pathArgs: 'none',
    };
  }
  return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'changes a setting in this repository', pathArgs: 'none' };
}

// --- gh and glab -----------------------------------------------------------

/** Verbs that only ever read, whatever noun they follow. */
const FORGE_READ_VERBS = new Set(['view', 'list', 'ls', 'status', 'diff', 'checks', 'show', 'get', 'search', 'browse']);
/** Verbs that destroy something on the server. */
const FORGE_DELETE_VERBS = new Set(['delete', 'remove', 'rm', 'destroy', 'purge']);
/** Verbs that change server state without destroying it. */
const FORGE_WRITE_VERBS = new Set([
  'create', 'new', 'set', 'add', 'edit', 'update', 'close', 'reopen', 'comment', 'review',
  'ready', 'merge', 'run', 'rerun', 'cancel', 'sync', 'rename', 'lock', 'unlock', 'pin',
  'transfer', 'archive', 'unarchive', 'enable', 'disable', 'approve', 'subscribe',
]);

/**
 * Root options that take a separate value. glab makes `--repo` persistent, so
 * `glab -R group/proj mr merge 1` puts `group/proj` where the noun should be
 * and the whole command reads as something else entirely.
 */
const FORGE_GLOBAL_VALUE_FLAGS = new Set(['-R', '--repo', '-H', '--hostname', '--config-dir']);

/** Index of the noun, stepping over root options and their values. */
function forgeGroupIndex(argv: string[]): number {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return i + 1 < argv.length ? i + 1 : -1;
    if (!a.startsWith('-')) return i;
    if (FORGE_GLOBAL_VALUE_FLAGS.has(a)) i++;
  }
  return -1;
}

/**
 * `gh` and `glab` are the same shape: a noun, a verb, and a server on the far
 * end. glab uses `mr` for pull requests and `ci` for workflow runs, so those
 * are folded onto the gh names and only the wording changes.
 */
function classifyForge(argv: string[], ctx: KnowledgeCtx, tool: 'gh' | 'glab'): Judgement {
  const forge = tool === 'gh' ? 'github' : 'gitlab';
  const groupAt = forgeGroupIndex(argv);
  const rawGroup = (groupAt >= 0 ? argv[groupAt]! : '').toLowerCase();
  if (rawGroup === '' || rawGroup === 'help' || rawGroup === 'version' || rawGroup === 'completion') {
    return { capability: 'meta', note: `prints ${tool} usage`, pathArgs: 'none' };
  }
  const rest = nonFlags(argv, groupAt + 1);
  const verb = (rest[0] ?? '').toLowerCase();
  const group = tool === 'glab'
    ? ({ mr: 'pr', ci: 'run', pipeline: 'run', project: 'repo', variable: 'secret', snippet: 'gist' }[rawGroup] ?? rawGroup)
    : rawGroup;

  // --- credentials --------------------------------------------------------
  if (group === 'auth') {
    if (verb === 'token') {
      return { capability: 'secret.read', note: `prints the stored ${forge} token`, pathArgs: 'none' };
    }
    if (verb === 'status') {
      if (hasFlag(argv, '--show-token', '-t')) {
        return { capability: 'secret.read', note: `prints the stored ${forge} token`, pathArgs: 'none' };
      }
      return { capability: 'exec.inspect', reach: 'network', note: 'reports which account is signed in', pathArgs: 'none' };
    }
    if (verb === 'setup-git' || verb === 'git-credential') {
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: `makes git hand every push and pull through ${tool} for credentials`,
        pathArgs: 'none',
      };
    }
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      exposure: 'reads-secrets',
      note: `changes the ${forge} credential stored on this machine`,
      pathArgs: 'none',
    };
  }

  // --- raw api ------------------------------------------------------------
  if (group === 'api') {
    // `/graphql` is the same endpoint, and `-X POST graphql` puts the method
    // where rest[0] used to be, so look at every positional rather than the first.
    if (rest.some((r) => r === 'graphql' || r === '/graphql')) {
      // A graphql call is a POST whether it reads or writes, and the operation
      // lives inside the query string rather than in argv.
      return {
        capability: 'exec.cloud',
        reach: 'external',
        opaque: true,
        note: `sends a graphql call to ${forge} that may read or change anything the token can`,
        pathArgs: 'none',
      };
    }
    const explicit = (flagValue(argv, '-X', '--method') ?? '').toUpperCase();
    const hasBody = hasFlag(argv, '-f', '--field', '-F', '--raw-field', '--input');
    const method = explicit || (hasBody ? 'POST' : 'GET');
    if (method === 'GET' || method === 'HEAD') {
      return { capability: 'net.fetch', reach: 'network', note: `reads from the ${forge} api`, pathArgs: 'none' };
    }
    if (method === 'DELETE') {
      return { capability: 'exec.cloud', reach: 'external', reversibility: 'irreversible', note: `deletes something on ${forge}`, pathArgs: 'none' };
    }
    return { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: `changes something on ${forge}`, pathArgs: 'none' };
  }

  // --- server-side secrets ------------------------------------------------
  if (group === 'secret' || group === 'variable') {
    if (FORGE_READ_VERBS.has(verb)) {
      return { capability: 'exec.cloud', reach: 'network', reversibility: 'trivial', note: `lists the secrets configured on ${forge}`, pathArgs: 'none' };
    }
    if (FORGE_DELETE_VERBS.has(verb)) {
      return { capability: 'exec.cloud', reach: 'external', reversibility: 'irreversible', note: `deletes a secret on ${forge}, which will break whatever used it`, pathArgs: 'none' };
    }
    return {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      // The value comes from a local file or the environment and ends up on
      // someone else's server, readable by every workflow in the repository.
      exposure: 'can-exfiltrate',
      note: `uploads a credential into ${forge}, where every workflow in the repository can use it`,
    };
  }

  // --- repositories -------------------------------------------------------
  if (group === 'repo') {
    if (verb === 'clone') {
      // Everything after `--` is handed straight to `git clone`, so this is a
      // second door onto `-c core.pager=...` and `--upload-pack=...`.
      if (namesAProgram(argv) || configExecutes(configPairs(argv, groupAt + 1, false))) {
        return {
          capability: 'exec.privilege',
          reach: 'machine',
          reversibility: 'hard',
          opaque: true,
          note: 'clones with git options that make git run a program of its own',
          pathArgs: 'none',
        };
      }
      const dest = rest[2];
      const outside = dest !== undefined && anyOutside([dest], ctx);
      return {
        capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
        reach: 'network',
        scale: 'many',
        note: `downloads a repository from ${forge}`,
        targets: remoteTargets(rest[1]),
      };
    }
    if (verb === 'fork') {
      return { capability: 'exec.vcs.publish', reach: 'external', reversibility: 'easy', note: `creates a fork under your ${forge} account`, pathArgs: 'none' };
    }
    if (verb === 'delete') {
      return {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: `deletes a repository on ${forge}, along with its issues and pull requests`,
        pathArgs: 'none',
      };
    }
    if (verb === 'create' || verb === 'edit') {
      const public_ = hasFlag(argv, '--public') || (flagValue(argv, '--visibility') ?? '').toLowerCase() === 'public';
      if (public_) {
        return {
          capability: 'exec.cloud',
          reach: 'external',
          reversibility: 'irreversible',
          exposure: 'can-exfiltrate',
          note: 'makes a repository public, which puts its contents on the open internet',
          pathArgs: 'none',
        };
      }
      return { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: `changes a repository on ${forge}`, pathArgs: 'none' };
    }
  }

  // --- pull requests (merge requests, on gitlab) --------------------------
  if (group === 'pr') {
    const change = tool === 'glab' ? 'merge request' : 'pull request';
    if (verb === 'checkout') {
      return { capability: 'exec.vcs.write', reach: 'network', note: `fetches a ${change} branch and switches to it`, pathArgs: 'none' };
    }
    if (verb === 'create') {
      // `pr create` will push the current branch first if it has no upstream.
      return { capability: 'exec.vcs.publish', reach: 'external', reversibility: 'easy', note: `pushes the branch if needed and opens a ${change} on ${forge}`, pathArgs: 'none' };
    }
    if (verb === 'merge') {
      // `--admin` merges past required reviews and failing checks, which is
      // the whole point of having them.
      const admin = hasFlag(argv, '--admin');
      return {
        capability: 'exec.vcs.publish',
        reach: admin ? 'production' : 'external',
        reversibility: 'hard',
        note: admin
          ? `merges a ${change} with admin rights, overriding the required reviews and checks on the base branch`
          : `merges a ${change} into the base branch, which can start whatever that repository runs on merge`,
        pathArgs: 'none',
      };
    }
  }

  // --- releases, workflows, runs ------------------------------------------
  if (group === 'release') {
    if (verb === 'download') {
      return { capability: 'fs.write.workspace', reach: 'network', scale: 'many', note: 'downloads release files into the working directory' };
    }
    if (verb === 'create' || verb === 'upload') {
      return {
        capability: 'exec.pkg.publish',
        reach: 'external',
        reversibility: hasFlag(argv, '--draft') ? 'easy' : 'hard',
        note: hasFlag(argv, '--draft') ? 'creates a draft release' : `publishes a release on ${forge} that anyone can download`,
      };
    }
    if (FORGE_DELETE_VERBS.has(verb) || verb === 'delete-asset') {
      return { capability: 'exec.cloud', reach: 'external', reversibility: 'irreversible', note: 'deletes a published release', pathArgs: 'none' };
    }
  }
  if (group === 'workflow' && (verb === 'run' || verb === 'enable' || verb === 'disable')) {
    return {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      note: `starts or changes a workflow on ${forge}, which then runs whatever that workflow says, including deployments`,
      pathArgs: 'none',
    };
  }
  if (group === 'run') {
    if (verb === 'download') {
      return { capability: 'fs.write.workspace', reach: 'network', scale: 'many', note: 'downloads build artifacts into the working directory' };
    }
    if (verb === 'rerun' || verb === 'cancel' || verb === 'delete') {
      return { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: `changes a workflow run on ${forge}`, pathArgs: 'none' };
    }
  }

  // --- gists and snippets: a one-command route to the public internet -----
  if (group === 'gist' && (verb === 'create' || verb === 'new' || (rest.length > 0 && !FORGE_READ_VERBS.has(verb)))) {
    const secret = touchesSecret(argv, ctx, groupAt + 1);
    return {
      capability: 'net.send',
      reach: 'network',
      exposure: 'can-exfiltrate',
      reversibility: 'hard',
      note: secret
        ? 'uploads a credential file to a gist on the internet'
        : 'uploads file contents to a gist on the internet',
    };
  }

  // --- keys, extensions, aliases, codespaces ------------------------------
  if (group === 'ssh-key' || group === 'gpg-key') {
    if (FORGE_READ_VERBS.has(verb)) {
      return { capability: 'exec.cloud', reach: 'network', reversibility: 'trivial', note: 'lists the keys on the account', pathArgs: 'none' };
    }
    return {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      exposure: 'reads-secrets',
      note: `reads a key file and attaches it to the ${forge} account, granting whoever holds it access`,
    };
  }
  if (group === 'extension' || group === 'extensions') {
    if (FORGE_READ_VERBS.has(verb)) return { capability: 'exec.inspect', note: 'lists installed extensions', pathArgs: 'none' };
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      opaque: true,
      note: `installs third-party ${tool} code that then runs on this machine`,
      pathArgs: 'none',
    };
  }
  if (group === 'alias' && !FORGE_READ_VERBS.has(verb)) {
    // gh aliases beginning with `!` are shell, run under the name of a
    // perfectly ordinary looking gh command.
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'easy',
      note: `defines a ${tool} alias, which can be an arbitrary shell command run later`,
      pathArgs: 'none',
    };
  }
  if (group === 'config' && !FORGE_READ_VERBS.has(verb)) {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: `changes ${tool} settings for your account`, pathArgs: 'none' };
  }
  if (group === 'codespace' || group === 'cs') {
    if (verb === 'ssh' || verb === 'code' || verb === 'cp' || verb === 'ports') {
      return { capability: 'exec.remote', reach: 'external', opaque: true, note: 'runs against a remote development machine', pathArgs: 'none' };
    }
  }
  if (group === 'browse') {
    return { capability: 'exec.inspect', reach: 'network', note: `opens a ${forge} page in the browser`, pathArgs: 'none' };
  }

  // --- generic noun/verb fallback -----------------------------------------
  if (FORGE_READ_VERBS.has(verb) || rest.length === 0) {
    return { capability: 'exec.vcs.read', reach: 'network', note: `reads from ${forge}`, pathArgs: 'none' };
  }
  if (FORGE_DELETE_VERBS.has(verb)) {
    return { capability: 'exec.cloud', reach: 'external', reversibility: 'irreversible', note: `deletes something on ${forge}`, pathArgs: 'none' };
  }
  if (FORGE_WRITE_VERBS.has(verb)) {
    return { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: `changes something on ${forge}`, pathArgs: 'none' };
  }
  return {
    capability: 'exec.cloud',
    reach: 'external',
    opaque: true,
    note: `runs a ${tool} command whose effect on ${forge} is not clear from the arguments`,
    pathArgs: 'none',
  };
}

// --- mercurial -------------------------------------------------------------

const HG_READ = new Set([
  'status', 'st', 'diff', 'log', 'history', 'id', 'identify', 'cat', 'annotate', 'blame',
  'summary', 'sum', 'heads', 'parents', 'tip', 'paths', 'manifest', 'grep', 'files', 'root',
  'version', 'branches', 'bookmarks', 'tags', 'show', 'locate', 'help',
]);

/** hg options that take a separate value, which is not the subcommand. */
const HG_GLOBAL_VALUE_FLAGS = new Set([
  '-R', '--repository', '--cwd', '--config', '--encoding', '--encodingmode', '--color', '--pager',
]);

/** Index of the subcommand, stepping over global options and their values. */
function hgSubcommandIndex(argv: string[]): number {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return i + 1 < argv.length ? i + 1 : -1;
    if (!a.startsWith('-')) return i;
    if (HG_GLOBAL_VALUE_FLAGS.has(a)) i++;
  }
  return -1;
}

/**
 * hg settings that name code to load or run. `extensions.x=/tmp/evil.py` is
 * imported before the subcommand starts, so it does not matter that the
 * subcommand is `status`.
 */
const HG_CONFIG_EXECUTES = /^(extensions|hooks|alias|defaults|merge-tools|ui\.(editor|merge|pager|ssh)|http_proxy|web\.)/i;

function classifyHg(argv: string[], ctx: KnowledgeCtx): Judgement {
  const at = hgSubcommandIndex(argv);
  const sub = (at >= 0 ? argv[at]! : '').toLowerCase();

  if (sub === '' || sub === 'help' || sub === 'version') {
    return { capability: 'meta', note: 'prints mercurial usage', pathArgs: 'none' };
  }
  if (flagValues(argv, '--config').some((c) => HG_CONFIG_EXECUTES.test(c))) {
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'hard',
      opaque: true,
      note: 'sets a mercurial option for this one command that makes it load or run code of your choosing',
      pathArgs: 'none',
    };
  }
  if (HG_READ.has(sub)) {
    if (touchesSecret(argv, ctx, at + 1)) {
      return { capability: 'secret.read', note: 'prints the contents of a credential file', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.read', pathArgs: 'none' };
  }
  if (sub === 'incoming' || sub === 'outgoing' || sub === 'in' || sub === 'out') {
    return { capability: 'exec.vcs.read', reach: 'network', note: 'asks the remote what it has', pathArgs: 'none' };
  }
  if (sub === 'clone') {
    const args = nonFlags(argv, at + 1);
    const dest = args[1];
    const outside = dest !== undefined && anyOutside([dest], ctx);
    return {
      capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
      reach: 'network',
      scale: 'many',
      note: 'downloads a repository from the network',
      targets: remoteTargets(args[0]),
    };
  }
  if (sub === 'pull' || sub === 'unbundle') {
    return { capability: 'exec.vcs.write', reach: 'network', note: 'downloads changesets from the remote', pathArgs: 'none' };
  }
  if (sub === 'push') {
    const forcing = hasFlag(argv, '-f', '--force') || hasFlag(argv, '--new-branch');
    return {
      capability: 'exec.vcs.publish',
      reach: 'external',
      reversibility: forcing ? 'irreversible' : 'hard',
      note: forcing ? 'publishes changesets to the remote, forcing past its safety checks' : 'publishes changesets to the remote',
      pathArgs: 'none',
      targets: remoteTargets(nonFlags(argv, at + 1)[0]),
    };
  }
  if (sub === 'serve') {
    return { capability: 'net.send', reach: 'network', exposure: 'can-exfiltrate', note: 'serves this repository to the network', pathArgs: 'none' };
  }
  // `hg revert` writes .orig backups unless told not to; `purge` and `strip`
  // have no such courtesy.
  if (sub === 'revert') {
    return {
      capability: 'exec.vcs.write',
      reversibility: hasFlag(argv, '--no-backup', '-C') ? 'irreversible' : 'hard',
      scale: hasFlag(argv, '-a', '--all') ? 'sweeping' : 'single',
      note: 'restores files to their committed contents, discarding uncommitted edits',
    };
  }
  if (sub === 'purge' || sub === 'clean') {
    return {
      capability: 'fs.delete',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note: 'deletes untracked files, which mercurial has no copy of',
      pathArgs: 'none',
    };
  }
  if (sub === 'strip' || sub === 'histedit' || sub === 'rebase' || sub === 'amend' || sub === 'uncommit') {
    return {
      capability: 'exec.vcs.write',
      reversibility: sub === 'strip' ? 'irreversible' : 'hard',
      scale: 'many',
      note: sub === 'strip' ? 'removes changesets from history for good' : 'rewrites local history',
      pathArgs: 'none',
    };
  }
  if (sub === 'update' || sub === 'up' || sub === 'checkout' || sub === 'co') {
    const forcing = hasFlag(argv, '-C', '--clean', '-f', '--force');
    return {
      capability: 'exec.vcs.write',
      reversibility: forcing ? 'irreversible' : 'easy',
      note: forcing ? 'switches revision and throws away uncommitted changes' : 'switches the working copy to another revision',
      pathArgs: 'none',
    };
  }
  if (sub === 'remove' || sub === 'rm' || sub === 'forget') {
    return {
      capability: sub === 'forget' ? 'exec.vcs.write' : 'fs.delete',
      reversibility: 'hard',
      note: sub === 'forget' ? 'stops tracking files but leaves them on disk' : 'deletes tracked files from disk',
    };
  }
  if (sub === 'commit' || sub === 'ci' || sub === 'add' || sub === 'branch' || sub === 'bookmark' || sub === 'tag') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'records changes in this repository only' };
  }
  if (sub === 'merge' || sub === 'graft' || sub === 'backout' || sub === 'shelve' || sub === 'unshelve' || sub === 'import') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', scale: 'many', note: 'changes the working copy and local history' };
  }
  return { capability: 'exec.vcs.write', reversibility: 'hard', opaque: true, scale: 'many', note: 'runs a mercurial command whose effect is not clear from the arguments' };
}

// --- subversion ------------------------------------------------------------

/**
 * svn has no local commit: `svn commit` goes straight to the central server
 * and everyone sees it immediately. That makes it a publish, not a local write,
 * and it is the single most important difference from git in this file.
 */
const SVN_READ = new Set([
  'status', 'st', 'stat', 'diff', 'di', 'log', 'info', 'list', 'ls', 'cat', 'blame', 'praise',
  'annotate', 'ann', 'propget', 'pget', 'pg', 'proplist', 'plist', 'pl', 'help', 'h',
]);

/** svn options that take a separate value, which is not the subcommand. */
const SVN_VALUE_FLAGS = new Set([
  '--username', '--password', '--config-dir', '--config-option', '--editor-cmd', '--diff-cmd',
  '--diff3-cmd', '--merge-cmd', '--encoding', '--extensions', '-x', '--depth', '--set-depth',
  '--changelist', '--cl', '--accept', '--limit', '-l', '--revision', '-r', '-m', '--message',
  '-F', '--file', '--with-revprop', '--targets', '--native-eol', '--strip', '--show-item',
]);

/** Index of the subcommand, stepping over global options and their values. */
function svnSubcommandIndex(argv: string[]): number {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') return i + 1 < argv.length ? i + 1 : -1;
    if (!a.startsWith('-')) return i;
    if (SVN_VALUE_FLAGS.has(a)) i++;
  }
  return -1;
}

function classifySvn(argv: string[], ctx: KnowledgeCtx): Judgement {
  const at = svnSubcommandIndex(argv);
  const sub = (at >= 0 ? argv[at]! : '').toLowerCase();
  const args = nonFlags(argv, at + 1);
  // svn takes a repository URL, or a `^/branches/x` path relative to the repo
  // root, in the same slot as a working copy path; on a URL the command hits
  // the server rather than the working copy.
  const onUrl = args.some((a) => gitHost(a) !== undefined || a.startsWith('^/'));

  if (sub === '' || sub === 'help' || sub === 'h') {
    return { capability: 'meta', note: 'prints subversion usage', pathArgs: 'none' };
  }
  // `--diff-cmd` and friends substitute a program of your choosing for
  // subversion's own, which makes even `svn diff` arbitrary execution.
  if (
    hasFlag(argv, '--diff-cmd', '--diff3-cmd', '--merge-cmd', '--editor-cmd') ||
    flagValues(argv, '--config-option').some((o) => /(diff|editor|merge)[-_]?cmd|helpers/i.test(o))
  ) {
    return {
      capability: 'exec.unknown',
      opaque: true,
      note: 'runs a program of your choosing in place of subversion\'s own diff or editor',
      pathArgs: 'none',
    };
  }
  if (SVN_READ.has(sub)) {
    if (touchesSecret(argv, ctx, at + 1)) {
      return { capability: 'secret.read', note: 'prints the contents of a credential file', pathArgs: 'none' };
    }
    // Most svn reads ask the server; only `status` without -u is purely local.
    const local = (sub === 'status' || sub === 'st' || sub === 'stat') && !hasFlag(argv, '-u', '--show-updates');
    return { capability: 'exec.vcs.read', reach: local ? 'workspace' : 'network', pathArgs: 'none' };
  }
  if (sub === 'checkout' || sub === 'co' || sub === 'export') {
    const dest = args[1];
    const outside = dest !== undefined && anyOutside([dest], ctx);
    return {
      capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
      reach: 'network',
      scale: 'many',
      note: 'downloads a working copy from the server',
      targets: remoteTargets(args[0]),
    };
  }
  if (sub === 'update' || sub === 'up' || sub === 'switch' || sub === 'sw') {
    return { capability: 'exec.vcs.write', reach: 'network', scale: 'many', note: 'brings the working copy in line with the server', pathArgs: 'none' };
  }
  if (sub === 'commit' || sub === 'ci' || sub === 'import') {
    return {
      capability: 'exec.vcs.publish',
      reach: 'external',
      reversibility: 'hard',
      scale: 'many',
      note: 'sends changes straight to the central server, where everyone sees them at once',
    };
  }
  if (sub === 'revert') {
    return {
      capability: 'exec.vcs.write',
      // svn revert keeps no backup at all: the edits are simply gone.
      reversibility: 'irreversible',
      scale: hasFlag(argv, '-R', '--recursive', '--depth') ? 'sweeping' : 'single',
      note: 'restores files to their checked-out contents, and subversion keeps no copy of what you had',
    };
  }
  if (sub === 'delete' || sub === 'del' || sub === 'remove' || sub === 'rm') {
    if (onUrl) {
      return { capability: 'exec.vcs.publish', reach: 'external', reversibility: 'hard', note: 'deletes a path on the central server for everyone', pathArgs: 'none' };
    }
    return { capability: 'fs.delete', reversibility: 'hard', note: 'deletes files from the working copy' };
  }
  if (sub === 'copy' || sub === 'cp' || sub === 'move' || sub === 'mv' || sub === 'mkdir') {
    if (onUrl) {
      return { capability: 'exec.vcs.publish', reach: 'external', reversibility: 'hard', note: 'changes the repository layout on the server, which is how svn makes branches and tags', pathArgs: 'none' };
    }
    return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'rearranges files in the working copy' };
  }
  if (sub === 'propset' || sub === 'pset' || sub === 'ps' || sub === 'propdel' || sub === 'pdel') {
    if (hasFlag(argv, '--revprop')) {
      return { capability: 'exec.vcs.publish', reach: 'external', reversibility: 'irreversible', note: 'rewrites a property on an existing revision, which subversion does not version', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'sets a property in the working copy' };
  }
  if (sub === 'merge' || sub === 'resolve' || sub === 'resolved' || sub === 'add' || sub === 'cleanup' || sub === 'lock' || sub === 'unlock') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', scale: 'many', note: 'changes the working copy' };
  }
  return { capability: 'exec.vcs.write', reversibility: 'hard', opaque: true, note: 'runs a subversion command whose effect is not clear from the arguments' };
}

// --- jujutsu ---------------------------------------------------------------

// `diffedit`, `resolve` and `sparse` are not in here on purpose: they read like
// viewers but each one writes. See the handling below.
const JJ_READ = new Set([
  'status', 'st', 'log', 'diff', 'show', 'cat', 'files', 'evolog', 'obslog', 'interdiff',
  'root', 'version', 'help',
]);

function classifyJj(argv: string[], ctx: KnowledgeCtx): Judgement {
  const at = firstNonFlagIndex(argv, 1);
  const sub = (at >= 0 ? argv[at]! : '').toLowerCase();
  const args = nonFlags(argv, at + 1);
  const verb = (args[0] ?? '').toLowerCase();

  if (sub === '' || sub === 'help' || sub === 'version') {
    return { capability: 'meta', note: 'prints jujutsu usage', pathArgs: 'none' };
  }

  // `jj git ...` is where jujutsu touches the network.
  if (sub === 'git') {
    if (verb === 'fetch') {
      return { capability: 'exec.vcs.read', reach: 'network', note: 'downloads commits from the remote', pathArgs: 'none', targets: remoteTargets(flagValue(argv, '--remote')) };
    }
    if (verb === 'clone') {
      const dest = args[2];
      const outside = dest !== undefined && anyOutside([dest], ctx);
      return {
        capability: outside ? 'fs.write.outside' : 'exec.vcs.write',
        reach: 'network',
        scale: 'many',
        note: 'downloads a repository from the network',
        targets: remoteTargets(args[1]),
      };
    }
    if (verb === 'push') {
      // jj moves bookmarks wherever they now point, so a push after a rebase
      // rewrites the remote branch without anyone typing --force.
      return {
        capability: 'exec.vcs.publish',
        reach: 'external',
        reversibility: 'irreversible',
        note: 'publishes bookmarks to the remote, overwriting whatever they pointed at there',
        pathArgs: 'none',
      };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'changes the git backing store of this jujutsu repository', pathArgs: 'none' };
  }

  if (JJ_READ.has(sub)) {
    if (touchesSecret(argv, ctx, at + 1)) {
      return { capability: 'secret.read', note: 'prints the contents of a credential file', pathArgs: 'none' };
    }
    return { capability: 'exec.vcs.read', pathArgs: 'none' };
  }
  // `diffedit` opens a diff editor and writes the result back into the commit;
  // `resolve` does the same through a merge tool. Both look like viewers and
  // neither is one, and what the tool does is not in argv.
  if (sub === 'diffedit' || sub === 'resolve') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      opaque: true,
      note: 'opens an external editor or merge tool and writes whatever comes back into the commit',
      pathArgs: 'none',
    };
  }
  if (sub === 'sparse') {
    if (verb === 'list') return { capability: 'exec.vcs.read', pathArgs: 'none' };
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      scale: 'sweeping',
      note: 'changes which files exist in the working copy at all',
      pathArgs: 'none',
    };
  }
  if (sub === 'util' && verb === 'exec') {
    return { capability: 'exec.unknown', opaque: true, note: 'runs a command of your choosing', pathArgs: 'none' };
  }
  if (sub === 'op' || sub === 'operation') {
    if (verb === 'log' || verb === 'show' || verb === 'diff') {
      return { capability: 'exec.vcs.read', note: 'lists past operations', pathArgs: 'none' };
    }
    if (verb === 'abandon') {
      return {
        capability: 'exec.vcs.write',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'erases the operation log, which is the only thing that can undo earlier jujutsu commands',
        pathArgs: 'none',
      };
    }
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'moves the repository back to an earlier operation', pathArgs: 'none' };
  }
  if (sub === 'util' && (verb === 'gc' || verb === 'garbage-collect')) {
    return { capability: 'exec.vcs.write', reversibility: 'irreversible', scale: 'many', note: 'permanently deletes objects that undo would need', pathArgs: 'none' };
  }
  if (sub === 'config' && verb !== 'list' && verb !== 'get') {
    // Same trap as `git config alias.*`: some of these keys are program names
    // that a later, innocent looking jj command will run.
    if (/^(ui\.(editor|diff|merge|pager)|merge-tools\.|aliases\.|signing\.)/i.test(args[1] ?? '')) {
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: 'sets a jujutsu setting that makes it run a program of your choosing on later commands',
        pathArgs: 'none',
      };
    }
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'changes jujutsu settings for your account', pathArgs: 'none' };
  }
  if (sub === 'undo') {
    return { capability: 'exec.vcs.write', reversibility: 'easy', note: 'undoes the previous operation', pathArgs: 'none' };
  }
  // Everything else local: new, describe, squash, rebase, abandon, restore,
  // split, edit, bookmark. The operation log records each one, so unlike git
  // these stay recoverable even when they discard working copy changes.
  return {
    capability: 'exec.vcs.write',
    reversibility: 'easy',
    scale: 'many',
    note: 'changes local jujutsu history, which the operation log can undo',
    pathArgs: 'none',
  };
}

// --- module ----------------------------------------------------------------

/**
 * `git apply` and `git am` take their file list from the patch, not the command
 * line. Like archive extraction, a patch can name `../../etc/cron.d/x`, and
 * nothing in argv reveals it.
 */
const GIT_CONTENT_CHOOSES_DESTINATION = new Set(['apply', 'am', 'mailinfo', 'mailsplit']);

export const vcs: ProgramKnowledge = {
  names: ['git', 'gh', 'hg', 'svn', 'glab', 'jj'],
  describe:
    'Version control: git and its forge clients, plus mercurial, subversion and jujutsu — reading history, rewriting it, and publishing it',

  classify(argv, ctx) {
    // Empty argv reaches here from a malformed parse; decline rather than
    // index into nothing.
    const name = argv[0];
    if (name === undefined) return null;
    if (name === 'git') return classifyGit(argv, ctx);
    if (name === 'gh') return classifyForge(argv, ctx, 'gh');
    if (name === 'glab') return classifyForge(argv, ctx, 'glab');
    if (name === 'hg') return classifyHg(argv, ctx);
    if (name === 'svn') return classifySvn(argv, ctx);
    if (name === 'jj') return classifyJj(argv, ctx);
    return null;
  },
};
