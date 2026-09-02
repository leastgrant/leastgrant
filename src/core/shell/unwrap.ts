/**
 * Wrapper unwrapping.
 *
 * `sudo rm -rf /` is not a `sudo` command, it is an `rm` command with extra
 * privileges. `bash -c "curl x | sh"` is not a `bash` command. `xargs rm` is an
 * `rm` command with arguments nobody can predict.
 *
 * Every allowlist that classifies on argv[0] alone is bypassed by this file's
 * contents. So we peel wrappers until we reach something we can name, and we
 * record what we peeled — because `sudo` is itself a fact worth reporting.
 *
 * When a wrapper hides the payload (a script file, a Makefile target, an
 * `eval`), we mark the result opaque rather than guessing. Opaque means the
 * action can never be auto-approved.
 */

import { parseShell, type ParsedCommand } from './parse.js';
import { UNRESOLVED, type TokenizeOptions } from './tokenize.js';

export interface WrapperLayer {
  /** The wrapper program, e.g. `sudo`. */
  name: string;
  /** Short human note, e.g. `runs as root`. */
  note: string;
  /** Machine tag used by the classifier. */
  tag: WrapperTag;
}

export type WrapperTag =
  | 'privilege'
  | 'env'
  | 'timing'
  | 'detach'
  | 'shell-eval'
  | 'stdin-args'
  | 'remote'
  | 'container'
  | 'k8s'
  | 'script-file'
  | 'make'
  | 'pkg-script'
  | 'pkg-fetch-run'
  | 'find-exec'
  | 'git-config'
  | 'deferred'
  | 'dynamic';

export interface EffectiveCommand {
  /** The command after peeling, or the wrapper itself when we cannot peel. */
  command: ParsedCommand;
  /** Layers peeled to reach it, outermost first. */
  wrappers: WrapperLayer[];
  /**
   * True when we do not know *which program* will run — `eval`, a script file,
   * a Makefile target, a container exec. This is the serious kind of unknown:
   * nothing about the action can be trusted, so it can never be auto-approved.
   */
  opaque: boolean;
  /**
   * True when we know the program but not all of its arguments — `rm "$TARGET"`,
   * `xargs rm`, a glob. This is the mild kind of unknown: it widens the blast
   * radius (an unknown path could be anywhere) without making the action
   * unknowable. `echo "$X"` is still just an echo.
   */
  argsUnknown: boolean;
  /** Human-readable observations to surface in explanations. */
  notes: string[];
  /**
   * Paths the *wrapper* named, which the inner command will act on.
   *
   * `find /etc -exec chmod {} ;` peels to `chmod`, and `chmod` on its own has
   * no arguments worth looking at — the tree being walked is where the damage
   * happens, and it belonged to the wrapper we just discarded.
   */
  wrapperPaths?: string[];
  /**
   * The other commands from an embedded payload.
   *
   * `trap 'a | b' EXIT` and `ssh host 'a; b'` both hide a whole command list
   * behind one argument. Returning only the head silently dropped everything
   * after the first separator, which is exactly the class of miss this file
   * exists to prevent — so the tail comes back here and the caller flattens it.
   */
  siblings?: EffectiveCommand[];
}

/**
 * `[` and `[[` are the test builtins, not glob patterns. Without this exemption
 * every `[ -f x ]` in a script is reported as a program whose identity depends
 * on expansion — which measured out at 98 of 101 pattern warnings against a
 * real corpus, i.e. the check was almost entirely noise.
 */
const SHELL_TEST_BUILTINS = new Set(['[', '[[']);

/** `trap` takes no value-bearing flags; -p and -l are switches. */
const TRAP_FLAGS = new Set(['-p', '-l']);

/**
 * Environment variables that can change *what program runs*, rather than how it
 * behaves. Setting one of these makes a command unlearnable.
 *
 * This list is not complete and cannot be — every toolchain release adds
 * another. It does not have to be: every assignment, recognised or not, is part
 * of the signature, so an unknown variable is learned under its own identity
 * instead of inheriting the trust of the bare command. This list is the second
 * line, for the ones where even a deliberate human approval would be a mistake.
 */
const REDIRECTS_EXECUTION = new Set([
  // shell and loader
  'PATH', 'BASH_ENV', 'ENV', 'SHELL', 'IFS', 'SHELLOPTS', 'BASHOPTS', 'PS4',
  'PROMPT_COMMAND', 'CDPATH', 'GLOBIGNORE', 'HOME', 'USERPROFILE',
  'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
  // the program a tool shells out to
  'EDITOR', 'VISUAL', 'PAGER', 'BROWSER', 'DIFFTOOL', 'MERGETOOL',
  // network redirection
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'FTP_PROXY',
  // credential and target redirection
  'KUBECONFIG', 'DOCKER_HOST', 'DOCKER_CONFIG', 'GOOGLE_APPLICATION_CREDENTIALS',
  'CLOUDSDK_CONFIG', 'VAULT_ADDR', 'VAULT_TOKEN',
]);

/**
 * Prefixes whose whole family redirects execution: GIT_*, LD_*, DYLD_*,
 * PYTHON*, PERL5*, RUBY*, NODE_*, JAVA_*, DOTNET_*, npm_config_*, AWS_*.
 */
const REDIRECTING_PREFIXES = [
  'GIT_', 'LD_', 'DYLD_', 'PYTHON', 'PERL5', 'PERLLIB', 'RUBYOPT', 'RUBYLIB',
  'NODE_', 'JAVA_', '_JAVA', 'DOTNET_', 'NPM_CONFIG_', 'AWS_', 'AZURE_',
  'PSMODULE',
];

/**
 * Anything with PATH in the name points the loader, the interpreter or the
 * package manager at a directory of someone's choosing.
 */
/**
 * Members of an otherwise-redirecting family that only carry a mode, a region
 * or a formatting choice. Without these, `NODE_ENV=production npm test` and
 * `PYTHONIOENCODING=utf-8 python x` — both completely ordinary — would be
 * permanently unlearnable.
 */
const REDIRECT_EXEMPT = new Set([
  "NODE_ENV", "NODE_NO_WARNINGS", "NODE_DISABLE_COLORS",
  "PYTHONUNBUFFERED", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED",
  "PYTHONWARNINGS",
  "GIT_TERMINAL_PROMPT", "GIT_ADVICE", "GIT_PAGER_IN_USE",
  "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PAGER", "AWS_DEFAULT_OUTPUT",
  "JAVA_OPTS_APPEND",
]);

export function redirectsExecution(name: string): boolean {
  const upper = name.toUpperCase();
  if (REDIRECT_EXEMPT.has(upper)) return false;
  if (REDIRECTS_EXECUTION.has(upper)) return true;
  if (upper.includes('PATH')) return true;
  return REDIRECTING_PREFIXES.some((p) => upper.startsWith(p));
}


const PRIVILEGE = new Set(['sudo', 'doas', 'runas', 'su', 'pkexec', 'gosu']);
const ENV_WRAPPERS = new Set(['env', 'stdbuf', 'setsid', 'unshare', 'chroot', 'setarch']);

/**
 * git config keys that make git run a program of the caller's choosing.
 *
 * This is a denylist, and denylists of a config system with hundreds of keys
 * are lists of what somebody thought of — so it is a second line, not the
 * defence. The first line is that every `-c key=` joins the signature, so a key
 * nobody has classified still cannot inherit an honest command's approvals.
 * What this list adds is opacity: for these, we say outright that we cannot
 * account for what will run.
 */
const GIT_CONFIG_EXECUTES =
  /^(core\.(pager|editor|sshcommand|hookspath|fsmonitor|gitproxy|askpass|externaldiff)|alias\.|gpg\.(program|.*\.program)|diff\.(external|.*\.(command|textconv))|merge\.(.*\.driver)|trailer\..*\.command|filter\.|protocol\.|uploadpack\.|receivepack\.|http\.proxy|credential\.helper|init\.templatedir|ssh\.variant|sequence\.editor|pager\.|.*\.process)/i;

const TIMING = new Set(['time', 'timeout', 'nice', 'ionice', 'ulimit', 'watch']);
const DETACH = new Set(['nohup', 'disown']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'busybox']);
const TRANSPARENT = new Set(['command', 'builtin', 'exec', 'nocorrect']);

/** Flags that take a value, per wrapper, so we can find the real argv start. */
const VALUE_FLAGS: Record<string, Set<string>> = {
  sudo: new Set(['-u', '-g', '-p', '-C', '-h', '-U', '-r', '-t', '--user', '--group', '--prompt']),
  doas: new Set(['-u', '-C']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  // `/usr/bin/time -f "%e" cmd` — without this, the format string is mistaken
  // for the program and every timed command gets its own junk signature.
  time: new Set(['-f', '--format', '-o', '--output', '-a', '--append']),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  stdbuf: new Set(['-i', '-o', '-e', '--input', '--output', '--error']),
  nice: new Set(['-n', '--adjustment']),
  ionice: new Set(['-c', '-n', '-p']),
  watch: new Set(['-n', '--interval', '-d']),
  xargs: new Set(['-n', '-P', '-I', '-d', '-s', '-L', '-a', '-E', '--max-args', '--replace', '--delimiter', '--max-procs', '--arg-file']),
  trap: new Set(['-p', '-l']),
  ssh: new Set(['-i', '-p', '-l', '-o', '-F', '-L', '-R', '-D', '-b', '-c', '-e', '-J', '-m', '-O', '-Q', '-S', '-W', '-w']),
};

/**
 * Peel one command down to what it actually runs.
 *
 * `depth` guards against pathological nesting like `sudo env sudo env ...`.
 */
export function unwrap(
  cmd: ParsedCommand,
  opts: TokenizeOptions = {},
  depth = 0,
): EffectiveCommand {
  const wrappers: WrapperLayer[] = [];
  const notes: string[] = [];
  let opaque = false;
  let argsUnknown = false;
  const wrapperPaths: string[] = [];
  let current = cmd;

  const push = (name: string, tag: WrapperTag, note: string) => {
    wrappers.push({ name, tag, note });
    if (!notes.includes(note)) notes.push(note);
  };

  for (let guard = 0; guard < 12; guard++) {
    const name = baseName(current.name);
    const argv = current.argv;

    if (current.assignments.length && guard === 0) {
      // Anything not on the benign list is treated as capable of redirecting
      // what runs. See BENIGN_ENV for why this is a list of the safe ones
      // rather than a list of the dangerous ones.
      for (const a of current.assignments) {
        if (!redirectsExecution(a.name)) continue;
        push(a.name, 'env', `sets ${a.name}, which can change which program actually runs`);
        opaque = true;
      }
    }

    if (TRANSPARENT.has(name)) {
      const rest = argv.slice(1);
      if (!rest.length) break;
      current = reargv(current, rest);
      continue;
    }

    if (PRIVILEGE.has(name)) {
      const rest = stripFlags(argv.slice(1), VALUE_FLAGS[name]);
      push(name, 'privilege', name === 'su' ? 'switches user' : 'runs with elevated privileges');
      if (name === 'su' || name === 'sudo') {
        const ci = rest.indexOf('-c');
        if (ci !== -1 && rest[ci + 1] !== undefined) {
          return intoShellString(rest[ci + 1]!, wrappers, notes, opts, depth, current, opaque);
        }
      }
      if (!rest.length) {
        opaque = true;
        notes.push('runs an interactive privileged shell');
        break;
      }
      current = reargv(current, rest);
      continue;
    }

    if (ENV_WRAPPERS.has(name)) {
      let rest = argv.slice(1);
      if (name === 'env') {
        rest = stripFlags(rest, VALUE_FLAGS['env']);
        // `env FOO=bar cmd` is `FOO=bar cmd`. These used to be dropped on the
        // floor, and that was a complete bypass of the assignment floor: the
        // check above only looks at `current.assignments`, which is where the
        // parser puts a *prefix* assignment, while `env`'s are argv tokens. So
        // `LD_PRELOAD=/tmp/evil.so npm test` correctly asked, and
        // `env LD_PRELOAD=/tmp/evil.so npm test` was allowed — with a signature
        // byte-identical to plain `npm test`, so it inherited every approval
        // the honest command had ever earned.
        //
        // Moving them into `assignments` rather than special-casing them here
        // is the point: they then flow through the same opacity check and the
        // same `assignmentSignature()` as any other assignment, and anything
        // learned about that machinery later applies to both spellings.
        const moved: { name: string; value: string }[] = [];
        while (rest.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[0]!)) {
          const tok = rest[0]!;
          const eq = tok.indexOf('=');
          moved.push({ name: tok.slice(0, eq), value: tok.slice(eq + 1) });
          rest = rest.slice(1);
        }
        if (moved.length) {
          current = { ...current, assignments: [...current.assignments, ...moved] };
          for (const a of moved) {
            if (!redirectsExecution(a.name)) continue;
            push(a.name, 'env', `sets ${a.name}, which can change which program actually runs`);
            opaque = true;
          }
        }
      } else {
        rest = stripFlags(rest, VALUE_FLAGS[name]);
      }
      if (name === 'chroot' && rest.length) {
        // The new root changes what every path in the inner command means, and
        // we have no idea what is inside it. `chroot /newroot rm -rf x` shared
        // a signature with a plain `rm -rf x`.
        push('chroot', 'privilege', `runs with ${rest[0]} as the filesystem root, so paths mean something else`);
        opaque = true;
        rest = rest.slice(1);
      }
      // `env -C dir cmd` and `env --chdir=dir cmd` move the command somewhere
      // else before it runs. We strip the flag to find the real program, so the
      // directory would otherwise vanish silently and every relative path in
      // the command would be resolved against the wrong place.
      if (name === 'env' && argv.some((a, k) => k > 0 && (a === '-C' || a === '--chdir' || a.startsWith('--chdir=')))) {
        // Opaque, not merely `argsUnknown`. Every relative path in the command
        // now means something else, which is the same reasoning that makes
        // `chroot` opaque — and `argsUnknown` alone left the signature
        // identical to the undirected command, so `env -C /etc npm test`
        // inherited plain `npm test`'s approvals.
        push('env -C', 'env', 'runs the command in a different directory, so every relative path in it means something else');
        opaque = true;
        argsUnknown = true;
      }
      // `unshare` puts the command in new namespaces — a different mount table,
      // a different user mapping, a different network. Nothing we resolved
      // about it is necessarily true in there.
      if (name === 'unshare' && argv.length > 1 && argv.some((a, k) => k > 0 && a.startsWith('-'))) {
        push('unshare', 'privilege', 'runs the command in a new namespace, so what it can see and do is not what we resolved');
        opaque = true;
      }
      if (!rest.length) break;
      push(name, 'env', `runs through ${name}`);
      current = reargv(current, rest);
      continue;
    }

    if (TIMING.has(name)) {
      let rest = stripFlags(argv.slice(1), VALUE_FLAGS[name]);
      if (name === 'timeout' && rest.length && /^[\d.]+[smhd]?$/.test(rest[0]!)) rest = rest.slice(1);
      if (!rest.length) break;
      push(name, 'timing', `runs under ${name}`);
      current = reargv(current, rest);
      continue;
    }

    if (DETACH.has(name)) {
      const rest = argv.slice(1);
      if (!rest.length) break;
      push(name, 'detach', 'runs detached from the terminal');
      current = reargv(current, rest);
      continue;
    }

    // Shell with -c: the payload is a string we can parse.
    if (SHELLS.has(name)) {
      // A shell can be told to source a file before it runs anything, and that
      // file is code. `bash --rcfile /tmp/evil -c ls` had the same signature as
      // `sh -c ls`, so it inherited every approval an ordinary `ls` had earned
      // — while running the attacker's file first. `--login` and
      // `--interactive` do the same thing via the profile and rc files.
      //
      // The flag is dropped from the signature deliberately, opacity carries
      // the meaning instead: what matters is not *which* file it sources but
      // that it sources one, and an action marked opaque can never be
      // auto-approved however often it is seen.
      const sourcing = argv.slice(1).find((a) =>
        /^(--rcfile|--init-file|--login|--profile|--norc$|-l$|-i$)/.test(a) || /^-[a-z]*[li][a-z]*$/.test(a),
      );
      if (sourcing && !/^-[a-z]*c/.test(sourcing)) {
        push(name, 'shell-eval', `runs ${name} with ${sourcing}, which makes it read and execute another file first`);
        opaque = true;
      }
      const ci = argv.findIndex((a, k) => k > 0 && (a === '-c' || a === '-lc' || a === '-ic'));
      if (ci !== -1 && argv[ci + 1] !== undefined) {
        push(name, 'shell-eval', `runs a shell command string via ${name} -c`);
        return intoShellString(argv[ci + 1]!, wrappers, notes, opts, depth, current, opaque);
      }
      // `bash script.sh` — a file whose contents we have not read.
      const script = argv.slice(1).find((a) => !a.startsWith('-'));
      if (script) {
        push(name, 'script-file', `runs the script ${script}, whose contents are not analysed`);
        opaque = true;
        break;
      }
      if (current.contexts.includes('pipe')) {
        push(name, 'shell-eval', 'executes whatever the previous command produced');
        opaque = true;
        break;
      }
      break;
    }

    // `trap 'rm -rf x' EXIT` registers shell code to run when the shell exits.
    // It is the purest form of the class this whole file exists for: a command
    // whose *argument* is a program. It is also worse than `bash -c`, because
    // the code runs after the visible command has apparently finished.
    if (name === 'trap') {
      const rest = stripFlags(argv.slice(1), TRAP_FLAGS);
      const code = rest[0];
      // `trap - EXIT` and `trap '' EXIT` remove or ignore a handler: no code.
      if (code === undefined || code === '-' || code === '') break;
      push('trap', 'deferred', 'schedules code to run later, when the shell exits or a signal arrives');
      return intoShellString(code, wrappers, notes, opts, depth, current, opaque);
    }

    if (name === 'eval') {
      push('eval', 'dynamic', 'builds and runs a command at runtime');
      opaque = true;
      break;
    }

    if (name === 'source' || name === '.') {
      const f = argv[1];
      push(name, 'script-file', `loads ${f ?? 'a script'} into the current shell`);
      opaque = true;
      break;
    }

    if (name === 'xargs') {
      const rest = stripFlags(argv.slice(1), VALUE_FLAGS['xargs']);
      push('xargs', 'stdin-args', 'runs a command once per line of input, so the arguments are not known in advance');
      if (!rest.length) break;
      current = reargv(current, rest);
      // We know the program; we do not know its arguments or how many times it
      // runs. That widens the blast radius rather than blinding us entirely.
      argsUnknown = true;
      continue;
    }

    if (name === 'find') {
      const ei = argv.findIndex((a) => a === '-exec' || a === '-execdir' || a === '-ok' || a === '-okdir');
      if (ei !== -1) {
        const inner = argv.slice(ei + 1, findExecEnd(argv, ei + 1));
        // The directories find was told to walk are where the inner command
        // will act. Peeling to the inner command threw them away, so
        // `find / -exec cat {} ;` looked like a bare `cat` with no target.
        for (const a of argv.slice(1, ei)) {
          if (!a.startsWith('-')) wrapperPaths.push(a);
        }
        if (!wrapperPaths.length) wrapperPaths.push('.');
        push('find', 'find-exec', `runs ${inner[0] ?? 'a command'} for every matching file`);
        if (inner.length) {
          current = reargv(current, inner);
          argsUnknown = true;
          continue;
        }
        opaque = true;
      }
      break;
    }

    if (name === 'ssh' || name === 'dropbear') {
      const rest = stripFlags(argv.slice(1), VALUE_FLAGS['ssh']);
      const host = rest[0];
      if (!host) {
        // No host: this is `ssh -V`, `ssh --help` and friends — entirely local.
        break;
      }
      const remote = rest.slice(1);
      push('ssh', 'remote', `runs a command on ${host}`);
      if (remote.length) {
        return intoShellString(remote.join(' '), wrappers, notes, opts, depth, current, opaque);
      }
      // A host with no command is an interactive session: anything could happen.
      wrappers[wrappers.length - 1]!.note = `opens an interactive shell on ${host}`;
      opaque = true;
      break;
    }

    if (name === 'docker' || name === 'podman') {
      const sub = argv[1];
      if (sub === 'exec' || sub === 'run') {
        push(name, 'container', `runs a command inside a container`);
        // Everything after the image name is the inner command, but finding the
        // image reliably means understanding every docker flag. We do not
        // pretend to.
        opaque = true;
      }
      break;
    }

    if (name === 'kubectl' && (argv[1] === 'exec' || argv[1] === 'run')) {
      push('kubectl', 'k8s', 'runs a command inside a cluster workload');
      opaque = true;
      break;
    }

    if (name === 'make' || name === 'gmake') {
      const targets = argv.slice(1).filter((a) => !a.startsWith('-'));
      push('make', 'make', `runs the Makefile target ${targets.join(' ') || '(default)'}, whose recipe is not analysed`);
      opaque = true;
      break;
    }

    if (name === 'npx' || name === 'pnpx' || name === 'bunx' || name === 'dlx') {
      push(name, 'pkg-fetch-run', 'may download a package from the registry and execute it');
      break;
    }

    if ((name === 'npm' || name === 'pnpm' || name === 'yarn' || name === 'bun') && isRunScript(argv)) {
      const script = scriptName(argv);
      push(name, 'pkg-script', `runs the "${script}" script from package.json, whose contents are not analysed here`);
      // Not opaque by itself: `npm run test` is a meaningful, learnable unit.
      // The script's *content* is unknown, which the classifier accounts for.
      break;
    }

    if (name === 'git') {
      const cfgIdx: number[] = [];
      for (let k = 1; k < argv.length - 1; k++) if (argv[k] === '-c') cfgIdx.push(k);
      if (cfgIdx.length) {
        // Every `-c key=value` joins the identity, not just the ones on the
        // list below.
        //
        // The list is a denylist, and a denylist of a config system with
        // hundreds of keys is a list of the ones somebody thought of. It was
        // missing `core.hooksPath`, `core.fsmonitor`, `gpg.program`,
        // `diff.external`, `init.templateDir`, `core.gitProxy`, `core.askPass`,
        // `ssh.variant`, `merge.*.driver` and `trailer.*.command` — every one
        // of which makes git execute a program of the caller's choosing.
        //
        // But the deeper defect was that the pair was stripped from argv in
        // *all* cases, including the recognised ones, so
        // `git -c core.hooksPath=/tmp/evil commit` was learned under the
        // identity `git commit` and spent that command's approvals. Keeping the
        // key in the signature means an unrecognised dangerous key still cannot
        // inherit trust from the honest command: it is simply a different
        // thing, which has to earn its own. The denylist then only decides
        // whether we additionally refuse to *understand* it.
        //
        // Values are dropped, keys kept: `core.hooksPath=/a` and
        // `core.hooksPath=/b` are equally dangerous and should not each need
        // their own approval.
        const kept: string[] = [];
        for (const k of cfgIdx) {
          const kv = argv[k + 1] ?? '';
          const key = kv.split('=')[0] ?? kv;
          kept.push(key.toLowerCase());
          if (GIT_CONFIG_EXECUTES.test(kv)) {
            push('git -c', 'git-config', `overrides git config ${key}, which can make git run another program`);
            opaque = true;
          }
        }
        const rest: string[] = [argv[0]!];
        for (const key of kept.sort()) rest.push('-c', key + '=<value>');
        for (let k = 1; k < argv.length; k++) {
          if (argv[k] === '-c') {
            k++;
            continue;
          }
          rest.push(argv[k]!);
        }
        current = reargv(current, rest);
        // `break`, not `continue`: the rewritten argv still contains `-c`
        // tokens (that is the point), so looping would rediscover them and
        // stack a duplicate wrapper layer on every pass. There is nothing
        // further to peel from a `git` command anyway.
        break;
      }
      break;
    }

    break;
  }

  if (current.dynamic) {
    argsUnknown = true;
    if (!notes.includes('some arguments are only known at runtime')) {
      notes.push('some arguments are only known at runtime');
    }
  }

  // A program name we cannot read is the one unknown we never tolerate.
  //
  // That includes a name still carrying shell metacharacters: `rm{,}` expands
  // to `rm`, `r*` may expand to anything on disk. The word we are holding is
  // not the program that runs, so we do not know what does.
  if (!current.name || current.name.includes(UNRESOLVED)) {
    opaque = true;
    notes.push('the program that would run is decided at runtime');
  } else if (!SHELL_TEST_BUILTINS.has(current.name) && /[{}*?[\]]/.test(current.name)) {
    opaque = true;
    notes.push('the program name is a pattern, so what actually runs depends on expansion');
  } else if (/[;|&<>()$`]/.test(current.name)) {
    // A name carrying a shell operator is not a program name at all — it is a
    // command string that ended up in argv[0] because something was peeled in
    // a way we did not anticipate. Whatever it is, we are not looking at the
    // thing that runs.
    //
    // Whitespace alone is deliberately NOT disqualifying: an absolute path can
    // legitimately contain a space (`/c/Program Files/Windows Defender/...`),
    // and flagging those was a false positive on real data.
    opaque = true;
    notes.push('what ended up in the program position is not a program name');
  }

  return { command: current, wrappers, opaque, argsUnknown, notes, ...(wrapperPaths.length ? { wrapperPaths } : {}) };
}

/** Parse an embedded shell string and return its most significant command. */
function intoShellString(
  code: string,
  wrappers: WrapperLayer[],
  notes: string[],
  opts: TokenizeOptions,
  depth: number,
  fallback: ParsedCommand,
  /**
   * Opacity already established before we descended into the payload — for
   * example a `BASH_ENV=` assignment that will make the inner shell run
   * something else first. Dropping it here would let
   * `BASH_ENV=/tmp/evil.sh bash -c "git status"` be judged as `git status`.
   */
  outerOpaque = false,
): EffectiveCommand {
  if (depth >= 4 || code.includes(UNRESOLVED)) {
    return {
      command: fallback,
      wrappers,
      opaque: true,
      argsUnknown: true,
      notes: [...notes, 'the embedded command string could not be resolved'],
    };
  }
  const inner = parseShell(code, opts);
  const first = inner.commands[0];
  if (!first) {
    return { command: fallback, wrappers, opaque: true, argsUnknown: true, notes };
  }
  const sub = unwrap(first, opts, depth + 1);
  const siblings = inner.commands
    .slice(1)
    .filter((c) => c.name)
    .map((c) => unwrap(c, opts, depth + 1));
  // Carry the outer command's assignments onto the payload.
  //
  // `BASH_ENV=/tmp/evil sh -c ls` peels to a freshly parsed `ls`, which of
  // course has no assignments of its own — so the signature came out as plain
  // `ls` and inherited every approval that ordinary `ls` had earned. Opacity
  // alone was not enough to stop it: in autopilot the floor for a
  // project-contained read is waived, and the action classifies as a read
  // because the assignment is no longer anywhere in it.
  //
  // Attaching them to the inner command puts them back in the signature, so the
  // dressed-up form is a different learned thing whatever posture is in force.
  const carried = fallback.assignments ?? [];
  const command =
    carried.length && sub.command !== fallback
      ? { ...sub.command, assignments: [...carried, ...sub.command.assignments] }
      : sub.command;
  return {
    command,
    wrappers: [...wrappers, ...sub.wrappers],
    opaque: outerOpaque || !inner.ok || sub.opaque,
    argsUnknown: sub.argsUnknown,
    notes: [...notes, ...sub.notes],
    ...(siblings.length ? { siblings } : {}),
  };
}

/**
 * Expand every command in a parsed script into its effective form.
 * Commands hidden inside `bash -c` strings are surfaced here too.
 */
export function effectiveCommands(
  commands: ParsedCommand[],
  opts: TokenizeOptions = {},
): EffectiveCommand[] {
  const out: EffectiveCommand[] = [];

  // Flatten any payload tail, however deeply it nests. This used to be a
  // special case for `sh -c` only, which meant `trap 'a | b'` and
  // `ssh host 'a; b'` lost everything after the first command.
  const emit = (e: EffectiveCommand, seen = 0) => {
    out.push(e);
    if (seen > 6) return;
    for (const sib of e.siblings ?? []) emit(sib, seen + 1);
  };

  for (const c of commands) {
    if (!c.name && c.assignments.length) continue; // bare assignment
    emit(unwrap(c, opts));
  }
  return out;
}

// --- helpers ---------------------------------------------------------------

function reargv(cmd: ParsedCommand, argv: string[]): ParsedCommand {
  return { ...cmd, name: argv[0] ?? '', argv };
}

export function baseName(p: string): string {
  if (!p) return '';
  const cleaned = p.replace(/\\/g, '/');
  const last = cleaned.slice(cleaned.lastIndexOf('/') + 1);
  return last.replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
}

/** Drop leading option flags, honouring the ones that consume a value. */
function stripFlags(argv: string[], valueFlags?: Set<string>): string[] {
  let k = 0;
  while (k < argv.length) {
    const a = argv[k]!;
    if (a === '--') {
      k++;
      break;
    }
    if (!a.startsWith('-') || a === '-') break;
    if (valueFlags?.has(a)) {
      k += 2;
      continue;
    }
    if (a.includes('=')) {
      k++;
      continue;
    }
    k++;
  }
  return argv.slice(k);
}

function findExecEnd(argv: string[], from: number): number {
  for (let k = from; k < argv.length; k++) {
    if (argv[k] === ';' || argv[k] === '+' || argv[k] === '\\;') return k;
  }
  return argv.length;
}

function isRunScript(argv: string[]): boolean {
  const sub = argv[1];
  if (!sub) return false;
  if (sub === 'run' || sub === 'run-script') return true;
  // `yarn test` / `pnpm test` implicitly run scripts, but so do real
  // subcommands. Only treat known-script-ish words as scripts.
  return false;
}

function scriptName(argv: string[]): string {
  return argv[2] ?? '(default)';
}
