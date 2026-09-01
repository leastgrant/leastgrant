/**
 * Package managers, build tools, test runners and formatters.
 *
 * Two things make this family dangerous out of proportion to how ordinary it
 * looks. First, *installing* is code execution: npm lifecycle scripts, python
 * setup.py, ruby native extensions and cargo build scripts all run as the
 * developer, from code that was downloaded a second earlier. Second,
 * *publishing* is a one-way door onto the public internet — npm, crates.io and
 * PyPI all refuse to let a version be replaced.
 *
 * Everything else here is the quiet majority — `npm test`, `cargo build`,
 * `eslint .` — and the whole point of the module is to be confident enough
 * about those that they never need a prompt.
 *
 * Two recurring traps are handled explicitly:
 *   - `npm run <name>`: the script body lives in package.json and is never
 *     analysed, so the name is only ever a hint. Unrecognised names are opaque.
 *   - formatter polarity: `black`, `isort`, `rustfmt`, `ruff format`, `go fmt`
 *     and `cargo fmt` REWRITE SOURCE BY DEFAULT and are read-only only when
 *     asked to check. Getting that backwards would silently destroy edits.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { flagValue, hasFlag, hostOf, nonFlags } from './types.js';

type Targets = NonNullable<Judgement['targets']>;

// --- program families ------------------------------------------------------

const JS_PMS = ['npm', 'pnpm', 'yarn', 'bun'];

const PYTHON_PMS = ['pip', 'pip3', 'pip2', 'uv', 'uvx', 'poetry', 'pipenv', 'conda', 'mamba', 'micromamba', 'twine'];

const SYSTEM_PMS = [
  'apt', 'apt-get', 'aptitude', 'yum', 'dnf', 'pacman', 'apk', 'zypper',
  'brew', 'choco', 'chocolatey', 'winget', 'scoop', 'snap', 'port',
];

const BUILD_TOOLS = [
  'tsc', 'webpack', 'vite', 'rollup', 'esbuild', 'parcel', 'turbo', 'nx',
  'bazel', 'bazelisk', 'cmake', 'ninja', 'meson', 'swc', 'babel', 'gulp', 'grunt',
];

const TEST_RUNNERS = [
  'jest', 'vitest', 'mocha', 'ava', 'tap', 'pytest', 'py.test', 'tox',
  'rspec', 'phpunit', 'playwright', 'cypress', 'karma',
];

const LINTERS = [
  'eslint', 'prettier', 'ruff', 'black', 'flake8', 'mypy', 'pylint',
  'rubocop', 'gofmt', 'rustfmt', 'shellcheck', 'biome', 'isort',
];

export const packages: ProgramKnowledge = {
  names: [
    ...JS_PMS,
    ...PYTHON_PMS,
    'cargo', 'go',
    'gem', 'bundle', 'bundler',
    'mvn', 'maven', 'mvnw', 'gradle', 'gradlew',
    'dotnet', 'composer',
    ...SYSTEM_PMS, 'nix', 'nix-env',
    ...BUILD_TOOLS,
    ...TEST_RUNNERS,
    ...LINTERS,
  ],
  describe: 'Package managers, build tools, test runners and formatters: installing runs downloaded code, publishing cannot be undone',

  classify(argv, ctx) {
    const name = argv[0]!;

    if (JS_PMS.includes(name)) return classifyJs(name, argv, ctx);
    if (PYTHON_PMS.includes(name)) return classifyPython(name, argv, ctx);
    if (name === 'cargo') return classifyCargo(argv, ctx);
    if (name === 'go') return classifyGo(argv, ctx);
    if (name === 'gem') return classifyGem(argv);
    if (name === 'bundle' || name === 'bundler') return classifyBundler(argv);
    if (name === 'mvn' || name === 'maven' || name === 'mvnw') return classifyMaven(argv);
    if (name === 'gradle' || name === 'gradlew') return classifyGradle(argv);
    if (name === 'dotnet') return classifyDotnet(argv, ctx);
    if (name === 'composer') return classifyComposer(argv);
    if (name === 'nix' || name === 'nix-env') return classifyNix(name, argv);
    if (SYSTEM_PMS.includes(name)) return classifySystem(name, argv);
    if (BUILD_TOOLS.includes(name)) return classifyBuildTool(name, argv, ctx);
    if (TEST_RUNNERS.includes(name)) return classifyTestRunner(name, argv);
    if (LINTERS.includes(name)) return classifyLinter(name, argv, ctx);

    return null;
  },
};

// --- shared helpers --------------------------------------------------------

/** Non-flag words after the program name; `words[0]` is the subcommand. */
function words(argv: string[]): string[] {
  return nonFlags(argv, 1);
}

/**
 * `hasFlag`, but an explicit false value means the flag is *not* set.
 *
 * Only ever use this for flags that make an invocation safer (`--dry-run`,
 * `--ignore-scripts`, `--check`). npm-family tools and tsc both accept
 * `--flag=false` and `--flag false`, so `npm publish --dry-run=false` is a real
 * publish; reading it as a dry run would be the worst kind of wrong.
 */
function flagOn(argv: string[], ...flags: string[]): boolean {
  const off = new Set(['false', '0', 'no', 'off']);
  let on = false;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    for (const f of flags) {
      if (a === f) {
        if (off.has((argv[i + 1] ?? '').toLowerCase())) return false;
        on = true;
      } else if (a.startsWith(f + '=')) {
        if (off.has(a.slice(f.length + 1).toLowerCase())) return false;
        on = true;
      }
    }
  }
  return on;
}

/** Asking the program to describe itself, with no subcommand to run. */
function helpOnly(argv: string[]): boolean {
  return hasFlag(argv, '-v', '-V', '--version', '-h', '--help');
}

/** Package-ish arguments, split so URLs become host targets instead. */
function pkgTargets(names: string[]): Targets {
  const out: Targets = [];
  for (const n of names) {
    if (out.length >= 8) break;
    if (n.startsWith('-')) continue;
    const host = hostOf(n);
    if (host) out.push({ type: 'host', value: host });
    else out.push({ type: 'package', value: n });
  }
  return out;
}

/**
 * Registries named on the command line. A non-default registry matters: it is
 * where the code about to be executed comes from.
 */
function registryTargets(argv: string[]): Targets {
  const out: Targets = [];
  const flags = ['--registry', '--index-url', '-i', '--extra-index-url', '--repository-url', '--find-links', '--default-registry'];
  for (const f of flags) {
    const v = flagValue(argv, f);
    const h = v ? hostOf(v) : undefined;
    if (h && !out.some((t) => t.value === h)) out.push({ type: 'host', value: h });
  }
  return out;
}

/** A formatter or codemod rewriting files in place; risk depends on where. */
function rewriteJudgement(argv: string[], ctx: KnowledgeCtx, note: string): Judgement {
  const outside = words(argv).some((a) => {
    const abs = ctx.resolve(a);
    return abs !== '' && !ctx.inWorkspace(abs);
  });
  return {
    capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
    reach: outside ? 'machine' : 'workspace',
    reversibility: 'easy',
    // Formatters are pointed at directories, so one invocation rewrites a tree.
    scale: 'many',
    note,
  };
}

/** Read-only inspection of local state. */
function inspect(note: string): Judgement {
  return { capability: 'exec.inspect', pathArgs: 'none', note };
}

/** A registry query: nothing changes, but the dependency list leaves the machine. */
function fetch(note: string, argv?: string[]): Judgement {
  return {
    capability: 'net.fetch',
    pathArgs: 'none',
    note,
    targets: argv ? registryTargets(argv) : undefined,
  };
}

/** Something whose real effect is decided by project files we do not read. */
function opaque(note: string, reach: Judgement['reach'] = 'machine'): Judgement {
  return { capability: 'exec.unknown', opaque: true, reach, pathArgs: 'none', note };
}

/** An upload to a public registry. These cannot be recalled. */
function publishJudgement(argv: string[], note: string): Judgement {
  // A dry run prints the file list and stops, so it is worth detecting: it is
  // exactly what a careful agent runs before the real thing. Only the spelled
  // out flags count — `-n` means something different in too many tools — and
  // `--dry-run=false` is a real publish wearing the flag.
  if (flagOn(argv, '--dry-run', '--dryrun')) {
    return inspect('shows what would be published without uploading anything');
  }
  return {
    capability: 'exec.pkg.publish',
    reach: 'external',
    reversibility: 'irreversible',
    pathArgs: 'none',
    note,
    targets: registryTargets(argv),
  };
}

/** A change to registry-side metadata: public, and not ours to undo. */
function registryAdmin(note: string): Judgement {
  return {
    capability: 'exec.pkg.publish',
    reach: 'external',
    reversibility: 'hard',
    pathArgs: 'none',
    note,
  };
}

/**
 * A stored registry credential. There is no `secret.write` capability, so
 * credential-adjacent commands land here: creating, storing or printing a
 * publish token all give the same thing away.
 */
function credential(note: string, reach: Judgement['reach'] = 'machine'): Judgement {
  return {
    capability: 'secret.read',
    reach,
    exposure: 'reads-secrets',
    reversibility: 'hard',
    pathArgs: 'none',
    note,
  };
}

// --- script-name heuristic -------------------------------------------------

/**
 * Script names that conventionally mean "check the code". Being wrong here is
 * cheap in one direction only, so the list stays short and boring.
 */
const TEST_SCRIPT_NAMES = new Set([
  'test', 'tests', 'jest', 'vitest', 'lint', 'typecheck', 'type-check', 'types',
  'tsc', 'check', 'unit', 'spec', 'e2e', 'coverage', 'mocha', 'pytest',
]);

const BUILD_SCRIPT_NAMES = new Set([
  'build', 'compile', 'bundle', 'format', 'fmt', 'prettier', 'assemble', 'dist',
]);

/** Long-running scripts: they hold a port open until something kills them. */
const SERVER_SCRIPT_NAMES = new Set(['dev', 'start', 'serve', 'preview']);

/**
 * Classify `npm run <name>` and friends by the *name* only.
 *
 * The body of the script is in package.json (or turbo.json, or composer.json)
 * and is never read, so this is a guess dressed as a heuristic. Namespaced
 * names are judged by their first segment — "build:prod" is a build, but
 * "deploy:build" is a deploy and stays unknown.
 */
function scriptJudgement(raw: string | undefined, kind: 'script' | 'task' = 'script'): Judgement {
  const script = (raw ?? '').toLowerCase();
  if (script === '') return inspect(`lists the available ${kind}s`);

  const head = script.split(':')[0] ?? '';
  const tail = `; the ${kind} body is not analysed`;

  if (TEST_SCRIPT_NAMES.has(head)) {
    return {
      capability: 'exec.test',
      pathArgs: 'none',
      note: `runs the "${script}" ${kind}, which by its name tests or checks the code${tail}`,
    };
  }
  if (BUILD_SCRIPT_NAMES.has(head)) {
    return {
      capability: 'exec.build',
      pathArgs: 'none',
      note: `runs the "${script}" ${kind}, which by its name builds or formats the project${tail}`,
    };
  }
  if (SERVER_SCRIPT_NAMES.has(head)) {
    return {
      capability: 'exec.build',
      pathArgs: 'none',
      note: `runs the "${script}" ${kind}, which usually starts a long-running server that keeps a port open${tail}`,
    };
  }
  return {
    capability: 'exec.unknown',
    opaque: true,
    reach: 'machine',
    pathArgs: 'none',
    note: `runs the "${script}" ${kind}${tail}, so it could do anything`,
  };
}

// --- javascript ------------------------------------------------------------

const JS_INSTALL_SUBS = new Set([
  'install', 'i', 'in', 'ins', 'isnt', 'add', 'ci', 'install-test', 'it',
  'install-ci-test', 'update', 'up', 'upgrade', 'upgrade-interactive',
  'remove', 'rm', 'uninstall', 'un', 'r', 'prune', 'dedupe', 'ddp', 'rebuild', 'rb', 'import',
]);

const JS_REMOVE_SUBS = new Set(['remove', 'rm', 'uninstall', 'un', 'r', 'prune']);

/** Subcommands npm-family tools understand; anything else may be a script. */
const JS_KNOWN_SUBS = new Set([
  ...JS_INSTALL_SUBS,
  'run', 'run-script', 'exec', 'dlx', 'x', 'create', 'init', 'test', 't', 'tst',
  'start', 'stop', 'restart', 'publish', 'unpublish', 'pack', 'version',
  'deprecate', 'dist-tag', 'access', 'owner', 'team', 'star', 'unstar',
  'login', 'adduser', 'logout', 'whoami', 'token', 'config', 'c', 'set', 'get',
  'audit', 'ls', 'list', 'la', 'll', 'view', 'v', 'info', 'show', 'search', 's', 'se',
  'find', 'outdated', 'ping', 'doctor', 'why', 'explain', 'fund', 'cache', 'store',
  'root', 'bin', 'prefix', 'edit', 'docs', 'repo', 'help', 'link', 'ln', 'unlink',
  'patch', 'patch-commit', 'licenses', 'completion', 'pkg', 'env', 'workspace', 'workspaces',
]);

function classifyJs(pm: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();
  const rest = w.slice(1);

  if (sub === '') {
    // Bare `yarn` installs the whole dependency tree; bare npm/pnpm/bun print
    // help. `yarn --version` installs nothing, so it must not look like one.
    if (pm === 'yarn' && !helpOnly(argv)) return jsInstall(argv, 'install', []);
    return inspect('prints help or version information');
  }

  if (JS_INSTALL_SUBS.has(sub)) return jsInstall(argv, sub, rest);

  // `npm audit fix` is not an audit — it installs new package versions.
  if (sub === 'audit') {
    if (sub2 === 'fix') return jsInstall(argv, 'install', rest.slice(1));
    return fetch('sends the dependency list to the registry to check for advisories', argv);
  }

  if (sub === 'publish') {
    return publishJudgement(argv, 'publishes this package to a public registry, where the version number can never be reused');
  }
  if (sub === 'unpublish') {
    return {
      capability: 'exec.pkg.publish',
      reach: 'external',
      reversibility: 'irreversible',
      pathArgs: 'none',
      note: 'removes a published version from the registry, which breaks everyone already depending on it',
    };
  }
  if (sub === 'deprecate' || sub === 'dist-tag' || sub === 'access' || sub === 'owner' || sub === 'team') {
    // The `ls` form of each of these only reads the registry.
    if (sub2 === 'ls' || sub2 === 'list') return fetch('asks the registry about this package settings', argv);
    return registryAdmin('changes public registry settings for this package, which other people see immediately');
  }

  if (sub === 'login' || sub === 'adduser') {
    return credential('signs in and stores a registry credential on this machine');
  }
  if (sub === 'logout') {
    return { capability: 'exec.pkg', reach: 'external', reversibility: 'easy', pathArgs: 'none', note: 'invalidates the stored registry credential' };
  }
  if (sub === 'token') {
    if (sub2 === 'revoke') {
      return { capability: 'exec.pkg', reach: 'external', reversibility: 'irreversible', pathArgs: 'none', note: 'revokes a registry token, which may break other people or other machines' };
    }
    if (sub2 === 'create') {
      return credential('creates a new registry token that grants publish rights', 'external');
    }
    return credential('lists registry tokens', 'network');
  }
  if (sub === 'config' || sub === 'c' || sub === 'set' || sub === 'get') {
    return jsConfig(argv, sub, sub2, rest);
  }

  // Package runners execute a package binary, downloading it first if it is
  // not already present, which makes them a quiet install-and-run path.
  if (sub === 'exec' || sub === 'dlx' || (pm === 'bun' && sub === 'x')) {
    return opaque('runs a package binary, downloading it first if it is not installed, and its contents are not analysed');
  }
  if (sub === 'create') {
    return opaque('downloads a project generator and runs it, which writes files and may install dependencies');
  }
  if (sub === 'init') {
    // `npm init vite` is a generator download; bare `npm init` just writes package.json.
    if (rest.length > 0) return opaque('downloads a project generator and runs it');
    return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'creates a package manifest' };
  }

  if (sub === 'link' || sub === 'ln') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      pathArgs: 'none',
      note: 'creates a global symlink, changing what other projects on this machine resolve this package to',
    };
  }
  if (sub === 'unlink') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'removes a global symlink' };
  }

  if (sub === 'run' || sub === 'run-script') return scriptJudgement(w[1]);
  if (sub === 'test' || sub === 't' || sub === 'tst') {
    // `bun test` is a built-in runner rather than a package.json script.
    if (pm === 'bun') return { capability: 'exec.test', pathArgs: 'none', note: 'runs the project test files, which is project code' };
    return scriptJudgement('test');
  }
  if (sub === 'start' || sub === 'restart' || sub === 'stop') return scriptJudgement(sub);

  if (sub === 'pack') {
    return { capability: 'fs.write.workspace', reversibility: 'trivial', pathArgs: 'none', note: 'writes a tarball of the package without uploading it' };
  }
  if (sub === 'version') {
    return {
      capability: 'exec.vcs.write',
      reversibility: 'easy',
      pathArgs: 'none',
      note: 'changes the version in the manifest and commits and tags it',
    };
  }
  if (sub === 'patch' || sub === 'patch-commit') {
    return { capability: 'fs.write.workspace', note: 'writes a patch file that changes an installed dependency' };
  }
  if (sub === 'cache' || sub === 'store') {
    if (sub2 === 'clean' || sub2 === 'prune' || sub2 === 'clear' || sub2 === 'rm' || sub2 === 'verify') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the shared package cache for every project on this machine' };
    }
    return inspect('reports on the package cache');
  }

  if (sub === 'pkg') {
    // `npm pkg set scripts.postinstall=...` is a manifest edit, not a read, and
    // what it writes runs by itself on the next install.
    if (sub2 === 'set' || sub2 === 'delete' || sub2 === 'fix') {
      return {
        capability: 'fs.write.workspace',
        reversibility: 'easy',
        pathArgs: 'none',
        note: 'edits the package manifest, which can add lifecycle scripts that run on their own during the next install',
      };
    }
    return inspect('reads fields out of the package manifest');
  }
  if (sub === 'env') {
    // `pnpm env use --global 20` downloads and installs a whole node runtime.
    if (sub2 === 'use' || sub2 === 'add' || sub2 === 'remove' || sub2 === 'rm') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'installs or removes a node runtime used by every project on this machine' };
    }
    return inspect('prints environment information');
  }

  if (['ls', 'list', 'la', 'll', 'why', 'explain', 'root', 'bin', 'prefix', 'doctor', 'whoami', 'help', 'completion', 'licenses', 'fund'].includes(sub)) {
    return inspect('reads local package information');
  }
  if (['view', 'v', 'info', 'show', 'search', 's', 'se', 'find', 'outdated', 'ping', 'docs', 'repo', 'star', 'unstar'].includes(sub)) {
    return fetch('asks the registry about packages', argv);
  }

  // `pnpm <script>`, `yarn <script>` and `bun <file>` all work without `run`.
  if (!JS_KNOWN_SUBS.has(sub) && pm !== 'npm') return scriptJudgement(sub);

  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function jsInstall(argv: string[], sub: string, pkgs: string[]): Judgement {
  const noScripts = flagOn(argv, '--ignore-scripts', '--no-scripts');
  const global = hasFlag(argv, '-g', '--global') || flagValue(argv, '--location') === 'global';
  const removing = JS_REMOVE_SUBS.has(sub);
  const targets = [...pkgTargets(pkgs), ...registryTargets(argv)];

  let note: string;
  if (removing) {
    note = 'removes dependencies, which can run their uninstall scripts';
  } else if (noScripts) {
    // The meaningful safety difference: bytes still land on disk, but nothing
    // downloaded gets to execute during the install itself.
    note = 'downloads dependencies without running any of their install scripts';
  } else {
    note = 'installs dependencies and runs their install scripts, which is freshly downloaded code running as you';
  }
  if (global) note += ', for every project on this machine';

  return {
    capability: 'exec.pkg',
    // Without --ignore-scripts an install is arbitrary local code execution;
    // with it, the reach is only as far as the download.
    reach: global ? 'machine' : noScripts ? 'network' : 'machine',
    reversibility: global ? 'hard' : 'easy',
    scale: 'many',
    pathArgs: 'none',
    note,
    targets: targets.length > 0 ? targets : undefined,
  };
}

/** Anything that looks like a registry token key in an npm config command. */
// `npmAuthToken`/`npmAuthIdent` are the yarn berry spellings, with no underscore.
const NPM_CREDENTIAL_KEY = /(_authtoken|_auth\b|_password|:_secret|:username|npmauth|\/\/[^\s]*:_)/i;

function jsConfig(argv: string[], sub: string, sub2: string, rest: string[]): Judgement {
  const all = argv.slice(1).join(' ');
  const writing = sub === 'set' || sub2 === 'set' || sub2 === 'delete' || sub2 === 'rm' || sub2 === 'edit';
  if (NPM_CREDENTIAL_KEY.test(all)) {
    return credential(writing
      ? 'writes a registry credential into the package manager configuration'
      : 'reads a registry credential out of the package manager configuration');
  }
  if (writing) {
    // The user-level .npmrc lives in the home directory, not the project.
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      pathArgs: 'none',
      note: 'changes package manager configuration for every project on this machine',
    };
  }
  if (rest.length === 0 && sub2 === '') return inspect('prints package manager configuration');
  return inspect('reads package manager configuration');
}

// --- python ----------------------------------------------------------------

function classifyPython(name: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  if (name === 'twine') return classifyTwine(argv);
  if (name === 'poetry') return classifyPoetry(argv);
  if (name === 'pipenv') return classifyPipenv(argv);
  if (name === 'conda' || name === 'mamba' || name === 'micromamba') return classifyConda(argv);
  if (name === 'uvx') {
    return opaque('downloads a python tool and runs it immediately, and its contents are not analysed');
  }
  if (name === 'uv') return classifyUv(argv, ctx);
  return classifyPip(argv, ctx);
}

function classifyPip(argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const rest = w.slice(1);

  if (sub === 'install') {
    if (flagOn(argv, '--dry-run')) return fetch('reports what would be installed without installing it', argv);
    const editable = hasFlag(argv, '-e', '--editable');
    const requirements = flagValue(argv, '-r', '--requirement');
    const local = rest.every((a) => {
      if (a.startsWith('-')) return false;
      const abs = ctx.resolve(a);
      return abs !== '' && ctx.inWorkspace(abs);
    });
    if (editable && rest.length > 0 && local) {
      // An editable install of the project itself: no download, and the build
      // code being run is the project's own.
      return {
        capability: 'exec.pkg',
        reach: 'machine',
        reversibility: 'easy',
        scale: 'single',
        pathArgs: 'none',
        note: 'installs this project into the environment in editable mode, running its own build script rather than downloading anything',
      };
    }
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: requirements ? 'many' : rest.length > 1 ? 'many' : 'single',
      pathArgs: 'none',
      note: 'installs python packages, and each one may run its own setup code while installing',
      targets: [...pkgTargets(rest), ...registryTargets(argv)],
    };
  }

  if (sub === 'uninstall') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'removes installed python packages from the environment' };
  }
  if (sub === 'download') {
    // Not a plain download: to work out what a source distribution needs, pip
    // builds it, which runs that package's own setup code.
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      pathArgs: 'none',
      note: 'downloads packages and builds any source distributions among them, which runs their setup code',
      targets: [...pkgTargets(rest), ...registryTargets(argv)],
    };
  }
  if (sub === 'wheel') {
    return { capability: 'exec.pkg', reach: 'machine', pathArgs: 'none', note: 'builds wheels, which runs each package build script' };
  }
  if (sub === 'search' || sub === 'index') return fetch('asks the package index about packages', argv);
  if (['list', 'show', 'freeze', 'check', 'inspect', 'debug', 'help'].includes(sub)) {
    return inspect('reads the list of installed packages');
  }
  if (sub === 'cache') {
    const sub2 = (w[1] ?? '').toLowerCase();
    if (sub2 === 'purge' || sub2 === 'remove') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the download cache shared by every project on this machine' };
    }
    return inspect('reports on the download cache');
  }
  if (sub === 'config') {
    const sub2 = (w[1] ?? '').toLowerCase();
    if (sub2 === 'set' || sub2 === 'unset' || sub2 === 'edit') {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes which package index every project on this machine installs from' };
    }
    return inspect('reads package manager configuration');
  }
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function classifyUv(argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();

  // `uv pip ...` is a drop-in for pip, so reuse the pip reasoning exactly.
  if (sub === 'pip') {
    const i = argv.indexOf('pip');
    return classifyPip(['pip', ...argv.slice(i + 1)], ctx);
  }
  if (sub === 'run') {
    return opaque('runs an arbitrary command in the project environment, installing whatever it needs first');
  }
  if (sub === 'tool') {
    if (sub2 === 'run') return opaque('downloads a python tool and runs it immediately');
    if (sub2 === 'install' || sub2 === 'upgrade' || sub2 === 'uninstall') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'installs or removes a python tool on the machine path for every project' };
    }
    return inspect('lists installed python tools');
  }
  if (['add', 'remove', 'sync', 'lock', 'install', 'upgrade'].includes(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'resolves and installs python dependencies, and each one may run its own build code',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'publish') {
    return publishJudgement(argv, 'uploads a release to a public package index, which cannot be taken back');
  }
  if (sub === 'build') return { capability: 'exec.build', pathArgs: 'none', note: 'builds a distributable package from the project' };
  if (sub === 'venv' || sub === 'init') return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'creates a project environment or scaffold' };
  if (sub === 'export') return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'writes a requirements file' };
  if (sub === 'self') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'replaces the package manager binary on this machine' };
  }
  if (sub === 'python') {
    // `uv python install 3.13` puts a whole interpreter on the machine.
    if (sub2 === 'install' || sub2 === 'uninstall' || sub2 === 'upgrade') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'downloads a python interpreter and installs it for every project on this machine' };
    }
    return inspect('lists the python interpreters uv can see');
  }
  if (sub === 'cache') {
    if (sub2 === 'clean' || sub2 === 'prune') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the download cache shared by every project on this machine' };
    }
    return inspect('reports on the download cache');
  }
  if (['tree', 'version'].includes(sub)) return inspect('reads local environment information');
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function classifyPoetry(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();
  const rest = w.slice(1);

  if (['add', 'install', 'update', 'lock', 'remove', 'sync'].includes(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'resolves and installs python dependencies, and each one may run its own build code',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'run') return opaque('runs an arbitrary command inside the project environment');
  if (sub === 'shell') return opaque('opens an interactive shell inside the project environment');
  if (sub === 'build') return { capability: 'exec.build', pathArgs: 'none', note: 'builds a distributable package from the project' };
  if (sub === 'publish') {
    return publishJudgement(argv, 'uploads a release to a public package index, which cannot be taken back');
  }
  if (sub === 'config') {
    // `poetry config pypi-token.pypi <token>` stores a publish credential.
    if (/http-basic|pypi-token|password/i.test(argv.slice(1).join(' '))) {
      return credential('stores a package index credential on this machine');
    }
    // A key on its own reads that key; a key with a value, or --unset, writes.
    if (rest.length > 1 || hasFlag(argv, '--unset')) {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes package manager configuration for every project on this machine' };
    }
    return inspect('reads package manager configuration');
  }
  if (sub === 'env' && (sub2 === 'remove' || sub2 === 'rm')) {
    return { capability: 'fs.delete', reach: 'machine', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'deletes a project virtual environment, which lives outside the project' };
  }
  if (sub === 'search') return fetch('asks the package index about packages', argv);
  if (sub === 'export') return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'writes a requirements file' };
  if (sub === 'new' || sub === 'init') return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'scaffolds a new project' };
  if (sub === 'self') return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'changes the package manager installation itself' };
  if (['show', 'check', 'about', 'env', 'version', 'help', 'list'].includes(sub)) return inspect('reads local environment information');
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function classifyPipenv(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  if (['install', 'uninstall', 'update', 'upgrade', 'sync', 'lock', 'clean'].includes(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'resolves and installs python dependencies, and each one may run its own build code',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'run') return opaque('runs an arbitrary command inside the project environment');
  if (sub === 'shell') return opaque('opens an interactive shell inside the project environment');
  if (sub === 'check' || sub === 'scan') return fetch('sends the dependency list away to be checked for advisories', argv);
  if (['graph', 'requirements', 'scripts', 'verify', 'open'].includes(sub)) return inspect('reads local environment information');
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function classifyConda(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();

  if (sub === 'activate' || sub === 'deactivate') {
    return { capability: 'meta', pathArgs: 'none', note: 'switches the active environment' };
  }
  if (sub === 'run') return opaque('runs an arbitrary command inside an environment');
  if (['install', 'create', 'update', 'upgrade', 'remove', 'uninstall'].includes(sub) ||
      (sub === 'env' && ['create', 'update', 'remove'].includes(sub2))) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      scale: 'many',
      pathArgs: 'none',
      note: 'installs or removes packages in a machine-wide environment, and packages may run their own setup code',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'init') {
    // `conda init` edits shell startup files, so it changes every future shell.
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'edits shell startup files so every new shell behaves differently' };
  }
  if (sub === 'clean') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the machine-wide package cache' };
  }
  if (sub === 'build') return { capability: 'exec.build', reach: 'machine', pathArgs: 'none', note: 'builds a package, running the recipe build script' };
  if (sub === 'search') return fetch('asks the package channel about packages', argv);
  if (sub === 'config') {
    // `conda config --add channels <url>` decides where every future package
    // on this machine is downloaded from, which is a supply chain change.
    if (hasFlag(argv, '--set', '--add', '--append', '--prepend', '--remove', '--remove-key', '--write-default', '--stdin')) {
      return {
        capability: 'fs.write.outside',
        reach: 'machine',
        reversibility: 'easy',
        pathArgs: 'none',
        note: 'changes which channels every environment on this machine installs from',
        targets: pkgTargets(w.slice(1)),
      };
    }
    return inspect('reads environment configuration');
  }
  if (['list', 'info', 'compare', 'env'].includes(sub)) return inspect('reads environment information');
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a package manager subcommand whose effect is not recognised');
}

function classifyTwine(argv: string[]): Judgement {
  const sub = (words(argv)[0] ?? '').toLowerCase();
  if (sub === 'upload') {
    return publishJudgement(argv, 'uploads a release to a public package index, where the version number can never be reused');
  }
  if (sub === 'register') {
    return registryAdmin('registers a package name on a public package index');
  }
  if (sub === 'check') return inspect('checks the built distribution files locally');
  return opaque('runs a publishing tool subcommand whose effect is not recognised');
}

// --- rust ------------------------------------------------------------------

function classifyCargo(argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();

  if (sub === 'build' || sub === 'b' || sub === 'check' || sub === 'c' || sub === 'clippy' || sub === 'doc' || sub === 'rustc' || sub === 'rustdoc') {
    // `cargo clippy --fix` is `cargo fix` with lints: it rewrites source.
    if (sub === 'clippy' && hasFlag(argv, '--fix')) {
      return rewriteJudgement(argv, ctx, 'rewrites source files in place to apply lint suggestions');
    }
    return {
      capability: 'exec.build',
      // Not pedantry: build.rs and procedural macros are ordinary code that
      // compiles and runs on this machine during a plain `cargo build`.
      note: 'compiles the project, which also runs build scripts and macros belonging to its dependencies',
    };
  }
  if (sub === 'test' || sub === 't' || sub === 'bench') {
    return { capability: 'exec.test', note: 'compiles and runs the project own test code' };
  }
  if (sub === 'fmt') {
    // Polarity trap: cargo fmt rewrites every source file in the crate unless
    // it is asked only to check.
    if (flagOn(argv, '--check')) return inspect('reports formatting differences without changing files');
    return rewriteJudgement(argv, ctx, 'rewrites source files in place to match the formatter');
  }
  if (sub === 'fix') {
    return rewriteJudgement(argv, ctx, 'rewrites source files in place to apply compiler suggestions');
  }
  if (sub === 'run' || sub === 'r') {
    return opaque('builds and runs the project own binary, whose behaviour is not analysed');
  }
  if (sub === 'install') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      pathArgs: 'none',
      note: 'compiles a crate from the registry and puts the resulting binary on the machine path',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'uninstall') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'removes an installed binary from the machine path' };
  }
  if (sub === 'publish') {
    return publishJudgement(argv, 'publishes a crate version to the public registry, and published versions can never be replaced or deleted');
  }
  if (sub === 'yank') {
    return registryAdmin('yanks a published version so other projects can no longer select it');
  }
  if (sub === 'owner') {
    return registryAdmin('changes who can publish this crate');
  }
  if (sub === 'login') {
    return credential('stores a registry token with publish rights on this machine');
  }
  if (sub === 'logout') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'removes the stored registry token' };
  }
  if (sub === 'add' || sub === 'remove' || sub === 'rm' || sub === 'update' || sub === 'upgrade' || sub === 'generate-lockfile') {
    return {
      capability: 'exec.pkg',
      // Editing the manifest and lockfile downloads metadata but does not
      // compile anything, so nothing from the registry runs yet.
      reach: 'network',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'changes the dependency list and downloads package metadata, without building anything yet',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'vendor' || sub === 'fetch') {
    return { capability: 'exec.pkg', reach: 'network', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'downloads dependency sources without compiling them' };
  }
  if (sub === 'clean') {
    return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', scale: 'sweeping', pathArgs: 'none', note: 'deletes the build output directory' };
  }
  if (sub === 'new' || sub === 'init') {
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'scaffolds a new crate' };
  }
  if (sub === 'package') return { capability: 'exec.build', pathArgs: 'none', note: 'builds a crate archive without uploading it' };
  if (sub === 'search') return fetch('asks the registry about crates', argv);
  if (['tree', 'metadata', 'version', 'locate-project', 'verify-project', 'help', 'pkgid', 'report'].includes(sub)) {
    return inspect('reads project and dependency information');
  }
  if (sub === '') return inspect('prints help or version information');
  // Unknown subcommands are cargo plugins: third-party binaries on the path.
  return opaque('runs a third-party cargo plugin, whose behaviour is not analysed');
}

// --- go --------------------------------------------------------------------

function classifyGo(argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();

  if (sub === 'build' || sub === 'vet') {
    // `-o` decides where the compiled binary lands, and it can land anywhere.
    const out = flagValue(argv, '-o');
    if (out) {
      const abs = ctx.resolve(out);
      if (abs !== '' && !ctx.inWorkspace(abs)) {
        return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'writes the compiled binary to a path outside the project' };
      }
    }
    return { capability: 'exec.build', note: 'compiles and analyses the project' };
  }
  if (sub === 'test') {
    return { capability: 'exec.test', note: 'compiles and runs the project own test code' };
  }
  if (sub === 'fmt') {
    // `go fmt` always rewrites; there is no check-only mode.
    return rewriteJudgement(argv, ctx, 'rewrites source files in place to match the formatter');
  }
  if (sub === 'fix') {
    return rewriteJudgement(argv, ctx, 'rewrites source files in place to apply automated fixes');
  }
  if (sub === 'run') {
    return opaque('builds and runs the project own program, whose behaviour is not analysed');
  }
  if (sub === 'generate') {
    // Every //go:generate comment in the tree is a shell command we cannot see.
    return opaque('runs the generate directives written in the source files, which are arbitrary commands');
  }
  if (sub === 'tool') {
    return opaque('runs a go toolchain program, whose behaviour is not analysed');
  }
  if (sub === 'install') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      pathArgs: 'none',
      note: 'compiles a package from the network and puts the resulting binary on the machine path',
      targets: pkgTargets(w.slice(1)),
    };
  }
  if (sub === 'get') {
    return {
      capability: 'exec.pkg',
      reach: 'network',
      reversibility: 'easy',
      pathArgs: 'none',
      note: 'downloads a module and changes the dependency list, without compiling it yet',
      targets: pkgTargets(w.slice(1)),
    };
  }
  if (sub === 'mod') {
    if (sub2 === 'tidy' || sub2 === 'download' || sub2 === 'vendor') {
      return { capability: 'exec.pkg', reach: 'network', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'downloads modules and rewrites the dependency files' };
    }
    if (sub2 === 'edit' || sub2 === 'init') {
      return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'changes the module definition file' };
    }
    return inspect('reads module information');
  }
  if (sub === 'work') {
    return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'changes the workspace module file' };
  }
  if (sub === 'clean') {
    if (hasFlag(argv, '-modcache', '-cache')) {
      return { capability: 'fs.delete', reach: 'machine', reversibility: 'easy', scale: 'sweeping', pathArgs: 'none', note: 'deletes the module cache shared by every project on this machine' };
    }
    return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', pathArgs: 'none', note: 'deletes build output' };
  }
  if (sub === 'env') {
    if (hasFlag(argv, '-w', '-u')) {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes the go environment settings for every project on this machine' };
    }
    return inspect('prints the go environment settings');
  }
  if (['list', 'doc', 'version', 'help', 'why'].includes(sub)) return inspect('reads project information');
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a go subcommand whose effect is not recognised');
}

// --- ruby ------------------------------------------------------------------

function classifyGem(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();

  if (sub === 'install' || sub === 'i' || sub === 'update') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      scale: 'many',
      pathArgs: 'none',
      note: 'installs gems for the whole machine, and gems with native extensions compile and run code while installing',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'uninstall' || sub === 'cleanup' || sub === 'pristine') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'removes or rebuilds gems installed for the whole machine' };
  }
  if (sub === 'push') {
    return publishJudgement(argv, 'publishes a gem version to the public registry, where the version number can never be reused');
  }
  if (sub === 'yank') {
    return registryAdmin('yanks a published gem version so other projects can no longer install it');
  }
  if (sub === 'owner') return registryAdmin('changes who can publish this gem');
  if (sub === 'signin' || sub === 'signout') {
    return credential('signs in and stores a gem registry credential on this machine');
  }
  if (sub === 'build') return { capability: 'exec.build', pathArgs: 'none', note: 'builds a gem file without uploading it' };
  if (sub === 'sources') {
    if (hasFlag(argv, '-a', '--add', '-r', '--remove', '-c', '--clear-all')) {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes which registry gems are installed from on this machine' };
    }
    return inspect('lists the configured gem sources');
  }
  if (sub === 'search' || sub === 'outdated') return fetch('asks the registry about gems', argv);
  if (['list', 'info', 'which', 'env', 'contents', 'dependency', 'query', 'help', 'check'].includes(sub)) {
    return inspect('reads information about installed gems');
  }
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a gem subcommand whose effect is not recognised');
}

function classifyBundler(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();

  if (sub === 'exec') {
    return opaque('runs another command inside the bundle, and that command is not analysed');
  }
  // Bare `bundle` installs the bundle, but `bundle --version` does not.
  if (sub === '' && helpOnly(argv)) return inspect('prints help or version information');
  if (sub === '' || ['install', 'update', 'add', 'remove', 'lock', 'package', 'cache', 'pristine', 'clean'].includes(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'installs the gems the project asks for, and gems with native extensions compile and run code while installing',
      targets: [...pkgTargets(w.slice(1)), ...registryTargets(argv)],
    };
  }
  if (sub === 'init' || sub === 'binstubs' || sub === 'gem') {
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'writes project scaffolding files' };
  }
  if (sub === 'config') {
    // `bundle config set --global gems.example.com user:token` stores a
    // credential for a private gem source in plain text.
    if (/http-basic|password|_auth|:\/\/[^\s/]+:[^\s/]+@/i.test(argv.slice(1).join(' '))) {
      return credential('stores a gem source credential on this machine');
    }
    const verb = (w[1] ?? '').toLowerCase();
    if (w.length === 1 || verb === 'get' || verb === 'list') return inspect('reads bundler configuration');
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes bundler configuration outside the project' };
  }
  if (sub === 'outdated') return fetch('asks the registry which gems are out of date', argv);
  if (['show', 'list', 'info', 'check', 'platform', 'why', 'version', 'help', 'viz'].includes(sub)) {
    return inspect('reads information about the bundle');
  }
  return opaque('runs a bundler subcommand whose effect is not recognised');
}

// --- java ------------------------------------------------------------------

/** Maven plugin goals that only report; everything else with a colon is opaque. */
const MAVEN_READONLY_GOALS = /^(dependency:(tree|list|analyze|resolve)|help:[a-z-]+|versions:display-[a-z-]+)$/;

function classifyMaven(argv: string[]): Judgement {
  const phases = words(argv).map((p) => p.toLowerCase());
  if (phases.length === 0) return inspect('prints help or version information');

  // `mvn deploy` and the release plugin push artifacts to a shared repository.
  if (phases.some((p) => p === 'deploy' || p.startsWith('deploy:') || p.startsWith('release:') || p.startsWith('nexus-staging:'))) {
    return publishJudgement(argv, 'uploads built artifacts to a shared repository, where other people and builds will pick them up');
  }
  if (phases.some((p) => p.startsWith('exec:') || p.startsWith('spring-boot:run') || p === 'jetty:run')) {
    return opaque('runs project code through a maven plugin, whose behaviour is not analysed');
  }
  if (phases.some((p) => p.includes(':') && !MAVEN_READONLY_GOALS.test(p))) {
    return opaque('runs a maven plugin goal, whose behaviour is not analysed', 'workspace');
  }
  if (phases.every((p) => MAVEN_READONLY_GOALS.test(p))) {
    return fetch('resolves dependencies and reports on them', argv);
  }
  if (phases.includes('install')) {
    // Maven "install" means the local ~/.m2 repository, not the system.
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'builds the project and copies the artifacts into the shared local repository on this machine',
    };
  }
  if (phases.includes('test') || phases.includes('verify') || phases.includes('integration-test')) {
    return { capability: 'exec.test', pathArgs: 'none', note: 'builds the project and runs its own test code' };
  }
  if (phases.length === 1 && phases[0] === 'clean') {
    return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', scale: 'sweeping', pathArgs: 'none', note: 'deletes the build output directory' };
  }
  return { capability: 'exec.build', pathArgs: 'none', note: 'builds the project, downloading any dependencies it is missing' };
}

const GRADLE_PUBLISH_TASKS = /^(publish|.*publishtomavenrepository|uploadarchives|bintrayupload|artifactorypublish|closeandreleaserepository)/;
const GRADLE_TEST_TASKS = /^(test|check|integrationtest|verify|lint|detekt|ktlintcheck|jacocotestreport)/;
const GRADLE_BUILD_TASKS = /^(build|assemble|compile|jar|war|bootjar|shadowjar|classes|distzip|installdist|bundle|processresources|spotlessapply|ktlintformat)/;

function classifyGradle(argv: string[]): Judgement {
  const tasks = words(argv).map((t) => t.toLowerCase());
  if (tasks.length === 0) {
    return { capability: 'exec.build', pathArgs: 'none', note: 'runs the default build tasks defined by the project' };
  }
  if (tasks.some((t) => GRADLE_PUBLISH_TASKS.test(t) && t !== 'publishtomavenlocal')) {
    return publishJudgement(argv, 'uploads built artifacts to a shared repository, where other people and builds will pick them up');
  }
  if (tasks.includes('publishtomavenlocal')) {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'copies the built artifacts into the shared local repository on this machine' };
  }
  if (tasks.some((t) => t === 'run' || t === 'bootrun' || t.endsWith(':run'))) {
    return opaque('builds and runs the project own program, whose behaviour is not analysed');
  }
  if (tasks.some((t) => GRADLE_TEST_TASKS.test(t))) {
    return { capability: 'exec.test', pathArgs: 'none', note: 'builds the project and runs its own test code' };
  }
  if (tasks.some((t) => GRADLE_BUILD_TASKS.test(t))) {
    return { capability: 'exec.build', pathArgs: 'none', note: 'builds the project, downloading any dependencies it is missing' };
  }
  if (tasks.length === 1 && tasks[0] === 'clean') {
    return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', scale: 'sweeping', pathArgs: 'none', note: 'deletes the build output directory' };
  }
  if (tasks.includes('wrapper')) {
    // Rewrites gradlew and gradle-wrapper.properties, which is what decides
    // the distribution every later `./gradlew` downloads and executes.
    return {
      capability: 'fs.write.workspace',
      reversibility: 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: 'rewrites the wrapper scripts that decide which gradle distribution later builds download and run',
      targets: registryTargets(argv),
    };
  }
  if (tasks.every((t) => ['tasks', 'projects', 'properties', 'dependencies', 'dependencyinsight', 'help', 'javatoolchains', 'model'].includes(t))) {
    return inspect('reports on the build configuration');
  }
  // Gradle task names are defined in the build script, which we never read.
  return opaque('runs a build task defined by the project, whose contents are not analysed', 'workspace');
}

// --- .net ------------------------------------------------------------------

function classifyDotnet(argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();

  if (sub === 'nuget') {
    // The only dotnet command that actually uploads to a registry.
    if (sub2 === 'push') {
      return publishJudgement(argv, 'uploads a package to a nuget feed, where the version number can never be reused');
    }
    if (sub2 === 'delete') {
      return registryAdmin('removes a published package version from a nuget feed');
    }
    if (sub2 === 'add' || sub2 === 'remove' || sub2 === 'update' || sub2 === 'enable' || sub2 === 'disable') {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes which package feeds this machine installs from' };
    }
    if (sub2 === 'locals') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the machine-wide package cache' };
    }
    return inspect('reads package feed configuration');
  }
  if (sub === 'publish' || sub === 'build' || sub === 'pack' || sub === 'msbuild' || sub === 'restore') {
    // `dotnet publish` is a local build layout step, NOT a registry upload.
    // Confusing it with `dotnet nuget push` would be a serious false alarm.
    const note = sub === 'publish'
      ? 'builds the project into a self-contained output folder on disk, and uploads nothing'
      : sub === 'restore'
        ? 'downloads the packages the project depends on'
        : 'builds the project, downloading any dependencies it is missing';
    return { capability: sub === 'restore' ? 'exec.pkg' : 'exec.build', reach: sub === 'restore' ? 'network' : undefined, pathArgs: 'none', note };
  }
  if (sub === 'test') return { capability: 'exec.test', pathArgs: 'none', note: 'builds the project and runs its own test code' };
  if (sub === 'run' || sub === 'watch') {
    return opaque('builds and runs the project own program, whose behaviour is not analysed');
  }
  if (sub === 'ef') {
    // Entity Framework commands talk to a real database, often a shared one.
    return {
      capability: 'exec.db',
      reach: 'external',
      reversibility: 'hard',
      opaque: true,
      pathArgs: 'none',
      note: 'runs a database migration tool that can change or drop the database it is pointed at',
    };
  }
  if (sub === 'tool') {
    if (sub2 === 'install' || sub2 === 'update' || sub2 === 'uninstall') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'installs or removes a tool on the machine path' };
    }
    if (sub2 === 'restore') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'downloads and installs every tool named in the tool manifest' };
    }
    // `dotnet tool run <name>` executes a tool; it is not a listing.
    if (sub2 === 'run' || sub2 === 'exec') {
      return opaque('runs an installed dotnet tool, whose behaviour is not analysed');
    }
    return inspect('lists installed tools');
  }
  if (sub === 'add' || sub === 'remove') {
    return { capability: 'exec.pkg', reach: 'network', reversibility: 'easy', pathArgs: 'none', note: 'changes the project dependency list and downloads packages' };
  }
  if (sub === 'format') {
    // dotnet format rewrites source unless asked only to verify.
    if (flagOn(argv, '--verify-no-changes', '--check')) return inspect('reports formatting differences without changing files');
    return rewriteJudgement(argv, ctx, 'rewrites source files in place to match the formatter');
  }
  if (sub === 'new') {
    // `dotnet new install <pkg>` fetches a template package onto the machine;
    // templates can carry post-actions that run when they are used.
    if (sub2 === 'install' || sub2 === 'uninstall' || sub2 === 'update' || hasFlag(argv, '--install', '--uninstall')) {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'installs or removes a template package for every project on this machine', targets: pkgTargets(w.slice(2)) };
    }
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'scaffolds files from a template' };
  }
  if (sub === 'clean') {
    return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', pathArgs: 'none', note: 'deletes build output' };
  }
  if (sub === 'list' || sub === 'sln' || sub === '') return inspect('reads project information');
  // `dotnet something.dll` executes an assembly.
  return opaque('runs a dotnet command or assembly whose behaviour is not analysed');
}

// --- php -------------------------------------------------------------------

const COMPOSER_KNOWN_SUBS = new Set([
  'install', 'update', 'upgrade', 'require', 'remove', 'global', 'create-project',
  'run-script', 'run', 'exec', 'dump-autoload', 'dumpautoload', 'show', 'outdated',
  'validate', 'licenses', 'why', 'why-not', 'depends', 'prohibits', 'status', 'audit',
  'search', 'diagnose', 'config', 'archive', 'init', 'self-update', 'clear-cache', 'help',
]);

function classifyComposer(argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const isGlobal = sub === 'global';
  const eff = isGlobal ? (w[1] ?? '').toLowerCase() : sub;
  const rest = isGlobal ? w.slice(2) : w.slice(1);

  // Bare `composer` installs, but `composer --version` does not.
  if (eff === '' && helpOnly(argv)) return inspect('prints help or version information');
  if (['install', 'update', 'upgrade', 'require', 'remove'].includes(eff) || eff === '') {
    const noScripts = flagOn(argv, '--no-scripts');
    return {
      capability: 'exec.pkg',
      reach: isGlobal ? 'machine' : noScripts ? 'network' : 'machine',
      reversibility: isGlobal ? 'hard' : 'easy',
      scale: 'many',
      pathArgs: 'none',
      note: noScripts
        ? 'downloads php dependencies without running any of their scripts'
        : 'installs php dependencies and runs the scripts declared for them, which is downloaded code running as you',
      targets: [...pkgTargets(rest), ...registryTargets(argv)],
    };
  }
  if (eff === 'create-project') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      scale: 'many',
      pathArgs: 'none',
      note: 'downloads a project template and runs its setup scripts',
      targets: pkgTargets(rest),
    };
  }
  if (eff === 'exec') return opaque('runs a vendor binary, whose behaviour is not analysed');
  if (eff === 'run-script' || eff === 'run') return scriptJudgement(rest[0]);
  if (eff === 'dump-autoload' || eff === 'dumpautoload') {
    return { capability: 'exec.build', pathArgs: 'none', note: 'regenerates the autoloader files' };
  }
  if (eff === 'config') {
    if (/http-basic|bearer|github-oauth|gitlab-token|password/i.test(argv.slice(1).join(' '))) {
      return credential('stores a package repository credential on this machine');
    }
    // A key on its own reads that key; a key with a value, or --unset, writes.
    if (rest.length <= 1 && !hasFlag(argv, '--unset')) return inspect('reads composer configuration');
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes composer configuration' };
  }
  if (eff === 'self-update') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'hard', pathArgs: 'none', note: 'replaces the composer binary on this machine' };
  }
  if (eff === 'clear-cache') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the machine-wide package cache' };
  }
  if (eff === 'archive') return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'writes an archive of the package' };
  if (eff === 'init') return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'creates a package manifest' };
  if (['outdated', 'audit', 'search', 'diagnose'].includes(eff)) {
    return fetch('asks the registry about packages', argv);
  }
  if (['show', 'validate', 'licenses', 'why', 'why-not', 'depends', 'prohibits', 'status', 'help'].includes(eff)) {
    return inspect('reads local package information');
  }
  // composer.json can define arbitrary named scripts invoked directly.
  if (!COMPOSER_KNOWN_SUBS.has(eff)) return scriptJudgement(eff);
  return opaque('runs a composer subcommand whose effect is not recognised');
}

// --- system package managers -----------------------------------------------

const SYS_INSTALL = new Set(['install', 'add', 'i', 'in', 'reinstall', 'localinstall', 'groupinstall', 'bundle']);
const SYS_REMOVE = new Set(['remove', 'uninstall', 'rm', 'del', 'delete', 'erase', 'purge', 'autoremove', 'autopurge']);
const SYS_UPGRADE = new Set(['upgrade', 'dist-upgrade', 'full-upgrade', 'up', 'dup', 'refresh-all']);
const SYS_READ_LOCAL = new Set([
  'list', 'ls', 'show', 'info', 'view', 'policy', 'depends', 'rdepends', 'deps',
  'uses', 'why', 'why-depends', 'which', 'files', 'contents', 'provides',
  'whatprovides', 'repolist', 'leaves', 'desc', 'status', 'help',
  'doctor', 'home', 'stats', 'tap-info', 'version',
]);
const SYS_READ_NET = new Set(['search', 'find', 'outdated', 'check-update', 'changelog', 'download', 'fetch']);

/** Managers where `update` only refreshes the package index rather than upgrading. */
const UPDATE_IS_REFRESH = new Set(['apt', 'apt-get', 'aptitude', 'apk', 'brew']);

function classifySystem(name: string, argv: string[]): Judgement {
  if (name === 'pacman') return classifyPacman(argv);

  const w = words(argv);
  const raw = (w[0] ?? '').toLowerCase();
  const rest = w.slice(1);

  // Normalise the handful of verbs that mean different things per manager.
  let sub = raw;
  if (raw === 'update') sub = UPDATE_IS_REFRESH.has(name) ? 'refresh' : 'upgrade';
  if (raw === 'refresh') sub = name === 'snap' ? 'upgrade' : 'refresh';
  if (raw === 'sync' || raw === 'ref') sub = 'refresh';

  if (name === 'brew' && raw === 'services') {
    return { capability: 'exec.process', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'starts or stops a background service on this machine' };
  }
  if (name === 'brew' && (raw === 'tap' || raw === 'untap')) {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'adds or removes a third-party source that future installs will trust' };
  }
  if (name === 'brew' && (raw === 'link' || raw === 'unlink' || raw === 'pin' || raw === 'unpin' || raw === 'cleanup')) {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes which installed versions the machine uses' };
  }
  if (name === 'snap' && raw === 'run') {
    return opaque('runs an installed application, whose behaviour is not analysed');
  }

  if (sub === 'refresh') {
    return fetch('refreshes the list of available packages without installing anything');
  }
  if (raw === 'clean' || raw === 'clean-all' || raw === 'autoclean') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'clears the downloaded package cache on this machine' };
  }
  if (raw === 'config' || raw === 'settings') {
    // `scoop config <name> <value>` and friends write; a bare read does not.
    if (rest.length > 1) {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', pathArgs: 'none', note: 'changes package manager settings for the whole machine' };
    }
    return inspect('reads package manager settings');
  }
  if (SYS_INSTALL.has(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      // System packages land in shared directories and run their own
      // post-install scripts, usually as root.
      reversibility: 'hard',
      scale: raw === 'bundle' || rest.length > 2 ? 'sweeping' : 'many',
      pathArgs: 'none',
      note: 'installs software for the whole machine, running package scripts with elevated rights',
      targets: pkgTargets(rest),
    };
  }
  if (SYS_REMOVE.has(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      scale: raw === 'autoremove' || raw === 'autopurge' ? 'sweeping' : 'many',
      pathArgs: 'none',
      note: raw === 'autoremove' || raw === 'autopurge'
        ? 'removes every package it considers unused, which can take out things other software depends on'
        : 'removes software from the whole machine',
      targets: pkgTargets(rest),
    };
  }
  if (SYS_UPGRADE.has(sub)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      // With no package named, this upgrades everything installed.
      scale: rest.length === 0 ? 'sweeping' : 'many',
      pathArgs: 'none',
      note: rest.length === 0
        ? 'upgrades every package on the machine, which can change or break unrelated software'
        : 'upgrades software for the whole machine',
      targets: pkgTargets(rest),
    };
  }
  if (SYS_READ_NET.has(sub)) return fetch('asks the package sources about available software');
  if (SYS_READ_LOCAL.has(sub)) return inspect('reads information about installed software');
  if (sub === '') return inspect('prints help or version information');

  // System package managers can do a lot; anything unrecognised gets asked about.
  return {
    capability: 'exec.pkg',
    reach: 'machine',
    reversibility: 'hard',
    opaque: true,
    pathArgs: 'none',
    note: 'runs a system package manager subcommand that may change software for the whole machine',
  };
}

/**
 * pacman takes an operation letter rather than a verb: -S installs, -R removes,
 * -Q queries, and lowercase modifiers change the meaning again (-Ss searches,
 * -Sy only refreshes, -Syu upgrades everything).
 */
function classifyPacman(argv: string[]): Judgement {
  const shortOps = argv
    .slice(1)
    .filter((a) => a.startsWith('-') && !a.startsWith('--'))
    .join('');
  const longOps = argv.slice(1).filter((a) => a.startsWith('--')).join(' ');
  const pkgs = pkgTargets(words(argv));

  const has = (letter: string) => shortOps.includes(letter);

  if (has('Q') || has('T') || /--query|--deptest/.test(longOps)) {
    return inspect('reads information about installed packages');
  }
  if (has('F') || /--files/.test(longOps)) return inspect('reads the package file database');

  if (has('R') || /--remove/.test(longOps)) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      scale: has('s') ? 'sweeping' : 'many',
      pathArgs: 'none',
      note: has('s')
        ? 'removes packages together with their unused dependencies, which can take out other software'
        : 'removes software from the whole machine',
      targets: pkgs,
    };
  }
  if (has('S') || has('U') || /--sync|--upgrade/.test(longOps)) {
    if (has('s') || has('i')) return fetch('searches the package databases');
    if (has('u') || /--sysupgrade/.test(longOps)) {
      return {
        capability: 'exec.pkg',
        reach: 'machine',
        reversibility: 'hard',
        scale: 'sweeping',
        pathArgs: 'none',
        note: 'upgrades every package on the machine, which can change or break unrelated software',
      };
    }
    if (has('y') && words(argv).length === 0) {
      return fetch('refreshes the list of available packages without installing anything');
    }
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'hard',
      scale: 'many',
      pathArgs: 'none',
      note: 'installs software for the whole machine, running package scripts with elevated rights',
      targets: pkgs,
    };
  }
  if (argv.length === 1 || helpOnly(argv)) return inspect('prints help or version information');
  // Operations this reading missed (-D and friends, which edit the local
  // database) still went to the system package manager, so they get asked
  // about rather than assumed to be a query.
  return {
    capability: 'exec.pkg',
    reach: 'machine',
    reversibility: 'hard',
    opaque: true,
    pathArgs: 'none',
    note: 'runs a system package manager operation that may change software for the whole machine',
  };
}

function classifyNix(name: string, argv: string[]): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();
  const sub2 = (w[1] ?? '').toLowerCase();

  if (name === 'nix-env') {
    if (hasFlag(argv, '-q', '--query')) return inspect('lists installed packages');
    if (hasFlag(argv, '-i', '--install', '-u', '--upgrade', '-e', '--uninstall', '-iA')) {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'changes the packages installed in the user profile on this machine' };
    }
    return inspect('reads package information');
  }
  if (sub === 'run' || sub === 'develop' || sub === 'shell') {
    return opaque('downloads a package and runs a program or shell from it, which is not analysed');
  }
  if (sub === 'profile') {
    if (sub2 === 'install' || sub2 === 'remove' || sub2 === 'upgrade' || sub2 === 'rollback') {
      return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', scale: 'many', pathArgs: 'none', note: 'changes the packages installed in the user profile on this machine' };
    }
    return inspect('lists the packages in the user profile');
  }
  if (sub === 'build') {
    return { capability: 'exec.build', reach: 'machine', note: 'builds a derivation, which downloads sources and runs their build scripts' };
  }
  if (sub === 'flake') {
    if (sub2 === 'update' || sub2 === 'lock') {
      return { capability: 'exec.pkg', reach: 'network', reversibility: 'easy', pathArgs: 'none', note: 'updates the pinned inputs recorded in the lock file' };
    }
    return fetch('reads flake metadata from its inputs');
  }
  if (sub === 'search') return fetch('searches available packages');
  if (sub === 'eval' || sub === 'why-depends' || sub === 'path-info' || sub === 'show-config' || sub === 'derivation') {
    return inspect('reads package expressions and metadata');
  }
  if (sub === 'copy') {
    return { capability: 'net.send', reach: 'network', reversibility: 'hard', pathArgs: 'none', note: 'copies built store paths to another machine' };
  }
  if (sub === '') return inspect('prints help or version information');
  return opaque('runs a nix subcommand whose effect is not recognised');
}

// --- build tools -----------------------------------------------------------

/** Flags and subcommands that turn a bundler into a long-running server. */
function isDevServer(name: string, argv: string[]): boolean {
  const sub = (words(argv)[0] ?? '').toLowerCase();
  if (['dev', 'serve', 'preview', 'start', 'watch'].includes(sub)) return true;
  if (hasFlag(argv, '--serve', '--watch', '-w')) return true;
  // Bare `vite` and bare `parcel <entry>` both start a dev server by default.
  if ((name === 'vite' || name === 'parcel') && sub === '') return true;
  if (name === 'parcel' && sub !== 'build') return true;
  return false;
}

function classifyBuildTool(name: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  const w = words(argv);
  const sub = (w[0] ?? '').toLowerCase();

  if (name === 'tsc') {
    if (flagOn(argv, '--noEmit', '--noemit')) {
      return { capability: 'exec.inspect', note: 'type-checks the project without writing any output' };
    }
    if (hasFlag(argv, '--init')) {
      return { capability: 'fs.write.workspace', reversibility: 'trivial', note: 'writes a compiler configuration file' };
    }
    return { capability: 'exec.build', note: 'compiles typescript and writes the compiled output' };
  }

  if (name === 'turbo' || name === 'nx') {
    // Both delegate to package scripts, so the task name is the only signal.
    const target = flagValue(argv, '-t', '--target', '--targets') ??
      (sub === 'run' || sub === 'run-many' || sub === 'affected'
        ? (w[1] ?? '').includes(':') ? (w[1] ?? '').split(':')[1] : w[1]
        : sub);
    const j = scriptJudgement(target, 'task');
    // A monorepo runner fans the same task out across every package.
    j.scale = 'sweeping';
    return j;
  }

  if (name === 'bazel' || name === 'bazelisk') {
    if (sub === 'run') return opaque('builds and runs a target, whose behaviour is not analysed');
    if (sub === 'test') return { capability: 'exec.test', pathArgs: 'none', note: 'builds and runs test targets, which is project code' };
    if (sub === 'clean') return { capability: 'fs.delete', reach: 'workspace', reversibility: 'easy', scale: 'sweeping', pathArgs: 'none', note: 'deletes the build output tree' };
    if (sub === 'query' || sub === 'info' || sub === 'cquery' || sub === 'aquery') return inspect('reports on the build graph');
    return { capability: 'exec.build', reach: 'machine', pathArgs: 'none', note: 'builds targets, downloading external dependencies and running build rules' };
  }

  if (name === 'cmake') {
    // `-E` is a portable shell (`cmake -E rm -rf <path>`, `cmake -E copy`) and
    // `-P` runs a script file: neither is a build, and both go where told.
    if (hasFlag(argv, '-E', '-P')) {
      return opaque('runs cmake in command or script mode, which copies, removes or executes whatever it is told to');
    }
    if (hasFlag(argv, '--install')) {
      // The install prefix is usually somewhere like /usr/local.
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'hard', scale: 'many', pathArgs: 'none', note: 'copies build output into a system directory outside the project' };
    }
    if (hasFlag(argv, '--build')) return { capability: 'exec.build', pathArgs: 'none', note: 'builds the configured project' };
    return { capability: 'exec.build', note: 'configures the build, which runs the project own cmake scripts' };
  }

  if (name === 'meson') {
    if (sub === 'install') {
      return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'hard', scale: 'many', pathArgs: 'none', note: 'copies build output into a system directory outside the project' };
    }
    if (sub === 'test') return { capability: 'exec.test', pathArgs: 'none', note: 'runs the project own test code' };
    return { capability: 'exec.build', note: 'configures or compiles the project' };
  }

  if (name === 'gulp' || name === 'grunt') {
    // Task bodies live in gulpfile/gruntfile and are ordinary javascript.
    return {
      capability: 'exec.build',
      opaque: true,
      pathArgs: 'none',
      note: 'runs a build task defined in the project build file, whose contents are not analysed',
    };
  }

  if (isDevServer(name, argv)) {
    const exposed = hasFlag(argv, '--host', '--open-host') || argv.includes('--host=0.0.0.0');
    // A watch-only build rebuilds forever but never listens on a port, so it
    // is worth saying which of the two long-running shapes this is.
    const watchOnly = !['dev', 'serve', 'preview', 'start'].includes(sub) && !hasFlag(argv, '--serve');
    return {
      capability: 'exec.build',
      reach: exposed ? 'network' : 'workspace',
      pathArgs: 'none',
      note: exposed
        ? 'starts a long-running dev server and exposes it to the network'
        : watchOnly
          ? 'keeps running and rebuilds every time a file changes, until it is stopped'
          : 'starts a long-running dev server that holds a port open until it is stopped',
    };
  }

  if (name === 'babel' || name === 'swc' || name === 'esbuild') {
    // These write wherever --out-dir points, which is normally in the project.
    const out = flagValue(argv, '-d', '--out-dir', '--outdir', '-o', '--outfile', '--out-file');
    if (out) {
      const abs = ctx.resolve(out);
      if (abs !== '' && !ctx.inWorkspace(abs)) {
        return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'hard', scale: 'many', note: 'writes compiled output outside the project' };
      }
    }
    return { capability: 'exec.build', note: 'compiles source files and writes the output' };
  }

  return { capability: 'exec.build', note: 'builds the project' };
}

// --- test runners ----------------------------------------------------------

function classifyTestRunner(name: string, argv: string[]): Judgement {
  const sub = (words(argv)[0] ?? '').toLowerCase();

  if (name === 'playwright' || name === 'cypress') {
    if (sub === 'install' || sub === 'install-deps' || sub === 'verify') {
      return {
        capability: 'exec.pkg',
        reach: 'machine',
        reversibility: 'easy',
        pathArgs: 'none',
        note: 'downloads browser binaries onto the machine',
      };
    }
    return {
      capability: 'exec.test',
      // A browser test suite loads whatever URLs the spec files point at.
      reach: 'network',
      note: 'runs tests in a real browser, which executes project code and can reach the network',
    };
  }

  if (name === 'tox') {
    return {
      capability: 'exec.test',
      reach: 'machine',
      note: 'creates environments and installs dependencies before running project test code',
    };
  }

  if (name === 'pytest' || name === 'py.test') {
    if (hasFlag(argv, '--collect-only', '--co')) {
      return { capability: 'exec.inspect', note: 'lists the tests that would run without running them' };
    }
    return { capability: 'exec.test', note: 'runs the project own test code, including any fixtures it defines' };
  }

  if (name === 'karma') {
    return { capability: 'exec.test', reach: 'network', note: 'launches a browser to run project test code' };
  }

  // Snapshot updates are the one common way a test run edits tracked files.
  if (hasFlag(argv, '-u', '--updateSnapshot', '--update-snapshots', '--update')) {
    return { capability: 'exec.test', note: 'runs project test code and rewrites the stored snapshot files' };
  }
  return { capability: 'exec.test', note: 'runs the project own test code' };
}

// --- linters and formatters ------------------------------------------------

/**
 * Whether this linter invocation writes to the files it is pointed at.
 *
 * The polarity differs per tool and getting it wrong loses work silently, so
 * each default is spelled out rather than inferred.
 */
function linterWrites(name: string, argv: string[]): boolean {
  const sub = (words(argv)[0] ?? '').toLowerCase();

  switch (name) {
    // Write-by-default tools: only a check or diff mode makes them read-only,
    // and `--check=false` is not a check.
    case 'black':
      return !flagOn(argv, '--check', '--diff');
    case 'isort':
      // `-d`/`--df` print to stdout and to a diff respectively.
      return !flagOn(argv, '--check', '--check-only', '--diff', '--df', '-c', '-d');
    case 'rustfmt':
      return !flagOn(argv, '--check') && flagValue(argv, '--emit') !== 'stdout';

    // Read-by-default tools: an explicit fix or write flag turns them around.
    case 'eslint':
      // --fix-dry-run reports the fixes instead of applying them.
      return hasFlag(argv, '--fix');
    case 'prettier':
      return hasFlag(argv, '--write', '-w');
    case 'gofmt':
      return hasFlag(argv, '-w');
    case 'rubocop':
      return hasFlag(argv, '-a', '-A', '--auto-correct', '--autocorrect', '--auto-correct-all', '--autocorrect-all', '--fix-layout');
    case 'biome':
      return hasFlag(argv, '--write', '--apply', '--apply-unsafe', '--fix');
    case 'ruff':
      // `ruff format` writes by default; `ruff check` only writes with --fix.
      if (sub === 'format') return !flagOn(argv, '--check', '--diff');
      return hasFlag(argv, '--fix', '--fix-only');

    // Pure analysers with no write mode at all.
    default:
      return false;
  }
}

function classifyLinter(name: string, argv: string[], ctx: KnowledgeCtx): Judgement {
  if (linterWrites(name, argv)) {
    return rewriteJudgement(argv, ctx, 'rewrites the matching source files in place');
  }
  // Report-only: these read the tree and print. Type checkers such as mypy
  // write a cache directory, which is not worth calling a write.
  return { capability: 'exec.inspect', scale: 'many', note: 'checks source files and reports problems without changing them' };
}
