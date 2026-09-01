/**
 * Containers, databases, system control, and language interpreters.
 *
 * These four families belong together because they share one awkward property:
 * the program name tells you almost nothing, and the thing that decides the
 * blast radius is buried in a flag or in a string argument.
 *
 * `docker run` is a sandbox right up until someone adds
 * `-v /var/run/docker.sock:/var/run/docker.sock`, at which point the container
 * can start a privileged sibling and own the machine. `psql -c` is a report
 * until the verb is DROP. `crontab` looks like a text editor and is really a
 * way to run code tomorrow, when nobody is watching. And `python` is a wrapper
 * around code we simply cannot see, which is what `opaque` exists for.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { flagValue, hasFlag, hostOf, nonFlags } from './types.js';

/** Derived rather than imported, so this module depends on `./types.js` alone. */
type Target = NonNullable<Judgement['targets']>[number];

// ---------------------------------------------------------------------------
// Program groups
// ---------------------------------------------------------------------------

const CONTAINERS = ['docker', 'podman', 'docker-compose', 'nerdctl', 'buildah', 'kind', 'minikube'];

const DB_CLIENTS = [
  'psql', 'mysql', 'mariadb', 'mongo', 'mongosh', 'redis-cli', 'sqlite3', 'sqlcmd',
  'clickhouse-client', 'cockroach', 'influx', 'cqlsh',
];

const DB_MIGRATORS = ['prisma', 'drizzle-kit', 'sequelize', 'alembic', 'flyway', 'liquibase', 'knex'];

const PROCESS_TOOLS = [
  'kill', 'killall', 'pkill', 'taskkill',
  'systemctl', 'service', 'launchctl', 'sc',
  'shutdown', 'reboot', 'halt', 'poweroff',
  'mount', 'umount', 'fdisk', 'diskutil',
  'mkfs', 'mkfs.ext2', 'mkfs.ext3', 'mkfs.ext4', 'mkfs.xfs', 'mkfs.btrfs', 'mkfs.vfat', 'mkfs.ntfs',
  'ifconfig', 'ip', 'iptables', 'ip6tables', 'ufw', 'netsh',
  'defaults', 'reg', 'crontab', 'at', 'schtasks',
];

const INTERPRETERS = [
  'python', 'python2', 'python3', 'node', 'deno', 'ruby', 'php', 'rscript', 'julia', 'lua',
  'osascript', 'powershell', 'pwsh', 'cmd', 'wscript', 'cscript',
];

export const runtime: ProgramKnowledge = {
  names: [...CONTAINERS, ...DB_CLIENTS, ...DB_MIGRATORS, ...PROCESS_TOOLS, ...INTERPRETERS],
  describe:
    'Containers, database clients and migrations, process and system control, and language interpreters',

  classify(argv, ctx) {
    const name = argv[0]!;
    if (CONTAINERS.includes(name)) return classifyContainer(argv, ctx, name);
    if (DB_CLIENTS.includes(name)) return classifyDbClient(argv, ctx, name);
    if (DB_MIGRATORS.includes(name)) return classifyMigrator(argv, name);
    if (PROCESS_TOOLS.includes(name)) return classifyProcess(argv, ctx, name);
    if (INTERPRETERS.includes(name)) return classifyInterpreter(argv, ctx, name);
    return null;
  },
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** A positional argument together with where it sits in argv. */
interface Positional {
  value: string;
  index: number;
}

/**
 * Positional words, skipping flags. `valueFlags` names the flags that consume
 * the following argument, so `docker -H tcp://x ps` yields `ps` and not the
 * host. Being wrong here only ever costs us a subcommand match, which falls
 * through to the conservative unknown branch.
 */
function positionals(argv: string[], valueFlags: string[], from = 1): Positional[] {
  const out: Positional[] = [];
  for (let i = from; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') continue;
    if (a.startsWith('-') && a !== '-') {
      if (!a.includes('=') && valueFlags.includes(a)) i++;
      continue;
    }
    out.push({ value: a, index: i });
  }
  return out;
}

/** Every value given for any of `flags`; `flagValue` only returns the first. */
function collectFlagValues(argv: string[], flags: string[]): string[] {
  const out: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    for (const f of flags) {
      if (a === f) {
        const v = argv[i + 1];
        if (v !== undefined) out.push(v);
      } else if (a.startsWith(f + '=')) {
        out.push(a.slice(f.length + 1));
      }
    }
  }
  return out;
}

/** Stitch note clauses together without turning into a bullet list. */
function joinNotes(parts: (string | undefined)[]): string | undefined {
  const kept = parts.filter((p): p is string => typeof p === 'string' && p.length > 0);
  if (kept.length === 0) return undefined;
  return kept.slice(0, 3).join(', and ');
}

/** Looks like a filesystem path rather than a named volume or an image tag. */
function looksLikePath(s: string): boolean {
  return s.startsWith('/') || s.startsWith('./') || s.startsWith('../') || s.startsWith('~') ||
    s.startsWith('\\') || /^[a-zA-Z]:[\\/]/.test(s) || s === '.' || s === '..';
}

/**
 * Names that suggest something real users depend on. Matched on separators so
 * that "reproduction-fixture" does not read as production.
 */
function looksProduction(s: string): boolean {
  return /(^|[^a-z])(prod|production|prd|live)([^a-z]|$)/i.test(s);
}

function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h === '';
}

// ---------------------------------------------------------------------------
// 1. Containers
// ---------------------------------------------------------------------------

/**
 * Flags that take a separate value and can appear *before* the subcommand.
 * Also includes a few common per-command flags so that two-word subcommands
 * like `volume rm` are still found when flags are interleaved.
 */
const CONTAINER_VALUE_FLAGS = [
  '-H', '--host', '--context', '-c', '--config', '--log-level', '--tlscacert', '--tlscert',
  '--tlskey', '-f', '--file', '--project-name', '-p', '--project-directory', '--env-file',
  '--profile', '--format', '--filter', '-n', '--tail', '--since', '--until', '--context-name',
];

/** Subcommand groups that act as nouns: `docker volume rm` -> noun volume, verb rm. */
const CONTAINER_NOUNS = new Set([
  'image', 'images', 'container', 'volume', 'network', 'system', 'builder', 'buildx', 'context',
  'compose', 'node', 'service', 'stack', 'secret', 'config', 'plugin', 'trust', 'manifest', 'swarm',
]);

/** Subcommands that only look. */
const CONTAINER_READ_VERBS = new Set([
  'ps', 'ls', 'list', 'images', 'inspect', 'logs', 'version', 'info', 'top', 'stats', 'port',
  'history', 'diff', 'events', 'df', 'wait', 'help', 'get-contexts',
]);

function classifyContainer(argv: string[], ctx: KnowledgeCtx, name: string): Judgement {
  const words = positionals(argv, CONTAINER_VALUE_FLAGS);
  const first = words[0]?.value?.toLowerCase() ?? '';
  const second = words[1]?.value?.toLowerCase() ?? '';

  if (name === 'kind' || name === 'minikube') return classifyLocalCluster(argv, name, first, second);

  // `docker-compose up` and `docker compose up` are the same tool.
  let noun = '';
  let verb = first;
  let rest = words.slice(1);
  if (first && CONTAINER_NOUNS.has(first) && second) {
    noun = first;
    verb = second;
    rest = words.slice(2);
  }
  if (name === 'docker-compose') {
    noun = 'compose';
    verb = first;
    rest = words.slice(1);
  }
  if (noun === 'compose') return classifyCompose(argv, ctx, verb, rest);

  switch (verb) {
    // --- looking around -----------------------------------------------------
    case 'ps':
    case 'ls':
    case 'list':
    case 'images':
    case 'inspect':
    case 'logs':
    case 'version':
    case 'info':
    case 'top':
    case 'stats':
    case 'port':
    case 'history':
    case 'diff':
    case 'events':
    case 'df':
    case 'wait':
    case 'help':
    case 'get-contexts':
      return { capability: 'exec.inspect', note: 'lists or inspects container state', pathArgs: 'none' };

    case 'search':
      // Queries a registry over the network, but changes nothing.
      return { capability: 'net.fetch', note: 'searches a remote image registry', pathArgs: 'none' };

    // --- building -----------------------------------------------------------
    case 'build':
    case 'bud': {
      // `buildx build --push` (or `--output type=registry`) uploads the finished
      // image in the same step, so the build is also a publish.
      const pushes = hasFlag(argv, '--push') ||
        collectFlagValues(argv, ['-o', '--output']).some((o) => /type=registry|push=true/i.test(o));
      if (pushes) {
        const all = argv.slice(1).join(' ');
        return {
          capability: 'exec.pkg.publish',
          reach: looksProduction(all) ? 'production' : 'external',
          reversibility: 'irreversible',
          note: 'builds a container image and pushes it to a remote registry in the same step',
        };
      }
      // A build downloads base layers and writes an image into the machine's
      // image store, so it reaches past the workspace even though it feels
      // like a compile step. The Dockerfile itself can run arbitrary commands.
      return {
        capability: 'exec.build',
        reach: 'machine',
        note: 'builds a container image, running the build steps and downloading base layers',
      };
    }

    case 'commit':
    case 'tag':
    case 'save':
    case 'export':
    case 'import':
    case 'load':
      return {
        capability: 'exec.container',
        reversibility: 'easy',
        note: 'moves an image between the image store and a file',
      };

    case 'pull':
    case 'fetch':
      return {
        capability: 'exec.container',
        reach: 'network',
        reversibility: 'easy',
        note: 'downloads an image from a remote registry',
        pathArgs: 'none',
      };

    // --- leaving the machine ------------------------------------------------
    case 'push': {
      const ref = rest[0]?.value ?? '';
      const registry = hostOf(ref) ?? (ref.includes('/') ? ref.split('/')[0] : undefined);
      const targets: Target[] = ref
        ? [{ type: 'package', value: ref }]
        : [];
      if (registry && registry.includes('.')) targets.push({ type: 'host', value: registry });
      return {
        capability: 'exec.pkg.publish',
        reach: looksProduction(ref) ? 'production' : 'external',
        reversibility: 'irreversible',
        note: 'publishes an image to a remote registry, where others can pull it',
        pathArgs: 'none',
        targets,
      };
    }

    case 'login':
      // The credential ends up stored on disk, and with `-p` it is sitting in
      // the command line where any process listing can read it.
      return {
        capability: 'secret.read',
        reach: 'network',
        exposure: 'reads-secrets',
        note: joinNotes([
          'signs in to a registry and stores the credential on this machine',
          hasFlag(argv, '-p', '--password') ? 'with a password in the command line' : undefined,
        ]),
        pathArgs: 'none',
      };

    case 'logout':
      return { capability: 'exec.container', reversibility: 'trivial', note: 'signs out of a registry', pathArgs: 'none' };

    // --- running code -------------------------------------------------------
    case 'run':
    case 'create':
    case 'exec':
      return containerRunJudgement(argv, ctx, verb);

    case 'start':
    case 'restart':
    case 'unpause':
      // Starting a container runs whatever entrypoint it was created with,
      // including any mounts and privileges chosen at creation time, which we
      // cannot see from here.
      return {
        capability: 'exec.container',
        opaque: true,
        note: 'starts a container, with whatever mounts and privileges it was created with',
        pathArgs: 'none',
      };

    case 'stop':
    case 'pause':
    case 'kill':
      return {
        capability: 'exec.container',
        reversibility: 'easy',
        note: 'stops a running container',
        pathArgs: 'none',
      };

    case 'attach':
      return { capability: 'exec.container', opaque: true, note: 'attaches to a running container', pathArgs: 'none' };

    case 'cp':
      return containerCopyJudgement(rest, ctx);

    // --- destroying ---------------------------------------------------------
    case 'rm':
    case 'remove':
    case 'rmi':
      return containerRemoveJudgement(argv, noun, verb, rest.length);

    case 'prune':
      return containerPruneJudgement(argv, noun);

    default:
      // An unrecognised subcommand of a tool that can do all of the above is
      // exactly the case where guessing "harmless" would be a bug.
      return {
        capability: 'exec.container',
        opaque: true,
        note: 'runs a container command that leastgrant does not recognise',
        pathArgs: 'none',
      };
  }
}

/** A host directory bound into a container. */
interface Mount {
  source: string;
  readOnly: boolean;
}

/**
 * Split a `-v` spec into host source and container destination.
 * Written by hand because a Windows source (`C:\src:/app`) also contains
 * colons, and a naive split turns `C` into the host path.
 */
function splitVolumeSpec(spec: string): string[] {
  const parts: string[] = [];
  let cur = '';
  for (let i = 0; i < spec.length; i++) {
    const ch = spec[i]!;
    const isDriveColon = cur.length === 1 && /[a-zA-Z]/.test(cur) && parts.length < 2;
    if (ch === ':' && !isDriveColon) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

/** Every host-path mount requested on the command line. */
function containerMounts(argv: string[]): Mount[] {
  const out: Mount[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    let value: string | undefined;
    let structured = false;

    if (a === '-v' || a === '--volume') value = argv[i + 1];
    else if (a.startsWith('--volume=')) value = a.slice('--volume='.length);
    else if (a.startsWith('-v=')) value = a.slice(3);
    else if (a.startsWith('-v') && a.length > 2) value = a.slice(2);
    else if (a === '--mount') {
      value = argv[i + 1];
      structured = true;
    } else if (a.startsWith('--mount=')) {
      value = a.slice('--mount='.length);
      structured = true;
    }
    if (!value) continue;

    if (structured) {
      // type=bind,source=/host,target=/ct,readonly
      let source = '';
      let readOnly = false;
      for (const field of value.split(',')) {
        const [rawKey, ...restParts] = field.split('=');
        const key = (rawKey ?? '').trim().toLowerCase();
        const val = restParts.join('=');
        if (key === 'source' || key === 'src') source = val;
        if ((key === 'readonly' || key === 'ro') && val !== 'false') readOnly = true;
      }
      if (source) out.push({ source, readOnly });
      continue;
    }

    const parts = splitVolumeSpec(value);
    // A single part is an anonymous volume (`-v /data`): no host path involved.
    if (parts.length < 2) continue;
    const source = parts[0] ?? '';
    const opts = parts[2] ?? '';
    if (!looksLikePath(source)) continue; // a named volume, not the host filesystem
    out.push({ source, readOnly: /(^|,)ro(,|$)/.test(opts) });
  }
  return out;
}

/** Sockets that hand the container control of the host's container runtime. */
function isRuntimeSocket(source: string): boolean {
  const s = source.toLowerCase().replace(/\\/g, '/');
  return s.endsWith('docker.sock') || s.endsWith('podman.sock') || s.endsWith('containerd.sock') ||
    s.endsWith('crio.sock') || s.includes('pipe/docker_engine');
}

function isFilesystemRoot(source: string): boolean {
  return source === '/' || source === '\\' || /^[a-zA-Z]:[\\/]?$/.test(source);
}

/** Capabilities that let a container step outside its own kernel namespace. */
const DANGEROUS_CAPS = new Set([
  'ALL', 'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_BOOT',
  'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'NET_ADMIN',
]);

function containerRunJudgement(argv: string[], ctx: KnowledgeCtx, verb: string): Judgement {
  const mounts = containerMounts(argv);
  const caps = collectFlagValues(argv, ['--cap-add']).map((c) => c.trim().toUpperCase());
  const network = (flagValue(argv, '--network', '--net') ?? '').toLowerCase();
  const pidNs = (flagValue(argv, '--pid') ?? '').toLowerCase();
  const ipcNs = (flagValue(argv, '--ipc') ?? '').toLowerCase();
  const userNs = (flagValue(argv, '--userns') ?? '').toLowerCase();
  const secOpts = collectFlagValues(argv, ['--security-opt']).join(',').toLowerCase();

  const socket = mounts.some((m) => isRuntimeSocket(m.source));
  const hostRoot = mounts.some((m) => isFilesystemRoot(m.source));
  const privileged = hasFlag(argv, '--privileged');
  const dangerousCap = caps.some((c) => DANGEROUS_CAPS.has(c));
  // `seccomp=unconfined`, `apparmor=unconfined`, `systempaths=unconfined` and
  // `label=disable` each remove one of the walls the container is made of.
  const unconfined = secOpts.includes('unconfined') || /label[=:]disable/.test(secOpts);
  const hostNetwork = network === 'host';
  const hostNamespace = pidNs === 'host' || ipcNs === 'host' || userNs === 'host';
  const devices = collectFlagValues(argv, ['--device']).length > 0;

  const targets: Target[] = [];
  let writableOutside = false;
  let readOnlyOutside = false;
  let secretMount = false;
  for (const m of mounts) {
    const abs = ctx.resolve(m.source);
    const inside = abs ? ctx.inWorkspace(abs) : false;
    const secret = abs ? ctx.isSecret(abs) : false;
    targets.push({ type: 'path', value: abs || m.source, inWorkspace: inside, secret });
    if (secret) secretMount = true;
    if (!inside) {
      if (m.readOnly) readOnlyOutside = true;
      else writableOutside = true;
    }
  }

  // Any of these means the container is no longer a box: code inside it can
  // reach the host, so the honest answer is that we cannot bound the effect.
  const escapes = socket || hostRoot || privileged || dangerousCap || hostNamespace || writableOutside ||
    devices || unconfined;

  const note = joinNotes([
    socket
      ? 'mounts the container runtime socket, which lets code inside the container control this whole machine'
      : undefined,
    hostRoot ? 'mounts the entire host filesystem into the container' : undefined,
    privileged ? 'runs the container with full host privileges' : undefined,
    dangerousCap ? 'grants the container extra kernel capabilities' : undefined,
    unconfined ? 'turns off the container security profile' : undefined,
    hostNamespace ? 'shares a host namespace, so the container can see host processes' : undefined,
    devices ? 'hands a host device through to the container' : undefined,
    writableOutside ? 'mounts a directory from outside the project that the container can write to' : undefined,
    secretMount ? 'mounts a directory that holds credentials' : undefined,
    readOnlyOutside ? 'mounts a directory from outside the project read-only' : undefined,
    hostNetwork ? 'shares the host network instead of an isolated one' : undefined,
    !escapes && !hostNetwork && !readOnlyOutside
      ? verb === 'exec'
        ? 'runs a command inside a running container'
        : 'runs a container, whose image contents are not visible here'
      : undefined,
  ]);

  return {
    capability: 'exec.container',
    reach: 'machine',
    // Host networking is not an escape by itself, but it does let the container
    // reach services that only listen on localhost, so it is not a plain run.
    reversibility: escapes ? 'irreversible' : hostNetwork ? 'hard' : 'easy',
    exposure: secretMount ? 'reads-secrets' : undefined,
    // Once the container can touch the host, argv no longer bounds the effect —
    // but neither does it for a plain `run`/`exec`, where the code is the image's
    // entrypoint or a command interpreted inside a container we cannot see.
    // Only `create`, which starts nothing, is bounded by what is written here.
    opaque: escapes || verb !== 'create',
    note,
    pathArgs: 'none',
    targets,
  };
}

function containerCopyJudgement(rest: Positional[], ctx: KnowledgeCtx): Judgement {
  // `name:/path` is a container reference; `C:\path` is not, so require the
  // part before the colon to be longer than a drive letter.
  const isContainerRef = (s: string) => /^[^:\\/]{2,}:[\\/]/.test(s);
  const src = rest[0]?.value ?? '';
  const dst = rest[1]?.value ?? '';

  if (src && isContainerRef(src)) {
    const abs = ctx.resolve(dst);
    const inside = abs ? ctx.inWorkspace(abs) : false;
    return {
      capability: inside ? 'fs.write.workspace' : 'fs.write.outside',
      reach: inside ? 'workspace' : 'machine',
      note: 'copies files out of a container onto this machine',
      targets: abs ? [{ type: 'path', value: abs, inWorkspace: inside }] : [],
    };
  }

  const abs = ctx.resolve(src);
  const secret = abs ? ctx.isSecret(abs) : false;
  return {
    capability: secret ? 'secret.read' : 'exec.container',
    exposure: secret ? 'reads-secrets' : undefined,
    note: secret
      ? 'copies a credential file into a container'
      : 'copies files from this machine into a container',
    targets: abs ? [{ type: 'path', value: abs, inWorkspace: ctx.inWorkspace(abs), secret }] : [],
  };
}

function containerRemoveJudgement(argv: string[], noun: string, verb: string, count: number): Judgement {
  if (noun === 'volume') {
    // A volume is where a container keeps the data it was supposed to keep:
    // databases, uploads, caches. Removing it is not a rebuild away.
    return {
      capability: 'fs.delete',
      reach: 'machine',
      reversibility: 'irreversible',
      scale: count > 1 ? 'many' : 'single',
      note: 'deletes a container volume along with all of the data stored in it',
      pathArgs: 'none',
    };
  }
  if (verb === 'rmi' || noun === 'image') {
    return {
      capability: 'exec.container',
      reach: 'machine',
      reversibility: 'hard',
      scale: count > 1 ? 'many' : 'single',
      note: 'deletes images, which have to be rebuilt or downloaded again',
      pathArgs: 'none',
    };
  }
  // `docker rm -v` takes the container's anonymous volumes with it.
  const withVolumes = hasFlag(argv, '-v', '--volumes');
  return {
    capability: 'exec.container',
    reach: 'machine',
    reversibility: withVolumes ? 'irreversible' : 'hard',
    scale: count > 1 ? 'many' : 'single',
    note: withVolumes
      ? 'deletes containers and the volumes attached to them, destroying their data'
      : 'deletes containers',
    pathArgs: 'none',
  };
}

function containerPruneJudgement(argv: string[], noun: string): Judgement {
  const volumes = noun === 'volume' || hasFlag(argv, '--volumes');
  const all = hasFlag(argv, '-a', '--all');
  return {
    capability: volumes ? 'fs.delete' : 'exec.container',
    reach: 'machine',
    // Pruning volumes throws away persistent data in bulk with no undo.
    reversibility: volumes ? 'irreversible' : 'hard',
    scale: 'sweeping',
    note: volumes
      ? 'deletes unused volumes in bulk, destroying whatever data was in them'
      : all
        ? 'deletes every unused image, container, and network on this machine'
        : 'deletes unused containers, networks, and dangling images',
    pathArgs: 'none',
  };
}

function classifyLocalCluster(argv: string[], name: string, first: string, second: string): Judgement {
  if (first === 'delete') {
    return {
      capability: 'exec.container',
      reach: 'machine',
      reversibility: 'hard',
      scale: 'sweeping',
      note: 'deletes the local cluster along with everything running in it',
      pathArgs: 'none',
    };
  }
  if (first === 'create' || first === 'start') {
    return {
      capability: 'exec.container',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      note: 'starts a local cluster, which downloads images and runs containers on this machine',
      pathArgs: 'none',
    };
  }
  if (first === 'stop' || first === 'pause' || first === 'unpause') {
    return { capability: 'exec.container', reversibility: 'easy', note: 'stops a local cluster', pathArgs: 'none' };
  }
  if (first === 'ssh' || (name === 'minikube' && first === 'kubectl')) {
    return {
      capability: 'exec.container',
      reach: 'machine',
      opaque: true,
      note: 'runs a command inside the cluster virtual machine',
      pathArgs: 'none',
    };
  }
  if (first === 'load' || second === 'docker-image' || first === 'image') {
    return { capability: 'exec.container', reach: 'machine', note: 'loads an image into the local cluster' };
  }
  if (first === 'get' || first === 'status' || first === 'version' || first === 'profile' || first === 'ip' ||
    first === 'logs' || first === 'export-logs' || first === 'config') {
    return { capability: 'exec.inspect', note: 'reads local cluster state', pathArgs: 'none' };
  }
  return {
    capability: 'exec.container',
    opaque: true,
    note: 'runs a local cluster command that leastgrant does not recognise',
    pathArgs: 'none',
  };
}

function classifyCompose(argv: string[], ctx: KnowledgeCtx, verb: string, rest: Positional[]): Judgement {
  // The compose file itself is a real path worth surfacing.
  const files = collectFlagValues(argv, ['-f', '--file']);
  const fileTargets: Target[] = files.map((f) => {
    const abs = ctx.resolve(f);
    return { type: 'path', value: abs || f, inWorkspace: abs ? ctx.inWorkspace(abs) : false };
  });

  switch (verb) {
    case 'ps':
    case 'ls':
    case 'top':
    case 'logs':
    case 'config':
    case 'images':
    case 'port':
    case 'version':
    case 'events':
      return { capability: 'exec.inspect', note: 'reads the state of the compose services', targets: fileTargets };

    case 'build':
      return {
        capability: 'exec.build',
        reach: 'machine',
        scale: 'many',
        note: 'builds the images for the compose services',
        targets: fileTargets,
      };

    case 'pull':
      return { capability: 'exec.container', reach: 'network', note: 'downloads the images for the compose services', targets: fileTargets };

    case 'push':
      return {
        capability: 'exec.pkg.publish',
        reach: 'external',
        reversibility: 'irreversible',
        note: 'publishes the compose images to a remote registry',
        targets: fileTargets,
      };

    case 'up':
    case 'start':
    case 'restart': {
      // Each service can carry its own mounts and privileges inside the compose
      // file, which we do not read, so the reach is the machine and the detail
      // is unknowable from argv.
      const j = containerRunJudgement(argv, ctx, 'run');
      return {
        capability: 'exec.container',
        reach: 'machine',
        reversibility: j.reversibility === 'irreversible' ? 'irreversible' : 'easy',
        scale: 'many',
        opaque: true,
        note: joinNotes([
          'starts the services defined in the compose file',
          'their mounts and privileges come from that file, not from this command',
        ]),
        targets: [...fileTargets, ...(j.targets ?? [])],
      };
    }

    case 'run':
    case 'exec': {
      const j = containerRunJudgement(argv, ctx, verb);
      return { ...j, targets: [...fileTargets, ...(j.targets ?? [])] };
    }

    case 'stop':
    case 'pause':
    case 'unpause':
    case 'kill':
      return { capability: 'exec.container', reversibility: 'easy', note: 'stops the compose services', targets: fileTargets };

    case 'down': {
      const withVolumes = hasFlag(argv, '-v', '--volumes');
      return {
        capability: withVolumes ? 'fs.delete' : 'exec.container',
        reach: 'machine',
        reversibility: withVolumes ? 'irreversible' : 'hard',
        scale: 'many',
        note: withVolumes
          ? 'stops the services and deletes their volumes, destroying the data in them'
          : 'stops and removes the compose services',
        targets: fileTargets,
      };
    }

    case 'rm':
      return {
        capability: 'exec.container',
        reach: 'machine',
        reversibility: 'hard',
        scale: 'many',
        note: 'removes the stopped compose containers',
        targets: fileTargets,
      };

    default:
      return {
        capability: 'exec.container',
        opaque: true,
        note: 'runs a compose command that leastgrant does not recognise',
        targets: fileTargets,
      };
  }
}

// ---------------------------------------------------------------------------
// 2. Databases
// ---------------------------------------------------------------------------

/** Flags whose value is a statement to execute. */
const SQL_FLAGS: Record<string, string[]> = {
  psql: ['-c', '--command'],
  mysql: ['-e', '--execute'],
  mariadb: ['-e', '--execute'],
  sqlcmd: ['-Q', '-q', '--query'],
  'clickhouse-client': ['-q', '--query'],
  cqlsh: ['-e', '--execute'],
  mongosh: ['--eval'],
  mongo: ['--eval'],
  cockroach: ['-e', '--execute'],
  influx: ['-e', '--execute'],
  'redis-cli': [],
  sqlite3: [],
};

/** Flags naming a file full of statements we cannot see. */
const SQL_FILE_FLAGS: Record<string, string[]> = {
  psql: ['-f', '--file'],
  mysql: [],
  mariadb: [],
  sqlcmd: ['-i', '--input-file'],
  'clickhouse-client': ['--queries-file'],
  cqlsh: ['-f', '--file'],
  mongosh: ['--file'],
  mongo: [],
  cockroach: ['-f', '--file'],
  influx: [],
  'redis-cli': ['--eval'],
  sqlite3: ['-init'],
};

/** Flags naming the server, per client. */
const HOST_FLAGS = ['-h', '--host', '-H', '--hostname', '-S', '--server', '--uri', '--connect'];
/** Flags naming the database or namespace. */
const DB_FLAGS = ['-d', '--dbname', '-D', '--database', '--db', '-k', '--keyspace', '-b', '--bucket'];

type SqlEffect = 'read' | 'write' | 'destructive' | 'unknown';

const SQL_DESTRUCTIVE = /\b(drop|truncate|delete|update|alter|grant|revoke|rename|purge|flushall|flushdb|shutdown|reset)\b/i;
const SQL_WRITE = /\b(insert|create|replace|upsert|merge|copy|load|import|call|do|refresh|reindex|vacuum|commit|begin|set)\b/i;
const SQL_READ = /\b(select|with|show|explain|describe|desc|list|pragma|count|analyze|values|table)\b/i;

/**
 * What does this statement text do? Verb matching is deliberately greedy in the
 * dangerous direction: `select 'drop' as x` will be read as destructive, which
 * costs one confirmation, while the reverse would be a silent data loss.
 */
function sqlEffect(text: string): SqlEffect {
  if (!text.trim()) return 'unknown';
  if (SQL_DESTRUCTIVE.test(text)) return 'destructive';
  if (SQL_WRITE.test(text)) return 'write';
  if (SQL_READ.test(text)) return 'read';
  return 'unknown';
}

/** JavaScript sent to mongo is classified on the collection method it calls. */
function mongoEffect(text: string): SqlEffect {
  if (/\b(drop|dropdatabase|dropindex|dropindexes|deletemany|deleteone|remove|updatemany|updateone|replaceone|renamecollection|bulkwrite|findandmodify|shutdownserver)\b/i.test(text)) {
    return 'destructive';
  }
  if (/\b(insertone|insertmany|insert|save|createindex|createcollection|createuser|bulkinsert)\b/i.test(text)) {
    return 'write';
  }
  if (/\b(find|findone|count|countdocuments|estimateddocumentcount|aggregate|distinct|stats|listcollections|getcollectionnames|getcollectioninfos|explain|hello|ismaster|serverstatus|version)\b/i.test(text)) {
    return 'read';
  }
  return 'unknown';
}

/** Redis commands, grouped by what they do to the keyspace. */
const REDIS_DESTRUCTIVE = new Set([
  'flushall', 'flushdb', 'del', 'unlink', 'shutdown', 'rename', 'renamenx', 'expire', 'pexpire',
  'migrate', 'swapdb', 'failover', 'replicaof', 'slaveof', 'debug', 'reset', 'script', 'persist',
  // Removing part of a value is still removing data, whatever the type is.
  'hdel', 'srem', 'zrem', 'lrem', 'lpop', 'rpop', 'spop', 'ltrim', 'xdel', 'xtrim', 'getdel',
  'move', 'acl', 'client', 'cluster', 'bgrewriteaof',
]);
/**
 * Commands that run code inside the server rather than touch one key: a lua
 * script or a loaded module can do anything the server itself can do, so the
 * command name tells us nothing about the effect.
 */
const REDIS_SCRIPTING = new Set([
  'eval', 'eval_ro', 'evalsha', 'evalsha_ro', 'fcall', 'fcall_ro', 'function', 'script', 'module',
]);
const REDIS_WRITE = new Set([
  'set', 'setex', 'setnx', 'mset', 'append', 'incr', 'incrby', 'decr', 'decrby', 'hset', 'hmset',
  'lpush', 'rpush', 'sadd', 'zadd', 'xadd', 'copy', 'restore', 'publish', 'setrange', 'getset',
]);

interface Conn {
  host?: string;
  database?: string;
  password: boolean;
  raw: string;
}

/** Pull the server, database, and any inline credential out of argv. */
function connectionOf(argv: string[], name: string): Conn {
  const args = argv.slice(1);
  const raw = args.join(' ');
  let host: string | undefined;
  let database: string | undefined;

  for (const a of args) {
    if (/^(postgres|postgresql|mysql|mariadb|mongodb(\+srv)?|redis|rediss|clickhouse|cockroachdb|influxdb|cassandra)(:\/\/)/i.test(a) ||
      /^jdbc:[a-z0-9]+:/i.test(a)) {
      host = hostOf(a.replace(/^jdbc:/i, '')) ?? host;
      const path = a.split('://')[1]?.split('/')[1];
      if (path) database = path.split('?')[0];
    }
  }

  host = flagValue(argv, ...HOST_FLAGS) ?? host;
  database = flagValue(argv, ...DB_FLAGS) ?? database;

  // psql and mysql both take a bare database name as a positional.
  if (!database && (name === 'psql' || name === 'mysql' || name === 'mariadb')) {
    const pos = positionals(argv, [...HOST_FLAGS, ...DB_FLAGS, '-U', '--username', '-u', '--user', '-P', '--port', '-p', ...(SQL_FLAGS[name] ?? []), ...(SQL_FILE_FLAGS[name] ?? [])]);
    const cand = pos[0]?.value;
    if (cand && !cand.includes('://')) database = cand;
  }
  // cqlsh takes host and port as positionals.
  if (!host && name === 'cqlsh') {
    const pos = positionals(argv, ['-u', '--username', '-p', '--password', '-k', '--keyspace', '-e', '--execute', '-f', '--file']);
    host = pos[0]?.value;
  }

  // A password sitting in argv is visible to anything that can list processes.
  const password = args.some((a) => {
    if (/^--password=./.test(a)) return true;
    if (/:\/\/[^/@\s]+:[^/@\s]+@/.test(a)) return true; // user:pass@host in a uri
    if ((name === 'mysql' || name === 'mariadb') && /^-p.+/.test(a)) return true;
    if (name === 'sqlcmd' && /^-P.+/.test(a)) return true;
    if (name === 'redis-cli' && /^-a.+/.test(a)) return true;
    return false;
  });

  return { host, database, password, raw };
}

/** Where does this connection land: local box, someone else's system, or prod? */
function dbReach(conn: Conn): 'machine' | 'external' | 'production' | undefined {
  const scope = [conn.host ?? '', conn.database ?? ''].join(' ');
  if (looksProduction(scope)) return 'production';
  if (conn.host) return isLocalHost(conn.host) ? 'machine' : 'external';
  // No host in argv: it comes from the environment or a config file. Leave it
  // unset so the capability default (external) applies rather than guessing local.
  return undefined;
}

function classifyDbClient(argv: string[], ctx: KnowledgeCtx, name: string): Judgement {
  if (name === 'sqlite3') return classifySqlite(argv, ctx);
  if (name === 'redis-cli') return classifyRedis(argv);
  if (name === 'influx') {
    const j = classifyInflux(argv);
    if (j) return j;
  }
  if (name === 'cockroach') {
    const j = classifyCockroach(argv);
    if (j) return j;
  }

  const conn = connectionOf(argv, name);
  const statements = collectFlagValues(argv, SQL_FLAGS[name] ?? []);
  const files = collectFlagValues(argv, SQL_FILE_FLAGS[name] ?? []);
  const text = statements.join('; ');

  // `psql -c '\! rm -rf /'` runs a shell command; psql is not only a client.
  // `copy t to program '...'` does the same thing on the server, which is worse.
  if (/\\!/.test(text) || /\bsystem\s*\(/i.test(text) || /\b(to|from)\s+program\b/i.test(text)) {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'the database client is being asked to run a shell command',
      pathArgs: 'none',
    };
  }

  let effect: SqlEffect;
  let opaque = false;
  let what: string;
  if (files.length > 0) {
    // A script file's statements are not in argv, so anything could be in it.
    effect = 'unknown';
    opaque = true;
    what = 'runs a script file against the database, whose statements are not visible here';
  } else if (text.trim()) {
    effect = name === 'mongo' || name === 'mongosh' ? mongoEffect(text) : sqlEffect(text);
    what =
      effect === 'read' ? 'reads from the database'
        : effect === 'write' ? 'writes new rows to the database'
          : effect === 'destructive' ? 'changes or removes data that is already in the database'
            : 'runs a statement whose effect leastgrant could not determine';
    if (effect === 'unknown') opaque = true;
  } else {
    effect = 'unknown';
    opaque = true;
    what = 'opens an interactive database session, where anything can be typed';
  }

  // `select ... into outfile '/var/www/x'` reads like a query and writes a file
  // on the server with the server's privileges. Same for lo_export.
  if (/\binto\s+(outfile|dumpfile)\b/i.test(text) || /\blo_export\b/i.test(text)) {
    if (effect === 'read' || effect === 'unknown') {
      effect = 'write';
      what = 'writes a file on the database server out of the query result';
    }
  }

  // An unqualified DELETE or UPDATE takes the whole table with it.
  const unqualified = effect === 'destructive' &&
    /\b(delete\s+from|update)\b/i.test(text) && !/\bwhere\b/i.test(text);

  const reach = dbReach(conn);
  const targets: Target[] = [];
  if (conn.host) targets.push({ type: 'host', value: conn.host });
  if (conn.database) targets.push({ type: 'service', value: conn.database });

  return {
    capability: 'exec.db',
    reach,
    reversibility:
      effect === 'read' ? 'trivial'
        : effect === 'destructive' ? 'irreversible'
          : 'hard',
    exposure: conn.password ? 'reads-secrets' : undefined,
    scale: unqualified ? 'sweeping' : effect === 'read' ? 'single' : 'many',
    opaque,
    note: joinNotes([
      what,
      unqualified ? 'with no condition, so it affects every row in the table' : undefined,
      reach === 'production' ? 'against something named like production' : undefined,
      conn.password ? 'with a password in the command line' : undefined,
    ]),
    pathArgs: files.length > 0 ? 'auto' : 'none',
    targets,
  };
}

/**
 * sqlite3 is a library with a prompt attached: the "server" is a file. A
 * destructive statement against a file in the repo is a git checkout away from
 * being fixed, which is a very different proposition from a remote server.
 */
function classifySqlite(argv: string[], ctx: KnowledgeCtx): Judgement {
  const pos = positionals(argv, ['-init', '-cmd', '-separator', '-nullvalue']);
  const dbArg = pos[0];
  const sql = pos.slice(1).map((p) => p.value).join('; ') + ' ' + collectFlagValues(argv, ['-cmd']).join('; ');
  const abs = dbArg ? ctx.resolve(dbArg.value) : '';
  const inside = abs ? ctx.inWorkspace(abs) : false;
  const inMemory = !dbArg || dbArg.value === ':memory:';

  // The dot-commands are not sql and are not bounded by the database file:
  // `.shell`/`.system`/`.excel` run a program, `.load` loads a native extension,
  // and `.output`/`.backup`/`.restore` read and write files anywhere on disk.
  if (/(^|[\s;'"])\.(shell|system|excel|load|import|output|once|backup|restore|save|clone)\b/i.test(sql)) {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'the sqlite shell is being asked to run a program, load an extension, or read and write files outside the database',
      pathArgs: 'none',
    };
  }

  const effect = sql.trim() ? sqlEffect(sql) : 'unknown';
  const interactive = !sql.trim();

  return {
    capability: 'exec.db',
    reach: inMemory ? 'none' : inside ? 'workspace' : 'machine',
    reversibility:
      effect === 'read' || inMemory ? 'trivial'
        : effect === 'destructive' ? (inside ? 'hard' : 'irreversible')
          : 'easy',
    scale: effect === 'destructive' ? 'many' : 'single',
    opaque: interactive || effect === 'unknown',
    note: joinNotes([
      interactive
        ? 'opens an interactive session against a database file'
        : effect === 'destructive'
          ? 'changes or removes data in a database file'
          : effect === 'read'
            ? 'reads from a database file'
            : 'runs a statement against a database file',
      !inMemory && !inside ? 'that lives outside the project' : undefined,
    ]),
    pathArgs: dbArg && !inMemory ? [dbArg.index] : 'none',
    targets: abs && !inMemory ? [{ type: 'path', value: abs, inWorkspace: inside }] : [],
  };
}

function classifyRedis(argv: string[]): Judgement {
  const conn = connectionOf(argv, 'redis-cli');
  const reach = dbReach(conn) ?? 'machine';
  const targets: Target[] = conn.host ? [{ type: 'host', value: conn.host }] : [];

  if (hasFlag(argv, '--eval')) {
    // A Lua script runs server-side and can do anything the server can.
    return {
      capability: 'exec.db',
      reach,
      reversibility: 'hard',
      opaque: true,
      note: 'runs a lua script inside the redis server',
      targets,
    };
  }

  const pos = positionals(argv, ['-h', '--host', '-p', '--port', '-a', '--pass', '--user', '-n', '--socket', '-t']);
  const cmd = pos[0]?.value?.toLowerCase();
  if (!cmd) {
    return {
      capability: 'exec.db',
      reach,
      opaque: true,
      note: 'opens an interactive redis session, where anything can be typed',
      pathArgs: 'none',
      targets,
    };
  }

  const sub = pos[1]?.value?.toLowerCase() ?? '';

  if (REDIS_SCRIPTING.has(cmd)) {
    return {
      capability: 'exec.db',
      reach,
      reversibility: 'hard',
      exposure: conn.password ? 'reads-secrets' : undefined,
      opaque: true,
      note: joinNotes([
        'runs a lua script or loads a module inside the redis server, which can do anything the server can',
        conn.password ? 'with a password in the command line' : undefined,
      ]),
      pathArgs: 'none',
      targets,
    };
  }

  const wipes = cmd === 'flushall' || cmd === 'flushdb';
  const destructive = REDIS_DESTRUCTIVE.has(cmd) ||
    (cmd === 'config' && (sub === 'set' || sub === 'rewrite' || sub === 'resetstat'));
  const write = REDIS_WRITE.has(cmd);
  // `config get requirepass` prints the server's password back at you.
  const configRead = cmd === 'config' && sub === 'get';

  return {
    capability: 'exec.db',
    reach,
    reversibility: destructive ? 'irreversible' : write ? 'hard' : 'trivial',
    exposure: conn.password || configRead ? 'reads-secrets' : undefined,
    scale: wipes ? 'sweeping' : 'single',
    note: joinNotes([
      configRead
        ? 'reads the redis server configuration, which includes its password'
        : wipes
          ? 'erases every key in the redis database at once'
          : destructive
            ? 'removes or reconfigures data in redis'
            : write
              ? 'writes a key in redis'
              : 'reads from redis',
      conn.password ? 'with a password in the command line' : undefined,
    ]),
    pathArgs: 'none',
    targets,
  };
}

function classifyInflux(argv: string[]): Judgement | null {
  const words = positionals(argv, ['--host', '-t', '--token', '-o', '--org', '-b', '--bucket', '-c', '--active-config']);
  const verb = words[0]?.value?.toLowerCase();
  const sub = words[1]?.value?.toLowerCase();
  if (!verb) return null;
  const conn = connectionOf(argv, 'influx');
  const reach = dbReach(conn);

  if (verb === 'query' || verb === 'export' || (verb === 'bucket' && sub === 'list')) {
    return { capability: 'exec.db', reach, reversibility: 'trivial', note: 'reads time series data', pathArgs: 'none' };
  }
  if (verb === 'write') {
    return { capability: 'exec.db', reach, reversibility: 'hard', note: 'writes time series data', pathArgs: 'none' };
  }
  if (verb === 'delete' || sub === 'delete') {
    return {
      capability: 'exec.db',
      reach,
      reversibility: 'irreversible',
      scale: 'many',
      note: 'deletes time series data, which cannot be recovered',
      pathArgs: 'none',
    };
  }
  return null;
}

function classifyCockroach(argv: string[]): Judgement | null {
  const words = positionals(argv, ['--host', '--url', '--certs-dir', '-e', '--execute', '-d', '--database']);
  const verb = words[0]?.value?.toLowerCase();
  if (!verb) return null;
  if (verb === 'sql') return null; // handled by the generic statement path
  if (verb === 'start' || verb === 'start-single-node') {
    return {
      capability: 'exec.db',
      reach: 'machine',
      reversibility: 'easy',
      note: 'starts a database server on this machine and listens for connections',
      pathArgs: 'none',
    };
  }
  if (verb === 'node' || verb === 'quit' || verb === 'drain') {
    return {
      capability: 'exec.db',
      reach: 'external',
      reversibility: 'hard',
      note: 'changes cluster membership, which affects everything connected to it',
      pathArgs: 'none',
    };
  }
  return null;
}

// --- migration tools -------------------------------------------------------

function classifyMigrator(argv: string[], name: string): Judgement {
  const words = positionals(argv, ['--schema', '--config', '-c', '--url', '--name', '-m', '--message', '-n', '--env', '--changelog-file']);
  const verb = (words[0]?.value ?? '').toLowerCase();
  const sub = (words[1]?.value ?? '').toLowerCase();
  const all = argv.slice(1).join(' ');

  // Migration tools take their connection from an env var or a config file far
  // more often than from argv, so say so instead of pretending it is local.
  const production = looksProduction(all) ? ('production' as const) : undefined;
  const password = /(-{1,2}password=|:\/\/[^/@\s]+:[^/@\s]+@)/i.test(all);
  const hidden = !/(--url|--uri|-h\b|--host|--connection)/i.test(all);
  const envNote = hidden ? 'against whichever database the environment points at' : undefined;
  const pwNote = password ? 'with a password in the command line' : undefined;

  const destructive = (note: string, scale: 'many' | 'sweeping' = 'sweeping'): Judgement => ({
    capability: 'exec.db',
    reach: production ?? 'external',
    reversibility: 'irreversible',
    scale,
    exposure: password ? 'reads-secrets' : undefined,
    note: joinNotes([note, envNote, pwNote]),
    pathArgs: 'none',
  });
  const applies = (note: string): Judgement => ({
    capability: 'exec.db',
    reach: production ?? 'external',
    reversibility: 'hard',
    scale: 'many',
    exposure: password ? 'reads-secrets' : undefined,
    note: joinNotes([note, envNote, pwNote]),
    pathArgs: 'none',
  });
  const reads = (note: string): Judgement => ({
    capability: 'exec.db',
    reach: production ?? undefined,
    reversibility: 'trivial',
    scale: 'single',
    note: joinNotes([note, envNote]),
    pathArgs: 'none',
  });
  const writesFiles = (note: string): Judgement => ({
    capability: 'fs.write.workspace',
    scale: 'many',
    note,
  });

  switch (name) {
    case 'prisma': {
      if (verb === 'generate' || verb === 'format' || verb === 'validate') {
        return writesFiles('generates or checks the prisma client and schema files');
      }
      if (verb === 'studio') {
        return {
          capability: 'exec.db',
          reach: production ?? undefined,
          reversibility: 'hard',
          note: joinNotes(['opens a local web page that can browse and edit the database', envNote]),
          pathArgs: 'none',
        };
      }
      if (verb === 'migrate') {
        if (sub === 'reset') {
          return destructive('drops the database and rebuilds it from the migrations, destroying every row in it');
        }
        if (sub === 'status' || sub === 'diff') return reads('compares the migrations with the database');
        if (sub === 'resolve') return applies('marks a migration as applied without running it');
        return applies('applies pending migrations, which change the database schema');
      }
      if (verb === 'db') {
        if (sub === 'push') {
          return hasFlag(argv, '--accept-data-loss') || hasFlag(argv, '--force-reset')
            ? destructive('pushes the schema and has been told to accept dropping columns or tables that no longer match')
            : applies('pushes the schema straight to the database without a migration file');
        }
        if (sub === 'pull') return writesFiles('reads the database schema into the prisma schema file');
        if (sub === 'seed') return applies('inserts seed data into the database');
        if (sub === 'execute') {
          return {
            capability: 'exec.db',
            reach: production ?? 'external',
            reversibility: 'hard',
            opaque: true,
            note: joinNotes(['runs a sql script against the database, whose statements are not visible here', envNote]),
            pathArgs: 'auto',
          };
        }
      }
      break;
    }

    case 'drizzle-kit': {
      const v = verb.split(':')[0] ?? verb; // old syntax was `push:pg`
      if (v === 'generate' || v === 'introspect' || v === 'pull' || v === 'check' || v === 'up') {
        return writesFiles('generates or checks migration files in the project');
      }
      if (v === 'studio') {
        return {
          capability: 'exec.db',
          reach: production ?? undefined,
          reversibility: 'hard',
          note: joinNotes(['opens a local web page that can browse and edit the database', envNote]),
          pathArgs: 'none',
        };
      }
      if (v === 'drop') return destructive('removes a migration, which can leave the database and the history disagreeing', 'many');
      if (v === 'push' || v === 'migrate') return applies('applies schema changes directly to the database');
      break;
    }

    case 'sequelize': {
      if (verb.startsWith('db:migrate:undo') || verb === 'db:drop' || verb === 'db:seed:undo:all') {
        return destructive('rolls back or drops the database, which throws away the data in it');
      }
      if (verb === 'db:migrate') return applies('applies pending migrations to the database');
      if (verb === 'db:seed' || verb === 'db:seed:all') return applies('inserts seed data into the database');
      if (verb === 'db:create') return applies('creates the database');
      if (verb.startsWith('migration:') || verb.startsWith('model:') || verb.startsWith('seed:')) {
        return writesFiles('generates migration or model files in the project');
      }
      break;
    }

    case 'alembic': {
      if (verb === 'downgrade') {
        return destructive('runs the downgrade steps, which typically drop the columns and tables the upgrade added');
      }
      if (verb === 'upgrade' || verb === 'stamp') return applies('applies migrations to the database');
      if (verb === 'revision' || verb === 'merge') return writesFiles('creates a new migration file in the project');
      if (verb === 'history' || verb === 'current' || verb === 'show' || verb === 'heads' || verb === 'branches') {
        return reads('reads the migration history');
      }
      break;
    }

    case 'flyway': {
      // `flyway clean` drops every object in the configured schemas. It exists
      // for throwaway databases and is catastrophic anywhere else.
      if (verb === 'clean') {
        return destructive('drops every table, view, and routine in the configured schema, leaving it empty');
      }
      if (verb === 'undo') return destructive('undoes an applied migration, dropping what it created');
      if (verb === 'migrate' || verb === 'baseline' || verb === 'repair') {
        return applies('applies or rewrites the migration state of the database');
      }
      if (verb === 'info' || verb === 'validate') return reads('reads the migration state');
      break;
    }

    case 'liquibase': {
      if (verb === 'dropall') {
        return destructive('drops every object in the database, leaving it empty');
      }
      if (verb.startsWith('rollback')) return destructive('rolls the database back, dropping what the rolled-back changes created');
      if (verb === 'update' || verb === 'changelogsync' || verb === 'tag') {
        return applies('applies changesets to the database');
      }
      if (verb === 'status' || verb === 'history' || verb === 'diff' || verb.endsWith('sql') || verb === 'validate') {
        return reads('reads or previews the changesets without applying them');
      }
      break;
    }

    case 'knex': {
      if (verb === 'migrate:rollback' || verb === 'migrate:down') {
        return destructive('rolls back migrations, dropping what they created', 'many');
      }
      if (verb === 'migrate:latest' || verb === 'migrate:up' || verb === 'seed:run') {
        return applies('applies migrations or seed data to the database');
      }
      if (verb === 'migrate:make' || verb === 'seed:make' || verb === 'init') {
        return writesFiles('creates a migration or seed file in the project');
      }
      if (verb === 'migrate:status' || verb === 'migrate:currentversion' || verb === 'migrate:list') {
        return reads('reads the migration state');
      }
      break;
    }
  }

  // Unknown subcommand of a tool whose whole job is changing databases.
  return {
    capability: 'exec.db',
    reach: production ?? 'external',
    reversibility: 'hard',
    opaque: true,
    note: joinNotes(['runs a migration command that leastgrant does not recognise', envNote]),
    pathArgs: 'none',
  };
}

// ---------------------------------------------------------------------------
// 3. Process and system control
// ---------------------------------------------------------------------------

/**
 * The one note that should always make a developer stop and read. Persistence
 * means code that runs later, on a schedule or at boot or at login, with no
 * agent session around it and nobody watching the output.
 */
const PERSISTENCE = 'sets up code to run later on its own, outside any agent session';

function classifyProcess(argv: string[], ctx: KnowledgeCtx, name: string): Judgement {
  switch (name) {
    case 'kill':
    case 'killall':
    case 'pkill':
    case 'taskkill':
      return killJudgement(argv, name);

    case 'systemctl':
      return systemctlJudgement(argv);

    case 'service': {
      const words = nonFlags(argv);
      const action = (words[1] ?? words[0] ?? '').toLowerCase();
      if (action === 'status') return { capability: 'exec.inspect', note: 'reads the state of a system service', pathArgs: 'none' };
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: action === 'stop' ? 'hard' : 'easy',
        note: action === 'stop' ? 'stops a system service that other things may depend on' : 'restarts a system service',
        pathArgs: 'none',
      };
    }

    case 'launchctl': {
      const words = nonFlags(argv);
      const verb = (words[0] ?? '').toLowerCase();
      // load/bootstrap/enable install a job that macOS starts at login or boot.
      if (verb === 'load' || verb === 'bootstrap' || verb === 'enable' || verb === 'submit') {
        return {
          capability: 'exec.process',
          reach: 'machine',
          reversibility: 'hard',
          note: joinNotes(['registers a launch job', PERSISTENCE]),
        };
      }
      if (verb === 'list' || verb === 'print' || verb === 'print-disabled' || verb === 'dumpstate') {
        return { capability: 'exec.inspect', note: 'lists launch jobs', pathArgs: 'none' };
      }
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: 'hard',
        note: 'changes which launch jobs are running on this machine',
      };
    }

    case 'sc': {
      const words = nonFlags(argv);
      const verb = (words[0] ?? '').toLowerCase();
      if (verb === 'create' || verb === 'config') {
        return {
          capability: 'exec.privilege',
          reach: 'machine',
          reversibility: 'hard',
          note: joinNotes(['installs or reconfigures a windows service', PERSISTENCE]),
          pathArgs: 'none',
        };
      }
      if (verb === 'query' || verb === 'queryex' || verb === 'qc' || verb === 'showsid') {
        return { capability: 'exec.inspect', note: 'reads windows service state', pathArgs: 'none' };
      }
      if (verb === 'delete') {
        return {
          capability: 'exec.process',
          reach: 'machine',
          reversibility: 'hard',
          note: 'removes a windows service',
          pathArgs: 'none',
        };
      }
      return {
        capability: 'exec.process',
        reach: 'machine',
        note: 'starts or stops a windows service',
        pathArgs: 'none',
      };
    }

    case 'shutdown':
    case 'reboot':
    case 'halt':
    case 'poweroff': {
      // `shutdown /a` and `shutdown -c` cancel a pending shutdown instead. But
      // `-c` is the *comment* flag on Windows, so `shutdown -r -t 0 -c "bye"`
      // still reboots: only read `-c` as a cancel when nothing else acts.
      const acting = hasFlag(argv, '-r', '/r', '-s', '/s', '-h', '-H', '-P', '-p', '/p', '/g',
        '--reboot', '--halt', '--poweroff');
      if (hasFlag(argv, '/a', '/A', '--cancel') || (hasFlag(argv, '-c') && !acting)) {
        return { capability: 'exec.process', reach: 'machine', reversibility: 'trivial', note: 'cancels a pending shutdown', pathArgs: 'none' };
      }
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: 'hard',
        scale: 'sweeping',
        note: name === 'reboot' || hasFlag(argv, '-r', '/r')
          ? 'restarts this machine, ending everything running on it'
          : 'shuts this machine down, ending everything running on it',
        pathArgs: 'none',
      };
    }

    case 'mount':
    case 'umount': {
      const bare = nonFlags(argv).length === 0;
      if (name === 'mount' && bare) {
        return { capability: 'exec.inspect', note: 'lists the mounted filesystems', pathArgs: 'none' };
      }
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: name === 'mount'
          ? 'attaches a filesystem to this machine'
          : 'detaches a filesystem, which breaks anything reading or writing it',
      };
    }

    case 'fdisk': {
      if (hasFlag(argv, '-l', '--list') || hasFlag(argv, '-s')) {
        return { capability: 'exec.inspect', note: 'lists the partition tables', pathArgs: 'none' };
      }
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'rewrites a disk partition table, which can make everything on the disk unreachable',
      };
    }

    case 'diskutil': {
      const verb = (nonFlags(argv)[0] ?? '').toLowerCase();
      if (verb === 'list' || verb === 'info' || verb === 'activity' || verb === 'verifydisk' || verb === 'verifyvolume') {
        return { capability: 'exec.inspect', note: 'reads disk layout', pathArgs: 'none' };
      }
      if (verb.startsWith('erase') || verb === 'partitiondisk' || verb === 'reformat' || verb === 'zerodisk' ||
        verb === 'securityerase' || verb === 'apfs' || verb === 'splitpartition' || verb === 'resizevolume') {
        return {
          capability: 'exec.privilege',
          reach: 'machine',
          reversibility: 'irreversible',
          scale: 'sweeping',
          note: 'erases or repartitions a disk, destroying everything stored on it',
          pathArgs: 'none',
        };
      }
      return { capability: 'exec.privilege', reach: 'machine', reversibility: 'hard', note: 'changes disk configuration', pathArgs: 'none' };
    }

    case 'ifconfig':
    case 'ip': {
      const words = nonFlags(argv);
      const verb = (words[1] ?? '').toLowerCase();
      const changing = ['add', 'del', 'delete', 'change', 'replace', 'set', 'flush', 'up', 'down'].includes(verb) ||
        (name === 'ifconfig' && words.length > 1);
      if (!changing) {
        return { capability: 'exec.inspect', note: 'reads the network configuration', pathArgs: 'none' };
      }
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: 'changes how this machine is connected to the network',
        pathArgs: 'none',
      };
    }

    case 'iptables':
    case 'ip6tables': {
      // `-n` only means numeric output; it can ride along with a rule change, so
      // it must not be what makes a command look like a listing on its own.
      if (hasFlag(argv, '-L', '-S', '--list', '--list-rules', '-C', '--check')) {
        return { capability: 'exec.inspect', note: 'lists the firewall rules', pathArgs: 'none' };
      }
      const flushing = hasFlag(argv, '-F', '--flush', '-X', '--delete-chain');
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        scale: flushing ? 'sweeping' : 'single',
        note: flushing
          ? 'clears the firewall rules, which can leave this machine open to the network'
          : 'changes the firewall rules, which changes what can reach this machine',
        pathArgs: 'none',
      };
    }

    case 'ufw': {
      const verb = (nonFlags(argv)[0] ?? '').toLowerCase();
      if (verb === 'status' || verb === 'show' || verb === 'version') {
        return { capability: 'exec.inspect', note: 'reads the firewall state', pathArgs: 'none' };
      }
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        scale: verb === 'reset' || verb === 'disable' ? 'sweeping' : 'single',
        note: verb === 'disable' || verb === 'reset'
          ? 'turns the firewall off, which can leave this machine open to the network'
          : 'changes the firewall rules, which changes what can reach this machine',
        pathArgs: 'none',
      };
    }

    case 'netsh': {
      const words = nonFlags(argv).map((w) => w.toLowerCase());
      const reading = words.includes('show') || words.includes('dump');
      if (reading) return { capability: 'exec.inspect', note: 'reads the windows network configuration', pathArgs: 'none' };
      const firewall = words.includes('advfirewall') || words.includes('firewall');
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: firewall
          ? 'changes the windows firewall, which changes what can reach this machine'
          : 'changes the windows network configuration',
        pathArgs: 'none',
      };
    }

    case 'defaults': {
      const verb = (nonFlags(argv)[0] ?? '').toLowerCase();
      if (verb === 'read' || verb === 'read-type' || verb === 'domains' || verb === 'find') {
        return { capability: 'exec.inspect', note: 'reads a system preference', pathArgs: 'none' };
      }
      const all = argv.join(' ').toLowerCase();
      const login = all.includes('loginwindow') || all.includes('launchagents') || all.includes('autologin');
      return {
        capability: 'fs.write.outside',
        reach: 'machine',
        reversibility: 'hard',
        note: login
          ? joinNotes(['changes a login-time system preference', PERSISTENCE])
          : 'changes a system preference outside the project',
        pathArgs: 'none',
      };
    }

    case 'reg': {
      const verb = (nonFlags(argv)[0] ?? '').toLowerCase();
      if (verb === 'query' || verb === 'export' || verb === 'compare') {
        return { capability: 'exec.inspect', note: 'reads the windows registry', pathArgs: 'none' };
      }
      const all = argv.join(' ').toLowerCase();
      // Keys the system reads at boot or login to decide what to launch.
      const startup = /(currentversion\\+run|runonce|runservices|winlogon|userinit|shell\b|image file execution options|\\services\\)/.test(all);
      if (startup) {
        return {
          capability: 'exec.privilege',
          reach: 'machine',
          reversibility: 'hard',
          note: joinNotes(['writes a windows registry key that decides what runs at startup', PERSISTENCE]),
          pathArgs: 'none',
        };
      }
      return {
        capability: 'exec.privilege',
        reach: 'machine',
        reversibility: 'hard',
        note: verb === 'delete' ? 'deletes a windows registry key' : 'writes a windows registry key',
        pathArgs: 'none',
      };
    }

    case 'crontab': {
      if (hasFlag(argv, '-l')) {
        return { capability: 'exec.inspect', note: 'lists the scheduled cron jobs', pathArgs: 'none' };
      }
      if (hasFlag(argv, '-r')) {
        return {
          capability: 'exec.process',
          reach: 'machine',
          reversibility: 'irreversible',
          scale: 'sweeping',
          note: 'deletes every cron job for this user, with no copy kept',
          pathArgs: 'none',
        };
      }
      const file = nonFlags(argv)[0];
      const abs = file ? ctx.resolve(file) : '';
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: 'hard',
        note: joinNotes(['installs a cron schedule', PERSISTENCE]),
        targets: abs ? [{ type: 'path', value: abs, inWorkspace: ctx.inWorkspace(abs) }] : [],
      };
    }

    case 'at': {
      if (hasFlag(argv, '-l')) return { capability: 'exec.inspect', note: 'lists the queued jobs', pathArgs: 'none' };
      return {
        capability: 'exec.process',
        reach: 'machine',
        reversibility: 'hard',
        opaque: true,
        note: joinNotes(['queues a command to run at a later time', PERSISTENCE]),
        pathArgs: 'none',
      };
    }

    case 'schtasks': {
      // Match each verb as a whole argument and check the writing ones first: a
      // task named `/query` must not make `schtasks /create` read like a listing.
      const words = argv.slice(1).map((a) => a.toLowerCase());
      const said = (verb: string) => words.some((w) => w === verb || w.startsWith(verb + ':'));
      if (said('/create') || said('/change')) {
        return {
          capability: 'exec.process',
          reach: 'machine',
          reversibility: 'hard',
          opaque: true,
          note: joinNotes(['creates a windows scheduled task', PERSISTENCE]),
          pathArgs: 'none',
        };
      }
      if (said('/delete')) {
        return { capability: 'exec.process', reach: 'machine', reversibility: 'hard', note: 'deletes a windows scheduled task', pathArgs: 'none' };
      }
      if (said('/query')) {
        return { capability: 'exec.inspect', note: 'lists the windows scheduled tasks', pathArgs: 'none' };
      }
      return { capability: 'exec.process', reach: 'machine', opaque: true, note: 'runs or changes a windows scheduled task', pathArgs: 'none' };
    }

    default:
      // Every mkfs.* variant lands here, and all of them format a filesystem.
      if (name.startsWith('mkfs')) {
        return {
          capability: 'exec.privilege',
          reach: 'machine',
          reversibility: 'irreversible',
          scale: 'sweeping',
          note: 'formats a disk or partition, destroying everything already on it',
        };
      }
      return { capability: 'exec.process', reach: 'machine', opaque: true, note: 'changes the state of this machine', pathArgs: 'none' };
  }
}

function killJudgement(argv: string[], name: string): Judgement {
  const all = argv.slice(1).join(' ');
  const force = hasFlag(argv, '-9', '-KILL', '-SIGKILL', '/F', '/f', '-f') || /\b-9\b/.test(all);
  // `kill -1`, `pkill -f .` and `taskkill /F /IM *` reach far beyond one process.
  const everything = /(^|\s)-1(\s|$)/.test(all) || /(^|\s)\*(\s|$)/.test(all);
  const byPattern = name === 'pkill' || name === 'killall' || hasFlag(argv, '-f', '/IM', '/im');

  return {
    capability: 'exec.process',
    reach: 'machine',
    // A killed process can be started again; what it was doing may not survive.
    //
    // 'hard' rather than 'easy' even for a single target, because the *identity*
    // is unlearnable: a pid is a number, so `kill 123` and `kill 1` normalise to
    // the same signature, and no amount of approving one says anything about the
    // other. Keeping it above the promotable band is the honest way to express
    // "this cannot be learned" — the alternative, refusing to normalise the pid,
    // would give every kill its own signature and never settle either.
    reversibility: 'hard',
    scale: everything ? 'sweeping' : byPattern ? 'many' : 'single',
    note: joinNotes([
      everything
        ? 'signals every process it can reach, which can log this session out'
        : byPattern
          ? 'kills every process whose name or command line matches, which may be more than intended'
          : 'stops a running process',
      force ? 'without letting it shut down cleanly' : undefined,
    ]),
    pathArgs: 'none',
  };
}

function systemctlJudgement(argv: string[]): Judgement {
  const words = nonFlags(argv);
  const verb = (words[0] ?? '').toLowerCase();
  const unit = words[1];
  const targets: Target[] = unit ? [{ type: 'service', value: unit }] : [];

  if (['status', 'list-units', 'list-unit-files', 'show', 'cat', 'is-active', 'is-enabled',
    'is-failed', 'list-timers', 'list-sockets', 'list-dependencies', 'get-default'].includes(verb)) {
    return { capability: 'exec.inspect', note: 'reads the state of a system service', pathArgs: 'none', targets };
  }
  if (verb === 'poweroff' || verb === 'reboot' || verb === 'halt' || verb === 'suspend' || verb === 'hibernate') {
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'hard',
      scale: 'sweeping',
      note: 'shuts this machine down or restarts it, ending everything running on it',
      pathArgs: 'none',
    };
  }
  if (verb === 'enable') {
    // Enabling a unit is how a service comes back after every reboot.
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'hard',
      note: joinNotes(['makes a service start automatically at boot', PERSISTENCE]),
      pathArgs: 'none',
      targets,
    };
  }
  if (verb === 'disable' || verb === 'mask') {
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'hard',
      note: 'stops a service from starting at boot, so it will not come back on its own',
      pathArgs: 'none',
      targets,
    };
  }
  if (verb === 'stop' || verb === 'kill') {
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'hard',
      note: 'stops a system service that other things on this machine may depend on',
      pathArgs: 'none',
      targets,
    };
  }
  if (verb === 'start' || verb === 'restart' || verb === 'reload' || verb === 'daemon-reload' || verb === 'try-restart') {
    return {
      capability: 'exec.process',
      reach: 'machine',
      reversibility: 'easy',
      note: 'starts or restarts a system service',
      pathArgs: 'none',
      targets,
    };
  }
  return {
    capability: 'exec.process',
    reach: 'machine',
    opaque: true,
    note: 'runs a service manager command that leastgrant does not recognise',
    pathArgs: 'none',
    targets,
  };
}

// ---------------------------------------------------------------------------
// 4. Interpreters
// ---------------------------------------------------------------------------

/** Flags that swallow the next argument, so it is not the script name. */
const INTERPRETER_VALUE_FLAGS: Record<string, string[]> = {
  python: ['-c', '-m', '-W', '-X', '--check-hash-based-pycs'],
  python2: ['-c', '-m', '-W', '-X'],
  python3: ['-c', '-m', '-W', '-X', '--check-hash-based-pycs'],
  node: ['-e', '--eval', '-p', '--print', '-r', '--require', '--import', '--loader', '--experimental-loader', '--max-old-space-size', '--conditions'],
  // Deno's permission flags only take a value in `--allow-read=x` form, so they
  // must not be listed here: doing so eats the script name that follows them.
  deno: ['--config', '-c', '--import-map', '--lock', '--cert', '--v8-flags', '--inspect-wait'],
  ruby: ['-e', '-r', '-I', '-C', '-F'],
  php: ['-r', '-d', '-c', '-S', '-t', '-B', '-R', '-E', '-F'],
  rscript: ['-e', '--vanilla-e'],
  julia: ['-e', '--eval', '-E', '-L', '--load', '-p', '--project', '-J'],
  lua: ['-e', '-l'],
  osascript: ['-e', '-l', '-s'],
  powershell: ['-Command', '-c', '-EncodedCommand', '-File', '-f', '-ExecutionPolicy', '-ep', '-WindowStyle', '-w', '-InputFormat', '-OutputFormat', '-Version'],
  pwsh: ['-Command', '-c', '-EncodedCommand', '-File', '-f', '-ExecutionPolicy', '-ep', '-WindowStyle', '-w', '-InputFormat', '-OutputFormat', '-Version'],
  cmd: ['/c', '/C', '/k', '/K'],
  wscript: ['//e', '//E'],
  cscript: ['//e', '//E'],
};

/** Inline-code flags, per interpreter. Any of these means unreadable code. */
const INLINE_FLAGS: Record<string, string[]> = {
  python: ['-c'],
  python2: ['-c'],
  python3: ['-c'],
  node: ['-e', '--eval', '-p', '--print'],
  deno: [],
  ruby: ['-e'],
  php: ['-r', '-B', '-R', '-F', '-E'],
  rscript: ['-e'],
  julia: ['-e', '--eval', '-E'],
  lua: ['-e'],
  osascript: ['-e'],
  powershell: [],
  pwsh: [],
  cmd: ['/c', '/C', '/k', '/K'],
  wscript: [],
  cscript: [],
};

function classifyInterpreter(argv: string[], ctx: KnowledgeCtx, name: string): Judgement {
  if (name === 'powershell' || name === 'pwsh') return powershellJudgement(argv, ctx, name);
  if (name === 'deno') return denoJudgement(argv, ctx);
  if (name === 'osascript') return osascriptJudgement(argv, ctx);

  const inline = collectFlagValues(argv, INLINE_FLAGS[name] ?? []);
  if (inline.length > 0) {
    // Inline source is code we cannot read, in a language that can do anything.
    // There is no version of this that is safe to auto-approve.
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'runs code written straight into the command line, which could do anything',
      pathArgs: 'none',
    };
  }

  // `python -m mod` runs a module from the environment, and some modules are
  // well-known enough to be worth classifying properly.
  if (name.startsWith('python')) {
    const mod = flagValue(argv, '-m');
    if (mod) return pythonModuleJudgement(argv, ctx, mod);
  }

  if (name === 'php') {
    // `php -S 0.0.0.0:8000` is a web server, not a script run.
    const serve = flagValue(argv, '-S');
    if (serve) {
      return {
        capability: 'net.fetch',
        reach: 'network',
        exposure: 'can-exfiltrate',
        note: 'starts a web server that serves local files to anything that can reach this machine',
        pathArgs: 'none',
        targets: [{ type: 'host', value: serve }],
      };
    }
    if (hasFlag(argv, '-l')) return { capability: 'exec.inspect', note: 'checks a php file for syntax errors' };
  }

  const script = positionals(argv, INTERPRETER_VALUE_FLAGS[name] ?? [])[0];

  // `python -` and a bare `node` read the program from standard input or a
  // prompt: there is no script name to look at at all.
  if (!script || script.value === '-') {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: script?.value === '-'
        ? 'reads the program to run from standard input'
        : 'starts an interactive session, where anything can be typed',
      pathArgs: 'none',
    };
  }

  return scriptJudgement(script, ctx, name);
}

/**
 * Running a script file. The contents are always unknown, so this is always
 * opaque; what changes with location is how far the code is likely to reach and
 * whether a human has ever seen it. A file in the repo has been reviewed at
 * least once; a file in a temp directory was written minutes ago by something.
 */
function scriptJudgement(script: Positional, ctx: KnowledgeCtx, name: string): Judgement {
  const abs = ctx.resolve(script.value);
  const inside = abs ? ctx.inWorkspace(abs) : false;
  const remote = /^(https?|jsr|npm|data):/i.test(script.value);

  if (remote) {
    return {
      capability: 'exec.unknown',
      reach: 'network',
      opaque: true,
      note: 'runs code downloaded from a url, which is not in the project and can change at any time',
      pathArgs: 'none',
      targets: [{ type: 'host', value: hostOf(script.value) ?? script.value }],
    };
  }

  const windowsHost = name === 'wscript' || name === 'cscript';
  return {
    capability: 'exec.unknown',
    reach: inside ? 'workspace' : 'machine',
    reversibility: 'hard',
    opaque: true,
    note: windowsHost
      ? 'runs a windows script host script, which has full access to this machine'
      : inside
        ? 'runs a script from the project, whose contents are not visible here'
        : 'runs a script from outside the project, whose contents are not visible here',
    pathArgs: [script.index],
    targets: abs ? [{ type: 'path', value: abs, inWorkspace: inside, secret: ctx.isSecret(abs) }] : [],
  };
}

function pythonModuleJudgement(argv: string[], ctx: KnowledgeCtx, mod: string): Judgement {
  const after = positionals(argv, ['-c', '-W', '-X']);
  // Everything after the module name is the module's own argv.
  const modIndex = after.findIndex((p) => p.value === mod);
  const modArgs = modIndex >= 0 ? after.slice(modIndex + 1).map((p) => p.value) : after.map((p) => p.value);
  const first = (modArgs[0] ?? '').toLowerCase();
  const second = (modArgs[1] ?? '').toLowerCase();

  switch (mod) {
    case 'pytest':
    case 'unittest':
    case 'nose':
    case 'nose2':
      return { capability: 'exec.test', note: 'runs the test suite' };

    case 'pip':
    case 'pip3': {
      if (first === 'install' || first === 'uninstall' || first === 'wheel') {
        return {
          capability: 'exec.pkg',
          reach: 'machine',
          note: first === 'uninstall'
            ? 'removes an installed python package'
            : 'installs python packages, which runs their setup code on this machine',
          pathArgs: 'none',
          targets: modArgs.slice(1).filter((a) => !a.startsWith('-')).map((a) => ({ type: 'package' as const, value: a })),
        };
      }
      if (first === 'download') return { capability: 'net.fetch', note: 'downloads python packages', pathArgs: 'none' };
      if (first === 'config' && (second === 'set' || second === 'unset' || second === 'edit')) {
        // Writing pip's config is how every later install gets repointed at a
        // different index, so it is a supply-chain change, not a query.
        return {
          capability: 'fs.write.outside',
          reach: 'machine',
          reversibility: 'hard',
          note: 'changes pip configuration, which can repoint every later install at a different package index',
          pathArgs: 'none',
        };
      }
      if (first === 'cache' && (second === 'purge' || second === 'remove')) {
        return { capability: 'fs.delete', reach: 'machine', scale: 'many', note: 'deletes the pip download cache', pathArgs: 'none' };
      }
      return { capability: 'exec.inspect', note: 'reads the installed python packages', pathArgs: 'none' };
    }

    case 'venv':
    case 'virtualenv': {
      const dir = modArgs.find((a) => !a.startsWith('-'));
      const abs = dir ? ctx.resolve(dir) : '';
      const inside = abs ? ctx.inWorkspace(abs) : true;
      return {
        capability: inside ? 'fs.write.workspace' : 'fs.write.outside',
        reach: inside ? 'workspace' : 'machine',
        scale: 'many',
        note: 'creates a python virtual environment directory',
      };
    }

    case 'json.tool': {
      // A second positional is an output file, and json.tool overwrites it.
      const written = modArgs.filter((a) => !a.startsWith('-'))[1];
      const outAbs = written ? ctx.resolve(written) : '';
      if (outAbs) {
        const inside = ctx.inWorkspace(outAbs);
        return {
          capability: inside ? 'fs.write.workspace' : 'fs.write.outside',
          reach: inside ? 'workspace' : 'machine',
          note: 'reformats json and overwrites the file named as its output',
          targets: [{ type: 'path', value: outAbs, inWorkspace: inside }],
        };
      }
      return { capability: 'exec.inspect', note: 'prints information and formats text' };
    }

    case 'this':
    case 'site':
    case 'sysconfig':
    case 'platform':
      return { capability: 'exec.inspect', note: 'prints information and formats text' };

    case 'http.server':
    case 'SimpleHTTPServer':
      // A one-liner that publishes the current directory to the network. It
      // feels like a debugging convenience and behaves like a file share.
      return {
        capability: 'net.fetch',
        reach: 'network',
        exposure: 'can-exfiltrate',
        note: 'starts a web server that shares this directory with anything that can reach this machine',
        pathArgs: 'none',
      };

    case 'build':
    case 'compileall':
    case 'py_compile':
      return { capability: 'exec.build', note: 'builds python artefacts from the project' };

    case 'twine':
      return {
        capability: 'exec.pkg.publish',
        reach: 'external',
        reversibility: 'irreversible',
        note: 'publishes a package to a public index, where it cannot be unpublished cleanly',
        pathArgs: 'none',
      };

    case 'ensurepip':
      return { capability: 'exec.pkg', reach: 'machine', note: 'installs pip into this python environment', pathArgs: 'none' };

    default:
      return {
        capability: 'exec.unknown',
        reach: 'machine',
        opaque: true,
        note: 'runs a python module whose behaviour is not visible here',
        pathArgs: 'none',
        targets: [{ type: 'package', value: mod }],
      };
  }
}

/**
 * Deno is the one interpreter where the command line tells you something real
 * about what the code may do, because permissions are opt-in. That distinction
 * is worth keeping: a plain `deno run` cannot touch the disk or the network.
 */
function denoJudgement(argv: string[], ctx: KnowledgeCtx): Judgement {
  const words = positionals(argv, INTERPRETER_VALUE_FLAGS['deno'] ?? []);
  const verb = (words[0]?.value ?? '').toLowerCase();

  if (verb === 'eval' || verb === 'repl' || !verb) {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: verb === 'eval'
        ? 'runs code written straight into the command line, which could do anything'
        : 'starts an interactive session, where anything can be typed',
      pathArgs: 'none',
    };
  }
  if (verb === 'fmt') return { capability: 'fs.write.workspace', scale: 'many', note: 'reformats source files in place' };
  if (verb === 'lint' || verb === 'check' || verb === 'info' || verb === 'doc') {
    return { capability: 'exec.inspect', note: 'checks the project without running it' };
  }
  if (verb === 'cache' || verb === 'upgrade') {
    return { capability: 'exec.pkg', reach: 'network', note: 'downloads dependencies', pathArgs: 'none' };
  }
  if (verb === 'install' || verb === 'add' || verb === 'uninstall' || verb === 'remove') {
    // `deno install -g -A` bakes every permission into the installed command, so
    // the sandbox is gone for every later invocation of it, not just this one.
    const baked = hasFlag(argv, '-A', '--allow-all');
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      note: baked
        ? 'installs a command on this machine with every deno permission baked into it'
        : 'installs or removes a dependency or a script command on this machine',
      pathArgs: 'none',
    };
  }
  if (verb === 'publish') {
    // Publishing to jsr is public and a version can never be reused.
    return {
      capability: 'exec.pkg.publish',
      reach: 'external',
      reversibility: 'irreversible',
      note: 'publishes this module to a public registry, where it cannot be unpublished cleanly',
      pathArgs: 'none',
    };
  }
  if (verb === 'compile' || verb === 'bundle') {
    return { capability: 'exec.build', note: 'builds an executable from the project' };
  }
  if (verb === 'task') {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'runs a task defined in the project config, whose command is not visible here',
      pathArgs: 'none',
    };
  }

  const allowAll = hasFlag(argv, '-A', '--allow-all');
  // Deno 2 spells the permission flags short as well: -R -W -N -E -S -I, bare or
  // with `=value`. Reading only the long forms makes a wide-open run look
  // sandboxed, which is the one mistake this whole function exists to avoid.
  const grants = argv.filter((a, i) => i > 0 && (a.startsWith('--allow-') || /^-[RWNESI](=|$)/.test(a)));
  const escalating = grants.some((g) => /^(--allow-(run|ffi|write|env|sys|all)|-[WES](=|$))/.test(g));

  // Only `run` and `serve` take a script; anything else here is a subcommand we
  // do not model, and must not fall through to the "sandboxed, so trivial" tail.
  const scriptish = /[./\\]/.test(verb) || /^(https?|jsr|npm):/i.test(verb);
  const target = scriptish ? words[0] : words[1];
  if (!scriptish && verb !== 'run' && verb !== 'serve' && verb !== 'test' && verb !== 'bench') {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'runs a deno subcommand that leastgrant does not recognise',
      pathArgs: 'none',
    };
  }

  if (verb === 'test' || verb === 'bench') {
    return {
      capability: 'exec.test',
      reach: allowAll || escalating ? 'machine' : 'workspace',
      note: allowAll
        ? 'runs the tests with every permission granted, so the sandbox does not apply'
        : 'runs the tests',
    };
  }

  const remote = target ? /^(https?|jsr|npm):/i.test(target.value) : false;
  if (remote && target) {
    return {
      capability: 'exec.unknown',
      reach: 'network',
      opaque: true,
      note: joinNotes([
        'runs code downloaded from a url, which is not in the project and can change at any time',
        allowAll ? 'with every permission granted' : undefined,
      ]),
      pathArgs: 'none',
      targets: [{ type: 'host', value: hostOf(target.value) ?? target.value }],
    };
  }

  if (allowAll || escalating) {
    const j = target
      ? scriptJudgement(target, ctx, 'deno')
      : { capability: 'exec.unknown' as const, opaque: true, pathArgs: 'none' as const, targets: [] };
    return {
      ...j,
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: allowAll
        ? 'runs a script with every permission granted, so the deno sandbox does not apply'
        : 'runs a script with file, process, or environment permissions granted, so the sandbox is partly open',
    };
  }

  const abs = target ? ctx.resolve(target.value) : '';
  const inside = abs ? ctx.inWorkspace(abs) : false;
  const pathArgs = target ? [target.index] : ('none' as const);
  const targets: Target[] = abs ? [{ type: 'path', value: abs, inWorkspace: inside }] : [];

  if (grants.length > 0) {
    // Some permissions granted but none of the escalating ones. The sandbox is
    // partly open, so argv no longer bounds what the script can do.
    const netGrant = grants.some((g) => g.startsWith('--allow-net') || /^-N(=|$)/.test(g));
    const readGrant = grants.some((g) => g.startsWith('--allow-read') || /^-R(=|$)/.test(g));
    return {
      capability: 'exec.unknown',
      reach: netGrant ? 'network' : inside ? 'workspace' : 'machine',
      reversibility: 'hard',
      exposure: netGrant && readGrant ? 'can-exfiltrate' : undefined,
      opaque: true,
      note: netGrant
        ? 'runs a script with network access granted, so it can reach out on its own'
        : 'runs a script with part of the deno sandbox opened by a permission flag',
      pathArgs,
      targets,
    };
  }

  // No --allow flags at all: the script cannot read files, reach the network,
  // read the environment, or start processes without stopping to ask a human.
  return {
    capability: 'exec.unknown',
    reach: inside ? 'workspace' : 'machine',
    reversibility: 'trivial',
    note: 'runs a script inside the deno sandbox, which has no file, network, or process access unless a permission flag is given',
    pathArgs,
    targets,
  };
}

/**
 * AppleScript is not sandboxed and is a scripting bridge into every other
 * application on the Mac: mail, browsers, the keychain prompt, the shell.
 */
function osascriptJudgement(argv: string[], ctx: KnowledgeCtx): Judgement {
  const inline = collectFlagValues(argv, ['-e']).join('\n');
  const admin = /with\s+administrator\s+privileges/i.test(inline);
  if (admin) {
    return {
      capability: 'exec.privilege',
      reach: 'machine',
      reversibility: 'hard',
      opaque: true,
      note: 'runs a command as an administrator through a system password prompt',
      pathArgs: 'none',
    };
  }
  if (inline) {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: 'runs applescript written into the command line, which can drive other applications on this machine',
      pathArgs: 'none',
    };
  }
  const script = positionals(argv, INTERPRETER_VALUE_FLAGS['osascript'] ?? [])[0];
  if (!script) {
    return { capability: 'exec.unknown', reach: 'machine', opaque: true, note: 'reads applescript from standard input', pathArgs: 'none' };
  }
  const j = scriptJudgement(script, ctx, 'osascript');
  return { ...j, reach: 'machine', note: 'runs an applescript file, which can drive other applications on this machine' };
}

function powershellJudgement(argv: string[], ctx: KnowledgeCtx, name: string): Judgement {
  // PowerShell accepts any unambiguous prefix, so `-enc`, `-e`, and `-EncodedC`
  // all mean -EncodedCommand. Match on prefixes rather than exact spellings.
  const isEncoded = argv.some((a, i) =>
    i > 0 && /^[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$/i.test(a));
  const commandIdx = argv.findIndex((a, i) =>
    i > 0 && /^[-/](c|co|com|comm|comma|comman|command)$/i.test(a));
  const fileIdx = argv.findIndex((a, i) => i > 0 && /^[-/](f|fi|fil|file)$/i.test(a));
  const fileValue = fileIdx > 0 ? argv[fileIdx + 1] : undefined;

  const all = argv.slice(1).join(' ');
  const bypass = /-(ex|exe|exec|execu|execut|executi|executio|execution|executionp|executionpo|executionpol|executionpoli|executionpolic|executionpolicy)\s+(bypass|unrestricted)/i.test(all);
  const hidden = /-(w|wi|win|wind|windo|window|windows|windowst|windowsty|windowstyl|windowstyle)\s+hidden/i.test(all);
  const downloadRun = /(invoke-expression|\biex\b|downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bcurl\b)/i.test(all);

  const extras = joinNotes([
    bypass ? 'turns off the script execution policy' : undefined,
    hidden ? 'hides its own window' : undefined,
    downloadRun ? 'looks like it downloads code and runs it in one step' : undefined,
  ]);

  if (isEncoded) {
    // Base64 on a command line has exactly one purpose: making the command
    // unreadable to whoever is looking at it. Say that out loud.
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      opaque: true,
      note: joinNotes([
        'runs a base64 encoded command, so what it actually does is hidden from anyone reading this line',
        extras,
      ]),
      pathArgs: 'none',
    };
  }

  if (commandIdx >= 0) {
    return {
      capability: 'exec.unknown',
      reach: downloadRun ? 'network' : 'machine',
      opaque: true,
      note: joinNotes(['runs a powershell command written into the command line, which could do anything', extras]),
      pathArgs: 'none',
    };
  }

  // PowerShell flags are case-insensitive and abbreviatable, so rather than
  // trusting a flag table to find the script, look for the thing that is
  // unmistakably a script. Anything else falls through to the opaque branch.
  const scriptValue = fileValue ?? argv.find((a, i) => i > 0 && /\.ps1$/i.test(a));
  if (scriptValue) {
    const index = argv.indexOf(scriptValue);
    const j = scriptJudgement({ value: scriptValue, index: index > 0 ? index : 1 }, ctx, name);
    return { ...j, note: joinNotes([j.note, extras]) };
  }

  return {
    capability: 'exec.unknown',
    reach: 'machine',
    opaque: true,
    note: joinNotes(['starts an interactive powershell session, where anything can be typed', extras]),
    pathArgs: 'none',
  };
}
