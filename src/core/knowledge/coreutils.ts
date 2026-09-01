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
      return { capability: 'meta', note: 'sets a shell variable', pathArgs: 'none' };
    }
    if (PRINTERS.includes(name)) {
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
      return readJudgement(argv, ctx);
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
      return { capability: 'fs.write.workspace', note: 'creates an archive' };
    }

    if (name === 'env') {
      // Bare `env` prints the environment. `env CMD` was unwrapped already.
      return { capability: 'exec.inspect', pathArgs: 'none' };
    }

    return null;
  },
};

/** A read whose risk depends entirely on *what* is being read. */
function readJudgement(argv: string[], ctx: KnowledgeCtx): Judgement {
  const args = nonFlags(argv);
  let sawSecret = false;
  let sawOutside = false;
  for (const a of args) {
    const abs = ctx.resolve(a);
    if (!abs) continue;
    if (ctx.isSecret(abs)) sawSecret = true;
    else if (!ctx.inWorkspace(abs)) sawOutside = true;
  }
  if (sawSecret) return { capability: 'secret.read', note: 'reads a credential file' };
  if (sawOutside) return { capability: 'fs.read.outside', note: 'reads outside the project' };
  return { capability: 'fs.read.workspace', scale: args.length > 1 ? 'many' : 'single' };
}

/** A write whose risk depends on where it lands. */
function writeJudgement(argv: string[], ctx: KnowledgeCtx, note: string): Judgement {
  const args = nonFlags(argv);
  let outside = false;
  let secret = false;
  for (const a of args) {
    const abs = ctx.resolve(a);
    if (!abs) continue;
    if (ctx.isSecret(abs)) secret = true;
    if (!ctx.inWorkspace(abs)) outside = true;
  }
  const j: Judgement = {
    capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
    reach: outside ? 'machine' : 'workspace',
    scale: args.length > 2 ? 'many' : 'single',
    note: secret ? `${note}, over a credential file` : note,
  };
  if (secret) j.exposure = 'reads-secrets';
  return j;
}
