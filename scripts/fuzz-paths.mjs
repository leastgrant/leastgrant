/**
 * Randomised symlink-topology fuzzing for path containment.
 *
 * The curated corpus covers the shapes somebody thought of. This generates
 * topologies and paths nobody chose: random link graphs (some pointing inside,
 * some out, some chained, some circular), then random path strings walking
 * through them with `..`, `.`, doubled separators and missing components mixed
 * in.
 *
 * Each generated path is judged three ways: by LeastGrant, and by two reference
 * resolvers written independently here (lexical and physical). The invariant is
 * the same one the fix is built on — if either reading lands outside the
 * project, LeastGrant must not call the path contained.
 *
 * Deterministic: the seed is fixed so a failure can be reproduced exactly.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const BS = String.fromCharCode(92);
const norm = (p) => p.split(BS).join('/');

// A small deterministic PRNG, so a failing case can be re-run.
const seed0 = Number(process.env['FUZZ_SEED'] ?? 20260901);
let seed = seed0;
const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
const pick = (a) => a[Math.floor(rnd() * a.length) % a.length];
const chance = (p) => rnd() < p;

const ROOT = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'lg-fz-')));
const WS = path.join(ROOT, 'ws');
const OUT = path.join(ROOT, 'outside');

const DIRS = ['src', 'lib', 'pkg', 'deep', 'deep/a', 'deep/a/b', '..hidden', '...', 'node_modules'];
for (const d of DIRS) fs.mkdirSync(path.join(WS, ...d.split('/')), { recursive: true });
fs.mkdirSync(path.join(OUT, 'sub', 'deeper'), { recursive: true });
fs.mkdirSync(path.join(OUT, '.ssh'), { recursive: true });
fs.writeFileSync(path.join(WS, 'src', 'a.ts'), '');
fs.writeFileSync(path.join(OUT, 'secret.txt'), '');
fs.writeFileSync(path.join(OUT, '.ssh', 'id_rsa'), '');
fs.writeFileSync(path.join(ROOT, 'planted.txt'), '');

/** Build a random link graph inside the workspace. */
const LINKS = [];
function mklink(name, target) {
  const at = path.join(WS, name);
  try {
    fs.symlinkSync(target, at, process.platform === 'win32' ? 'junction' : 'dir');
    LINKS.push(name);
    return true;
  } catch {
    return false;
  }
}
const TARGETS_OUT = [OUT, path.join(OUT, 'sub'), path.join(OUT, 'sub', 'deeper'), path.join(OUT, '.ssh'), ROOT];
const TARGETS_IN = [path.join(WS, 'src'), path.join(WS, 'lib'), path.join(WS, 'deep'), path.join(WS, 'deep', 'a', 'b')];
let made = 0;
for (let i = 0; i < 8; i++) if (mklink('out' + i, pick(TARGETS_OUT))) made++;
for (let i = 0; i < 8; i++) if (mklink('in' + i, pick(TARGETS_IN))) made++;
// Chains: a link to a link.
for (let i = 0; i < 4; i++) if (LINKS.length && mklink('chain' + i, path.join(WS, pick(LINKS)))) made++;
if (!made) {
  console.log('this machine will not create links; skipping');
  process.exit(0);
}

// --- independent references -------------------------------------------------

function win32Trim(p) {
  if (process.platform !== 'win32') return p;
  return p
    .split(/([\\/])/)
    .map((s) => (s === '.' || s === '..' || s === BS || s === '/' ? s : s.replace(/[. ]+$/, '')))
    .join('');
}

function refLexical(input) {
  let p = path.resolve(WS, input);
  for (let i = 0; i < 64; i++) {
    try {
      return fs.realpathSync.native(p);
    } catch {
      const parent = path.dirname(p);
      if (parent === p) return path.resolve(WS, input);
      const tail = path.relative(parent, p);
      try {
        return path.join(fs.realpathSync.native(parent), tail);
      } catch {
        p = parent;
      }
    }
  }
  return path.resolve(WS, input);
}

function refPhysical(input) {
  const isAbs = path.isAbsolute(input);
  let cur = isAbs ? path.parse(path.resolve(input)).root : fs.realpathSync.native(WS);
  const rest = isAbs ? input.slice(path.parse(input).root.length) : input;
  let queue = rest.split(/[\\/]+/).filter(Boolean);
  let hops = 0;
  let gone = false;
  for (let steps = 0; queue.length && steps < 4096; steps++) {
    const c = queue.shift();
    if (c === '.') continue;
    if (c === '..') {
      const up = path.dirname(cur);
      cur = up === cur ? cur : up;
      continue;
    }
    const cand = path.join(cur, c);
    if (gone) {
      cur = cand;
      continue;
    }
    let st;
    try {
      st = fs.lstatSync(cand);
    } catch (e) {
      if (e && e.code && e.code !== 'ENOENT' && e.code !== 'ENOTDIR') return null;
      gone = true;
      cur = cand;
      continue;
    }
    if (!st.isSymbolicLink()) {
      cur = cand;
      continue;
    }
    if (++hops > 40) return null;
    const t = fs.readlinkSync(cand);
    const troot = path.parse(t).root;
    if (troot) {
      cur = troot;
      queue = [...t.slice(troot.length).split(/[\\/]+/).filter(Boolean), ...queue];
    } else {
      queue = [...t.split(/[\\/]+/).filter(Boolean), ...queue];
    }
  }
  return cur;
}

const WSC = fs.realpathSync.native(WS);
const insideRef = (p) => {
  if (!p) return false;
  const a = norm(path.resolve(p)).toLowerCase();
  const b = norm(WSC).toLowerCase();
  return a === b || a.startsWith(b + '/');
};

// --- subject -----------------------------------------------------------------

const { canonicalize, inWorkspace, candidatesOf } = await import('../dist/src/core/paths.js');
const contained = (input) => {
  const cands = candidatesOf(canonicalize(input, WS));
  return cands.length > 0 && cands.every((a) => inWorkspace(a, [WSC]));
};

// --- generate ------------------------------------------------------------------

const LEAVES = ['a.ts', 'secret.txt', 'id_rsa', 'planted.txt', 'nope.txt', 'newfile'];
function genPath() {
  const parts = [];
  const n = 1 + Math.floor(rnd() * 6);
  for (let i = 0; i < n; i++) {
    const r = rnd();
    if (r < 0.3) parts.push(pick(LINKS));
    else if (r < 0.55) parts.push('..');
    else if (r < 0.65) parts.push('.');
    else if (r < 0.8) parts.push(pick(DIRS).split('/')[0]);
    else parts.push(pick(['sub', 'deeper', '.ssh', 'missing', 'x']));
  }
  parts.push(pick(LEAVES));
  const sep = chance(0.15) ? '//' : path.sep;
  const body = parts.join(sep);
  return chance(0.35) ? WS + path.sep + body : body;
}

const N = Number(process.env['FUZZ_N'] ?? 2500);
const CI = Boolean(process.env['GITHUB_ACTIONS']);
const NL = String.fromCharCode(10);
let unsafe = 0;
let overstrict = 0;
let ambiguous = 0;
const bad = [];
for (let i = 0; i < N; i++) {
  const input = genPath();
  const trimmed = win32Trim(input);
  let lex;
  let phys;
  try {
    lex = refLexical(trimmed);
    phys = refPhysical(trimmed);
  } catch {
    continue;
  }
  const refInside = phys !== null && insideRef(lex) && insideRef(phys);
  if (phys !== null && insideRef(lex) !== insideRef(phys)) ambiguous++;
  let got;
  try {
    got = contained(input);
  } catch (e) {
    bad.push({ input: input.replace(ROOT, '<R>'), why: 'threw: ' + e.message });
    unsafe++;
    continue;
  }
  if (got && !refInside) {
    unsafe++;
    if (bad.length < 10)
      bad.push({
        input: input.replace(ROOT, '<R>'),
        lex: String(lex).replace(ROOT, '<R>'),
        phys: String(phys).replace(ROOT, '<R>'),
      });
  } else if (!got && refInside) {
    overstrict++;
    if (bad.length < 10)
      bad.push({ input: input.replace(ROOT, '<R>'), overstrict: true, lex: String(lex).replace(ROOT, '<R>') });
  }
}

console.log(`${N} generated paths over ${LINKS.length} random links (seed ${seed0})`);
console.log(`  ${ambiguous} genuinely ambiguous (the two readings disagree)`);
console.log(`  ${unsafe} called CONTAINED while a reading lands outside  <-- security failures`);
console.log(`  ${overstrict} called outside while both readings are inside  <-- friction`);
for (const b of bad) console.log('     ', JSON.stringify(b));

fs.rmSync(ROOT, { recursive: true, force: true });

if (unsafe) {
  const msg =
    unsafe +
    ' generated path(s) were reported as inside the project while a reading of them lands outside' +
    ' (seed ' + seed0 + ')';
  console.error(CI ? '::error::' + msg : NL + msg);
  process.exit(1);
}
// Friction is not a security failure, but a fix that called everything outside
// would pass the check above and be useless, so it fails the run too.
if (overstrict) {
  const msg = overstrict + ' ordinary path(s) were reported as outside the project (seed ' + seed0 + ')';
  console.error(CI ? '::error::' + msg : NL + msg);
  process.exit(1);
}
console.log(NL + 'no containment failures');
