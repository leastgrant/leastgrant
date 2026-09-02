// Shim: strip a leading UTF-8 BOM, then hand the payload to the real hook.
// Used only to prove the BOM is the sole blocker; not a proposed fix.
const { spawnSync } = require('child_process');
let s = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (s += c));
process.stdin.on('end', () => {
  const clean = s.replace(/^\uFEFF/, '');
  const r = spawnSync(process.execPath, ['D:\\LeastGrant\\bin\\leastgrant.js', 'hook', '--agent', 'cursor'], {
    input: clean,
    encoding: 'utf8',
    cwd: 'D:\\LeastGrant',
  });
  process.stdout.write(r.stdout || '');
  process.stderr.write(r.stderr || '');
  process.exitCode = r.status ?? 0;
});
