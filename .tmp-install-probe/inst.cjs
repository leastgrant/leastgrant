const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const home = path.resolve('D:/LeastGrant/.tmp-install-probe/home');
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true });

const env = { ...process.env, USERPROFILE: home, HOME: home };
delete env.HOMEDRIVE;
delete env.HOMEPATH;
delete env.CLAUDE_CONFIG_DIR;

const BIN = path.resolve('D:/LeastGrant/bin/leastgrant.js');
console.log('bin exists:', fs.existsSync(BIN));

const hd = spawnSync(process.execPath, ['-e', 'console.log(require("os").homedir())'], { encoding: 'utf8', env });
console.log('child homedir:', JSON.stringify(hd.stdout.trim()));

for (const agent of ['cursor', 'claude-code']) {
  const r = spawnSync(process.execPath, [BIN, 'install', agent, '--json'], {
    encoding: 'utf8',
    env,
    cwd: path.resolve('D:/LeastGrant'),
  });
  console.log('=== ' + agent + ' status=' + r.status + ' ===');
  if (r.error) console.log('ERROR:', r.error.message);
  console.log(r.stdout || '(no stdout)');
  if (r.stderr) console.log('STDERR:', r.stderr);
}

console.log('\n########## RESULTING FILES ##########');
for (const rel of ['.cursor/hooks.json', '.claude/settings.json']) {
  const f = path.join(home, rel);
  console.log('\n----- ' + rel + ' (' + (fs.existsSync(f) ? 'exists' : 'MISSING') + ') -----');
  if (fs.existsSync(f)) console.log(fs.readFileSync(f, 'utf8'));
}
