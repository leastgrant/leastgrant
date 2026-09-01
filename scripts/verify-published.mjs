/**
 * Registry-side checks, before and after publishing.
 *
 * Two jobs, both about the same question — is what is on the registry exactly
 * what this workflow verified?
 *
 *   node scripts/verify-published.mjs leastgrant 0.1.0 --exists
 *       exit 0  the version is already on the registry
 *       exit 3  it is not
 *       exit 2  the registry could not be reached (do not treat as "not there")
 *
 *   node scripts/verify-published.mjs leastgrant 0.1.0 \
 *       --integrity sha512-... [--expect-provenance]
 *       exit 0  the published bytes match, and provenance is present if required
 *       exit 1  they do not
 *
 * The integrity comparison is the load-bearing one. `npm pack` is byte
 * reproducible, so the sha512 of the tarball this workflow verified is exactly
 * the `dist.integrity` the registry reports for an honest publish of it. If
 * they differ, something between the verification and the registry changed the
 * artifact, and that is worth a red build even though the version is already
 * gone.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

const CI = Boolean(process.env['GITHUB_ACTIONS']);
const err = (msg) => console.error(CI ? `::error::${msg}` : `  ERROR: ${msg}`);

const [name, version] = process.argv.slice(2);
if (!name || !version) {
  console.error('usage: node scripts/verify-published.mjs <name> <version> [--exists] [--integrity <sha512-...>] [--expect-provenance]');
  process.exit(2);
}
const args = process.argv.slice(4);
const existsOnly = args.includes('--exists');
const expectProvenance = args.includes('--expect-provenance');
// Report provenance but do not fail on its absence. Used for a version that was
// already on the registry when the run started: this workflow cannot vouch for
// how somebody else published it, and the very first release of a package is
// necessarily a hand publish without provenance, because a trusted publisher
// cannot be configured until the package exists.
const advisoryProvenance = args.includes('--provenance-advisory');
const iIdx = args.indexOf('--integrity');
const wantIntegrity = iIdx >= 0 ? args[iIdx + 1] : '';

const WIN = process.platform === 'win32';
const npm = (argv, opts = {}) => {
  if (!WIN) return spawnSync('npm', argv, { encoding: 'utf8', ...opts });
  const line = ['npm.cmd', ...argv.map((a) => (/[\s"&|<>^]/.test(a) ? `"${a.replace(/"/g, '""')}"` : a))].join(' ');
  return spawnSync(line, { encoding: 'utf8', shell: true, ...opts });
};

const spec = `${name}@${version}`;

// --- what does the registry say? ---------------------------------------------

const view = npm(['view', spec, '--json']);
const stderr = view.stderr || '';
const missing = /E404|is not in this registry|No match found/i.test(stderr);

if (existsOnly) {
  if (view.status === 0 && (view.stdout || '').trim()) {
    console.log(`${spec} is already on the registry`);
    process.exit(0);
  }
  if (missing) {
    console.log(`${spec} is not on the registry yet`);
    process.exit(3);
  }
  // Anything else — a network failure, a 5xx, an auth problem — must not be
  // read as "not published". Treating an outage as "go ahead and publish" is
  // how a workflow double-publishes.
  err(`could not determine whether ${spec} exists: ${stderr.trim().slice(0, 300)}`);
  process.exit(2);
}

if (view.status !== 0) {
  err(`${spec} is not on the registry after publishing: ${stderr.trim().slice(0, 300)}`);
  process.exit(1);
}

let meta;
try {
  meta = JSON.parse(view.stdout);
} catch {
  err(`could not parse the registry response for ${spec}`);
  process.exit(1);
}

let problems = 0;

// --- 1. the published bytes are the verified bytes ----------------------------

const published = meta?.dist?.integrity;
console.log(`  registry integrity  ${published}`);
if (wantIntegrity) {
  console.log(`  verified integrity  ${wantIntegrity}`);
  if (published !== wantIntegrity) {
    err(
      `the published artifact is not the one this workflow verified\n` +
        `  registry: ${published}\n  verified: ${wantIntegrity}`,
    );
    problems++;
  } else {
    console.log('  ok    the published tarball is byte-identical to the verified one');
  }
}

if (meta.version !== version) {
  err(`the registry reports version ${meta.version} for ${spec}`);
  problems++;
}

// --- 2. provenance ------------------------------------------------------------
//
// With trusted publishing npm generates provenance automatically, so its
// absence means the publish did not go through OIDC — which is exactly the
// thing this pipeline exists to guarantee. Checked by installing the published
// version into a scratch directory and asking npm to verify its attestations.

if (expectProvenance || advisoryProvenance) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-attest-'));
  const init = npm(['init', '-y'], { cwd: dir });
  if (init.status !== 0) {
    err(`could not prepare an attestation check: ${init.stderr}`);
    problems++;
  } else {
    const inst = npm(['install', '--ignore-scripts', spec], { cwd: dir });
    if (inst.status !== 0) {
      err(`could not install ${spec} to verify its attestations: ${inst.stderr.slice(0, 300)}`);
      problems++;
    } else {
      const audit = npm(['audit', 'signatures'], { cwd: dir });
      const out = `${audit.stdout || ''}${audit.stderr || ''}`;
      console.log(
        out
          .split('\n')
          .filter((l) => l.trim())
          .map((l) => `  | ${l}`)
          .join('\n'),
      );
      if (/verified attestation/i.test(out)) {
        console.log('  ok    provenance attestation verified');
      } else if (advisoryProvenance) {
        console.log(
          '  note  no provenance attestation. Expected for a version published by hand — ' +
            'the first release of a package always is, since a trusted publisher cannot be ' +
            'configured until the package exists.',
        );
      } else {
        err(
          `${spec} has no verified provenance attestation. With trusted publishing npm ` +
            `generates one automatically, so its absence means the publish did not use OIDC.`,
        );
        problems++;
      }
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
}

if (problems) {
  console.error(`\n${problems} problem(s) with the published package.`);
  process.exit(1);
}
console.log(`\n${spec} verified on the registry`);
