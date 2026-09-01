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
 *       --integrity sha512-... [--expect-provenance | --provenance-advisory]
 *       exit 0  the published bytes match, and provenance is present if required
 *       exit 1  they do not
 *
 * The integrity comparison is the load-bearing one. `npm pack` is byte
 * reproducible, so the sha512 of the tarball this workflow verified is exactly
 * the `dist.integrity` the registry reports for an honest publish of it. If they
 * differ, something between the verification and the registry changed the
 * artifact, and that is worth a red build even though the version is already
 * gone.
 *
 * Two things in here are shaped by bugs that actually happened, both of which
 * turned a healthy package into a failed release:
 *
 *   - The registry is queried over HTTP, not through `npm view`. The CLI's JSON
 *     shape is not a contract — npm 11 merges the version manifest into the
 *     packument so `.version` and `.dist` sit at the top level, and a later npm
 *     does not. This script read the integrity as `undefined` and failed.
 *   - Nothing calls `process.exit()` after a `fetch`. Exiting while an undici
 *     socket is still open trips a libuv assertion and returns 127, which the
 *     workflow reads as "the registry is unreachable".
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

const CI = Boolean(process.env['GITHUB_ACTIONS']);
const err = (msg) => console.error(CI ? `::error::${msg}` : `  ERROR: ${msg}`);

const WIN = process.platform === 'win32';
const npm = (argv, opts = {}) => {
  if (!WIN) return spawnSync('npm', argv, { encoding: 'utf8', ...opts });
  const line = ['npm.cmd', ...argv.map((a) => (/[\s"&|<>^]/.test(a) ? `"${a.replace(/"/g, '""')}"` : a))].join(' ');
  return spawnSync(line, { encoding: 'utf8', shell: true, ...opts });
};

function registryBase() {
  const fromEnv = process.env['npm_config_registry'];
  const raw = fromEnv || (npm(['config', 'get', 'registry']).stdout || '').trim();
  const url = raw && raw.startsWith('http') ? raw : 'https://registry.npmjs.org';
  return url.replace(/\/+$/, '');
}

/** Ask npm whether the published version carries a verified attestation. */
function checkProvenance(spec, advisory) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lg-attest-'));
  try {
    const init = npm(['init', '-y'], { cwd: dir });
    if (init.status !== 0) {
      err(`could not prepare an attestation check: ${init.stderr}`);
      return 1;
    }
    const inst = npm(['install', '--ignore-scripts', spec], { cwd: dir });
    if (inst.status !== 0) {
      err(`could not install ${spec} to verify its attestations: ${(inst.stderr || '').slice(0, 300)}`);
      return 1;
    }
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
      return 0;
    }
    if (advisory) {
      console.log(
        '  note  no provenance attestation. Expected for a version published by hand — ' +
          'the first release of a package always is, since a trusted publisher cannot be ' +
          'configured until the package exists.',
      );
      return 0;
    }
    err(
      `${spec} has no verified provenance attestation. With trusted publishing npm ` +
        `generates one automatically, so its absence means the publish did not use OIDC.`,
    );
    return 1;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  const [name, version] = process.argv.slice(2);
  if (!name || !version) {
    console.error(
      'usage: node scripts/verify-published.mjs <name> <version> [--exists] ' +
        '[--integrity <sha512-...>] [--expect-provenance|--provenance-advisory]',
    );
    return 2;
  }

  const args = process.argv.slice(4);
  const existsOnly = args.includes('--exists');
  const expectProvenance = args.includes('--expect-provenance');
  // Report provenance but do not fail on its absence. Used for a version that
  // was already on the registry when the run started: this workflow cannot
  // vouch for how somebody else published it, and the very first release of a
  // package is necessarily a hand publish without provenance, because a trusted
  // publisher cannot be configured until the package exists.
  const advisoryProvenance = args.includes('--provenance-advisory');
  const iIdx = args.indexOf('--integrity');
  const wantIntegrity = iIdx >= 0 ? args[iIdx + 1] : '';

  const spec = `${name}@${version}`;
  const registry = registryBase();
  // A scoped name carries a slash, which must be escaped in the path segment.
  const url = `${registry}/${name.split('/').join('%2f')}/${encodeURIComponent(version)}`;

  let status;
  let body;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    status = res.status;
    // Consumed even when unused, so undici releases the socket.
    body = await res.text();
  } catch (e) {
    err(`could not reach ${registry}: ${e.message}`);
    return 2;
  }

  if (existsOnly) {
    if (status === 200) {
      console.log(`${spec} is already on the registry`);
      return 0;
    }
    if (status === 404) {
      console.log(`${spec} is not on the registry yet`);
      return 3;
    }
    // Anything else — an outage, a 5xx, a proxy — must not be read as "not
    // published". Treating that as permission to publish is how a workflow
    // publishes the same version twice.
    err(`could not determine whether ${spec} exists: HTTP ${status} from ${url}`);
    return 2;
  }

  if (status !== 200) {
    err(`${spec} is not on the registry after publishing: HTTP ${status}`);
    return 1;
  }

  let meta;
  try {
    meta = JSON.parse(body);
  } catch {
    err(`could not parse the registry response for ${spec}`);
    return 1;
  }

  let problems = 0;

  // --- the published bytes are the verified bytes -----------------------------

  const published = meta?.dist?.integrity;
  console.log(`  registry integrity  ${published}`);
  if (!published) {
    err(`the registry returned no dist.integrity for ${spec}`);
    problems++;
  }
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

  // --- provenance ---------------------------------------------------------------

  if (expectProvenance || advisoryProvenance) {
    problems += checkProvenance(spec, advisoryProvenance);
  }

  if (problems) {
    console.error(`\n${problems} problem(s) with the published package.`);
    return 1;
  }
  console.log(`\n${spec} verified on the registry`);
  return 0;
}

// `exitCode`, not `exit()`: see the note at the top of this file.
process.exitCode = await main();
