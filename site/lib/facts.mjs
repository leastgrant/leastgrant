/**
 * Everything the site states as fact, read out of the repository.
 *
 * A marketing page that hardcodes "46 bypasses" is wrong the first time
 * somebody adds a forty-seventh. Worse, it stays wrong quietly. So no number
 * on this website is typed into a template: each one is either counted from
 * source here, or extracted from the canonical Markdown with an assertion that
 * the sentence it came from still exists.
 *
 * The assertions are the point. If the README stops saying what this file
 * expects, the build fails and somebody has to look, rather than the website
 * continuing to advertise last month's claim.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { REPO } from './capture.mjs';
import {
  loadCompatibility,
  assess,
  deriveVerification,
  LEVEL_LABEL,
} from '../../dist/src/core/compatibility.js';

const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

/** Pull one capture group out of `text`, or fail the build saying which. */
function must(text, re, what, source) {
  const m = text.match(re);
  if (!m) {
    throw new Error(
      `${source} no longer contains ${what}.\n` +
        `  The website quotes this figure, so it cannot be published without it.\n` +
        `  Either restore the sentence, or update site/lib/facts.mjs to match the new wording.`,
    );
  }
  return m[1];
}

export function gather() {
  const pkg = JSON.parse(read('package.json'));
  const readme = read('README.md');
  const bypass = read('test/bypass.test.ts');
  const threat = read('THREAT-MODEL.md');

  // --- the package ---------------------------------------------------------

  const runtimeDeps = Object.keys(pkg.dependencies || {}).length;
  if (runtimeDeps !== 0) {
    throw new Error(
      `package.json now has ${runtimeDeps} runtime dependencies. The website says there are none.`,
    );
  }

  // --- the bypass corpus ---------------------------------------------------
  //
  // The named evasions now live in corpus/bypasses.json, which is the file the
  // test iterates and the file this page publishes, so the count is read rather
  // than scraped. It used to be scraped out of the test source with a regex,
  // and moving the cases to JSON broke that parser on the same commit — which
  // is exactly the drift the corpus was extracted to prevent, caught by the
  // check below one layer further out than intended.
  //
  // The symlink traversals are still counted from their test, because they are
  // built as a table inside it rather than as corpus entries. Summed for the
  // figure the page shows.

  const corpus = JSON.parse(read('corpus/bypasses.json'));
  const named = Array.isArray(corpus.cases) ? corpus.cases.length : 0;
  const symlinkBlock = bypass.slice(bypass.indexOf("describe('symlink traversal"));
  const symlink = (symlinkBlock.match(/^\s*\['[^']+', '/gm) || []).length;
  if (named < 20 || symlink < 3) {
    throw new Error(
      `the bypass corpus parser found ${named} cases in corpus/bypasses.json and ${symlink} ` +
        `symlink cases in test/bypass.test.ts, which does not look right any more`,
    );
  }

  const testFiles = fs
    .readdirSync(path.join(REPO, 'test'))
    .filter((f) => f.endsWith('.test.ts'))
    .sort();

  // --- figures the README states, quoted rather than invented ---------------

  const measured = {
    // "Measured against 6,057 real Bash commands ... the shell parser accounted
    // for 6,054 of them, with 0 crashes and 0.03 ms average parse time."
    commands: must(readme, /against ([\d,]+) real Bash commands/, 'the parsed-command count', 'README.md'),
    parsed: must(readme, /accounted for\s+\*\*([\d,]+) of them/, 'the accounted-for count', 'README.md'),
    parseMs: must(readme, /and ([\d.]+) ms average parse time/, 'the average parse time', 'README.md'),
    understood: must(readme, /\*\*([\d.]+)% are ones LeastGrant will say it fully/, 'the understood share', 'README.md'),
    // "took it from 5% to 41% of actions running without a prompt"
    before: must(readme, /took it from ([\d]+)% to \*\*[\d]+%/, 'the before figure', 'README.md'),
    after: must(readme, /took it from [\d]+% to \*\*([\d]+)%/, 'the after figure', 'README.md'),
    actions: must(readme, /([\d,]+) actions, about \d+ days of history/, 'the action count', 'README.md'),
    sessions: must(readme, /✓ (\d+) sessions across \d+ projects/, 'the session count', 'README.md'),
    projects: must(readme, /✓ \d+ sessions across (\d+) projects/, 'the project count', 'README.md'),
    refusals: must(readme, /of the (\d+) actions you turned down/, 'the refusal count', 'README.md'),
  };

  // The one sentence that keeps the numbers honest. If it disappears from the
  // README, the website must stop presenting them as measurements.
  if (!/sample of one/.test(readme)) {
    throw new Error(
      'README.md no longer carries the "sample of one" caveat. The website repeats these ' +
        'figures and relies on that caveat being the project\'s own position, not the ' +
        "website's invention.",
    );
  }

  // --- agent support, parsed from the README table -------------------------
  //
  // The exact wording matters here: "Enforcing, not yet verified against a live
  // install" is a claim the website must not round up to "supported". Taking
  // the cells verbatim means it cannot.

  const agents = parseAgentTable(readme);
  if (agents.length < 4) throw new Error('could not parse the agent support table from README.md');

  // --- the decision order, parsed from the README --------------------------

  const order = parseOrderTable(readme);
  if (order.length !== 6) {
    throw new Error(`expected 6 steps in the README decision order, parsed ${order.length}`);
  }

  const evidence = parseEvidenceTable(readme);
  if (evidence.length !== 4) {
    throw new Error(`expected 4 evidence kinds in README.md, parsed ${evidence.length}`);
  }

  const promotion = parsePromotionTable(readme);
  if (promotion.length !== 3) {
    throw new Error(`expected 3 promotion rows in README.md, parsed ${promotion.length}`);
  }

  const postures = parsePostureTable(readme);
  if (postures.length !== 4) {
    throw new Error(`expected 4 postures in README.md, parsed ${postures.length}`);
  }

  return {
    version: pkg.version,
    name: pkg.name,
    license: pkg.license,
    node: pkg.engines.node,
    description: pkg.description,
    runtimeDeps,
    devDeps: Object.keys(pkg.devDependencies || {}),
    commands: Object.keys(pkg.bin),
    repo: 'https://github.com/leastgrant/leastgrant',
    npm: 'https://www.npmjs.com/package/leastgrant',
    advisories: 'https://github.com/leastgrant/leastgrant/security/advisories/new',
    bypass: { named, symlink, total: named + symlink },
    testFiles,
    measured,
    agents,
    failure: parseFailureModes(),
    order,
    evidence,
    promotion,
    postures,
    threatModelSections: (threat.match(/^## \d+\. .+$/gm) || []).map((h) => h.replace(/^##\s*/, '')),
  };
}

/** Rows of a GitHub Markdown table under a given heading. */
function tableUnder(markdown, heading, { skipHeader = true } = {}) {
  const at = markdown.indexOf(heading);
  if (at === -1) return [];
  const lines = markdown.slice(at + heading.length).split('\n');
  const rows = [];
  let started = false;
  for (const line of lines) {
    const isRow = line.trim().startsWith('|');
    if (!isRow) {
      if (started) break;
      continue;
    }
    started = true;
    if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue;
    rows.push(
      line
        .trim()
        .replace(/^\|/, '')
        .replace(/\|$/, '')
        .split('|')
        .map((c) => c.trim()),
    );
  }
  return skipHeader ? rows : rows;
}

function parseAgentTable(readme) {
  // Read from the compatibility records, not from the README's rendering of
  // them. This function used to parse that table and infer a level by matching
  // the status words — `/^Enforcing, tested/`, `/^Enforcing/`, `/Installer
  // only/` — and when the status words changed, every one of those stopped
  // matching and every agent on the home page fell through to the worst
  // level. Five green pips went grey and no test noticed, because the tests
  // compared the README's words to the site's words and the two still agreed.
  //
  // Deriving from the same records `doctor` reads removes the inference. The
  // README is still checked below, but as a cross-check rather than as the
  // source: if the generated table and these records ever disagree about an
  // agent, that is a build failure and not a quiet downgrade.
  const records = loadCompatibility();
  if (!records.length) throw new Error('no compatibility records — the agent facts cannot be built');

  const shipped = records.filter((a) => a.adapter);
  const agents = shipped.map((a) => {
    const level = assess(a).level;
    return {
      agent: a.name,
      status: LEVEL_LABEL[level] ?? level,
      how: deriveVerification(a),
      // Green only when something has actually been run inside the real agent.
      // Amber when the contract or the transport has been established and the
      // agent itself has not. Grey is for an integration nothing supports.
      level:
        deriveVerification(a) === 'LIVE VERIFIED'
          ? 'verified'
          : deriveVerification(a) === 'UNVERIFIED'
            ? 'none'
            : 'unverified',
    };
  });

  // The cross-check. The README block is generated from these same records, so
  // a disagreement means one of the two generators has drifted.
  const rows = tableUnder(readme, '## Agent support').filter(
    (r) => r.length >= 3 && r[0] && !/^Agent$/i.test(r[0]),
  );
  for (const { agent, status, how } of agents) {
    const row = rows.find((r) => r[0].replace(/\*\*/g, '') === agent);
    if (!row) {
      throw new Error(
        `README.md's agent table has no row for ${agent}, which compatibility/ says ships an ` +
          `adapter. Run: npm run gen:readme`,
      );
    }
    if (row[1] !== status || row[2] !== how) {
      throw new Error(
        `README.md says ${agent} is "${row[1]} / ${row[2]}" and the compatibility record derives ` +
          `"${status} / ${how}". Run: npm run gen:readme`,
      );
    }
  }
  return agents;
}

/**
 * What each host does when the hook itself fails.
 *
 * This exists because the site said "it fails open" as a flat property of
 * LeastGrant, in a callout, in a page description, and on the home page. That
 * was true when Claude Code was the only agent it ran under. It is now false
 * for three of the five shipped adapters, and false in the direction that
 * matters: a Cursor user reading it would expect a crashed hook to let the call
 * through, when it actually blocks the call.
 *
 * Derived rather than written, so it cannot go stale again the way the sentence
 * it replaced did. `onCrash` is the honest axis to split on — every shipped
 * record has probe or source evidence for it, whereas Copilot's timeout
 * behaviour is still `unknown` and must not be rounded up to match its crash
 * behaviour.
 */
function parseFailureModes() {
  const shipped = loadCompatibility().filter((a) => a.adapter);
  const open = [];
  const closed = [];
  const unknown = [];
  for (const a of shipped) {
    const v = a.failure?.onCrash?.value;
    if (v === 'closed') closed.push(a.name);
    else if (v === 'open') open.push(a.name);
    else unknown.push(a.name);
  }
  if (unknown.length) {
    throw new Error(
      `compatibility/ has no onCrash value for ${unknown.join(', ')}. The website states what ` +
        `happens when the hook fails, and cannot state it for an agent whose record does not say.`,
    );
  }
  if (!open.length || !closed.length) {
    throw new Error(
      `every shipped adapter now fails ${open.length ? 'open' : 'closed'} on crash. The site ` +
        `copy contrasts the two cases, so it needs rewriting rather than regenerating.`,
    );
  }
  // Only claim a *timeout* fails closed where the record actually says so.
  const closedOnTimeout = shipped
    .filter((a) => a.failure?.onTimeout?.value === 'closed')
    .map((a) => a.name);
  return { open, closed, closedOnTimeout, total: shipped.length };
}

function parseOrderTable(readme) {
  const rows = tableUnder(readme, '## How it decides');
  return rows
    .filter((r) => r.length >= 3 && /^\d+$/.test(r[0]))
    .map(([n, name, effect]) => ({
      n: Number(n),
      name: name.replace(/\*\*/g, ''),
      effect,
      verdict: (effect.match(/^`(allow|ask|deny)`/) || [])[1] || 'ask',
    }));
}

function parseEvidenceTable(readme) {
  const rows = tableUnder(readme, '### Evidence is typed by how it was obtained');
  return rows
    .filter((r) => r.length >= 3 && /^\*\*/.test(r[0]))
    .map(([kind, means, promotes]) => ({
      kind: kind.replace(/\*\*/g, ''),
      means,
      promotes,
    }));
}

function parsePromotionTable(readme) {
  const rows = tableUnder(readme, '### How much evidence, exactly');
  return rows
    .filter((r) => r.length >= 3 && /^\d+$/.test(r[0]))
    .map(([approvals, confidence, unlocks]) => ({ approvals, confidence, unlocks }));
}

function parsePostureTable(readme) {
  const rows = tableUnder(readme, '## Settings');
  return rows
    .filter((r) => r.length >= 2 && /^`/.test(r[0]))
    .map(([name, blurb]) => ({
      name: name.replace(/`/g, ''),
      blurb,
      isDefault: /\*\*default\.\*\*/.test(blurb),
    }));
}
