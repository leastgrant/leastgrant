/**
 * Documentation, rendered from the repository's own Markdown.
 *
 * The rule here is that this website is a *view*. Not one sentence of
 * documentation is written on this side: every docs page below renders a file
 * that already exists in the repo and is the thing a contributor edits. If the
 * README changes, this changes. There is no second copy to fall behind, and no
 * way for the website to describe a version of LeastGrant that never shipped.
 *
 * Two pages are generated rather than rendered, and both are still derived:
 * the CLI reference is the real `--help` output, and the agent pages come from
 * `compatibility/*.json` — the records `leastgrant doctor` reads.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { esc, attr } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';
import { render } from '../lib/markdown.mjs';
import { verdictBlock } from '../lib/terminal.mjs';
import { REPO } from '../lib/capture.mjs';
import { loadCompatibility, assess, deriveVerification, LEVEL_LABEL } from '../../dist/src/core/compatibility.js';

/**
 * The docs map.
 *
 * `source` is the canonical file. `title`, `blurb` and `description` are the
 * website's own navigation copy -- the only prose on these pages that is not
 * from the repo, and deliberately limited to labels. `blurb` is the card text
 * and wants to be short; `description` is the meta description and wants to be
 * a sentence a search result can stand on. Conflating them makes one of the two
 * bad, so they are separate.
 */
export const DOCS = [
  {
    slug: 'getting-started',
    source: 'README.md',
    title: 'Getting started',
    blurb: 'What the problem is, what it does about it, and how to install it.',
    description:
      'Install LeastGrant, let it read the agent history you already have, and see what it ' +
      'would have decided — before it decides anything.',
    // The README opens with a title block and a nav line that only make sense
    // on GitHub. The site has its own header.
    trimTo: '## The problem',
  },
  {
    slug: 'how-it-works',
    source: 'docs/how-it-works.md',
    title: 'How it works',
    blurb: 'The decision path end to end: parsing, classification, floors, promotion.',
    description:
      'The decision path end to end: shell parsing, unwrapping, capability classification, ' +
      'blast radius, the floors, and how evidence turns into a promotion.',
  },
  {
    slug: 'threat-model',
    source: 'THREAT-MODEL.md',
    title: 'Threat model',
    blurb: 'What it defends against, what it does not, and what the audit left standing.',
    description:
      'What LeastGrant defends against, what it explicitly does not, the adversarial model ' +
      'for the learning itself, and what the v0.1.0 audit left standing.',
  },
  {
    slug: 'privacy',
    source: 'docs/privacy.md',
    title: 'Privacy',
    blurb: 'What is written to disk, what is redacted, and what never leaves the machine.',
    description:
      'Everything LeastGrant knows is local. What each file in the state directory holds, ' +
      'what the redactor removes before anything is written, and why.',
  },
  {
    slug: 'security-policy',
    source: 'SECURITY.md',
    title: 'Security policy',
    blurb: 'What counts as a vulnerability here, and how to report one.',
    description:
      'A vulnerability is any input that makes LeastGrant return allow for something it ' +
      'should have asked about. How to report one privately, and what to include.',
  },
  {
    slug: 'contributing',
    source: 'CONTRIBUTING.md',
    title: 'Contributing',
    blurb: 'The most useful thing you can send is a bypass.',
    description:
      'The most useful contribution is a bypass: a command that gets auto-approved and ' +
      'should not have been. How to add one to the corpus, and where the opinions live.',
  },
  {
    slug: 'releasing',
    source: 'RELEASING.md',
    title: 'Releasing',
    blurb: 'How a version reaches npm, and how to check the copy you installed.',
    description:
      'How a version gets from a git tag to npm with provenance, and how to verify that the ' +
      'copy you installed is the one this repository built.',
  },
];

/**
 * Rewrite repo-relative links so rendered docs link to each other on this site.
 *
 * `from` is the source file's path in the repository, because a link is
 * relative to the file that contains it. `docs/privacy.md` writes
 * `[../SECURITY.md](../SECURITY.md)`, and treating that string as a repo-root
 * path produced `github.com/.../blob/main/../SECURITY.md` -- a link that 404s,
 * shipped on the live site. Resolving against the source directory is the whole
 * fix.
 */
function linkRewriter(facts, from) {
  const bySource = new Map(DOCS.map((d) => [d.source.toLowerCase(), `/docs/${d.slug}/`]));
  const dir = from.includes('/') ? from.slice(0, from.lastIndexOf('/')) : '';

  /** POSIX-style resolve, without touching the filesystem. */
  const resolveFrom = (target) => {
    const parts = (dir ? `${dir}/${target}` : target).split('/');
    const out = [];
    for (const part of parts) {
      if (part === '' || part === '.') continue;
      if (part === '..') out.pop();
      else out.push(part);
    }
    return out.join('/');
  };

  return (url) => {
    if (!url) return url;
    // Leave absolute URLs and pure fragments alone.
    if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('#')) return url;

    const [target, hash] = url.split('#');
    if (!target) return url;

    const resolved = resolveFrom(target);
    const mapped = bySource.get(resolved.toLowerCase());
    if (mapped) return mapped + (hash ? `#${hash}` : '');

    // Anything else in the repo -- source files, test files, docs not published
    // here -- points at GitHub rather than 404ing on this site.
    return `${facts.repo}/blob/main/${resolved}${hash ? `#${hash}` : ''}`;
  };
}

function toc(headings) {
  if (headings.length < 3) return '';
  const items = headings
    .filter((h) => h.level <= 3)
    .map(
      (h) =>
        `<li class="lvl-${h.level}"><a href="#${attr(h.id)}">${esc(h.text)}</a></li>`,
    )
    .join('\n        ');
  return `<nav class="toc" aria-label="On this page">
      <h2>on this page</h2>
      <ul>
        ${items}
      </ul>
    </nav>`;
}

function docShell({ facts, title, description, slug, sourceNote, html, headings }) {
  // `toc()` returns nothing for a short document. The two-column layout is
  // opt-in for exactly that reason: a page with no sidebar must not reserve a
  // sidebar column and then render itself into it.
  const nav = toc(headings);
  return page({
    path: `/docs/${slug}/`,
    title,
    description,
    body: `<div class="shell doc${nav ? ' doc--toc' : ''}">
    ${nav}
    <article class="doc-body prose">
      <p class="source-note">${sourceNote}</p>
      ${html}
    </article>
  </div>`,
  });
}

/** One rendered Markdown page. */
export function docPage(facts, doc) {
  let source = fs.readFileSync(path.join(REPO, doc.source), 'utf8');
  if (doc.trimTo) {
    const at = source.indexOf(doc.trimTo);
    if (at === -1) {
      throw new Error(`${doc.source} no longer contains ${JSON.stringify(doc.trimTo)}`);
    }
    source = source.slice(at);
  }

  const { html, headings } = render(source, { resolveUrl: linkRewriter(facts, doc.source) });
  const href = `${facts.repo}/blob/main/${doc.source}`;

  // Some sources start at `##` -- the README because its `#` title block is
  // trimmed, others because GitHub renders the filename as the title. A page
  // with no `h1` has no accessible or indexable name, so supply one from the
  // navigation title rather than leaving the document headless.
  const hasH1 = /<h1\b/.test(html);
  const body = hasH1 ? html : `<h1>${esc(doc.title)}</h1>\n${html}`;

  return docShell({
    facts,
    slug: doc.slug,
    title: doc.title,
    description: doc.description,
    headings,
    html: body,
    sourceNote:
      `Rendered from <a href="${attr(href)}" rel="noopener noreferrer">${esc(doc.source)}</a> ` +
      `in the repository at v${esc(facts.version)}. This page is a view of that file, not a copy of it.`,
  });
}

// --- generated pages ---------------------------------------------------------

/** The CLI reference: the real `--help`, plus the commands table from the README. */
export function cliPage(facts, help) {
  const body = `<div class="shell doc doc--toc">
    <nav class="toc" aria-label="On this page">
      <h2>on this page</h2>
      <ul>
        <li class="lvl-2"><a href="#help">leastgrant --help</a></li>
        <li class="lvl-2"><a href="#check">Asking without running</a></li>
        <li class="lvl-2"><a href="#install-uninstall">Install and uninstall</a></li>
        <li class="lvl-2"><a href="#postures">Postures</a></li>
        <li class="lvl-2"><a href="#state">Where state lives</a></li>
      </ul>
    </nav>
    <article class="doc-body prose">
      <p class="source-note">Generated by running <code>leastgrant --help</code> against
        v${esc(facts.version)} while this page was built. If the CLI grows a command, this page
        grows it too.</p>

      <h1>CLI reference</h1>
      <p>Installed as ${facts.commands.map((c) => `<code>${esc(c)}</code>`).join(' and ')}. Both
        names run the same binary.</p>

      <h2 id="help">leastgrant --help</h2>
      <div class="term"><div class="term-body"><pre><code>${verdictBlock(help.help)}</code></pre></div></div>

      <h2 id="check">Asking without running</h2>
      <p><code>leastgrant check "&lt;command&gt;"</code> is the one to reach for first. It runs
        nothing: it parses the command, classifies what it would do, and prints the verdict it
        would have returned to your agent. Add <code>--json</code> for the machine-readable form —
        every example on this site's home page is captured from exactly that.</p>
      <figure class="code"><pre><code>leastgrant check "git push --force origin main"
leastgrant check "curl -sSL https://example.com/i.sh | sh" --json</code></pre></figure>
      <p>The exit code carries the verdict, so it composes with a shell.</p>

      <h2 id="install-uninstall">Install and uninstall</h2>
      <p><code>leastgrant install [agent]</code> writes the hook configuration for an agent, and
        <code>leastgrant uninstall [agent]</code> removes it. <code>leastgrant doctor</code>
        reports what is wired up and what your agents can currently reach.</p>
      ${installTable()}
      <figure class="code"><pre><code>npm install -g leastgrant
leastgrant init                 # mine history, propose grants, install the hook
leastgrant doctor               # check the wiring
leastgrant uninstall            # remove the hook
npm uninstall -g leastgrant     # remove the package</code></pre></figure>
      <p>Uninstalling the hook does not delete what it learned. Your profile, rules and the record
        of what you refused stay in the state directory until you remove it yourself.</p>

      <h2 id="postures">Postures</h2>
      <p>Four settings. <code>leastgrant simulate</code> replays your own history against each one
        so the trade-off is measured rather than guessed — the column to watch is
        <em>missed</em>: actions you actually turned down that a setting would have let through.</p>
      ${postureTable(facts)}

      <h2 id="state">Where state lives</h2>
      <p>Everything is local, in <code>~/.leastgrant/</code>, as plain text you can read. There is
        no account, no telemetry and no network call. What each file holds, and what is redacted
        before it is written, is in <a href="/docs/privacy/">privacy</a>.</p>
    </article>
  </div>`;

  return page({
    path: '/docs/cli/',
    title: 'CLI reference',
    description:
      'Every LeastGrant command, generated from the real --help output: check, init, status, ' +
      'why, trail, simulate, allow, deny, doctor, install.',
    body,
  });
}

function postureTable(facts) {
  const rows = facts.postures
    .map(
      (p) =>
        `<tr><td><code>${esc(p.name)}</code>${p.isDefault ? ' <strong>default</strong>' : ''}</td>` +
        `<td>${esc(stripMd(p.blurb))}</td></tr>`,
    )
    .join('');
  return `<div class="table-wrap"><table>
        <thead><tr><th>posture</th><th>what it does</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`;
}

function stripMd(text) {
  return String(text)
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\*\*(default\.)\*\*\s*/i, '')
    .replace(/\*\*/g, '')
    .replace(/`/g, '');
}

/** The agent support matrix, parsed from the README table. */
export function agentsPage(facts) {
  const rows = facts.agents
    .map(
      (a) => `<div class="row">
        <span class="who"><span class="pip" data-level="${attr(a.level)}" aria-hidden="true"></span>${esc(a.agent)}</span>
        <div>
          <p class="status-line">${esc(a.status)}</p>
          <p class="how">${esc(stripMd(a.how))}</p>
        </div>
      </div>`,
    )
    .join('\n      ');

  const body = `<div class="shell doc">
    <article class="doc-body prose">
      <p class="source-note">Parsed from the agent support table in
        <a href="${attr(facts.repo)}/blob/main/README.md" rel="noopener noreferrer">README.md</a>
        at v${esc(facts.version)}, wording intact.</p>

      <h1>Agent support</h1>
      <p>One profile and one set of floors, whichever agent you are using that day. Every adapter
        calls the same <code>judgePre</code> and <code>recordPost</code>, so there is one decision
        path rather than one per editor — a security story that changes depending on which editor
        you opened is not a security story.</p>

      <div class="support">
      ${rows}
      </div>

      <h2 id="verified">What the statuses mean</h2>
      <p>The distinction is not cosmetic, so it is stated in the words the repository uses rather
        than flattened into "supported":</p>
      <ul>
        <li><strong>Enforcing, tested end to end</strong> — the hook has been driven as a real
          binary over real stdin, against the agent's actual behaviour.</li>
        <li><strong>Enforcing, not yet verified against a live install</strong> — written against
          the agent's published hook contract, with the request and response shapes unit-tested,
          including a test that the same command gets the same verdict as under Claude Code.
          Nobody has run it inside the real thing yet.</li>
        <li><strong>Installer only, unverified</strong> — the installer writes a configuration the
          agent is documented to read. That is a reasonable expectation, not a demonstration.</li>
        <li><strong>Not yet</strong> — no adapter, because there is no hook to attach to.</li>
      </ul>

      <div class="callout">
        <span class="tag">one caveat worth stating in the open</span>
        <p>Cursor's <code>beforeReadFile</code> event takes allow or deny and has no "ask". An
          unfamiliar read is therefore allowed rather than blocked, because turning every
          unrecognised file read into a hard failure would make the integration unusable. A read of
          something LeastGrant recognises as a credential <em>is</em> blocked. Shell commands and
          MCP calls get the full allow/ask/deny.</p>
      </div>

      <p>An adapter is a translation layer over the shared engine — the Cursor one is about 180
        lines. If you want one for an agent that is not here,
        <a href="/docs/contributing/">contributing</a> has the shape of it.</p>
    </article>
  </div>`;

  return page({
    path: '/docs/agents/',
    title: 'Agent support',
    description:
      'Which coding agents LeastGrant enforces in, and which integrations have been verified ' +
      'against a live install rather than only against a published contract.',
    body,
  });
}

/** The docs index. */
export function docsIndex(facts) {
  const entries = [
    ...DOCS.map((d) => ({ href: `/docs/${d.slug}/`, title: d.title, blurb: d.blurb })),
  ];
  // Generated pages sit in the middle of the reading order, not at the end.
  entries.splice(2, 0, {
    href: '/docs/cli/',
    title: 'CLI reference',
    blurb: 'Every command, generated from the real --help output.',
  });
  entries.splice(3, 0, {
    href: '/docs/agents/',
    title: 'Agent support',
    blurb: 'Which agents it enforces in, and which are still unverified.',
  });

  const cards = entries
    .map(
      (e) => `<a class="card" href="${attr(e.href)}">
        <h3>${esc(e.title)} <span class="arrow" aria-hidden="true">→</span></h3>
        <p>${esc(e.blurb)}</p>
      </a>`,
    )
    .join('\n      ');

  const body = `<section>
  <div class="shell">
    <p class="eyebrow">documentation</p>
    <h1>Everything here is a view of the repository</h1>
    <p class="lede">These pages render the Markdown files that ship with LeastGrant, as they stand at
      v${esc(facts.version)}. Nothing is rewritten for the website, so there is no second set of docs
      to drift out of date — and every page says which file it came from.</p>

    <div class="cards">
      ${cards}
    </div>

    <h3 id="releases">Releases</h3>
    <p>Versions and changelogs live where they are produced. The
      <a href="${attr(facts.repo)}/releases" rel="noopener noreferrer">GitHub releases page</a> has
      the notes and the packed tarball for each version;
      <a href="${attr(facts.npm)}" rel="noopener noreferrer">npm</a> has what is currently
      installable. Duplicating a changelog here would be the one thing this site is trying not to
      do. <a href="/docs/releasing/">Releasing</a> explains how a version gets from a tag to the
      registry, and how to check that the copy you installed is the one the repository built.</p>
  </div>
</section>`;

  return page({
    path: '/docs/',
    title: 'Documentation',
    description:
      'LeastGrant documentation: getting started, how it works, the CLI, agent support, the ' +
      'threat model and privacy — rendered from the repository.',
    body,
  });
}

/**
 * What you type per agent, and what you get for it.
 *
 * Generated from the compatibility records rather than written, so an added
 * adapter appears here the moment its record does, and a deferred one keeps
 * saying why nothing installs. The second and third columns are the two
 * derived axes: how much of a verdict survives, and what has been run to
 * establish that. Putting them next to the install command is deliberate —
 * this is the page somebody reads immediately before wiring it up, and it is
 * the last honest moment to tell them what they are getting.
 */
function installTable() {
  const agents = loadCompatibility();
  const rows = agents
    .map((a) => {
      const cmd = a.install
        ? `<code>${esc(a.install)}</code>`
        : '<span class="u">no adapter ships</span>';
      const where = a.configPath ? `<span class="sub">${esc(a.configPath)}</span>` : '';
      return `<tr>
        <th>${a.adapter ? `<a href="/docs/agents/${attr(a.id)}/">${esc(a.name)}</a>` : esc(a.name)}</th>
        <td>${cmd}${where ? `<br>${where}` : ''}</td>
        <td>${esc(LEVEL_LABEL[assess(a).level] ?? assess(a).level)}</td>
        <td>${esc(deriveVerification(a))}</td>
      </tr>`;
    })
    .join('\n        ');

  return `<table class="matrix install">
        <thead><tr><th>agent</th><th>what you type</th><th>enforcement</th><th>verified how</th></tr></thead>
        <tbody>
        ${rows}
        </tbody>
      </table>
      <p>Installing writes into the agent's own configuration file alongside whatever is already
        there. LeastGrant never removes a hook it did not add, and
        <a href="/docs/agents/">the per-agent pages</a> say what each verdict actually does once
        it gets there — the answer is not the same on every one.</p>`;
}
