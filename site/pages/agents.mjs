/**
 * The Agents reference.
 *
 * An index and one page per agent, generated entirely from `compatibility/*.json`
 * — the same records `leastgrant doctor` reads and the README table is built
 * from. Not one fact on these pages is written here.
 *
 * The page this replaced was 2,217 characters of prose that re-parsed the
 * README's own table, and it carried three claims the data had already
 * outgrown: status wording from two releases ago, a Cursor caveat pinned in
 * HTML, and an adapter line count that was wrong by half. That is what a
 * hand-written view of generated data decays into.
 *
 * The organising idea is that "supported" is not a boolean and must never be
 * rendered as one. Two independent axes are shown side by side and never
 * collapsed:
 *
 *   enforcement   how much of a verdict survives the trip through this agent
 *   verification  what has actually been RUN to establish that
 *
 * An adapter can be strong on the first and weak on the second — Antigravity is
 * exactly that today, with the best ask semantics of any agent here and nothing
 * having exercised them. Showing one number would have to lie about one of them.
 */

import { esc, attr } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';
import { LEVEL_LABEL } from '../../dist/src/core/compatibility.js';

/** Cell text for a verdict value, and how worried to look about it. */
const VERDICT = {
  honoured: ['yes', 'ok'],
  ignored: ['ignored', 'bad'],
  unsupported: ['none', 'bad'],
  degrades: ['degrades', 'warn'],
  partial: ['partial', 'warn'],
  unknown: ['unknown', 'warn'],
};

const INTERCEPT = {
  gated: ['gated', 'ok'],
  observed: ['seen after', 'warn'],
  none: ['not covered', 'bad'],
  unknown: ['unknown', 'warn'],
};

const GRADE_TONE = {
  'LIVE VERIFIED': 'ok',
  'REAL TRANSPORT PROBED': 'ok',
  'CONTRACT / BINARY VERIFIED': 'warn',
  'CONFORMANCE TESTED': 'warn',
  UNVERIFIED: 'bad',
};

const fact = (o, group, key) => o?.[group]?.[key];
const val = (o, group, key) => String(fact(o, group, key)?.value ?? 'unknown');
const note = (o, group, key) => fact(o, group, key)?.note ?? '';
const evidence = (o, group, key) => fact(o, group, key)?.evidence ?? 'unknown';

const EVIDENCE_WORD = {
  probe: 'someone ran it',
  source: 'read from the shipped build',
  docs: 'from official documentation',
  unknown: 'not established',
};

/** A value with its evidence grade attached, because the two travel together. */
function graded(o, group, key) {
  const f = fact(o, group, key);
  if (!f) return '<td class="u">—</td>';
  const map = group === 'interception' ? INTERCEPT : VERDICT;
  const [word, tone] = map[String(f.value)] ?? [String(f.value), 'warn'];
  return `<td class="v" data-tone="${attr(tone)}"><span>${esc(word)}</span><em title="${attr(
    EVIDENCE_WORD[f.evidence ?? 'unknown'],
  )}">${esc(f.evidence ?? '?')}</em></td>`;
}

function runLine(kind, run, label) {
  if (!run) return `<li class="u"><strong>${esc(label)}</strong> — no record</li>`;
  if (!run.done) {
    return `<li data-done="no"><strong>${esc(label)}</strong> — not done. ${esc(
      run.blockedBy ?? 'no reason recorded',
    )}</li>`;
  }
  const where = [run.version, (run.os ?? []).join(', '), run.date].filter(Boolean).join(' · ');
  return `<li data-done="yes"><strong>${esc(label)}</strong> — ${esc(run.what ?? '')} <span class="where">${esc(
    where,
  )}</span></li>`;
}

/**
 * One page per agent. Every heading below answers a question somebody choosing
 * an agent actually has, in the order they would ask it.
 */
export function agentPage(facts, a, assessment, grade, gradeMeaning) {
  const tone = GRADE_TONE[grade] ?? 'warn';
  const limits = [...(a.upstreamLimitations ?? []), ...(a.leastgrantLimitations ?? [])];
  const modes = Array.isArray(a.modes?.known) ? a.modes.known : [];
  const askSurvives = Array.isArray(a.modes?.askSurvives) ? a.modes.askSurvives : [];
  const v = a.verification ?? {};

  const interceptRows = Object.entries(a.interception ?? {})
    .map(
      ([k, f]) => `<tr><th>${esc(humanise(k))}</th>${graded(a, 'interception', k)}<td class="n">${esc(
        f?.note ?? '',
      )}</td></tr>`,
    )
    .join('\n        ');

  const body = `<div class="shell doc">
    <article class="doc-body prose">
      <p class="source-note">Generated from
        <a href="${attr(a.repoFile)}" rel="noopener noreferrer">compatibility/${esc(a.id)}.json</a>,
        the same record <code>leastgrant doctor</code> reads. Last verified ${esc(a.lastVerified)}.</p>

      <p class="eyebrow"><a href="/docs/agents/">all agents</a></p>
      <h1>${esc(a.name)}</h1>

      <div class="badges">
        <span class="badge" data-tone="${attr(toneOf(assessment.level))}">${esc(LEVEL_LABEL[assessment.level] ?? assessment.level)}</span>
        <span class="badge" data-tone="${attr(tone)}">${esc(grade)}</span>
        <span class="badge" data-tone="info">${esc(a.versionTested)}</span>
        <span class="badge" data-tone="info">${esc((a.osTested ?? []).join(', ') || 'no OS recorded')}</span>
      </div>

      <p class="lede">${esc(gradeMeaning)}.</p>

      <h2 id="what-it-does">How it attaches</h2>
      <p>${esc(a.mechanism ?? 'No integration mechanism recorded.')}</p>
      ${
        a.install
          ? `<p>Install it with <code>${esc(a.install)}</code>. Configuration is written to
             <code>${esc(a.configPath ?? 'the agent’s own settings file')}</code>, alongside anything
             already there — LeastGrant never removes a hook it did not add.</p>`
          : `<p><strong>No adapter ships for this agent.</strong> ${esc(a.deferredBecause ?? '')}</p>`
      }

      <h2 id="verdicts">What a verdict does here</h2>
      <p>The three verdicts do not travel equally well. This is the table that decides whether
        LeastGrant is a prompt, a veto, or a suggestion on this agent.</p>
      <table class="matrix">
        <thead><tr><th>verdict</th><th>lands?</th><th>what actually happens</th></tr></thead>
        <tbody>
          <tr><th>allow</th>${graded(a, 'verdicts', 'allow')}<td class="n">${esc(note(a, 'verdicts', 'allow'))}</td></tr>
          <tr><th>ask</th>${graded(a, 'verdicts', 'ask')}<td class="n">${esc(note(a, 'verdicts', 'ask'))}</td></tr>
          <tr><th>deny</th>${graded(a, 'verdicts', 'deny')}<td class="n">${esc(note(a, 'verdicts', 'deny'))}</td></tr>
        </tbody>
      </table>

      <h2 id="interactive">Interactive and unattended</h2>
      <p>${
        a.modes?.exposesMode?.value
          ? `This agent tells the hook which permission mode it is in${
              note(a, 'modes', 'exposesMode') ? ` — ${esc(note(a, 'modes', 'exposesMode'))}` : '.'
            }`
          : 'This agent does not tell the hook which mode it is in, so LeastGrant cannot distinguish an attended session from an unattended one and treats every session as unattended.'
      }</p>
      ${
        modes.length
          ? `<p>Modes it reports: ${modes.map((m) => `<code>${esc(m)}</code>`).join(', ')}.
             ${
               askSurvives.length
                 ? `An <code>ask</code> reaches a person in ${askSurvives
                     .map((m) => `<code>${esc(m)}</code>`)
                     .join(', ')}.`
                 : '<strong>An <code>ask</code> reaches a person in none of them.</strong>'
             }
             ${esc(a.modes?.askSurvivesNote ?? '')}</p>`
          : ''
      }

      <h2 id="failure">When the hook breaks</h2>
      <p>The question nobody asks until it matters: if LeastGrant crashes, times out, or cannot
        start, does the tool call still run?</p>
      <ul class="facts">
        <li><strong>On crash</strong> — ${esc(val(a, 'failure', 'onCrash') === 'closed' ? 'the call is refused' : val(a, 'failure', 'onCrash') === 'open' ? 'the call runs anyway' : 'not established')}.
          <em>(${esc(evidence(a, 'failure', 'onCrash'))})</em> ${esc(note(a, 'failure', 'onCrash'))}</li>
        <li><strong>On timeout</strong> — ${esc(val(a, 'failure', 'onTimeout') === 'closed' ? 'the call is refused' : val(a, 'failure', 'onTimeout') === 'open' ? 'the call runs anyway' : 'not established')},
          after ${esc(String(val(a, 'failure', 'timeoutDefaultSeconds')))}s by default.
          ${esc(note(a, 'failure', 'onTimeout'))}</li>
        <li><strong>Can it be made to fail closed?</strong> —
          ${val(a, 'failure', 'canFailClosed') === 'true' ? 'yes' : 'no'}.
          ${esc(note(a, 'failure', 'canFailClosed'))}</li>
      </ul>

      <h2 id="coverage">What it can see</h2>
      <p>A verdict is only worth as much as the set of actions it is asked about. <em>gated</em>
        means LeastGrant is consulted before the thing happens; <em>seen after</em> means it is told
        afterwards and can at best withhold the result; <em>not covered</em> means the action
        happens with LeastGrant never hearing about it.</p>
      <table class="matrix">
        <thead><tr><th>tool class</th><th>coverage</th><th>detail</th></tr></thead>
        <tbody>
        ${interceptRows}
        </tbody>
      </table>

      <h2 id="verification">What has actually been run</h2>
      <p>Four different things, deliberately not collapsed into one badge. Reproducing an agent's
        invocation is not running the agent; a passing conformance suite says our side is right and
        nothing about whether the host ever calls us.</p>
      <ul class="runs">
        ${runLine('live', v.live, 'Live agent test')}
        ${runLine('transport', v.transport, 'Real transport probed')}
        ${runLine('contract', v.contract, 'Contract read from the shipped build')}
        ${runLine('conformance', v.conformance, 'Conformance suite')}
      </ul>
      ${
        (a.osUntested ?? []).length
          ? `<p>Not exercised on ${(a.osUntested ?? []).map((o) => `<code>${esc(o)}</code>`).join(', ')}.</p>`
          : ''
      }

      <h2 id="limitations">What it cannot do</h2>
      <p>Not a disclaimer. The point of everything above is that this list exists and is specific.</p>
      <ul class="limits">
        ${limits.map((l) => `<li>${esc(l)}</li>`).join('\n        ') || '<li>Nothing recorded.</li>'}
      </ul>
    </article>
  </div>`;

  return page({
    path: `/docs/agents/${a.id}/`,
    title: `${a.name} — agent support`,
    description:
      `How LeastGrant enforces inside ${a.name}: what each verdict does, what it can see, ` +
      `how it fails, and exactly what has been run to establish that. ${grade}.`,
    body,
  });
}

const humanise = (k) =>
  ({
    shell: 'shell commands',
    fileRead: 'file reads',
    fileWrite: 'file writes',
    fileDelete: 'deletions',
    mcp: 'MCP calls',
    subagentSpawn: 'subagent spawn',
    network: 'network / web',
  })[k] ?? k;

const toneOf = (level) =>
  ({ enforcing: 'ok', partial: 'warn', degraded: 'warn', unverified: 'bad', none: 'bad' })[level] ?? 'warn';

/** The index: one row per agent, and the two axes side by side. */
export function agentsIndex(facts, entries) {
  const rows = entries
    .map(({ agent: a, assessment, grade }) => {
      const tone = GRADE_TONE[grade] ?? 'warn';
      return `<tr>
        <th><a href="/docs/agents/${attr(a.id)}/">${esc(a.name)}</a></th>
        <td class="v" data-tone="${attr(toneOf(assessment.level))}"><span>${esc(LEVEL_LABEL[assessment.level] ?? assessment.level)}</span></td>
        <td class="v" data-tone="${attr(tone)}"><span>${esc(grade)}</span></td>
        ${graded(a, 'verdicts', 'ask')}
        ${graded(a, 'verdicts', 'deny')}
        <td class="n">${esc(a.versionTested)} · ${esc((a.osTested ?? []).join(', ') || '—')}</td>
      </tr>`;
    })
    .join('\n        ');

  const body = `<div class="shell doc">
    <article class="doc-body prose">
      <p class="source-note">Generated from
        <a href="${attr(facts.repo)}/tree/main/compatibility" rel="noopener noreferrer">compatibility/</a>,
        the same records <code>leastgrant doctor</code> and the README table read.</p>

      <h1>Agent support</h1>
      <p>One profile and one set of floors, whichever agent you are using that day. Every adapter
        calls the same <code>judgePre</code> and <code>recordPost</code>, so there is one decision
        path rather than one per editor — a security story that changes depending on which editor
        you opened is not a security story.</p>
      <p>What differs is how much of a decision survives the trip out. These pages are the honest
        version of that, per agent, and they are worth reading even if you never install
        LeastGrant: the differences between these permission systems are real and mostly
        undocumented.</p>

      <h2 id="matrix">The two questions</h2>
      <p><strong>Enforcement</strong> is how much of a verdict lands. <strong>Verification</strong>
        is what has been run to establish that. They are separate on purpose: an agent can have the
        best permission semantics here and still have had nothing exercise them.</p>
      <table class="matrix">
        <thead><tr>
          <th>agent</th><th>enforcement</th><th>verification</th><th>ask</th><th>deny</th><th>tested against</th>
        </tr></thead>
        <tbody>
        ${rows}
        </tbody>
      </table>

      <h2 id="caveats">The one thing to know about each</h2>
      <p>Every agent has a sharpest edge. Carrying it here rather than only on the per-agent page is
        deliberate: a support table read on its own is exactly where somebody forms the belief that
        an integration is complete.</p>
      <ul class="limits">
        ${entries
          .map(({ agent: a }) => {
            const first = (a.upstreamLimitations ?? [])[0] ?? (a.leastgrantLimitations ?? [])[0];
            if (!first) return '';
            return `<li><a href="/docs/agents/${attr(a.id)}/"><strong>${esc(a.name)}</strong></a> — ${esc(first)}</li>`;
          })
          .filter(Boolean)
          .join('\n        ')}
      </ul>

      <h2 id="grades">What the verification grades mean</h2>
      <p>These are not a ladder of politeness. Each one names a different thing that was done, and
        the gap between the first two is where a real bug lived: LeastGrant refused every tool call
        on Cursor for a full release because its Windows transport prefixes a byte-order mark, and
        nothing short of reproducing that transport would have found it.</p>
      <dl class="grades">
        ${entries
          .map(({ grade }) => grade)
          .filter((g, i, all) => all.indexOf(g) === i)
          .map(
            (g) =>
              `<dt data-tone="${attr(GRADE_TONE[g] ?? 'warn')}">${esc(g)}</dt><dd>${esc(
                facts.gradeMeaning[g] ?? '',
              )}.</dd>`,
          )
          .join('\n        ')}
      </dl>

      <h2 id="adding">Adding one</h2>
      <p>An adapter is a translation layer over the shared engine, and it cannot ship without a
        record like the ones above: the build fails if an adapter has no compatibility file, if the
        conformance suite does not drive it, or if its record claims more than the runs it lists.
        <a href="/docs/contributing/">Contributing</a> has the shape of it.</p>
    </article>
  </div>`;

  return page({
    path: '/docs/agents/',
    title: 'Agent support',
    description:
      'How permission enforcement differs between Claude Code, Codex, Copilot, Cursor and ' +
      'Antigravity: what each verdict does, what each agent can see, and what has been run.',
    body,
  });
}
