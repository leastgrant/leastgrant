import { esc, attr, codeSpans } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';

/**
 * The compatibility page.
 *
 * Rendered from `compatibility/*.json` and graded by the same `assess()` in
 * core that `leastgrant doctor` calls, so the page and the CLI cannot come to
 * different conclusions about the same agent. Nothing here is written by hand.
 *
 * The hard part of a page like this is that it is mostly bad news, and a
 * support matrix is structurally bad at bad news: a gap becomes an empty cell,
 * and an empty cell reads as "fine". So the summary table carries words rather
 * than ticks, "not intercepted" is styled as loudly as "gated", and every agent
 * expands into the specifics underneath rather than hiding them in a footnote.
 *
 * It is deliberately the page most likely to talk somebody out of using this
 * with their agent. Someone who installs LeastGrant expecting it to gate file
 * writes in Cursor, and finds out later that Cursor has no such event, has been
 * misled by us — and that costs more than the install was worth.
 */

const CLASSES = [
  ['shell', 'shell'],
  ['fileRead', 'reads'],
  ['fileWrite', 'writes'],
  ['fileDelete', 'deletes'],
  ['mcp', 'MCP'],
];

const VERDICT_LABEL = {
  honoured: ['yes', 'ok'],
  degrades: ['degrades', 'warn'],
  partial: ['partial', 'warn'],
  unsupported: ['none', 'bad'],
  ignored: ['ignored', 'bad'],
  unknown: ['unknown', 'unknown'],
};

const REACH_LABEL = {
  gated: ['gated', 'ok'],
  observed: ['after the fact', 'warn'],
  partial: ['partial', 'warn'],
  none: ['not seen', 'bad'],
  unknown: ['unknown', 'unknown'],
};

const FAIL_LABEL = {
  closed: ['refuses', 'ok'],
  open: ['runs anyway', 'warn'],
  none: ['no timeout', 'bad'],
  unknown: ['unknown', 'unknown'],
};

/**
 * One graded cell, carrying how it was established.
 *
 * The page says "every claim on this page carries how it was established" and
 * then rendered 81 bare cells, so the sentence was false and the grading
 * vocabulary it introduced had nothing to attach to. The marker is the same
 * shorthand the per-agent pages use.
 */
const cell = (table, fact) => {
  const [text, tone] = table[String(val(fact))] ?? table['unknown'];
  const how = fact?.evidence;
  return (
    `<td><span class="cap" data-tone="${attr(tone)}">${esc(text)}</span>` +
    (how ? `<span class="ev" title="${attr(EVIDENCE_TITLE[how] ?? how)}">${esc(how)}</span>` : '') +
    '</td>'
  );
};

/** Spelled out on hover, because three of these are easy to read as synonyms. */
const EVIDENCE_TITLE = {
  probe: 'someone ran the real agent and watched this happen',
  source: 'read from the shipped binary or its documentation',
  inferred: 'derived from something else that was established',
  unknown: 'not established',
};

const val = (fact) => String(fact?.value ?? 'unknown');

export function compatibility(facts, assessments) {
  const rows = assessments
    .map(({ agent, level }) => {
      const shipped = Boolean(agent.adapter);
      return `<tr>
      <th scope="row"><a href="#${attr(agent.id)}">${esc(agent.name)}</a>
        <span class="ver">${esc(agent.versionTested)}</span></th>
      <td><span class="cap" data-tone="${attr(toneForLevel(level))}">${esc(level)}</span></td>
      ${shipped ? cell(VERDICT_LABEL, agent.verdicts.allow) : emptyCell()}
      ${shipped ? cell(VERDICT_LABEL, agent.verdicts.ask) : emptyCell()}
      ${shipped ? cell(VERDICT_LABEL, agent.verdicts.deny) : emptyCell()}
      ${shipped ? cell(FAIL_LABEL, agent.failure.onCrash) : emptyCell()}
      ${CLASSES.map(([k]) => (shipped ? cell(REACH_LABEL, agent.interception[k]) : emptyCell())).join('')}
    </tr>`;
    })
    .join('\n');

  const detail = assessments.map((a) => agentSection(a)).join('\n');

  const body = `<section>
  <div class="shell">
    <p class="eyebrow">compatibility</p>
    <h1>What survives the trip to your agent</h1>
    <p class="lede">The same policy runs everywhere. What reaches you at the other end does not.
      One agent turns an unanswerable question into a prompt, another into a refusal, and a third
      cannot see the tool call at all. This page says which, for each one, and how we know.</p>

    <div class="callout" data-tone="ask">
      <span class="tag">read the gaps, not the ticks</span>
      <p>This is the page most likely to talk you out of using LeastGrant with your agent, and it
        is written that way on purpose. Finding out after you install that your editor has no
        event for file writes is worse than not installing.</p>
    </div>
  </div>
</section>

<section>
  <div class="shell">
    <div class="table-wrap">
      <div class="table-wrap"><table class="matrix">
        <caption>Generated from <code>compatibility/</code> in the repository. Nothing here is typed by hand.</caption>
        <thead>
          <tr>
            <th scope="col">Agent</th>
            <th scope="col">Overall</th>
            <th scope="col">allow</th>
            <th scope="col">ask</th>
            <th scope="col">deny</th>
            <th scope="col">on hook error</th>
            ${CLASSES.map(([, label]) => `<th scope="col">${esc(label)}</th>`).join('')}
          </tr>
        </thead>
        <tbody>
${rows}
        </tbody>
      </table></div>
    </div>

    <h3>How the evidence is graded</h3>
    <p>Every graded cell in the table above carries how it was established, under the label,
      because the grades are not interchangeable and the difference has already mattered here.</p>
    <ul>
      <li><strong>probed</strong> — someone ran the real agent and watched this happen.</li>
      <li><strong>read</strong> — someone read the shipped binary. Strong evidence about the
        contract, none at all about the integration.</li>
      <li><strong>documented</strong> — the vendor says so. Weakest, and it never alone justifies
        the word verified: Cursor's own documentation says its hooks fail open by default, and
        reading what ships shows that depends on the failure kind.</li>
      <li><strong>unknown</strong> — nobody has checked. Printed as unknown rather than left
        blank, because a blank reads as fine.</li>
    </ul>
  </div>
</section>

${detail}`;

  return page({
    title: 'Compatibility — what LeastGrant enforces on each agent',
    description:
      'Which verdicts survive on Claude Code, Codex, Cursor, Copilot and others, what each agent cannot intercept, and how every claim was established.',
    path: '/compatibility/',
    body,
    facts,
  });
}

const emptyCell = () => '<td><span class="cap" data-tone="none">—</span></td>';

const toneForLevel = (level) =>
  level === 'enforcing' ? 'ok'
  : level === 'partial' ? 'warn'
  : level === 'degraded' ? 'warn'
  : level === 'unverified' ? 'bad'
  : 'none';

function agentSection({ agent, level, findings }) {
  const limits = (title, items) =>
    items.length
      ? `<h4>${esc(title)}</h4><ul>${items.map((i) => `<li>${codeSpans(i)}</li>`).join('')}</ul>`
      : '';

  const evidenceNote = agent.osTested.length
    ? `Verified against ${esc(agent.name)} ${esc(agent.versionTested)} on ${esc(agent.osTested.join(', '))}.`
    : `The contract was read from ${esc(agent.name)} ${esc(agent.versionTested)} as shipped. Nobody has run LeastGrant inside it.`;

  return `<section id="${attr(agent.id)}">
  <div class="shell">
    <p class="eyebrow">${esc(level)}</p>
    <h2>${esc(agent.name)}</h2>
    <p class="lede">${evidenceNote}${
      agent.osUntested && agent.osUntested.length
        ? ` Untested on ${esc(agent.osUntested.join(', '))}.`
        : ''
    }</p>

    <ul class="findings">
      ${findings
        .filter((f) => f.status !== 'info')
        .map((f) => `<li data-tone="${attr(f.status)}">${codeSpans(f.text)}</li>`)
        .join('')}
    </ul>

    ${limits('What the agent itself cannot do', agent.upstreamLimitations)}
    ${limits('What LeastGrant has not done yet', agent.leastgrantLimitations)}

    <p class="disclaimer">Last checked ${esc(agent.lastVerified)}${
      agent.adapter ? ` · adapter <code>${esc(agent.adapter)}</code>` : ' · no adapter ships'
    }</p>
  </div>
</section>`;
}
