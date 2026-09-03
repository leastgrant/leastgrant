import { esc, attr, list } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';
import { verdictBlock, heroSession, firstLine } from '../lib/terminal.mjs';

/**
 * Which of the six steps answered.
 *
 * Derived from the verdict the engine actually returned, not from a table
 * written alongside it: `floor` and the reason codes come out of
 * `leastgrant check --json`, so if the engine starts deciding one of these
 * somewhere else, the page moves the marker.
 */
function decidedAt(v) {
  const codes = v.reasons.map((r) => r.code);
  if (v.decision === 'deny' && codes.includes('guard.self-write')) return 1;
  if (codes.includes('rule.allow')) return 3;
  if (v.floor) return 4;
  if (v.decision === 'allow') return 5;
  return 6;
}

/** Short label for why this example is interesting, in the picker. */
const GLYPH = { allow: '✓', ask: '?', deny: '✗' };

export function home(facts, verdicts) {
  const shown = verdicts.filter((v) => v.state === 'learned');
  const fresh = verdicts.find((v) => v.id === 'npm-test-fresh');

  // The hero types its way through a session, so its length is a time cost paid
  // by every visitor. Five commands is about five seconds, and it already
  // covers all three verdicts and both interesting asks. `curl | sh` is the
  // longest line by some way and the least surprising verdict of the set, so it
  // sits in the walkthrough below instead of the opening title sequence.
  const opening = shown.filter((v) => v.id !== 'curl-pipe-sh');
  const hero = heroSession(
    opening.map((v) => ({ command: v.command, first: firstLine(v.text) })),
  );

  return page({
    home: true,
    path: '/',
    title: 'LeastGrant — let routine work flow, catch the weird stuff',
    description:
      'A permission layer for coding agents. It learns what yours normally do, lets that ' +
      'through, and stops on the rest. Local, open source, zero dependencies.',
    body: [
      heroSection(facts, hero, shown),
      gauntletSection(facts, shown),
      pairSection(),
      learnsSection(facts, fresh),
      installSection(facts),
      agentsSection(facts),
      honestySection(facts),
    ].join('\n'),
  });
}

// --- hero --------------------------------------------------------------------

function heroSection(facts, hero, shown) {
  return `<section class="hero">
  <div class="shell hero-grid">
    <div>
      <h1>LeastGrant</h1>
      <p class="tagline">Let routine work flow.<br>Catch the weird stuff.</p>
      <p class="lede">Your agent asks about <code>git status</code> with the same gravity as
        <code>git push --force</code>, forty times an hour, until you stop reading and turn
        permissions off entirely. LeastGrant is the layer in between. It knows the difference
        between your hundredth <code>npm test</code> and the first time anything on this machine
        has tried to read a private key.</p>
      <div class="cta-row">
        <a class="btn btn-primary" href="#install">Install</a>
        <a class="btn" href="https://github.com/leastgrant/leastgrant" rel="noopener noreferrer">View on GitHub</a>
      </div>
      <p class="hero-note">v${esc(facts.version)} · ${esc(facts.license)} ·
        zero dependencies · fully local</p>
    </div>

    <div>
      <div class="term" data-term-demo>
        <div class="term-bar">
          <span class="dot" aria-hidden="true"></span>
          <span class="grow">leastgrant check</span>
        </div>
        <div class="term-body"><pre><code>${hero}</code></pre></div>
        <div class="term-foot">
          <span>real output, captured from v${esc(facts.version)} at build time</span>
          <span class="spacer"></span>
          <button type="button" class="replay" data-replay hidden>replay</button>
        </div>
      </div>
      <p class="legend" aria-hidden="true">
        <span><span class="v-allow">✓ allow</span> runs, no prompt</span>
        <span><span class="v-ask">? ask</span> you decide</span>
        <span><span class="v-deny">✗ deny</span> never</span>
      </p>
    </div>
  </div>
</section>`;
}

// --- the gauntlet ------------------------------------------------------------

function gauntletSection(facts, shown) {
  const picker = shown
    .map(
      (v) => `<button type="button" class="pick" data-pick="${attr(v.id)}" aria-pressed="false">
          <span class="glyph ${attr(toneClass(v.decision))}" aria-hidden="true">${esc(GLYPH[v.decision])}</span>
          <span class="cmdtext">${esc(v.command)}</span>
        </button>`,
    )
    .join('\n        ');

  const panels = shown.map((v) => panel(facts, v)).join('\n');

  return `<section id="decides">
  <div class="shell">
    <p class="eyebrow">how it decides</p>
    <h2>Six steps, in this order</h2>
    <p class="lede">The order is the product. Your own rules sit above the floors, because a rule
      <em>is</em> an answer you already gave. Learning only ever operates at step five — it decides
      whether to stop asking about things that were already in the automatic band. It never widens
      that band.</p>

    <div class="gauntlet" data-gauntlet>
      <div>
        <div class="picker" role="group" aria-label="Choose a command">
        ${picker}
        </div>
        <p class="disclaimer">Not a simulation. Each answer below is the output of
          <code>leastgrant check</code> run against v${esc(facts.version)} while this page was
          built. The step markers are derived from the same JSON the CLI prints.</p>
      </div>
      <div>
${panels}
      </div>
    </div>
  </div>
</section>`;
}

function toneClass(decision) {
  return decision === 'allow' ? 'v-allow' : decision === 'deny' ? 'v-deny' : 'v-ask';
}

function panel(facts, v) {
  const hit = decidedAt(v);

  const gates = facts.order
    .map((step) => {
      const state = step.n === hit ? 'hit' : step.n < hit ? 'passed' : 'unreached';
      return `          <div class="gate" data-state="${attr(state)}" data-verdict="${attr(step.verdict)}">
            <span class="n">${esc(String(step.n))}</span>
            <span class="what">${esc(step.name)}</span>
            <span class="emits">${esc(step.verdict)}</span>
          </div>`;
    })
    .join('\n');

  const why = v.reasons
    .map((r) => `<li>${esc(r.text)}</li>`)
    .join('');

  const blast = v.blast
    ? `reach ${v.blast.reach} · undo ${v.blast.reversibility} · scale ${v.blast.scale}` +
      (v.blast.exposure && v.blast.exposure !== 'none' ? ` · secrets ${v.blast.exposure}` : '')
    : '';

  return `        <div class="panel" data-panel="${attr(v.id)}">
          <p class="panel-label">${esc(v.command)}</p>
          <div class="gates" data-run>
${gates}
          </div>
          <p class="gate-key">
            <span class="k-passed"><i></i>looked, nothing to say</span>
            <span class="k-hit"><i></i>answered</span>
            <span class="k-unreached"><i></i>never reached</span>
          </p>
          <div class="outcome">
            <p class="outcome-head"><span class="${attr(toneClass(v.decision))}">${esc(GLYPH[v.decision])} ${esc(v.decision)}</span>
              <span class="muted">${esc(v.caption)}</span></p>
            <ul class="outcome-why">${why}</ul>
            ${blast ? `<p class="outcome-blast">${esc(blast)}${v.understood === false ? ' · not fully understood' : ''}</p>` : ''}
          </div>
          <details class="full">
            <summary>full output</summary>
            <div class="term">
              <div class="term-body"><pre><code>${verdictBlock(v.text)}</code></pre></div>
            </div>
          </details>
        </div>`;
}

// --- normal is not safe ------------------------------------------------------

function pairSection() {
  return `<section id="normal">
  <div class="shell">
    <p class="eyebrow">the part that is not an allowlist</p>
    <div class="pair">
      <div>
        <h3>Normal <span class="ne">≠</span> Safe</h3>
        <p>An action can be the most familiar thing on the machine and still be one LeastGrant
          will not wave through. Reading a credential, sending data off the box, running code
          nobody has read — those are decided before learning is consulted at all. There is no
          number of boring, patient, approved repetitions that adds up to permission to read a
          private key, because that is not decided at step five.</p>
      </div>
      <div>
        <h3>Safe <span class="ne">≠</span> Normal</h3>
        <p>The reverse mistake is worse for you day to day. Something unfamiliar is not therefore
          dangerous, so LeastGrant does not block it — it asks. New work should cost you one
          keystroke, not a support ticket. The only outright <span class="v-deny">deny</span> in
          the default configuration is an agent editing LeastGrant's own records.</p>
      </div>
    </div>
    <p class="pull">Typicality is strong evidence of abnormality and weak evidence of safety.
      LeastGrant uses it in the first direction only — because a learning permission system that
      conflates the two can be trained by the thing it is supposed to be watching.</p>
  </div>
</section>`;
}

// --- it learns ---------------------------------------------------------------

function learnsSection(facts, fresh) {
  const m = facts.measured;

  return `<section id="learns">
  <div class="shell">
    <p class="eyebrow">setup</p>
    <h2>It reads the history you already have</h2>
    <p class="lede"><code>leastgrant init</code> does not ask you to write a policy. It finds the
      session transcripts your agents have already left on disk, replays every tool call through
      the decision engine, and shows you what it would have done — including what it would have
      got wrong.</p>

    <div class="facts">
      <div class="fact">
        <dt>evidence is typed</dt>
        <dd>4 kinds<span class="sub">Approving something and merely doing it are recorded
          differently. Work that ran unattended teaches LeastGrant what is typical here. It does
          not count as your consent.</span></dd>
      </div>
      <div class="fact">
        <dt>promotion bar</dt>
        <dd>${esc(facts.promotion[0].approvals)} → ${esc(facts.promotion[1].approvals)}<span class="sub">Approvals
          needed to stop asking, by blast radius, spread over at least two sessions and two days so
          one runaway session cannot bootstrap its own trust. Reads and inspections that stay inside
          the project take a weaker second route — 8 sightings across 2 sessions, no second day.
          Nothing that writes, deletes or reaches the network is eligible for it.</span></dd>
      </div>
      <div class="fact">
        <dt>denials</dt>
        <dd>permanent<span class="sub">Approvals decay on a 90-day half-life. Refusals do not
          expire, so waiting one out is not a strategy.</span></dd>
      </div>
    </div>

    <h3>What that did on one machine</h3>
    <p>On the machine LeastGrant was written on, <code>init</code> found
      ${esc(m.sessions)} sessions across ${esc(m.projects)} projects — ${esc(m.actions)} real tool
      calls. Approving the starter bundles it proposed took that history from ${esc(m.before)}% to
      <strong>${esc(m.after)}% of actions running without a prompt</strong>, with none of the
      ${esc(m.refusals)} actions actually refused on record slipping through.</p>

    <div class="callout">
      <span class="tag">read this before believing the number</span>
      <p>That is one developer, one month, one command mix — a sample of one, and the project says
        so itself. It is on this page because a permission tool that never says how often it gets
        out of the way is hiding the only number that matters. Re-derive it on your own machine:
        <code>leastgrant init --dry-run</code> writes nothing and tells you what it found.</p>
    </div>

    <h3>The first day looks different</h3>
    <p>Before it has seen anything, almost everything asks. That is the honest starting state, and
      it is what the same <code>npm test</code> looks like on a fresh install:</p>
    <div class="term">
      <div class="term-body"><pre><code>${verdictBlock(fresh.text)}</code></pre></div>
    </div>
  </div>
</section>`;
}

// --- install -----------------------------------------------------------------

function installSection(facts) {
  return `<section id="install">
  <div class="shell">
    <p class="eyebrow">install</p>
    <h2>Two commands</h2>

    <div class="install-box">
      <code id="install-cmd" data-clipboard="npm install -g leastgrant"><span class="prompt" aria-hidden="true">$</span>npm install -g leastgrant</code>
      <button type="button" class="copy" data-copy="install-cmd" hidden>copy</button>
    </div>

    <ol class="steps">
      <li>
        <div>
          <h3>Install it</h3>
          <p>Node ${esc(facts.node)}. No postinstall script, no account, no configuration file to
            write.</p>
        </div>
      </li>
      <li>
        <div>
          <h3>Let it read what already happened</h3>
          <p><code>leastgrant init</code> replays your existing agent history, reports its own
            mistakes against it, and proposes a starting set of grants. You answer once.</p>
          <figure class="code"><pre><code>leastgrant init</code></pre></figure>
        </div>
      </li>
      <li>
        <div>
          <h3>Try it before you trust it</h3>
          <p>Ask what it would decide, without running anything. Every verdict on this page came
            out of this command.</p>
          <figure class="code"><pre><code>leastgrant check "git push --force origin main"</code></pre></figure>
        </div>
      </li>
    </ol>

    <p class="disclaimer">Prefer to watch first? <code>leastgrant init</code> defaults to the
      <code>assist</code> posture, and <code>observe</code> never intervenes at all — run it for a
      week and it cannot get in your way. <code>leastgrant simulate</code> replays your history
      against the three postures that reach a verdict, so you can compare before switching;
      <code>observe</code> is not in that comparison, because a setting that never intervenes has
      nothing to trade off.</p>
  </div>
</section>`;
}

// --- agents ------------------------------------------------------------------

function agentsSection(facts) {
  const rows = facts.agents
    .map(
      (a) => `      <div class="row">
        <span class="who"><span class="pip" data-level="${attr(a.level)}" aria-hidden="true"></span>${esc(a.agent)}</span>
        <div>
          <p class="status-line">${esc(a.status)}</p>
          <p class="how">${esc(stripMarkdown(a.how))}</p>
        </div>
      </div>`,
    )
    .join('\n');

  return `<section id="agents">
  <div class="shell">
    <p class="eyebrow">where it runs</p>
    <h2>One engine, one set of floors</h2>
    <p class="lede">Every adapter calls the same decision path, so the answer does not change with
      the editor you opened. The status column is deliberately blunt about which integrations have
      actually been run against a live install and which have only been tested against a published
      contract.</p>
    <div class="support">
${rows}
    </div>
    <p class="disclaimer">One caveat that does not fit in a table. Cursor's
      <code>beforeReadFile</code> event takes allow or deny and has no "ask", so an unfamiliar read
      is allowed there rather than blocked — turning every unrecognised file read into a hard
      failure would make the integration unusable. A read of something LeastGrant recognises as a
      credential <em>is</em> still blocked, and shell commands and MCP calls get the full
      allow/ask/deny. <a href="/docs/agents/">The full matrix</a> spells this out.</p>
  </div>
</section>`;
}

/** The README table cells carry links and emphasis; the site shows the words. */
function stripMarkdown(text) {
  return String(text)
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\*\*/g, '')
    .replace(/`/g, '');
}

// --- what it is not ----------------------------------------------------------

function honestySection(facts) {
  return `<section id="limits">
  <div class="shell">
    <p class="eyebrow">what it is not</p>
    <h2>It is not a sandbox</h2>
    <p class="lede">It answers a question the agent asks it. It does not confine a process,
      intercept syscalls, or contain anything already running. And if the hook itself crashes or
      times out, what happens is the host's call, not ours: ${esc(list(facts.failure.open))} run
      the tool call anyway; ${esc(list(facts.failure.closed))} block it. LeastGrant is a reliable
      veto and a best-effort grant on all of them, and it is designed around that asymmetry.</p>

    <div class="facts">
      <div class="fact">
        <dt>bypass corpus</dt>
        <dd>${esc(String(facts.bypass.total))}<span class="sub">Real allowlist evasions — separators,
          substitution, wrappers, encodings, <code>..</code> stepped off the end of a symlink — each
          checked against a LeastGrant deliberately trained with hundreds of approvals for the
          innocuous-looking prefix. One auto-approval fails the build.</span></dd>
      </div>
      <div class="fact">
        <dt>runtime dependencies</dt>
        <dd>${esc(String(facts.runtimeDeps))}<span class="sub">No third-party code in the permission
          path. The only devDependencies are TypeScript and its types.</span></dd>
      </div>
      <div class="fact">
        <dt>shell parser</dt>
        <dd>${esc(m2(facts).parsed)}<span class="sub">of ${esc(m2(facts).commands)} real agent commands
          accounted for, 0 crashes, ${esc(m2(facts).parseMs)} ms average — again, one machine's command
          mix.</span></dd>
      </div>
      <div class="fact">
        <dt>fully understood</dt>
        <dd>${esc(m2(facts).understood)}%<span class="sub">Of that same one machine's commands. The
          rest contain inline code, a script file or a program it has no knowledge of; those are
          marked not-understood and always ask. It is the largest single source of prompts and the
          honest answer.</span></dd>
      </div>
    </div>

    <p>The complete version — what it defends against, what it does not, the adversarial model for
      the learning itself, and what the v${esc(facts.version)} audit left standing — is in the
      <a href="/docs/threat-model/">threat model</a>. The
      <a href="/security/">security page</a> is the short version, including how to report
      something.</p>
  </div>
</section>`;
}

function m2(facts) {
  return facts.measured;
}
