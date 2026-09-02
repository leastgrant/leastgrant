import { esc, attr } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';

/**
 * The security page.
 *
 * Written to be useful to someone deciding whether to trust this in their
 * permission path, which means leading with the limits rather than burying
 * them. There is no assurance claim here that a reader cannot check: every
 * number is derived from the repository, and every "we tested X" links to the
 * test.
 */
export function security(facts) {
  const m = facts.measured;

  const body = `<section>
  <div class="shell">
    <p class="eyebrow">security</p>
    <h1>LeastGrant is not a sandbox</h1>
    <p class="lede">It is a decision layer. It answers a question your agent asks it, and the
      agent is what enforces the answer. It does not confine a process, intercept syscalls, or
      contain anything already running. If that is what you need, you need a sandbox, and
      LeastGrant is not a substitute for one.</p>

    <div class="callout" data-tone="deny">
      <span class="tag">it fails open</span>
      <p>If the hook crashes, times out, or exits non-zero, Claude Code treats that as a
        non-blocking error and runs the tool call anyway. That is the hook contract, not a design
        choice. LeastGrant is a <strong>reliable veto and a best-effort grant</strong>, and the
        whole thing is built around that asymmetry: a crash costs you protection for one call, not
        your workflow.</p>
    </div>
  </div>
</section>

<section>
  <div class="shell">
    <p class="eyebrow">reporting</p>
    <h2>Found a way through?</h2>
    <p class="lede">The definition here is narrower and blunter than most:
      <strong>a vulnerability is any input that causes LeastGrant to return <code>allow</code> for
      an action that should have been asked about or denied.</strong> It does not matter how
      contrived the input looks or how it got there.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="${attr(facts.advisories)}" rel="noopener noreferrer">Open a private advisory</a>
      <a class="btn" href="/docs/security-policy/">Read the full policy</a>
      <a class="btn" href="/security/corpus/">See the bypass corpus</a>
    </div>
    <p class="disclaimer">There is deliberately no email address. An address nobody monitors is
      worse than no address at all, and an advisory reaches the same place with a record attached.
      If the finding is that LeastGrant is <em>too</em> cautious, that is a normal issue and it is
      wanted — it just does not need to be private.</p>

    <h3>What to include</h3>
    <ul>
      <li>The exact input. For a shell command, the literal string, not a description of it.</li>
      <li>The output of <code>leastgrant check "&lt;that input&gt;"</code>, and what you expected.</li>
      <li>Your posture — the answer differs between <code>assist</code>, <code>autopilot</code>
        and <code>strict</code>.</li>
      <li>Your platform. Path handling and the credential-path table differ across Windows, macOS
        and Linux.</li>
    </ul>
  </div>
</section>

<section>
  <div class="shell">
    <p class="eyebrow">what is actually tested</p>
    <h2>Evidence, and what it is worth</h2>
    <p class="lede">These are the checks that run on every commit. They are the reason to believe
      specific claims, not a reason to believe the whole thing is safe. Nothing here says
      "unhackable"; the point of the list is that each line is something you can go and read.</p>

    <div class="facts">
      <div class="fact">
        <dt>bypass corpus</dt>
        <dd>${esc(String(facts.bypass.total))}<span class="sub">${esc(String(facts.bypass.named))} allowlist
          evasions and ${esc(String(facts.bypass.symlink))} symlink traversals, each run against an
          engine deliberately trained with hundreds of approvals for the innocuous prefix. If one is
          ever auto-approved, the build fails.</span></dd>
      </div>
      <div class="fact">
        <dt>test files</dt>
        <dd>${esc(String(facts.testFiles.length))}<span class="sub">Run on three operating systems
          across Node 20, 22 and 24, because path containment is exactly where platforms
          differ.</span></dd>
      </div>
      <div class="fact">
        <dt>runtime dependencies</dt>
        <dd>${esc(String(facts.runtimeDeps))}<span class="sub">There is no third-party code in the
          permission path. A dependency there would be code you did not read, deciding what your
          agent may do.</span></dd>
      </div>
      <div class="fact">
        <dt>fuzzing</dt>
        <dd>randomised<span class="sub">Generated symlink topologies compared against a reference
          resolver written independently of the one under test — on Linux and Windows, the two
          platforms whose link semantics differ most. Path containment is the one place where being
          wrong is silent.</span></dd>
      </div>
    </div>

    <h3>The measurements, with their caveat attached</h3>
    <p>The shell parser accounted for ${esc(m.parsed)} of ${esc(m.commands)} real agent commands with
      0 crashes and ${esc(m.parseMs)} ms average parse time. Of those, ${esc(m.understood)}% are ones
      LeastGrant will say it fully understands; the rest contain inline code, a script file or a
      program it has no knowledge of, and always ask.</p>
    <p class="disclaimer">Those figures come from one developer's machine and one month of work — a
      sample of one, and a property of that command mix as much as of LeastGrant. They are here
      because a tool that hides its own hit rate is hiding the thing you need to decide with.
      Re-derive them on yours rather than taking them from a website.</p>
  </div>
</section>

<section>
  <div class="shell">
    <p class="eyebrow">the honest list</p>
    <h2>What it does not defend against</h2>
    <p class="lede">A short version. The
      <a href="/docs/threat-model/">threat model</a> is ${esc(String(facts.threatModelSections.length))}
      sections and does not flatter the design; it includes the adversarial model for the learning
      itself and what the v${esc(facts.version)} audit left standing.</p>
    <ul>
      <li><strong>Anything already running.</strong> Once a command is approved, LeastGrant has no
        further say. Approving <code>npm test</code> approves whatever the test script does.</li>
      <li><strong>Code it cannot read.</strong> It can see that a script will run. It cannot see
        what is in it — which is why <code>curl | sh</code> always asks instead of being
        classified.</li>
      <li><strong>A compromised machine.</strong> State is plain text in your home directory. An
        attacker who can already write there has better options than editing a permission profile,
        but it is worth being clear that nothing is sealed.</li>
      <li><strong>Its own opinions being wrong.</strong> The classification knowledge is exactly
        that — opinion. It lives in readable modules so you can disagree with it and send a
        patch.</li>
    </ul>
  </div>
</section>

<section>
  <div class="shell">
    <p class="eyebrow">this website</p>
    <h2>The site itself</h2>
    <p class="lede">A security tool with a careless website is an argument against itself, so this
      one is built to the same rules the product is.</p>
    <div class="facts">
      <div class="fact">
        <dt>third-party JavaScript</dt>
        <dd>0<span class="sub">No analytics, no tag manager, no CDN. The page makes exactly the
          requests its HTML declares, all to this origin.</span></dd>
      </div>
      <div class="fact">
        <dt>cookies and storage</dt>
        <dd>none<span class="sub">Nothing is set, read, or persisted. There is no consent banner
          because there is nothing to consent to.</span></dd>
      </div>
      <div class="fact">
        <dt>fonts</dt>
        <dd>self-hosted<span class="sub">Subset to the glyphs used and served from this origin. A
          webfont CDN would see every reader of this page.</span></dd>
      </div>
      <div class="fact">
        <dt>content policy</dt>
        <dd>no inline<span class="sub">No inline script or style anywhere in the output, so the CSP
          needs neither <code>unsafe-inline</code> nor a nonce.</span></dd>
      </div>
    </div>
    <p>The documentation pages render Markdown from the repository through a renderer that never
      emits HTML it did not write: raw HTML in the source is escaped rather than passed through,
      and link targets go through a scheme allowlist. That is checked by tests with hostile
      payloads, alongside assertions over the built output for leaked paths, unexpected origins and
      a policy that has not quietly been widened. The site is in the same repository, under
      <a href="${attr(facts.repo)}/tree/main/site" rel="noopener noreferrer"><code>site/</code></a>.</p>
  </div>
</section>`;

  return page({
    path: '/security/',
    title: 'Security',
    description:
      'LeastGrant is a decision layer, not a sandbox, and it fails open. What it defends ' +
      'against, what it does not, what is tested, and how to report a bypass privately.',
    body,
  });
}
