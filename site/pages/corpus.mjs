import { esc, attr, codeSpans } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';

/**
 * The bypass corpus, published.
 *
 * Read from `corpus/bypasses.json` — the same file `test/bypass.test.ts`
 * iterates. That is the only reason this page is allowed to exist: it lets the
 * site say "every one of these is regression-tested" as a description of what
 * ran rather than as a promise somebody maintains by hand. If the corpus were
 * transcribed here, the sentence would be a claim; because the test reads the
 * same file, it is a fact about the build.
 *
 * What this page must not become is a scoreboard. A list of defeated attacks
 * invites the reading "therefore it is secure", which is exactly the claim the
 * project refuses to make. So the framing is deliberately narrow: these
 * specific inputs, in this specific version, are not auto-approved. Nothing
 * about the ones nobody has thought of.
 */
/**
 * The payload a wire-shape case actually arrives as.
 *
 * Some cases are not defeated by the text of the command but by the shape it is
 * delivered in — an argv array, a per-call working directory. Showing only the
 * equivalent shell text would make them look like duplicates of cases already
 * on the page, and would hide the thing the case is actually about. The shell
 * text stays because it says what the payload *means*.
 */
function wire(c) {
  if (!c.wire) return '';
  const payload = JSON.stringify(c.wire.toolInput);
  const label = c.identity === 'distinct' ? 'must not match' : 'must match';
  return `<div class="wire"><span class="tag">${esc(c.wire.agent)} ${esc(c.wire.tool)} payload — ${esc(label)}</span>
      <code>${esc(payload)}</code></div>`;
}

export function corpus(facts, data) {
  const byClass = new Map();
  for (const c of data.cases) {
    if (!byClass.has(c.class)) byClass.set(c.class, []);
    byClass.get(c.class).push(c);
  }

  const sections = [...byClass.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(
      ([cls, cases]) => `<section>
  <div class="shell">
    <h3 id="${attr(cls)}">${esc(cls.replace(/-/g, ' '))}</h3>
    <p>${codeSpans(data.classes[cls] ?? '')}</p>
    <div class="table-wrap">
      <table class="corpus">
        <thead>
          <tr><th scope="col">input</th><th scope="col">why it is here</th></tr>
        </thead>
        <tbody>
          ${cases
            .map(
              (c) => `<tr>
            <td><code>${esc(c.command)}</code>${wire(c)}</td>
            <td>${codeSpans(c.note)}</td>
          </tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </div>
  </div>
</section>`,
    )
    .join('\n');

  const body = `<section>
  <div class="shell">
    <p class="eyebrow">security</p>
    <h1>${data.cases.length} ways people have defeated command allowlists</h1>
    <p class="lede">Every one of these runs against the real engine on every
      commit, after the engine has been <em>trained heavily</em> on the innocuous
      command each one is wearing as a disguise. None of them may be
      auto-approved. If one ever is, the build fails.</p>

    <div class="callout" data-tone="deny">
      <span class="tag">what this does not mean</span>
      <p>It does not mean LeastGrant is secure, and it is not a score. This is a
        list of attacks somebody thought of. The interesting ones are the ones
        nobody has thought of yet, and no corpus can contain those. What this
        page supports is one narrow claim: <strong>these specific inputs are not
        auto-approved in v${esc(facts.version)}</strong>, and you can check that
        yourself by running them.</p>
    </div>

    <p>The test is harsher than reality on purpose. Before each case the engine
      is given forty sessions of human approvals for <code>git status</code>,
      <code>npm test</code> and friends — the attacker's best case, a tool that
      has every reason to trust the shape in front of it. The assertion is that
      no amount of learned trust in a shape can be spent on a different action
      wearing that shape.</p>

    <p class="disclaimer">Generated from
      <a href="${attr(facts.repo)}/blob/main/corpus/bypasses.json" rel="noopener noreferrer">corpus/bypasses.json</a>,
      which is the file the test iterates. Adding an attack means adding it
      there; there is nowhere else to put it, which is what keeps this page
      true.</p>
  </div>
</section>

${sections}`;

  return page({
    title: `The bypass corpus — ${data.cases.length} regression-tested evasions`,
    description:
      'Every command-allowlist evasion LeastGrant regression-tests, generated from the same file the test suite reads. Not a security claim; a list of what is covered.',
    path: '/security/corpus/',
    body,
    facts,
  });
}
