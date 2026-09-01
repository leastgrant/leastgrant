import { esc, attr } from '../lib/html.mjs';
import { page } from '../lib/layout.mjs';

/**
 * 404.
 *
 * Deliberately does not echo the requested path. Reflecting whatever was in the
 * URL back into the page is the classic way a static site grows a reflected-XSS
 * hole -- and it is a bad look on this particular site. There is nothing here a
 * visitor supplied.
 */
export function notFound(facts) {
  const body = `<section>
  <div class="shell">
    <p class="eyebrow">404</p>
    <h1>Nothing here</h1>
    <p class="lede">That page does not exist. It may have moved into the documentation, which is
      rendered from the repository and reorganises when the repository does.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="/">Home</a>
      <a class="btn" href="/docs/">Documentation</a>
      <a class="btn" href="${attr(facts.repo)}" rel="noopener noreferrer">GitHub</a>
    </div>
    <p class="disclaimer">If you followed a link from somewhere that should work,
      <a href="${attr(facts.repo)}/issues" rel="noopener noreferrer">an issue</a> is welcome —
      v${esc(facts.version)}.</p>
  </div>
</section>`;

  return page({
    path: '/404.html',
    title: 'Not found',
    description:
      'That page does not exist on leastgrant.xyz. The documentation is rendered from the ' +
      'repository and moves when the repository does — start from the docs index.',
    body,
  });
}
