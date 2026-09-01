/**
 * The mark.
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │  The L is the boundary. The G is what lives inside it.                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * LeastGrant's most load-bearing distinction is containment: is this path
 * inside the project or outside it? Is this action inside what you have already
 * agreed to, or outside it? So the L is not drawn as a letter that happens to
 * be first in the name — it is drawn as a corner, a wall and a floor, which is
 * the shape a containment check actually has. The G sits inside that corner
 * with visible clearance on both sides, contained rather than caged, and its
 * own aperture is left open at the top right: the gate that routine work goes
 * through.
 *
 * A monogram is usually the least interesting answer to a logo brief. It earns
 * its place here only because these two letters happen to mean the thing the
 * product means. If they did not, this would be a worse mark than an abstract
 * one.
 *
 * WHAT IT IS NOT, deliberately: not a shield, not a padlock, not a keyhole, not
 * a fingerprint, not a robot, not a hexagon. Seven other directions were
 * explored and discarded — a narrowing aperture (reads as a filter funnel), a
 * gate with descenders (reads as a portcullis, which is an enclosure, which is
 * the oldest cliché in the category), three verdicts as one glyph (reads as a
 * CLI spinner), a structural question mark (reads as a help icon), stacked
 * short-circuit gates (reads as a hamburger menu), an odd-one-out cadence
 * (reads as text-align), and an open boundary with two objects (reads as a bar
 * chart). Each of those was a better *idea* than a monogram and a worse *mark*.
 *
 * GEOMETRY. 32-unit grid, stroke 4.5, butt caps, mitre joins. Every clearance
 * was chosen so the mark survives 16px, where thin strokes and tight counters
 * die:
 *
 *   ink bounds          x 2 → 30, y 2 → 30      (2 units of air on all sides)
 *   L wall              x 2.0–6.5
 *   gap, L wall to G    5.75 units
 *   gap, G to L floor   2.25 units
 *   G counter           9 units
 *   G aperture          2.5 units               (the opening; if this closes
 *                                                the G reads as an O and the
 *                                                whole mark reads as "LO")
 *
 * `currentColor` throughout, so it inverts on light and dark without a second
 * asset, and takes a verdict colour only where the page allows one.
 */

/** The primary mark, as the inner elements of a 32×32 viewBox. */
export const MARK_PATHS =
  '<path d="M4.25 2V27.75H30"/><path d="M30 7.5H14.5V21H30V14.5H22.5"/>';

const STROKE = 'fill="none" stroke="currentColor" stroke-width="4.5" stroke-linecap="butt" stroke-linejoin="miter"';

/**
 * The mark as a standalone SVG.
 *
 * @param {object} o
 * @param {string} [o.title]  accessible name; omit for decorative use
 * @param {string} [o.cls]    class attribute
 * @param {boolean} [o.animate] add the classes the descent animation hooks
 */
export function markSvg({ title, cls, animate = false } = {}) {
  const a11y = title
    ? ` role="img" aria-label="${title}"`
    : ' aria-hidden="true" focusable="false"';
  const klass = cls ? ` class="${cls}"` : '';
  const paths = animate
    ? '<path class="lg-wall" d="M4.25 2V27.75H30"/><path class="lg-bowl" d="M30 7.5H14.5V21H30V14.5H22.5"/>'
    : MARK_PATHS;
  return `<svg${klass} viewBox="0 0 32 32" ${STROKE}${a11y}>${paths}</svg>`;
}

/**
 * The favicon / app icon: the mark on a bone tile.
 *
 * Light rather than dark, and achromatic rather than amber.
 *
 * Achromatic because the site's one visual rule is that colour is a verdict; a
 * logo in amber would say the logo is an `ask`. Light because a browser tab
 * strip is mostly dark-on-light noise, and a pale tile with a hard black mark
 * is both more legible at 16px and less like everything around it than another
 * dark square with a glyph in it.
 */
export function iconSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" role="img" aria-label="LeastGrant">
  <title>LeastGrant</title>
  <rect width="32" height="32" rx="7" fill="#f2ede5"/>
  <g transform="translate(3.4 3.4) scale(0.7875)" fill="none" stroke="#0b0a09" stroke-width="5.2" stroke-linecap="butt" stroke-linejoin="miter">
    ${MARK_PATHS}
  </g>
</svg>
`;
}

/**
 * The animation, described here so it is documented next to the geometry it
 * animates rather than buried in the stylesheet.
 *
 * The mark draws itself in two strokes, in the order the product evaluates:
 * the boundary first, then the thing being judged against it. The L is already
 * there before the G arrives, because a floor is a precondition, not an
 * outcome — the same reason the decision table puts the floors above learning.
 * 420ms, once, on load, and skipped entirely under prefers-reduced-motion.
 *
 * It is not a spin and not a pulse. If it ever becomes one, delete it.
 */
export const ANIMATION_NOTE =
  'the boundary is drawn first, then what lives inside it — the evaluation order, at 420ms';
