# leastgrant.xyz

The website, in this repository on purpose.

```bash
npm run site:build      # build to site/dist
npm run site:serve      # http://127.0.0.1:8787
npm run site:test       # build, then 156 assertions over the result
```

## Why it lives here

The site makes claims about a product. Kept in its own repository it would make
those claims about whatever version of the product it last heard about, and the
gap would open silently — a docs page describing a flag that was renamed, a
verdict that the engine no longer returns, a "46 bypasses" that became 51.

So nothing about LeastGrant is written down twice:

| what the site shows | where it comes from |
|---|---|
| every terminal block | `leastgrant check`, run during the build |
| the CLI reference | `leastgrant --help`, captured during the build |
| all seven docs pages | the repo's own Markdown, rendered |
| the agent support matrix | parsed out of the README's table, wording intact |
| the bypass corpus size | counted from `test/bypass.test.ts` |
| version, licence, dependency count | `package.json` |
| the measured figures | extracted from README.md, with an assertion that the sentence still exists |

That last row is the load-bearing one. If the README stops saying what
`site/lib/facts.mjs` expects, **the build fails** rather than the website
continuing to advertise last month's number.

## Zero dependencies

The same argument the product makes about itself. This builds the public face of
a tool whose pitch is that there is no third-party code in the permission path;
a generator with forty transitive packages would undercut that on the first
`npm audit`.

So the Markdown renderer, the HTML escaping, the static server and the tar-free
build are all in `site/lib/`, about a thousand lines, readable in a sitting. The
notable absence is `marked` + `dompurify`: that pairing exists to make *raw HTML
inside Markdown* safe, and the renderer here never emits HTML it did not write,
so there is no sanitiser arms race to lose.

## Layout

```
site/
  build.mjs              the whole build
  serve.mjs              the production origin server (also `npm run site:serve`)
  lib/
    html.mjs             escaping and the URL scheme allowlist
    markdown.mjs         Markdown → HTML, escape-first, no raw HTML
    terminal.mjs         colouring for captured CLI output
    capture.mjs          runs the real CLI; refuses to leak build-machine paths
    facts.mjs            everything the site states as fact, read from the repo
    layout.mjs           document shell, head, header, footer
  pages/                 home, security, docs, 404
  assets/                app.css, app.js, self-hosted subset fonts
  static/                favicon, icons, og.png
  tools/render-images.mjs  regenerates og.png and the PNG icons (run by hand)
  test/                  markdown / build / server
  deploy/                systemd unit and deploy script
  DEPLOY.md              the Cloudflare + VPS runbook
```

## The mark

**The L is the boundary. The G is what lives inside it.**

LeastGrant's most load-bearing distinction is containment — is this path inside
the project or outside it, is this action inside what you already agreed to or
outside it. So the L is not drawn as a letter that happens to be first in the
name. It is drawn as a corner, a wall and a floor, which is the shape a
containment check actually has, and the G sits inside that corner with clearance
on both sides. The G's own aperture is left open at the top right: the gate that
routine work goes through.

A monogram is usually the weakest answer to a logo brief. It earns its place
here only because these two letters happen to mean the thing the product means.

Eight conceptual directions were explored and seven discarded, each because the
mark collided with something a developer already looks at all day:

| direction | why it was dropped |
|---|---|
| narrowing aperture | reads as a filter funnel — and asserts the wrong throughput claim: almost everything *passes* |
| gate with descenders | reads as a portcullis, which is an enclosure, which is the oldest cliché in the category |
| three verdicts as one glyph | reads as a CLI spinner frame strip |
| structural question mark | reads as a help or FAQ icon |
| stacked short-circuit gates | reads as a hamburger menu |
| odd-one-out cadence | reads as a text-align icon |
| open boundary, two objects | reads as a bar chart |

Each of those was a better *idea* than a monogram and a worse *mark*. The test
applied throughout: with the word "LeastGrant" removed, does this look like
LeastGrant's own, or like any security startup? An abstract mark that reads as
Material Symbols `filter_alt` fails that test worse than initials do.

Not used, deliberately: shield, padlock, keyhole, fingerprint, robot, eye,
hexagon.

**Geometry.** 32-unit grid, stroke 4.5, butt caps, mitre joins, 2 units of air
on all four sides. The numbers that decide whether it survives 16px are the
clearances: 5.75 between the L's wall and the G, 2.25 between the G and the
floor, a 9-unit counter, and a 2.5-unit aperture. If the aperture closes, the G
becomes an O and the mark reads "LO" — that failure was found by rendering it,
not by reasoning about it.

**Colour: none.** The mark is `currentColor` and the favicon is black on bone.
Amber would have been the obvious choice and is wrong: on this site amber means
`ask`, and a logo in amber claims to be a verdict.

**Animation.** The mark draws itself once on load, in two strokes, in the order
the engine evaluates — the boundary first, then what is judged against it. 420ms,
skipped under `prefers-reduced-motion`. It is not a spin and not a pulse; if it
ever becomes one, delete it.

Defined once in [`lib/brand.mjs`](lib/brand.mjs). The favicon is generated from
it at build time, the lockup is checked against it at build time, and the PNGs
are regenerated by `site/tools/render-images.mjs`.

```bash
node site/tools/render-images.mjs    # og.png + icon-{180,192,512}.png
python site/tools/make-lockup.py     # logo-lockup.svg (wordmark as outlines)
node site/tools/logo-lab.mjs         # the iteration bench, if the mark changes
```

The lockup's wordmark is converted to outlines from IBM Plex Mono SemiBold — the
face the site sets its headings in — rather than drawn by hand. The first
hand-built attempt rendered "LedstGrdnt", because an `a` on a 32-unit grid is one
coordinate away from a `d`.

## Design rules

**Colour is a verdict.** The page is warm near-black, bone, and four greys. The
only saturated pixels are the three decisions the product returns — allow
`#7ea75e`, ask `#e2a63f`, deny `#d06043`. There is no brand accent and adding one
would break the system: if colour can mean "this is a button", it can no longer
mean "this is a decision".

**Lowercase structural labels.** The CLI writes `what it does` and `blast
radius`, never `WHAT IT DOES`. The site's section labels follow, instead of
importing the small-caps eyebrow every landing page uses.

**Monospace display type.** IBM Plex Mono for every heading, IBM Plex Sans for
prose. Both self-hosted and subset to the glyphs actually used, 222 KB → 41 KB.

**No inline anything.** No inline `<script>`, no inline `<style>`, no `style=`
attribute, in any output. That is what lets the CSP say `script-src 'self'` and
`style-src 'self'` with no `unsafe-inline` and no nonce machinery, and it is
asserted in the tests so it cannot be given away later for one convenient
animation.

**The page works without JavaScript.** Every state the script can produce is
already in the HTML. It only reveals, hides and replays.

## Regenerating the images

`site/static/og.png` and the PNG icons are committed, so the build needs nothing
but Node. They are produced from HTML by a browser, once, when the artwork
changes:

```bash
node site/tools/render-images.mjs
```

## What the tests check

`npm run site:test` builds and then asserts, over the generated artifact and over
real HTTP responses:

- the Markdown renderer emits no tag or attribute outside an allowlist, against
  ~40 XSS payloads
- the URL allowlist rejects `javascript:`, `data:`, scheme-relative and
  control-character-split schemes
- no inline script, style, or event handler in any page
- no subresource from any origin but this one; no CDN, analytics or tag manager
- no build-machine path, token or key in any output file
- `app.js` contains no `eval`, no `innerHTML`, no `fetch`, no storage API
- canonical URLs, `og:` metadata, one `<h1>` per page, descriptions in range
- every internal link and every `#anchor` resolves to something that exists
- the CSP has no `unsafe-*`, no wildcard, and no external origin
- path traversal, encoded traversal, null bytes and backslash traversal all 404
- `TRACE`, `CONNECT`, `POST` and friends are refused
- the 404 page does not reflect the requested path
- the build is byte-identical across two runs

Deployment is [DEPLOY.md](DEPLOY.md).
