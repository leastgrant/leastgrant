/**
 * The mark, as geometry rather than as taste.
 *
 * Most of what makes a logo good cannot be asserted. These are the parts that
 * can: that one definition feeds every asset, that the clearances which keep it
 * legible at 16px are still there, and that nothing that ships contains
 * anything a browser would execute.
 *
 * The aperture check is the one that matters. It was found by rendering, not by
 * reading: close the G's opening and the mark reads "LO", which is a different
 * company.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MARK_PATHS, markSvg, iconSvg } from '../lib/brand.mjs';

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(SITE, 'dist');

/** Pull the numbers back out of the path data, so the test reads the shipped geometry. */
function geometry() {
  // <path d="M4.25 2V27.75H30"/><path d="M30 7.5H14.5V21H30V14.5H22.5"/>
  const wall = MARK_PATHS.match(/M([\d.]+) 2V([\d.]+)H([\d.]+)/);
  const bowl = MARK_PATHS.match(/M([\d.]+) ([\d.]+)H([\d.]+)V([\d.]+)H([\d.]+)V([\d.]+)H([\d.]+)/);
  assert.ok(wall, 'the L path is no longer in the expected form');
  assert.ok(bowl, 'the G path is no longer in the expected form');
  const stroke = Number(markSvg().match(/stroke-width="([\d.]+)"/)[1]);
  return {
    stroke,
    wallX: Number(wall[1]),
    floorY: Number(wall[2]),
    rightX: Number(wall[3]),
    top: Number(bowl[2]),
    gX: Number(bowl[3]),
    bottom: Number(bowl[4]),
    cross: Number(bowl[6]),
  };
}

describe('the mark stays legible at 16px', () => {
  const g = geometry();
  const half = () => g.stroke / 2;

  test('the stroke is heavy enough to survive halving', () => {
    // A 32-unit grid rendered at 16px halves every measurement. Below 4 units
    // the stroke lands under 2 device pixels and greys out.
    assert.ok(g.stroke >= 4, `stroke is ${g.stroke}`);
  });

  test('the G aperture is open — otherwise the mark reads "LO"', () => {
    const aperture = g.cross - g.top - g.stroke;
    assert.ok(aperture >= 2, `aperture is ${aperture} units; below 2 it closes at small sizes`);
  });

  test('the G counter is open', () => {
    const counter = g.bottom - g.top - g.stroke;
    assert.ok(counter >= 7, `counter is ${counter} units`);
  });

  test('the G clears the L on both sides', () => {
    const fromWall = g.gX - half() - (g.wallX + half());
    const fromFloor = g.floorY - half() - (g.bottom + half());
    assert.ok(fromWall >= 4, `only ${fromWall} units between the L wall and the G`);
    assert.ok(fromFloor >= 1.5, `only ${fromFloor} units between the G and the floor`);
  });

  test('nothing is clipped by the viewBox', () => {
    assert.ok(g.wallX - half() >= 0, 'the L wall is cut off on the left');
    assert.ok(g.floorY + half() <= 32, 'the floor is cut off at the bottom');
    assert.ok(g.rightX <= 32, 'the floor runs past the right edge');
    assert.ok(g.top - half() >= 0, 'the G is cut off at the top');
  });
});

describe('the mark is defined once', () => {
  test('the navbar, the favicon and the lockup all use the same geometry', () => {
    assert.ok(markSvg().includes(MARK_PATHS), 'markSvg drifted from MARK_PATHS');
    assert.ok(iconSvg().includes(MARK_PATHS), 'iconSvg drifted from MARK_PATHS');

    const lockup = fs.readFileSync(path.join(SITE, 'static', 'logo-lockup.svg'), 'utf8');
    assert.ok(
      lockup.includes(MARK_PATHS),
      'logo-lockup.svg drifted — regenerate with: python site/tools/make-lockup.py',
    );
  });

  test('the favicon in the build is the generated one', () => {
    const shipped = fs.readFileSync(path.join(DIST, 'favicon.svg'), 'utf8');
    assert.equal(shipped, iconSvg());
  });

  test('the lockup spells the name', () => {
    // The hand-built first attempt rendered "LedstGrdnt". The outlines come
    // from the real font now, and the accessible name is the check that the
    // right word went in.
    const lockup = fs.readFileSync(path.join(SITE, 'static', 'logo-lockup.svg'), 'utf8');
    assert.match(lockup, /aria-label="LeastGrant"/);
    assert.match(lockup, /<title>LeastGrant<\/title>/);
  });
});

describe('nothing that ships is executable', () => {
  let svgs = [];
  before(() => {
    svgs = fs
      .readdirSync(DIST, { recursive: true })
      .filter((f) => typeof f === 'string' && f.endsWith('.svg'))
      .map((f) => ({ file: f, body: fs.readFileSync(path.join(DIST, f), 'utf8') }));
    assert.ok(svgs.length >= 2, `expected the favicon and the lockup, found ${svgs.length}`);
  });

  test('no SVG contains a script, an external reference or a handler', () => {
    for (const { file, body } of svgs) {
      for (const bad of ['<script', '<foreignObject', '<image', 'xlink:href', 'href=', 'javascript:', '<use']) {
        assert.ok(!body.includes(bad), `${file} contains ${bad}`);
      }
      assert.ok(!/\son\w+\s*=/.test(body), `${file} has an event handler`);
    }
  });

  test('no SVG loads a font or reaches another origin', () => {
    for (const { file, body } of svgs) {
      assert.ok(!body.includes('<text'), `${file} uses <text>, which depends on a font being present`);
      assert.ok(!/https?:\/\//.test(body.replace(/xmlns="[^"]*"/g, '')), `${file} references an external origin`);
    }
  });
});

describe('colour is still a verdict', () => {
  test('the mark takes no colour of its own', () => {
    // Amber is `ask`. A logo in amber would be claiming to be a verdict.
    assert.ok(markSvg().includes('currentColor'), 'the mark should inherit its colour');
    for (const verdict of ['#e2a63f', '#7ea75e', '#d06043']) {
      assert.ok(!markSvg().includes(verdict), `the mark hardcodes the verdict colour ${verdict}`);
      assert.ok(!iconSvg().includes(verdict), `the icon hardcodes the verdict colour ${verdict}`);
    }
  });

  test('the navbar mark is bone, not amber', () => {
    const css = fs.readFileSync(path.join(SITE, 'assets', 'app.css'), 'utf8');
    const rule = css.match(/\.wordmark \.mark \{[^}]*\}/);
    assert.ok(rule, 'the navbar mark has no rule');
    assert.match(rule[0], /color: var\(--bright\)/);
    assert.ok(!/var\(--ask\)/.test(rule[0]), 'the navbar mark uses the ask colour');
  });
});

describe('the animation is an extension of the meaning', () => {
  let css = '';
  before(() => {
    css = fs.readFileSync(path.join(SITE, 'assets', 'app.css'), 'utf8');
  });

  test('it draws the boundary before what is judged against it', () => {
    const wall = css.match(/\.wordmark \.mark \.lg-wall \{[^}]*animation:[^;]*;/);
    const bowl = css.match(/\.wordmark \.mark \.lg-bowl \{[^}]*animation:[^;]*;/);
    assert.ok(wall && bowl, 'the two-stroke animation is missing');

    const delayOf = (rule) => {
      const times = [...rule.matchAll(/(\d+)ms/g)].map((m) => Number(m[1]));
      return times.length > 1 ? times[1] : 0;
    };
    assert.ok(
      delayOf(bowl[0]) > delayOf(wall[0]),
      'the G should not start before the L: a floor is a precondition, not an outcome',
    );
  });

  test('it runs once and is short', () => {
    const block = css.slice(css.indexOf('.wordmark .mark .lg-wall'), css.indexOf('@keyframes lg-draw'));
    assert.ok(!/infinite/.test(block), 'the mark animation loops');
    for (const [, ms] of block.matchAll(/(\d+)ms/g)) {
      assert.ok(Number(ms) <= 600, `${ms}ms is too long for a load animation`);
    }
  });

  test('it is not a spin or a pulse', () => {
    const frames = css.slice(css.indexOf('@keyframes lg-draw'));
    const body = frames.slice(0, frames.indexOf('}\n\n'));
    for (const bad of ['rotate', 'scale(', 'opacity']) {
      assert.ok(!body.includes(bad), `the mark animation uses ${bad}`);
    }
  });

  test('reduced motion switches it off entirely', () => {
    assert.match(css, /prefers-reduced-motion[\s\S]*?\.wordmark \.mark path \{[\s\S]*?animation: none/);
  });
});
