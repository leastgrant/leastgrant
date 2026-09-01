/**
 * The origin server, over real HTTP.
 *
 * Reading `serve.mjs` and agreeing that it looks right is not the same as
 * asking it for `/../../package.json` and seeing what comes back. Every
 * assertion here goes through a socket, because the thing being tested is the
 * response a browser gets -- headers included -- and not the intent of the code
 * that produced it.
 *
 * The headers matter twice over. They are the site's actual security posture,
 * and they are the part most likely to be quietly weakened later by somebody
 * who needs one inline script "just for now".
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createServer, securityHeaders } from '../serve.mjs';

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(SITE, 'dist');

let server;
let origin;

before(async () => {
  assert.ok(fs.existsSync(DIST), 'run `npm run site:build` before the site tests');
  server = createServer({ root: DIST, hsts: false });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

/**
 * Send a request line verbatim, without a URL parser normalising it first.
 *
 * `fetch('/a/../../etc')` resolves the dots in the client, so it can never test
 * what the server does with them. A traversal test that uses fetch is testing
 * the client.
 */
function raw(requestLine, headers = '') {
  return new Promise((resolve, reject) => {
    const socket = net.connect(server.address().port, '127.0.0.1', () => {
      socket.write(`${requestLine} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n${headers}\r\n`);
    });
    let body = '';
    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error('timeout'));
    });
    socket.on('data', (chunk) => (body += chunk.toString('latin1')));
    socket.on('end', () => resolve(body));
    socket.on('error', reject);
  });
}

const statusOf = (response) => Number((response.match(/^HTTP\/1\.1 (\d{3})/) || [])[1]);

/** The build gives fonts content-hashed names, so find one rather than guess it. */
function aFont() {
  const name = fs.readdirSync(path.join(DIST, 'fonts')).find((f) => f.endsWith('.woff2'));
  assert.ok(name, 'no font in the build');
  return name;
}

// --- headers -------------------------------------------------------------------

describe('security headers', () => {
  const expected = {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
  };

  for (const [header, value] of Object.entries(expected)) {
    test(`${header} is ${value} on a page`, async () => {
      const res = await fetch(`${origin}/`);
      assert.equal(res.headers.get(header), value);
    });
  }

  test('every response carries the policy, not just HTML', async () => {
    const css = [...fs.readdirSync(DIST)].find((f) => /^app\.[0-9a-f]+\.css$/.test(f));
    for (const url of ['/', '/security/', '/docs/', `/${css}`, '/favicon.svg', '/robots.txt']) {
      const res = await fetch(origin + url);
      assert.equal(res.status, 200, url);
      assert.ok(res.headers.get('content-security-policy'), `${url} has no CSP`);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff', url);
    }
  });

  test('the 404 response is protected too', async () => {
    const res = await fetch(`${origin}/no-such-page`);
    assert.equal(res.status, 404);
    assert.ok(res.headers.get('content-security-policy'));
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });

  test('permissions-policy switches off what the site does not use', async () => {
    const res = await fetch(`${origin}/`);
    const policy = res.headers.get('permissions-policy');
    for (const feature of ['camera', 'microphone', 'geolocation', 'payment', 'usb']) {
      assert.match(policy, new RegExp(`${feature}=\\(\\)`), `${feature} is not disabled`);
    }
  });

  test('HSTS is off by default and on when asked', async () => {
    const res = await fetch(`${origin}/`);
    assert.equal(
      res.headers.get('strict-transport-security'),
      null,
      'HSTS should not be sent until the deployment is confirmed over HTTPS',
    );
    assert.match(
      securityHeaders({ hsts: true })['Strict-Transport-Security'],
      /max-age=31536000/,
    );
  });

  test('the server does not announce itself', async () => {
    const res = await fetch(`${origin}/`);
    for (const header of ['server', 'x-powered-by']) {
      assert.equal(res.headers.get(header), null, `${header} is being sent`);
    }
  });

  test('the share image is embeddable cross-origin, pages are not', async () => {
    // Social scrapers fetch og.png from another origin; if CORP blocks it the
    // preview silently breaks.
    const image = await fetch(`${origin}/og.png`);
    assert.equal(image.headers.get('cross-origin-resource-policy'), 'cross-origin');

    const page = await fetch(`${origin}/`);
    assert.equal(page.headers.get('cross-origin-resource-policy'), 'same-origin');
  });
});

describe('the content security policy', () => {
  let csp = '';
  let directives = new Map();

  before(async () => {
    const res = await fetch(`${origin}/`);
    csp = res.headers.get('content-security-policy');
    directives = new Map(
      csp.split(';').map((part) => {
        const [name, ...values] = part.trim().split(/\s+/);
        return [name, values];
      }),
    );
  });

  test('has no escape hatches', () => {
    for (const bad of ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", 'strict-dynamic']) {
      assert.ok(!csp.includes(bad), `CSP contains ${bad}: ${csp}`);
    }
  });

  test('has no wildcard sources', () => {
    for (const [name, values] of directives) {
      for (const value of values) {
        assert.ok(value !== '*', `${name} allows *`);
        assert.ok(!value.startsWith('*.'), `${name} allows the wildcard host ${value}`);
        assert.ok(value !== 'data:', `${name} allows data: URLs`);
        assert.ok(value !== 'blob:', `${name} allows blob: URLs`);
        assert.ok(value !== 'https:', `${name} allows any https origin`);
      }
    }
  });

  test('locks down the directives that matter most', () => {
    assert.deepEqual(directives.get('default-src'), ["'self'"]);
    assert.deepEqual(directives.get('script-src'), ["'self'"]);
    assert.deepEqual(directives.get('style-src'), ["'self'"]);
    assert.deepEqual(directives.get('object-src'), ["'none'"]);
    assert.deepEqual(directives.get('base-uri'), ["'none'"]);
    assert.deepEqual(directives.get('frame-ancestors'), ["'none'"]);
    assert.deepEqual(directives.get('form-action'), ["'none'"]);
  });

  test('allows no network calls at all, because the page makes none', () => {
    assert.deepEqual(directives.get('connect-src'), ["'none'"]);
  });

  test('names no external origin anywhere', () => {
    assert.ok(!/https?:\/\//.test(csp), `CSP references an external origin: ${csp}`);
  });
});

// --- path handling ---------------------------------------------------------------

describe('nothing outside the root is reachable', () => {
  const attempts = [
    'GET /../package.json',
    'GET /../../package.json',
    'GET /..%2f..%2fpackage.json',
    'GET /%2e%2e/%2e%2e/package.json',
    'GET /..%252f..%252fpackage.json',
    'GET /....//....//package.json',
    'GET /..\\..\\package.json',
    'GET /%5c..%5cpackage.json',
    'GET /docs/../../package.json',
    'GET /docs/%2e%2e/%2e%2e/src/index.ts',
    'GET /./../../src/core/paths.ts',
    'GET //etc/passwd',
    'GET /%00../package.json',
    'GET /index.html%00.txt',
    'GET /../.git/config',
    'GET /../site/serve.mjs',
    'GET /../../../../../../etc/passwd',
  ];

  for (const attempt of attempts) {
    test(attempt, async () => {
      const response = await raw(attempt);
      const status = statusOf(response);
      assert.ok(
        status === 404 || status === 400 || status === 308,
        `${attempt} returned ${status}`,
      );
      // Whatever the status, nothing from outside the root may appear.
      assert.ok(!/"name":\s*"leastgrant"/.test(response), `${attempt} served package.json`);
      assert.ok(!/root:.*x:0:0/.test(response), `${attempt} served /etc/passwd`);
      assert.ok(!/createServer/.test(response), `${attempt} served server source`);
    });
  }

  test('a directory with no index is not listed', async () => {
    const res = await fetch(`${origin}/fonts/`);
    assert.equal(res.status, 404);
    const body = await res.text();
    // The 404 page itself preloads a font, so "mentions a font file" is not the
    // test. A listing would name several files and would not be the 404 page.
    assert.match(body, /Nothing here/, 'expected the 404 page');
    const fontMentions = (body.match(/IBMPlex\w+-\w+\.woff2/g) || []).length;
    assert.ok(fontMentions <= 2, `the font directory looks listed (${fontMentions} font files named)`);
    assert.ok(!body.includes('OFL.txt'), 'the font directory was listed');
  });

  test('the dotfile-ish and source paths that do not exist stay 404', async () => {
    for (const url of ['/.git/config', '/.env', '/package.json', '/src/index.ts', '/site/build.mjs']) {
      const res = await fetch(origin + url);
      assert.equal(res.status, 404, `${url} returned ${res.status}`);
    }
  });
});

// --- protocol behaviour ------------------------------------------------------------

describe('protocol behaviour', () => {
  test('a bare page path redirects to the trailing-slash form', async () => {
    const res = await fetch(`${origin}/security`, { redirect: 'manual' });
    assert.equal(res.status, 308);
    assert.equal(res.headers.get('location'), '/security/');
  });

  test('methods other than GET and HEAD are refused', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const res = await fetch(`${origin}/`, { method });
      assert.equal(res.status, 405, `${method} returned ${res.status}`);
      assert.equal(res.headers.get('allow'), 'GET, HEAD');
    }
  });

  test('TRACE and CONNECT are refused too', async () => {
    // fetch() refuses to issue these at all -- they are forbidden methods in
    // the spec -- so they have to go down a raw socket. TRACE is worth checking
    // explicitly: a server that echoes the request back is a cross-site tracing
    // problem, and "we never implemented it" is not the same as a 405.
    for (const method of ['TRACE', 'CONNECT']) {
      const response = await raw(`${method} /`);
      assert.equal(statusOf(response), 405, `${method} was not refused`);
      assert.ok(!/Host: 127\.0\.0\.1/.test(response.split('\r\n\r\n')[1] || ''), `${method} echoed the request`);
    }
  });

  test('HEAD returns the headers and no body', async () => {
    const res = await fetch(`${origin}/`, { method: 'HEAD' });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), '');
    assert.ok(Number(res.headers.get('content-length')) > 1000);
  });

  test('content types are correct and charset-qualified', async () => {
    const css = [...fs.readdirSync(DIST)].find((f) => /^app\.[0-9a-f]+\.css$/.test(f));
    const js = [...fs.readdirSync(DIST)].find((f) => /^app\.[0-9a-f]+\.js$/.test(f));
    const cases = [
      ['/', 'text/html; charset=utf-8'],
      [`/${css}`, 'text/css; charset=utf-8'],
      [`/${js}`, 'text/javascript; charset=utf-8'],
      ['/favicon.svg', 'image/svg+xml'],
      ['/og.png', 'image/png'],
      [`/fonts/${aFont()}`, 'font/woff2'],
      ['/site.webmanifest', 'application/manifest+json; charset=utf-8'],
      ['/sitemap.xml', 'application/xml; charset=utf-8'],
      ['/robots.txt', 'text/plain; charset=utf-8'],
    ];
    for (const [url, type] of cases) {
      const res = await fetch(origin + url);
      assert.equal(res.status, 200, url);
      assert.equal(res.headers.get('content-type'), type, url);
    }
  });

  test('caching says immutable only for content-hashed names', async () => {
    const css = [...fs.readdirSync(DIST)].find((f) => /^app\.[0-9a-f]+\.css$/.test(f));

    const page = await fetch(`${origin}/`);
    assert.match(page.headers.get('cache-control'), /must-revalidate/);

    const asset = await fetch(`${origin}/${css}`);
    assert.match(asset.headers.get('cache-control'), /immutable/);

    const font = await fetch(`${origin}/fonts/${aFont()}`);
    assert.match(font.headers.get('cache-control'), /max-age=31536000/);
  });

  test('fonts are content-hashed, so a year of immutable is safe', () => {
    // `immutable` under a name that never changes means a font can be replaced
    // in the build and never reach anyone who has already visited.
    for (const name of fs.readdirSync(path.join(DIST, 'fonts')).filter((f) => f.endsWith('.woff2'))) {
      assert.match(name, /\.[0-9a-f]{8,}\.woff2$/, `${name} is not content-hashed`);
    }
  });

  test('an ETag round-trips to a 304', async () => {
    const first = await fetch(`${origin}/`);
    const tag = first.headers.get('etag');
    assert.ok(tag, 'no ETag');
    const second = await fetch(`${origin}/`, { headers: { 'If-None-Match': tag } });
    assert.equal(second.status, 304);
  });

  test('precompressed bodies are served when accepted, and only then', async () => {
    const withBr = await raw('GET /', 'Accept-Encoding: br\r\n');
    assert.match(withBr, /content-encoding: br/i);
    assert.match(withBr, /vary: Accept-Encoding/i);

    const plain = await raw('GET /', 'Accept-Encoding: identity\r\n');
    assert.ok(!/content-encoding:/i.test(plain), 'compressed a client that did not ask');
    assert.match(plain, /<!doctype html>/i);
  });

  test('a malformed request does not crash the server', async () => {
    await raw('GET /%%%%');
    await raw('GET ' + '/a'.repeat(4000));
    await raw('GET /?' + 'x'.repeat(8000));
    const res = await fetch(`${origin}/`);
    assert.equal(res.status, 200, 'the server stopped answering after malformed input');
  });

  test('no internal path or stack ever reaches the client', async () => {
    for (const url of ['/no-such-page', '/../package.json', '/%%%']) {
      const response = await raw(`GET ${url}`);
      assert.ok(!/at \w+ \(/.test(response), `${url} leaked a stack trace`);
      assert.ok(!/[A-Za-z]:[\\/]LeastGrant/.test(response), `${url} leaked the checkout path`);
      assert.ok(!/node_modules/.test(response), `${url} leaked a module path`);
    }
  });
});

// --- the served pages themselves ---------------------------------------------------

describe('what a browser actually receives', () => {
  test('the home page arrives complete and inert', async () => {
    const html = await (await fetch(`${origin}/`)).text();
    assert.match(html, /<h1>LeastGrant<\/h1>/);
    assert.match(html, /npm install -g leastgrant/);
    // Everything the reader needs is in the HTML, before any script runs.
    assert.match(html, /✓ allow/);
    assert.match(html, /✗ deny/);
  });

  test('the 404 body does not echo the requested path', async () => {
    // Reflecting the URL is the classic way a static site grows a reflected
    // XSS, and there is nothing on this site that needs to.
    const res = await fetch(`${origin}/${encodeURIComponent('<script>alert(1)</script>')}`);
    const body = await res.text();
    assert.equal(res.status, 404);
    assert.ok(!body.includes('alert(1)'), 'the 404 page reflected the request');
    assert.ok(!body.includes('script>alert'), 'the 404 page reflected the request');
  });

  test('a query string cannot change what is served', async () => {
    const plain = await (await fetch(`${origin}/`)).text();
    const noisy = await (await fetch(`${origin}/?x=<script>&y=../../etc/passwd`)).text();
    assert.equal(plain, noisy);
  });
});

// --- regressions from the adversarial review --------------------------------
//
// Every case below was found by an independent reviewer attacking the built
// site, reproduced, and fixed. They are here so the fix cannot be undone
// quietly.

describe('content negotiation says what it means', () => {
  test('an explicit q=0 is a refusal, not an acceptance', async () => {
    // `br;q=0` means "do not send me brotli". A substring test for "br" says
    // yes and the client gets a body it told us it cannot decode.
    const refused = await raw('GET /', 'Accept-Encoding: br;q=0, gzip;q=0\r\n');
    assert.ok(!/content-encoding:/i.test(refused), 'compressed a client that refused both');
    assert.match(refused, /<!doctype html>/i);
  });

  test('a wildcard is honoured, and a specific refusal beats it', async () => {
    const wild = await raw('GET /', 'Accept-Encoding: *\r\n');
    assert.match(wild, /content-encoding: br/i);

    const mixed = await raw('GET /', 'Accept-Encoding: *, br;q=0\r\n');
    assert.ok(!/content-encoding: br/i.test(mixed), 'brotli sent despite br;q=0');
  });

  test('the ETag describes the bytes actually sent, not the identity file', async () => {
    // An ETag identifies a representation. Serving brotli under the identity
    // file's tag lets a cache satisfy one request with the other.
    const plain = await raw('GET /', 'Accept-Encoding: identity\r\n');
    const brotli = await raw('GET /', 'Accept-Encoding: br\r\n');
    const tagOf = (r) => (r.match(/etag: (\S+)/i) || [])[1];
    assert.ok(tagOf(plain) && tagOf(brotli), 'missing ETag');
    assert.notEqual(tagOf(plain), tagOf(brotli), 'both variants share one ETag');
  });

  test('If-None-Match: * is a 304', async () => {
    const res = await fetch(`${origin}/`, { headers: { 'If-None-Match': '*' } });
    assert.equal(res.status, 304);
  });
});

describe('one resource, one URL', () => {
  test('a request target starting with // is refused, not routed by authority', async () => {
    // `new URL('//evil/docs/', base)` reads `evil` as the host and returns
    // `/docs/`, so this would otherwise serve the docs page under unbounded
    // numbers of URLs.
    for (const target of ['GET //evil.example/docs/', 'GET //x/', 'GET ///']) {
      const response = await raw(target);
      assert.equal(statusOf(response), 400, `${target} was routed`);
    }
  });

  test('an NTFS alternate data stream suffix does not reach the file', async () => {
    for (const target of ['GET /index.html::$DATA', 'GET /index.html:x', 'GET /docs/:$i30:$INDEX_ALLOCATION']) {
      const response = await raw(target);
      assert.notEqual(statusOf(response), 200, `${target} was served`);
    }
  });

  test('trailing dots and spaces do not name the same file twice', async () => {
    for (const target of ['GET /index.html.', 'GET /index.html%20', 'GET /index.html%2e']) {
      const response = await raw(target);
      assert.notEqual(statusOf(response), 200, `${target} was served`);
    }
  });
});

describe('every response is a complete response', () => {
  test('the redirect can be cached but not forever', async () => {
    const res = await fetch(`${origin}/security`, { redirect: 'manual' });
    assert.equal(res.status, 308);
    assert.match(res.headers.get('cache-control'), /max-age=\d+/);
  });

  test('the CONNECT and Upgrade refusals still carry a type and nosniff', async () => {
    for (const method of ['CONNECT', 'TRACE']) {
      const response = await raw(`${method} /`);
      assert.equal(statusOf(response), 405);
      assert.match(response, /content-type: text\/plain/i, `${method} has no content type`);
      assert.match(response, /x-content-type-options: nosniff/i, `${method} can be sniffed`);
    }
  });
});

describe('one file, one address', () => {
  // Found by the adversarial review: the resolver normalises before it looks a
  // file up, so the same page was reachable at unboundedly many URLs. Each is a
  // separate cache key at the edge, and for a hashed asset each is a separate
  // year-long entry.
  test('an authority-shaped target is refused, not silently dropped', async () => {
    for (const target of ['GET //docs/', 'GET //evil.example/security/', 'GET http://evil.example/security/']) {
      const response = await raw(target);
      assert.equal(statusOf(response), 400, `${target} was served`);
    }
  });

  test('every other alias redirects to the canonical address', async () => {
    const aliases = [
      ['GET /docs//', '/docs/'],
      ['GET /%5C/docs/', '/docs/'],
      ['GET /%2f/docs/', '/docs/'],
      ['GET /.//docs/', '/docs/'],
      ['GET /index.html', '/'],
      ['GET /security', '/security/'],
    ];
    for (const [target, expected] of aliases) {
      const response = await raw(target);
      assert.equal(statusOf(response), 308, `${target} did not redirect`);
      const location = (response.match(/location: (\S+)/i) || [])[1];
      assert.equal(location, expected, `${target} redirected to ${location}`);
    }
  });

  test('a redirect target is always root-relative and never attacker-controlled', async () => {
    // Location is built from the resolved file's path under the root, so no
    // request can steer it off-site.
    for (const target of ['GET /docs//', 'GET /security', 'GET /%5C/docs/']) {
      const location = ((await raw(target)).match(/location: (\S+)/i) || [])[1];
      assert.ok(location.startsWith('/'), `${target} -> ${location}`);
      assert.ok(!location.startsWith('//'), `${target} -> ${location} is protocol-relative`);
      assert.ok(!/[a-z]+:/i.test(location), `${target} -> ${location} carries a scheme`);
    }
  });

  test('the query string survives the redirect', async () => {
    const location = ((await raw('GET /security?a=1')).match(/location: (\S+)/i) || [])[1];
    assert.equal(location, '/security/?a=1');
  });

  test('paths the URL parser already canonicalises are served, not bounced', async () => {
    // `/./docs/` and `/security/.` normalise to the canonical path in the
    // parser itself, so every intermediary agrees on one cache key and there is
    // nothing to redirect.
    for (const target of ['GET /./docs/', 'GET /security/.']) {
      assert.equal(statusOf(await raw(target)), 200, `${target} should be served directly`);
    }
  });
});
