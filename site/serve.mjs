/**
 * The origin server for leastgrant.xyz.
 *
 *     node site/serve.mjs                     127.0.0.1:8787, serves site/dist
 *     node site/serve.mjs --port 8080 --root /srv/leastgrant/current
 *
 * This is the production origin, not a dev server. Cloudflare Tunnel connects
 * to it over loopback and Cloudflare terminates TLS at the edge, so this
 * process never listens on a public interface and never needs a certificate.
 *
 * Zero dependencies, and small enough to read in one sitting -- which is the
 * point. The alternative was a general-purpose web server with a configuration
 * file, and for a site that is 24 static files the configuration file is the
 * larger attack surface.
 *
 * What it deliberately does not do: directory listings, symlink following out
 * of the root, range requests, byte-serving, virtual hosts, rewrites, or
 * anything with a request body. Every request is either a file that exists
 * under the root or a 404.
 *
 * Security headers are attached here rather than at the edge, because this is
 * where the response is actually produced. Cloudflare can add more; it cannot
 * be relied on to add these.
 */

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// --- options -----------------------------------------------------------------

function options(argv) {
  const get = (flag, fallback) => {
    const i = argv.indexOf(flag);
    return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
  };
  return {
    port: Number(get('--port', process.env['PORT'] || 8787)),
    host: get('--host', '127.0.0.1'),
    root: path.resolve(get('--root', path.join(HERE, 'dist'))),
    // Off by default. Turning HSTS on before the domain is confirmed working
    // over HTTPS is how a mistake becomes a mistake nobody can visit their way
    // out of for the length of max-age.
    hsts: argv.includes('--hsts'),
  };
}

// --- headers -----------------------------------------------------------------

/**
 * The policy.
 *
 * Derived from what the site actually loads, not copied from a template:
 *
 *   default-src 'self'     everything defaults to this origin
 *   script-src  'self'     one external file, no inline, no eval
 *   style-src   'self'     one stylesheet, no inline, no style attributes
 *   img-src     'self'     the favicon and the icons; no remote images anywhere
 *   font-src    'self'     four self-hosted subsets
 *   connect-src 'none'     the page makes no fetch, XHR, beacon or websocket
 *   form-action 'none'     there is no form on this site
 *   frame-src   'none'     nothing is embedded
 *   frame-ancestors 'none' and nothing embeds this
 *   base-uri    'none'     a <base> tag could re-point every relative URL
 *   object-src  'none'     no plugins, ever
 *
 * `unsafe-inline` and `unsafe-eval` are absent because the build produces no
 * inline script or style and the one script file uses neither `eval` nor
 * `new Function`. That is checked in the tests, so widening this later means
 * failing a test rather than quietly editing a string.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "manifest-src 'self'",
  'upgrade-insecure-requests',
].join('; ');

/** Features this site does not use, switched off for anything it embeds. */
const PERMISSIONS = [
  'accelerometer=()',
  'autoplay=()',
  'camera=()',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=()',
  'geolocation=()',
  'gyroscope=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'usb=()',
  'xr-spatial-tracking=()',
].join(', ');

export function securityHeaders({ hsts = false, shareable = false } = {}) {
  const headers = {
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': PERMISSIONS,
    // Redundant with frame-ancestors for anything current, and free for
    // anything that is not.
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    // Social previews are fetched by other origins, so the image and icons have
    // to stay reachable. Everything else is same-origin only.
    'Cross-Origin-Resource-Policy': shareable ? 'cross-origin' : 'same-origin',
  };
  if (hsts) headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  return headers;
}

// --- content types -----------------------------------------------------------

const TYPES = new Map(
  Object.entries({
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.webmanifest': 'application/manifest+json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.txt': 'text/plain; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',
  }),
);

/**
 * Cache policy.
 *
 * HTML is revalidated every time, so a deploy is visible immediately. Fonts and
 * images are effectively immutable -- changing one means changing its name --
 * so they get a year. CSS and JS sit in between: the build gives them a
 * content hash in the filename, so they are immutable too, but the unhashed
 * names are still served for anyone with an old link.
 */
function cacheFor(rel, ext) {
  if (ext === '.html' || rel === 'sitemap.xml' || rel === 'robots.txt') {
    return 'public, max-age=0, must-revalidate';
  }
  if (/\.[0-9a-f]{8,}\.(css|js)$/.test(rel)) return 'public, max-age=31536000, immutable';
  if (ext === '.woff2') return 'public, max-age=31536000, immutable';
  if (ext === '.png' || ext === '.svg' || ext === '.ico') return 'public, max-age=604800';
  return 'public, max-age=3600';
}

/** Files that other origins are allowed to embed: the share image and icons. */
function isShareable(rel) {
  return /^(og\.png|favicon\.svg|icon-\d+\.png)$/.test(rel);
}

// --- path resolution ---------------------------------------------------------

/**
 * Turn a request URL into a file under `root`, or null.
 *
 * The containment check is done on the resolved real path, not on the string.
 * A prefix comparison against an unresolved path is exactly the bug LeastGrant
 * exists to catch in other people's tools, and it would be embarrassing to ship
 * it in this one: `..` after a symlink is resolved physically by the kernel, so
 * a string that looks contained can name a file that is not.
 */
async function resolve(root, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null; // malformed percent-encoding
  }
  if (decoded.includes('\0')) return null;

  // Backslash is a separator on Windows and a literal elsewhere. Normalising it
  // here means the same request resolves the same way on either.
  const clean = decoded.replace(/\\/g, '/');
  if (!clean.startsWith('/')) return null;

  // No path this site serves contains a colon, and on Windows a colon opens an
  // NTFS alternate data stream: `/index.html::$DATA` names the same file by
  // another route, which slips past any check keyed on the visible name. Reject
  // it everywhere rather than only where it is exploitable, so the Linux origin
  // and a Windows developer machine behave identically.
  if (clean.includes(':')) return null;

  // Windows also silently strips trailing dots and spaces from filenames, so
  // `/index.html.` and `/index.html ` resolve to the same file under different
  // names. Same argument.
  if (clean.split('/').some((segment) => /[ .]$/.test(segment) && segment !== '.' && segment !== '..')) {
    return null;
  }

  const candidates = [];
  const rel = clean.slice(1);
  if (clean.endsWith('/')) {
    candidates.push(path.join(root, rel, 'index.html'));
  } else {
    candidates.push(path.join(root, rel));
    candidates.push(path.join(root, rel, 'index.html'));
    candidates.push(path.join(root, `${rel}.html`));
  }

  const realRoot = await fsp.realpath(root);
  for (const candidate of candidates) {
    let stat;
    let real;
    try {
      real = await fsp.realpath(candidate);
      stat = await fsp.stat(real);
    } catch {
      continue;
    }
    if (!stat.isFile()) continue;

    // Compare component-wise. `realRoot + path.sep` as a string prefix is the
    // usual shortcut and it says yes to a sibling directory whose name starts
    // with the root's name.
    const relative = path.relative(realRoot, real);
    if (relative.startsWith('..') || path.isAbsolute(relative)) continue;

    return { file: real, rel: relative.split(path.sep).join('/'), size: stat.size, mtime: stat.mtimeMs };
  }
  return null;
}

// --- the server --------------------------------------------------------------

const etags = new Map();

async function etagFor(file, size, mtime) {
  const key = `${file}:${size}:${mtime}`;
  const cached = etags.get(key);
  if (cached) return cached;
  const hash = createHash('sha256').update(await fsp.readFile(file)).digest('base64url').slice(0, 22);
  const tag = `"${hash}"`;
  etags.set(key, tag);
  return tag;
}

/**
 * Parse Accept-Encoding properly, including the quality values.
 *
 * A substring test for "br" is wrong in the one case that matters: a client
 * sending `br;q=0` is explicitly refusing brotli, and `/\bbr\b/` says yes. The
 * same client then receives a body it told us it cannot decode.
 */
function accepts(header) {
  // An explicit q=0 is a refusal and must beat a wildcard, so refusals are
  // tracked separately rather than by absence from the allowed set.
  const weights = new Map();
  for (const part of String(header || '').split(',')) {
    const [token, ...params] = part.trim().split(';');
    if (!token.trim()) continue;
    const q = params.map((p) => p.trim().match(/^q=([\d.]+)$/i)).find(Boolean);
    weights.set(token.trim().toLowerCase(), q ? Number(q[1]) : 1);
  }
  return (encoding) => {
    if (weights.has(encoding)) return weights.get(encoding) > 0;
    if (weights.has('*')) return weights.get('*') > 0;
    return false;
  };
}

/**
 * Pick a precompressed sibling the client will accept.
 *
 * The sibling is only used if it is at least as new as the file it compresses.
 * The build writes both together, so a stale `.br` means somebody edited the
 * web root by hand -- and serving a year-cacheable, hash-named asset whose
 * *compressed* variant is from a different build is exactly the kind of
 * mismatch content hashing exists to prevent.
 */
function encodingFor(accept, file) {
  const ok = accepts(accept);
  const source = fs.statSync(file, { throwIfNoEntry: false });
  for (const [enc, ext] of [
    ['br', '.br'],
    ['gzip', '.gz'],
  ]) {
    if (!ok(enc)) continue;
    const sibling = `${file}${ext}`;
    const stat = fs.statSync(sibling, { throwIfNoEntry: false });
    if (!stat || !source) continue;
    if (stat.mtimeMs + 1000 < source.mtimeMs) continue; // stale; serve the original
    return { enc, file: sibling, size: stat.size, mtime: stat.mtimeMs };
  }
  return null;
}

export function createServer(opts) {
  const server = http.createServer(handler(opts));

  // CONNECT and Upgrade never reach the request handler -- Node routes them to
  // their own events, and with no listener it simply drops the socket. Dropping
  // is safe, but an origin should refuse them out loud rather than by omission:
  // a static file server that can be talked into proxying or upgrading is a
  // pivot into whatever else is on this host's loopback interface.
  //
  // These are hand-written onto the socket because there is no `res` to write
  // through, so they need their headers spelled out. A response without a
  // declared type and `nosniff` is one a browser is free to sniff.
  const refuse = (socket, what) => {
    const body = `${what} is not supported\n`;
    socket.end(
      'HTTP/1.1 405 Method Not Allowed\r\n' +
        'Allow: GET, HEAD\r\n' +
        'Content-Type: text/plain; charset=utf-8\r\n' +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        'X-Content-Type-Options: nosniff\r\n' +
        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'\r\n" +
        'Cache-Control: no-store\r\n' +
        'Connection: close\r\n\r\n' +
        body,
    );
  };
  server.on('connect', (_req, socket) => refuse(socket, 'CONNECT'));
  server.on('upgrade', (_req, socket) => refuse(socket, 'upgrade'));

  return server;
}

function handler(opts) {
  return async (req, res) => {
    const send = (status, body, headers = {}) => {
      res.writeHead(status, {
        ...securityHeaders({ hsts: opts.hsts }),
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': Buffer.byteLength(body),
        ...headers,
      });
      res.end(req.method === 'HEAD' ? undefined : body);
    };

    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        send(405, 'method not allowed\n', { Allow: 'GET, HEAD' });
        return;
      }

      // `req.url` is a path, but parse it properly rather than splitting on '?'
      // -- a request line may carry an absolute URI, and the query is not the
      // only thing that can follow the path.
      //
      // A request target starting with `//` is rejected rather than parsed.
      // `new URL('//evil/x', base)` reads `evil` as the authority and returns
      // `/x`, so `GET //anything/docs/` would happily serve `/docs/`. Nothing
      // here needs that, and one resource reachable at unbounded numbers of
      // URLs is a cache-key problem waiting to happen.
      if (!req.url || !req.url.startsWith('/') || req.url.startsWith('//')) {
        send(400, 'bad request\n');
        return;
      }

      let urlPath;
      try {
        urlPath = new URL(req.url, 'http://localhost').pathname;
      } catch {
        send(400, 'bad request\n');
        return;
      }

      const found = await resolve(opts.root, urlPath);

      if (!found) {
        const notFound = path.join(opts.root, '404.html');
        if (fs.existsSync(notFound)) {
          const body = await fsp.readFile(notFound);
          res.writeHead(404, {
            ...securityHeaders({ hsts: opts.hsts }),
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': body.length,
            'Cache-Control': 'no-store',
          });
          res.end(req.method === 'HEAD' ? undefined : body);
        } else {
          send(404, 'not found\n');
        }
        return;
      }

      // One file, one address.
      //
      // The resolver normalises before it looks anything up -- it decodes,
      // turns backslashes into slashes, and lets `path.join` collapse `.` and
      // empty segments. That is correct for finding the file and wrong for
      // deciding what to answer: `/./docs/`, `/docs//`, `/%5C/docs/` and
      // `//docs/` all land on the same page, so the same bytes are reachable at
      // unboundedly many URLs. Each is a separate cache key at the edge, and
      // for hashed assets each is a separate year-long entry.
      //
      // So the requested path is compared against the canonical path of the
      // file that was found, and anything else is redirected to it rather than
      // served. This subsumes the trailing-slash rule, which was only one
      // member of the family.
      const canonical = found.rel.endsWith('index.html')
        ? `/${found.rel.slice(0, -'index.html'.length)}`
        : `/${found.rel}`;

      if (urlPath !== canonical) {
        const to = canonical + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
        res.writeHead(308, {
          ...securityHeaders({ hsts: opts.hsts }),
          Location: to,
          // A 308 is permanent by status, but a browser caching it forever with
          // no expiry makes a URL layout change unrecoverable for that visitor.
          'Cache-Control': 'public, max-age=3600',
          'Content-Length': '0',
        });
        res.end();
        return;
      }

      const ext = path.extname(found.file).toLowerCase();
      const shareable = isShareable(found.rel);

      // Choose the variant *before* computing the validator.
      //
      // An ETag identifies a representation, not a file. Serving the brotli
      // bytes under the identity file's tag means a cache that stored one can
      // satisfy a request for the other -- and it means the tag no longer
      // certifies what was actually sent, which is the entire job of a content
      // hash on an immutable asset.
      const compressed = /\.(html|css|js|svg|json|xml|txt|webmanifest)$/.test(found.file)
        ? encodingFor(req.headers['accept-encoding'], found.file)
        : null;

      const file = compressed ? compressed.file : found.file;
      const size = compressed ? compressed.size : found.size;
      const mtime = compressed ? compressed.mtime : found.mtime;
      const tag = await etagFor(file, size, mtime);

      const headers = {
        ...securityHeaders({ hsts: opts.hsts, shareable }),
        'Content-Type': TYPES.get(ext) || 'application/octet-stream',
        'Cache-Control': cacheFor(found.rel, ext),
        ETag: tag,
        Vary: 'Accept-Encoding',
      };
      if (compressed) headers['Content-Encoding'] = compressed.enc;

      // `If-None-Match: *` means "if any representation exists" -- which one
      // does, so the answer is 304.
      const inm = req.headers['if-none-match'];
      if (inm === tag || inm === '*') {
        res.writeHead(304, headers);
        res.end();
        return;
      }

      const body = await fsp.readFile(file);
      headers['Content-Length'] = body.length;
      res.writeHead(200, headers);
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch (err) {
      // Never let an internal path or stack reach the client.
      process.stderr.write(`serve: ${err && err.message}\n`);
      if (!res.headersSent) send(500, 'internal error\n');
      else res.end();
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const opts = options(process.argv.slice(2));
  if (!fs.existsSync(opts.root)) {
    console.error(`no such root: ${opts.root}\nrun \`npm run site:build\` first`);
    process.exit(1);
  }
  const server = createServer(opts);

  // A stack trace is the wrong way to say "that port is taken". This is the
  // process a service manager restarts in a loop; the log it leaves has to be
  // readable by whoever is looking at 3am.
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`port ${opts.port} on ${opts.host} is already in use`);
    } else if (err.code === 'EACCES') {
      console.error(`not permitted to bind ${opts.host}:${opts.port}`);
    } else {
      console.error(`could not start: ${err.message}`);
    }
    process.exit(1);
  });

  server.listen(opts.port, opts.host, () => {
    console.log(`leastgrant.xyz origin  http://${opts.host}:${opts.port}  (root ${opts.root})`);
    if (opts.hsts) console.log('HSTS enabled');
  });
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => server.close(() => process.exit(0)));
  }
}
