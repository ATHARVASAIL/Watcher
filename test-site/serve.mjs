#!/usr/bin/env node
/**
 * Fixture server for manual testing and the e2e suite.
 *
 *   node test-site/serve.mjs        → http://localhost:8765 (use localhost, not 127.0.0.1)
 *
 * Serves a strict page CSP (no inline scripts, connect-src 'none') to show the
 * extension's scanner works on hardened sites. Only GET/HEAD, no directory
 * listings, path traversal is rejected, and it binds to loopback only.
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
};

const csp = (port) =>
  [
    "default-src 'self'",
    `script-src 'self' http://127.0.0.1:${port}`,
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ].join('; ');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Start the fixture server. Resolves with { url, close }. */
export function startServer({ port = 8765, quiet = false } = {}) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);
    // ?delay=ms simulates a slow asset (used by the cancel test); never cached so it stays slow.
    const delay = Math.min(Number(url.searchParams.get('delay')) || 0, 10_000);

    const send = (status, body = '', type = 'text/plain; charset=utf-8') => {
      res.writeHead(status, {
        'Content-Type': type,
        'Content-Security-Policy': csp(port),
        'Cache-Control': delay ? 'no-store' : 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      });
      res.end(req.method === 'HEAD' ? undefined : body);
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, 'Method not allowed');

    if (delay > 0) await sleep(delay);

    let pathname;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      return send(400, 'Bad request');
    }
    const filePath = normalize(join(ROOT, pathname === '/' ? 'index.html' : pathname));
    if (!filePath.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep) || pathname.includes('\0')) {
      return send(403, 'Forbidden');
    }
    try {
      const info = await stat(filePath);
      if (!info.isFile()) return send(404, 'Not found');
      const body = await readFile(filePath);
      send(200, body, MIME[extname(filePath)] || 'application/octet-stream');
      if (!quiet) console.log(`[fixture] ${req.method} ${url.pathname}${url.search} 200`);
    } catch {
      send(404, 'Not found');
      if (!quiet) console.log(`[fixture] ${req.method} ${url.pathname} 404`);
    }
    return undefined;
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () =>
      resolve({
        url: `http://localhost:${port}`,
        close: () => new Promise((done) => server.close(() => done())),
      }),
    );
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT) || 8765;
  const { url } = await startServer({ port });
  console.log(`Fixture site: ${url}  (Ctrl+C to stop)`);
}
