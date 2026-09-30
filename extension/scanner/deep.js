/**
 * Watcher — deep scan passes (page context, same-origin, no extra permissions).
 *
 *   - crawl:      follow same-site links, read same-origin iframes, scan Service Worker caches
 *   - probeFiles: GET a list of commonly-exposed files on this origin
 *
 * Everything here is read-only GET traffic to the page's own origin (or, with
 * "Full access" on, cross-origin too). It reuses the scan orchestrator's own
 * file/inline scanners through the `api` object, so source maps and grouping
 * behave exactly as they do for the main pass.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.deep) return;

  const { LIMITS, PROBE_PATHS } = ns.config;
  const src = ns.sources;

  const NON_HTML_EXT =
    /\.(?:js|mjs|cjs|css|png|jpe?g|gif|svg|webp|avif|ico|pdf|zip|gz|mp4|webm|woff2?|ttf|map)$/i;
  const sameOrigin = (url) => url.origin === location.origin;

  /* ------------------------------------------------------------ same-origin iframes */

  async function scanIframes(opts, api) {
    const frames = [...document.querySelectorAll('iframe')].slice(0, LIMITS.maxIframes);
    let n = 0;
    for (const frame of frames) {
      if (api.signal.aborted) break;
      let doc;
      try {
        doc = frame.contentDocument; // throws or null across origins
      } catch {
        continue;
      }
      if (!doc) continue;
      n++;
      const label = `iframe #${n}${frame.src ? ` (${src.oneLine(frame.src, 80)})` : ''}`;
      try {
        // Inline scripts inside the frame.
        doc.querySelectorAll('script:not([src])').forEach((s, i) => {
          if (s.textContent && s.textContent.trim())
            api.scanInline(s.textContent, 'inline-script', `${label} › inline <script> #${i + 1}`);
        });
        // The frame's markup (comments, attributes).
        api.scanInline(doc.documentElement.outerHTML.slice(0, 2_000_000), 'html', `${label} › HTML`);
        // Same-origin files the frame loaded.
        for (const s of doc.querySelectorAll('script[src]')) {
          const url = src.absUrl(s.getAttribute('src'), doc.baseURI);
          if (url && (sameOrigin(url) || opts.includeCrossOrigin))
            await api.scanFileUrl(url.href, 'script-file', label);
        }
      } catch {
        /* frame navigated away mid-scan */
      }
      api.report(label);
    }
  }

  /* ------------------------------------------------------------ crawl same-site pages */

  function internalLinks() {
    const urls = new Map();
    for (const a of document.querySelectorAll('a[href]')) {
      const url = src.absUrl(a.getAttribute('href'));
      if (!url || !sameOrigin(url)) continue;
      if (url.pathname === location.pathname && url.search === location.search) continue;
      if (NON_HTML_EXT.test(url.pathname)) continue;
      if (!/^https?:$/.test(url.protocol)) continue;
      urls.set(url.href, url);
    }
    return [...urls.values()].slice(0, LIMITS.maxCrawlPages);
  }

  async function crawlPages(opts, api) {
    const pages = internalLinks();
    let cursor = 0;
    const worker = async () => {
      while (cursor < pages.length && !api.signal.aborted) {
        const url = pages[cursor++];
        if (api.markSeen(url.href)) continue;
        const r = await api.fetchText(url.href, { allowHtml: true });
        if (r.error) {
          api.skipped.push({ label: src.displayUrl(url), reason: `crawl: ${r.error}` });
          api.report(`crawled ${src.displayUrl(url)}`);
          continue;
        }
        const label = `${src.displayUrl(url)} (crawled)`;
        api.scanInline(r.text, 'html', label);
        // Pull scripts/styles referenced by the crawled page and scan them too.
        try {
          const doc = new DOMParser().parseFromString(r.text, 'text/html');
          doc.querySelectorAll('script:not([src])').forEach((s, i) => {
            if (s.textContent && s.textContent.trim())
              api.scanInline(s.textContent, 'inline-script', `${label} › inline <script> #${i + 1}`);
          });
          for (const el of doc.querySelectorAll('script[src], link[rel~="stylesheet"][href]')) {
            const raw = el.getAttribute('src') || el.getAttribute('href');
            const ref = src.absUrl(raw, url.href);
            if (!ref || (!sameOrigin(ref) && !opts.includeCrossOrigin)) continue;
            await api.scanFileUrl(ref.href, el.tagName === 'LINK' ? 'style-file' : 'script-file', label);
          }
        } catch {
          /* unparseable page */
        }
        api.report(`crawled ${src.displayUrl(url)}`);
      }
    };
    await Promise.all(Array.from({ length: Math.min(LIMITS.probeConcurrency, pages.length) }, worker));
  }

  /* ------------------------------------------------------------ Service Worker caches */

  async function scanCaches(opts, api) {
    let names;
    try {
      if (!self.caches) return;
      names = await caches.keys();
    } catch {
      return;
    }
    let scanned = 0;
    for (const name of names) {
      if (api.signal.aborted || scanned >= LIMITS.maxCacheEntries) break;
      let cache, requests;
      try {
        cache = await caches.open(name);
        requests = await cache.keys();
      } catch {
        continue;
      }
      for (const request of requests) {
        if (api.signal.aborted || scanned >= LIMITS.maxCacheEntries) break;
        const url = src.absUrl(request.url);
        if (!url || (!sameOrigin(url) && !opts.includeCrossOrigin)) continue;
        // Skip obvious binary assets up front; a text-like content-type can still let others through.
        const textExt = /\.(?:js|mjs|cjs|json|css|txt|map|html?)$/i.test(url.pathname);
        if (!textExt && NON_HTML_EXT.test(url.pathname)) continue;
        let text;
        try {
          const res = await cache.match(request);
          if (!res) continue;
          const type = res.headers.get('content-type') || '';
          if (!textExt && !/javascript|json|text|css/i.test(type)) continue;
          text = (await res.text()).slice(0, LIMITS.maxBytesPerFile);
        } catch {
          continue;
        }
        if (!text) continue;
        scanned++;
        api.scanInline(text, 'script-file', `SW cache "${src.oneLine(name, 40)}" › ${src.displayUrl(url)}`);
        api.report(`cache ${src.displayUrl(url)}`);
      }
    }
  }

  /* ------------------------------------------------------------ exposed-file probes */

  async function probeFiles(opts, api) {
    const base = location.origin;
    let cursor = 0;
    const worker = async () => {
      while (cursor < PROBE_PATHS.length && !api.signal.aborted) {
        const probe = PROBE_PATHS[cursor++];
        const url = `${base}${probe.path}`;
        const r = await api.fetchText(url, { probe: true });
        api.report(`probe ${probe.path}`);
        if (r.error) continue; // 404, SPA HTML fallback, or blocked — not exposed
        if (!r.text || !r.text.trim()) continue;

        api.addFinding(
          api.manual({ type: 'exposed-file', label: probe.path, url }, probe.path, {
            ruleId: 'exposed-file',
            title: `Exposed file: ${probe.label}`,
            severity: probe.severity,
            category: 'infrastructure',
            redact: false,
            value: probe.path,
            groupKey: `exposed-file|${probe.path}`,
            note: `This file is publicly reachable at ${probe.path} and returned content, not a 404. Block it at the web server or move it outside the web root — source-control, environment and backup files must never be served.`,
          }),
        );
        // Also scan the file body for concrete secrets (an exposed .env, config.json, …).
        api.scanInline(r.text, 'exposed-file', `${probe.path} (exposed)`, url);
      }
    };
    await Promise.all(Array.from({ length: Math.min(LIMITS.probeConcurrency, PROBE_PATHS.length) }, worker));
  }

  /* ------------------------------------------------------------ entry */

  /**
   * @param {object} opts   sanitised scan options
   * @param {object} api    { signal, skipped, report, fetchText, scanInline, scanFileUrl,
   *                          addFinding, manual, markSeen }
   */
  async function run(opts, api) {
    if (opts.crawl) {
      await scanIframes(opts, api);
      await crawlPages(opts, api);
      await scanCaches(opts, api);
    }
    if (opts.probeFiles) await probeFiles(opts, api);
  }

  ns.deep = Object.freeze({ run });
})();
