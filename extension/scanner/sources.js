/**
 * Watcher — source collection.
 *
 * Everything here is strictly read-only:
 *   - DOM is read, never written; no event listeners are added;
 *   - Web Storage is read with getItem, cookies with document.cookie;
 *   - attribute values come from getAttribute (what the server shipped),
 *     never from live .value properties (what a user typed);
 *   - the page's own JS/CSS/source maps are re-read with GET, cache first,
 *     same-origin by default, with timeouts and size caps.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.sources) return;

  const { LIMITS } = ns.config;

  /* ------------------------------------------------------------ small helpers */

  function absUrl(raw, base = document.baseURI) {
    try {
      const url = new URL(raw, base);
      url.hash = '';
      return url;
    } catch {
      return null;
    }
  }

  const displayUrl = (url) => (url.origin === location.origin ? url.pathname + url.search : url.href);

  const oneLine = (text, max) => text.replace(/[\r\n]+/g, ' ').slice(0, max);

  function describeElement(el) {
    const bits = [];
    for (const name of ['id', 'name', 'property', 'type', 'rel']) {
      const value = el.getAttribute(name);
      if (value) bits.push(`${name}="${value.slice(0, 40)}"`);
    }
    return `<${el.tagName.toLowerCase()}${bits.length ? ` ${bits.join(' ')}` : ''}>`;
  }

  /* ------------------------------------------------------------ inventory */

  /**
   * Decide what to scan. Local sources carry a `collect()`; files carry a `url`.
   * @returns {{items: object[], skipped: {label: string, reason: string}[]}}
   */
  function inventory(opts) {
    const items = [];
    const skipped = [];
    const seen = new Set();

    if (opts.html)
      items.push({ type: 'html', label: 'Page HTML (attributes & comments)', collect: collectHtml });
    if (opts.storage) {
      items.push({ type: 'storage', label: 'localStorage', collect: () => collectStorage('localStorage') });
      items.push({
        type: 'storage',
        label: 'sessionStorage',
        collect: () => collectStorage('sessionStorage'),
      });
    }
    if (opts.cookies) items.push({ type: 'cookie', label: 'document.cookie', collect: collectCookies });

    if (opts.inlineScripts) {
      document.querySelectorAll('script:not([src])').forEach((script, i) => {
        const text = script.textContent;
        if (!text || !text.trim()) return;
        const type = (script.getAttribute('type') || '').trim();
        const id = script.id ? ` id="${script.id.slice(0, 40)}"` : '';
        const typeAttr = type ? ` type="${type.slice(0, 40)}"` : '';
        items.push({ type: 'inline-script', label: `Inline <script${id}${typeAttr}> #${i + 1}`, text });
      });
    }
    if (opts.stylesheets) {
      document.querySelectorAll('style').forEach((style, i) => {
        const text = style.textContent;
        if (text && text.trim())
          items.push({ type: 'inline-style', label: `Inline <style> #${i + 1}`, text });
      });
    }

    const addUrl = (raw, type) => {
      const url = absUrl(raw);
      if (!url || seen.has(url.href)) return;
      seen.add(url.href);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        skipped.push({ label: oneLine(url.href, 120), reason: `${url.protocol} URL is not fetched` });
      } else if (url.origin !== location.origin && !opts.includeCrossOrigin) {
        skipped.push({ label: url.href, reason: 'third-party origin (enable "Include third-party files")' });
      } else {
        items.push({ type, label: displayUrl(url), url: url.href });
      }
    };

    if (opts.externalScripts) {
      document.querySelectorAll('script[src]').forEach((s) => addUrl(s.getAttribute('src'), 'script-file'));
      document
        .querySelectorAll('link[rel~="modulepreload"][href], link[rel~="preload"][as="script"][href]')
        .forEach((l) => addUrl(l.getAttribute('href'), 'script-file'));
    }
    if (opts.stylesheets) {
      document
        .querySelectorAll('link[rel~="stylesheet"][href]')
        .forEach((l) => addUrl(l.getAttribute('href'), 'style-file'));
    }

    // Lazily loaded chunks (webpack/Vite/Next) are often no longer in the DOM, but the
    // resource timeline still lists them. Match on file type, not initiator: CSS-initiated
    // fonts and images must never be fetched.
    try {
      for (const entry of performance.getEntriesByType('resource')) {
        const url = absUrl(entry.name);
        if (!url) continue;
        const isJs =
          /\.(?:m?js|cjs)$/i.test(url.pathname) ||
          (entry.initiatorType === 'script' && !/\.[a-z0-9]{2,5}$/i.test(url.pathname));
        if (isJs && opts.externalScripts) addUrl(url.href, 'script-file');
        else if (/\.css$/i.test(url.pathname) && opts.stylesheets) addUrl(url.href, 'style-file');
      }
    } catch {
      /* Performance API unavailable */
    }

    // Enforce the file cap on fetched items only.
    let files = 0;
    const kept = [];
    for (const item of items) {
      if (item.url && ++files > opts.maxFiles) {
        skipped.push({ label: item.label, reason: `file limit (${opts.maxFiles}) reached` });
      } else {
        kept.push(item);
      }
    }
    return { items: kept, skipped };
  }

  /* ------------------------------------------------------------ local collectors */

  /** Comments and selected attributes, one synthetic line per item so findings map back to an element. */
  function collectHtml() {
    const lines = [];
    const lineLabels = [];
    const structural = [];
    const push = (line, label) => {
      lines.push(oneLine(line, 20_000));
      lineLabels.push(label);
    };

    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    let n = 0;
    while ((node = walker.nextNode())) {
      n++;
      if (node.nodeValue && node.nodeValue.trim()) push(`<!-- ${node.nodeValue} -->`, `HTML comment #${n}`);
    }

    const INTERESTING =
      /^(?:href|src|action|formaction|content|value|poster|data|srcdoc|xlink:href)$|^data-|^on|key|token|secret|pass|auth/i;
    for (const el of document.getElementsByTagName('*')) {
      const tag = el.tagName.toLowerCase();
      let description = null;
      for (const attr of el.attributes) {
        if (!attr.value || !INTERESTING.test(attr.name)) continue;
        let key = attr.name;
        if (tag === 'meta' && attr.name === 'content') {
          key =
            el.getAttribute('name') ||
            el.getAttribute('property') ||
            el.getAttribute('http-equiv') ||
            'content';
        } else if (tag === 'input' && attr.name === 'value') {
          key = el.getAttribute('name') || el.id || 'value';
        }
        description ??= describeElement(el);
        push(`${key}="${attr.value.slice(0, LIMITS.maxAttrChars)}"`, `${description} → ${attr.name}`);
      }
      if (tag === 'input' && (el.getAttribute('type') || '').toLowerCase() === 'password') {
        const shipped = el.getAttribute('value');
        if (shipped) structural.push({ where: describeElement(el), value: shipped });
      }
    }
    return { text: lines.join('\n'), lineLabels, structural };
  }

  function collectStorage(areaName) {
    let area;
    try {
      area = window[areaName];
      if (!area) return { error: 'not available' };
    } catch {
      return { error: 'access denied (sandboxed or blocked by browser settings)' };
    }
    const lines = [];
    const lineLabels = [];
    const entries = [];
    for (let i = 0; i < area.length; i++) {
      const key = area.key(i);
      if (key === null) continue;
      const value = area.getItem(key) ?? '';
      lines.push(`${oneLine(key, 500)}="${oneLine(value, LIMITS.maxStorageValueChars)}"`);
      lineLabels.push(`${areaName}["${oneLine(key, 80)}"]`);
      entries.push({ key, value, line: lines.length });
    }
    return { text: lines.join('\n'), lineLabels, entries };
  }

  /** Cookies visible to document.cookie — by definition, the ones without HttpOnly. */
  function collectCookies() {
    let raw;
    try {
      raw = document.cookie || '';
    } catch {
      return { error: 'access denied (sandboxed document)' };
    }
    const lines = [];
    const lineLabels = [];
    const entries = [];
    for (const part of raw.split(/;\s*/)) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const name = eq === -1 ? part : part.slice(0, eq);
      let value = eq === -1 ? '' : part.slice(eq + 1);
      try {
        value = decodeURIComponent(value);
      } catch {
        /* keep raw */
      }
      lines.push(`${oneLine(name, 200)}="${oneLine(value, 8_192)}"`);
      lineLabels.push(`document.cookie["${oneLine(name, 80)}"]`);
      entries.push({ key: name, value, line: lines.length });
    }
    return { text: lines.join('\n'), lineLabels, entries };
  }

  /* ------------------------------------------------------------ network (own origin) */

  /**
   * GET a text resource with a timeout, a byte cap and the scan's abort signal.
   * @returns {Promise<{text: string, bytes: number, truncated: boolean, sourceMapHeader: string|null} | {error: string}>}
   */
  async function fetchText(url, { budget, signal, maxBytes = LIMITS.maxBytesPerFile }) {
    const timeout = AbortSignal.timeout(LIMITS.fetchTimeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    try {
      const res = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'force-cache', // reuse what the browser already downloaded where possible
        redirect: 'follow',
        referrerPolicy: 'same-origin',
        signal: combined,
      });
      if (!res.ok) return { error: `HTTP ${res.status}` };
      const contentType = res.headers.get('content-type') || '';
      if (/text\/html/i.test(contentType))
        return { error: 'server returned HTML (SPA fallback or error page)' };

      const cap = Math.min(maxBytes, budget.remaining);
      if (cap <= 0) return { error: 'total size budget reached' };
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = '';
      let bytes = 0;
      let truncated = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (bytes + value.byteLength > cap) {
          text += decoder.decode(value.subarray(0, cap - bytes), { stream: true });
          bytes = cap;
          truncated = true;
          reader.cancel().catch(() => {});
          break;
        }
        bytes += value.byteLength;
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
      budget.remaining -= bytes;
      const sourceMapHeader = res.headers.get('sourcemap') || res.headers.get('x-sourcemap');
      return { text, bytes, truncated, sourceMapHeader };
    } catch (e) {
      if (signal?.aborted) return { error: 'cancelled' };
      return { error: e && e.name === 'TimeoutError' ? 'timed out' : 'network error or blocked by CORS' };
    }
  }

  /* ------------------------------------------------------------ source maps */

  /**
   * Find source-map references at the end of a file (plus the SourceMap response header).
   * Uses lastIndexOf instead of a regex because inline maps can be megabytes long.
   */
  function findSourceMapRefs(text, header) {
    const refs = [];
    if (header) refs.push(header.trim());
    let pos = text.length;
    for (let i = 0; i < 3; i++) {
      const at = text.lastIndexOf('sourceMappingURL=', pos);
      if (at === -1) break;
      const lead = text.slice(Math.max(0, at - 4), at);
      if (/(?:\/\/|\/\*)\s*[#@]\s*$/.test(lead)) {
        const rest = text.slice(at + 'sourceMappingURL='.length);
        const ref = rest.match(/^[^\s'"`]+/)?.[0]?.replace(/\*\/$/, '');
        if (ref) refs.push(ref);
      }
      pos = at - 1;
      if (pos < 0) break;
    }
    return [...new Set(refs)];
  }

  /** Validate a parsed source map (v3) and return its original sources. */
  function parseSourceMap(text) {
    let map;
    try {
      map = JSON.parse(text.replace(/^\)\]\}'[^\n]*\n/, '')); // strip XSSI prefix if present
    } catch {
      return null;
    }
    if (!map || typeof map !== 'object' || !Array.isArray(map.sources)) return null;
    const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
    const root = typeof map.sourceRoot === 'string' ? map.sourceRoot : '';
    return {
      originals: map.sources.map((path, i) => ({
        path: `${root}${String(path)}`.slice(0, 300),
        content: typeof contents[i] === 'string' ? contents[i] : null,
      })),
    };
  }

  /** "webpack://acme/./src/config.ts" → "src/config.ts" */
  const cleanSourcePath = (path) =>
    path
      .replace(/^[a-z-]+:\/\/[^/]*\//i, '')
      .replace(/^(?:\.\/|\/)+/, '')
      .slice(0, 160) || path;

  const isLibraryPath = (path) =>
    /(?:^|\/)(?:node_modules|bower_components|vendor\/bundle|\(webpack\))\//i.test(path);

  ns.sources = Object.freeze({
    absUrl,
    displayUrl,
    oneLine,
    inventory,
    fetchText,
    findSourceMapRefs,
    parseSourceMap,
    cleanSourcePath,
    isLibraryPath,
  });
})();
