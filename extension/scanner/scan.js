/**
 * Watcher — scan orchestrator (entry point in the page).
 *
 * Runs in the page's ISOLATED world after the user presses Scan. Exposes
 * `__WATCHER.start(options, scanId)` and `__WATCHER.cancel()`; reports back to the
 * extension by chrome.runtime messages. Nothing is sent to any other server.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.start) return;

  const { DEFAULT_OPTIONS, LIMITS, MSG, PROGRESS_THROTTLE_MS } = ns.config;
  const { classifyHost } = ns.util;
  const { scanText, manualFinding } = ns.engine;
  const src = ns.sources;

  const SENSITIVE_KEY_RE =
    /token|jwt|auth|session|sess|sid|secret|passw|pwd|credential|api[_-]?key|bearer|refresh/i;
  const BENIGN_KEY_RE =
    /csrf|xsrf|nonce|captcha|expir|ttl|timestamp|created|updated|issued|last_?seen|state|theme|lang|locale|consent|redirect|return_?to|_at$/i;
  /** Analytics/consent cookies that match "sid"/"session" but are not auth material. */
  const ANALYTICS_COOKIE_RE =
    /^(?:_ga|_gid|_gat|_fbp|_fbc|_hj|_clck|_clsk|__stripe_|ajs_|amplitude|mp_|_pk_|intercom-)/i;

  /* ------------------------------------------------------------ messaging */

  function send(type, scanId, payload) {
    try {
      chrome.runtime.sendMessage({ type, scanId, ...payload }).catch(() => {});
    } catch {
      /* extension reloaded; nothing to report to */
    }
  }

  function progressReporter(scanId) {
    let last = 0;
    return (done, total, current) => {
      const now = Date.now();
      if (now - last < PROGRESS_THROTTLE_MS && done < total) return;
      last = now;
      send(MSG.PROGRESS, scanId, { done, total, current });
    };
  }

  function sanitizeOptions(raw) {
    const opts = { ...DEFAULT_OPTIONS };
    for (const key of Object.keys(DEFAULT_OPTIONS)) {
      if (raw && typeof raw[key] === typeof DEFAULT_OPTIONS[key]) opts[key] = raw[key];
    }
    opts.maxFiles = Math.max(1, Math.min(1000, Math.floor(opts.maxFiles) || DEFAULT_OPTIONS.maxFiles));
    return opts;
  }

  /* ------------------------------------------------------------ post-passes */

  /** Session-like Web Storage keys / cookies whose values matched no rule. */
  function clientStoreFindings(env, source, label, entries, found) {
    const linesWithHits = new Set(found.map((f) => f.line));
    const out = [];
    for (const entry of entries) {
      if (linesWithHits.has(entry.line)) continue;
      if (!SENSITIVE_KEY_RE.test(entry.key) || BENIGN_KEY_RE.test(entry.key)) continue;
      const where = `${label}["${src.oneLine(entry.key, 80)}"]`;
      const value = src.oneLine(entry.value, 400);

      if (source.type === 'cookie') {
        if (ANALYTICS_COOKIE_RE.test(entry.key) || entry.value.length < 16) continue;
        out.push(
          manualFinding(env, source, where, {
            ruleId: 'cookie-not-httponly',
            title: 'Session-like cookie readable by JavaScript',
            severity: 'low',
            category: 'storage',
            confidence: 'heuristic',
            value,
            note: 'This cookie is visible to document.cookie, which proves it is missing the HttpOnly flag. If it carries a session, an XSS can steal it. Set HttpOnly, Secure and SameSite (CSRF double-submit cookies are the exception: they must be readable).',
          }),
        );
        continue;
      }

      const password = /passw|pwd/i.test(entry.key);
      if (entry.value.length < (password ? 4 : 16)) continue;
      out.push(
        manualFinding(env, source, where, {
          ruleId: 'storage-sensitive-key',
          title: password ? 'Password-named key in Web Storage' : 'Sensitive-named key in Web Storage',
          severity: password ? 'medium' : 'info',
          category: 'storage',
          confidence: 'heuristic',
          value,
          note: 'The key name suggests session or credential material. Web Storage is readable by any script on this origin; review whether it needs to be here and prefer HttpOnly cookies for session tokens.',
        }),
      );
    }
    return out;
  }

  /* ------------------------------------------------------------ scan */

  async function runScan(opts, scanId, signal) {
    const startedAt = Date.now();
    let seq = 0;
    const env = {
      pageHost: location.hostname.toLowerCase(),
      // Scanning staging.example.com? Then links to other staging hosts are expected.
      // (localhost is NOT treated this way: it is where people test production builds.)
      pageIsNonProd: classifyHost(location.hostname) === 'environment',
      nextId: () => `${scanId.slice(0, 8)}-${++seq}`,
      signal,
    };

    const { items, skipped } = src.inventory(opts);
    const report = progressReporter(scanId);
    const findings = [];
    const sources = [];
    const budget = { remaining: LIMITS.maxTotalBytes };
    const mapsSeen = new Set();
    let bytesScanned = 0;
    let findingsTruncated = false;
    let done = 0;
    let total = items.length;

    const addFindings = (list) => {
      for (const f of list) {
        if (findings.length >= LIMITS.maxFindings) {
          findingsTruncated = true;
          return;
        }
        findings.push(f);
      }
    };

    /** Check a referenced source map; if reachable, report it and scan the original sources. */
    async function processSourceMap(ref, parent) {
      let mapText;
      let mapLabel;
      let mapUrl = null;
      let external = false;

      if (/^data:/i.test(ref)) {
        mapText = ns.util.decodeDataUrl(ref);
        mapLabel = `inline source map in ${parent.label}`;
        if (mapText === null) return [];
      } else {
        const url = src.absUrl(ref, parent.url || document.baseURI);
        if (!url || mapsSeen.has(url.href)) return [];
        mapsSeen.add(url.href);
        mapLabel = src.displayUrl(url);
        if (url.protocol !== 'https:' && url.protocol !== 'http:') return [];
        if (url.origin !== location.origin && !opts.includeCrossOrigin) {
          skipped.push({ label: url.href, reason: 'third-party source map not fetched' });
          return [];
        }
        const res = await src.fetchText(url.href, { budget, signal, maxBytes: LIMITS.maxBytesPerSourceMap });
        if (res.error) {
          skipped.push({ label: mapLabel, reason: `source map not reachable (${res.error})` });
          return [];
        }
        if (res.truncated) {
          skipped.push({ label: mapLabel, reason: 'source map larger than the size limit' });
          return [];
        }
        mapText = res.text;
        mapUrl = url.href;
        external = true;
        bytesScanned += res.bytes;
      }

      const map = src.parseSourceMap(mapText);
      if (!map) {
        if (external) skipped.push({ label: mapLabel, reason: 'not a valid source map' });
        return [];
      }

      const own = map.originals.filter((o) => !src.isLibraryPath(o.path));
      const withContent = own.filter((o) => o.content !== null).slice(0, LIMITS.maxSourcesPerMap);
      const out = [];
      const mapSource = { type: 'source-map', label: mapLabel, url: mapUrl };

      if (external) {
        out.push(
          manualFinding(env, mapSource, mapLabel, {
            ruleId: 'source-map-exposed',
            title: 'Source map publicly accessible',
            severity: 'low',
            category: 'debug',
            redact: false,
            value: mapLabel,
            note: `Confirmed reachable: it lists ${map.originals.length} original file(s), ${own.length} of them your own code, ${withContent.length} with full source embedded. Anyone can reconstruct your unminified source, comments and internal paths. Stop publishing .map files (or restrict them) and upload maps only to your error tracker.`,
          }),
        );
      }

      for (const original of withContent) {
        if (signal.aborted) break;
        const label = `${src.cleanSourcePath(original.path)} (from ${mapLabel.split('/').pop()})`;
        const origSource = { type: 'source-map', label, url: mapUrl, parent: parent.label };
        const hits = await scanText(original.content, origSource, env);
        // Reference/inline-map findings inside original sources are noise.
        out.push(
          ...hits.filter((h) => h.ruleId !== 'source-map-reference' && h.ruleId !== 'inline-source-map'),
        );
        bytesScanned += original.content.length;
      }

      sources.push({
        type: 'source-map',
        label: mapLabel,
        url: mapUrl,
        bytes: mapText.length,
        truncated: false,
        findings: out.length,
        originals: withContent.length,
        libraryFilesSkipped: map.originals.length - own.length,
      });
      return out;
    }

    async function processItem(item) {
      let text = item.text;
      let extra = null;
      let bytes = 0;
      let truncated = false;
      let sourceMapHeader = null;

      if (item.collect) {
        const r = item.collect();
        if (r.error) {
          skipped.push({ label: item.label, reason: r.error });
          return;
        }
        text = r.text;
        extra = r;
      } else if (item.url) {
        const r = await src.fetchText(item.url, { budget, signal });
        if (r.error) {
          skipped.push({ label: item.label, reason: r.error });
          return;
        }
        ({ text, bytes, truncated, sourceMapHeader } = r);
      }
      bytes ||= text.length;
      bytesScanned += bytes;

      const source = { type: item.type, label: item.label, url: item.url, lineLabels: extra?.lineLabels };
      let found = text ? await scanText(text, source, env) : [];

      for (const s of extra?.structural || []) {
        found.push(
          manualFinding(env, source, s.where, {
            ruleId: 'prefilled-password-input',
            title: 'Password field pre-filled in HTML',
            severity: 'medium',
            category: 'credential',
            value: s.value,
            note: 'A password input ships with a value attribute in the markup, so every visitor receives it. Remove the default value.',
          }),
        );
      }
      if (extra?.entries) found.push(...clientStoreFindings(env, source, item.label, extra.entries, found));

      // Source maps: confirm exposure and scan what they reveal.
      if (
        opts.sourceMaps &&
        (item.type === 'script-file' || item.type === 'style-file' || item.type === 'inline-script')
      ) {
        const refs = src.findSourceMapRefs(text, sourceMapHeader);
        if (refs.length) {
          total += refs.length;
          for (const ref of refs) {
            const mapFindings = await processSourceMap(ref, item);
            if (mapFindings.some((f) => f.ruleId === 'source-map-exposed')) {
              // Exposure is confirmed, so the plain "referenced" note is redundant.
              found = found.filter((f) => f.ruleId !== 'source-map-reference');
            }
            addFindings(mapFindings);
            report(++done, total, `source map for ${item.label}`);
          }
        }
      }

      addFindings(found);
      sources.push({
        type: item.type,
        label: item.label,
        url: item.url || null,
        bytes,
        truncated,
        findings: found.length,
      });
    }

    // Quick local sources first, then fetched files through a small pool.
    const local = items.filter((i) => !i.url);
    const remote = items.filter((i) => i.url);

    const guarded = async (item) => {
      try {
        await processItem(item);
      } catch (e) {
        skipped.push({
          label: item.label,
          reason: `scanner error: ${String((e && e.message) || e).slice(0, 200)}`,
        });
      }
      report(++done, total, item.label);
    };

    for (const item of local) {
      if (signal.aborted) break;
      await guarded(item);
    }

    let cursor = 0;
    const worker = async () => {
      while (cursor < remote.length && !signal.aborted) await guarded(remote[cursor++]);
    };
    await Promise.all(Array.from({ length: Math.min(LIMITS.concurrency, remote.length) }, worker));

    return {
      scanId,
      version: chrome.runtime.getManifest().version,
      url: location.href,
      origin: location.origin,
      title: document.title.slice(0, 200),
      startedAt,
      finishedAt: Date.now(),
      options: opts,
      stats: {
        sourcesScanned: sources.length,
        bytesScanned,
        findingsTruncated,
        cancelled: signal.aborted,
        pageIsNonProd: env.pageIsNonProd,
      },
      sources,
      skipped,
      findings,
    };
  }

  /* ------------------------------------------------------------ entry points */

  let controller = null;

  /** Called via chrome.scripting.executeScript. Returns immediately; results arrive by message. */
  ns.start = (rawOptions, scanId) => {
    if (controller) return { ok: false, error: 'A scan is already running on this page.' };
    if (typeof scanId !== 'string' || !/^[0-9a-f-]{36}$/.test(scanId))
      return { ok: false, error: 'Invalid scan id.' };

    controller = new AbortController();
    const { signal } = controller;
    runScan(sanitizeOptions(rawOptions), scanId, signal)
      .then((result) => send(MSG.RESULT, scanId, { result }))
      .catch((e) => send(MSG.ERROR, scanId, { error: String((e && e.message) || e) }))
      .finally(() => {
        controller = null;
      });
    return { ok: true };
  };

  /** Stop the running scan; partial results are still reported. */
  ns.cancel = () => {
    if (!controller) return { ok: false };
    controller.abort();
    return { ok: true };
  };
})();
