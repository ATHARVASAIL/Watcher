/**
 * Watcher — shared configuration and helpers.
 *
 * Classic script loaded in every context: the service worker (importScripts),
 * the popup (<script> before the modules) and the page's isolated world (first
 * file injected). It defines `globalThis.__WATCHER.config` and `globalThis.__WATCHER.common`.
 */
(() => {
  'use strict';

  const ns = (globalThis.__WATCHER = globalThis.__WATCHER || {});
  if (ns.config) return; // already loaded in this context

  const deepFreeze = (obj) => {
    for (const value of Object.values(obj)) {
      if (value && typeof value === 'object') deepFreeze(value);
    }
    return Object.freeze(obj);
  };

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  ns.config = deepFreeze({
    SEVERITIES,
    SEVERITY_LABELS: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' },

    /** Options the scanner accepts. `exportRaw` is popup-only and never leaves the popup. */
    DEFAULT_OPTIONS: {
      inlineScripts: true,
      externalScripts: true,
      stylesheets: true,
      html: true,
      storage: true,
      cookies: true,
      sourceMaps: true,
      includeCrossOrigin: false,
      maxFiles: 150,
    },
    POPUP_ONLY_OPTIONS: { exportRaw: false },

    LIMITS: {
      maxBytesPerFile: 10 * 1024 * 1024,
      maxBytesPerSourceMap: 30 * 1024 * 1024,
      maxTotalBytes: 120 * 1024 * 1024,
      maxSourcesPerMap: 500,
      maxStorageValueChars: 1_000_000,
      maxAttrChars: 5_000,
      fetchTimeoutMs: 15_000,
      concurrency: 4,
      maxFindings: 3_000,
      maxAcceptedPerOrigin: 5_000,
    },

    /** Message types between popup, service worker and scanner. */
    MSG: {
      START: 'watcher:start',
      CANCEL: 'watcher:cancel',
      REFRESH_BADGE: 'watcher:refresh-badge',
      PROGRESS: 'watcher:progress',
      RESULT: 'watcher:result',
      ERROR: 'watcher:error',
    },

    STORAGE: {
      scanPrefix: 'scan:', // chrome.storage.session — results (memory only)
      options: 'options', // chrome.storage.local — option toggles only
      acceptedPrefix: 'accepted:', // chrome.storage.local — salted hashes only, never values
      salt: 'install-salt',
    },

    /** Injection order matters: config → helpers → rules → engine → sources → entry point. */
    SCANNER_FILES: [
      'shared/common.js',
      'scanner/lib/helpers.js',
      'scanner/rules/vendor.js',
      'scanner/rules/generic.js',
      'scanner/rules/infrastructure.js',
      'scanner/rules/debug.js',
      'scanner/engine.js',
      'scanner/sources.js',
      'scanner/scan.js',
    ],
    RULE_SETS: ['vendor', 'generic', 'infrastructure', 'debug'],

    STALE_AFTER_MS: 60_000,
    PROGRESS_THROTTLE_MS: 400,
    PROGRESS_WRITE_EVERY_MS: 500,

    BADGE_COLORS: {
      critical: '#b3261e',
      high: '#b54708',
      medium: '#8c5e00',
      low: '#1e7045',
      info: '#4a5565',
      clean: '#1e7045',
      running: '#4a5565',
    },
  });

  const RANK = Object.freeze(Object.fromEntries(SEVERITIES.map((s, i) => [s, i])));

  /** Group findings that share a value (same secret in several files) into one entry. */
  function groupFindings(findings) {
    const groups = new Map();
    for (const f of findings) {
      let g = groups.get(f.groupKey);
      if (!g) {
        g = { key: f.groupKey, severity: f.severity, head: f, items: [] };
        groups.set(f.groupKey, g);
      }
      g.items.push(f);
      if (RANK[f.severity] < RANK[g.severity]) {
        g.severity = f.severity;
        g.head = f;
      }
    }
    return [...groups.values()].sort(
      (a, b) => RANK[a.severity] - RANK[b.severity] || a.head.title.localeCompare(b.head.title),
    );
  }

  const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

  /** SHA-256 hex digest of a string (extension contexts are always secure contexts). */
  async function sha256(text) {
    return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  }

  /**
   * Stable, non-reversible identifier for a finding group on an origin.
   * Salted per install so persisted triage state never stores or exposes the secret.
   */
  async function fingerprint(salt, origin, groupKey) {
    return (await sha256(`${salt}\u0000${origin}\u0000${groupKey}`)).slice(0, 40);
  }

  ns.common = Object.freeze({ RANK, groupFindings, sha256, fingerprint });
})();
