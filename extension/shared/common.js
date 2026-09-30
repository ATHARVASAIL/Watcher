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
      // Deep-scan passes (all same-origin, no extra permissions):
      crawl: false, // follow same-site links, scan same-origin iframes and Service Worker caches
      probeFiles: false, // GET a list of commonly-exposed files on this origin
      // Powered by optional permissions the user grants per scan (see OPTIONAL_FEATURES):
      fullAccess: false, // read HttpOnly cookies and third-party files (needs host + cookies permission)
      networkCapture: false, // capture API responses while the page runs (needs the debugger permission)
      maxFiles: 150,
    },
    POPUP_ONLY_OPTIONS: { exportRaw: false },

    /** Options that need a Chrome permission before they can run. */
    OPTIONAL_FEATURES: {
      fullAccess: { permissions: ['cookies'], origins: ['*://*/*'] },
      networkCapture: { permissions: ['debugger'] },
    },

    /**
     * Same-origin paths probed when "Check for exposed files" is on. GET only; a hit
     * is a file that should never be publicly served, not a guess about its contents.
     */
    PROBE_PATHS: [
      { path: '/.env', label: 'Environment file', severity: 'critical' },
      { path: '/.env.local', label: 'Local environment file', severity: 'critical' },
      { path: '/.env.production', label: 'Production environment file', severity: 'critical' },
      { path: '/.env.development', label: 'Development environment file', severity: 'high' },
      { path: '/.git/config', label: 'Git repository config', severity: 'high' },
      { path: '/.git/HEAD', label: 'Git repository metadata', severity: 'high' },
      { path: '/.svn/entries', label: 'Subversion metadata', severity: 'high' },
      { path: '/.hg/requires', label: 'Mercurial metadata', severity: 'medium' },
      { path: '/config.json', label: 'Config file', severity: 'high' },
      { path: '/app.config.json', label: 'App config file', severity: 'high' },
      { path: '/appsettings.json', label: 'ASP.NET settings', severity: 'high' },
      { path: '/config.php', label: 'PHP config', severity: 'high' },
      { path: '/wp-config.php.bak', label: 'WordPress config backup', severity: 'critical' },
      { path: '/.aws/credentials', label: 'AWS credentials file', severity: 'critical' },
      { path: '/.npmrc', label: 'npm config (may hold a token)', severity: 'high' },
      { path: '/.dockercfg', label: 'Docker registry credentials', severity: 'high' },
      { path: '/docker-compose.yml', label: 'Docker Compose file', severity: 'medium' },
      { path: '/.DS_Store', label: 'macOS directory index', severity: 'low' },
      { path: '/backup.sql', label: 'SQL database dump', severity: 'critical' },
      { path: '/db.sqlite', label: 'SQLite database', severity: 'critical' },
      { path: '/.htpasswd', label: 'Apache password file', severity: 'high' },
      { path: '/phpinfo.php', label: 'phpinfo() output', severity: 'medium' },
      { path: '/server-status', label: 'Apache server-status', severity: 'medium' },
      { path: '/actuator/env', label: 'Spring Boot actuator env', severity: 'critical' },
      { path: '/actuator/health', label: 'Spring Boot actuator', severity: 'low' },
      { path: '/debug/vars', label: 'Go expvar debug endpoint', severity: 'medium' },
      { path: '/.vscode/settings.json', label: 'Editor settings', severity: 'low' },
      { path: '/.well-known/security.txt', label: 'security.txt', severity: 'info' },
    ],

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
      // Deep scan
      maxCrawlPages: 25, // extra same-site pages fetched when crawling
      maxIframes: 20, // same-origin iframes read directly
      maxCacheEntries: 200, // Service Worker cache responses scanned
      probeTimeoutMs: 8_000,
      probeConcurrency: 6,
      networkCaptureMs: 45_000, // hard ceiling for a network-capture session
      maxCaptureBodies: 400,
      maxCaptureBodyBytes: 2 * 1024 * 1024,
    },

    /** Message types between popup, service worker and scanner. */
    MSG: {
      START: 'watcher:start',
      CANCEL: 'watcher:cancel',
      REFRESH_BADGE: 'watcher:refresh-badge',
      PROGRESS: 'watcher:progress',
      RESULT: 'watcher:result',
      ERROR: 'watcher:error',
      CAPTURE_STOP: 'watcher:capture-stop', // popup → SW: end a network-capture session
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
      'scanner/rules/vendor-extra.js',
      'scanner/rules/generic.js',
      'scanner/rules/infrastructure.js',
      'scanner/rules/debug.js',
      'scanner/engine.js',
      'scanner/sources.js',
      'scanner/deep.js',
      'scanner/scan.js',
    ],
    /** Rule + engine modules that are DOM-free, so the service worker can run them too. */
    ENGINE_FILES: [
      'shared/common.js',
      'scanner/lib/helpers.js',
      'scanner/rules/vendor.js',
      'scanner/rules/vendor-extra.js',
      'scanner/rules/generic.js',
      'scanner/rules/infrastructure.js',
      'scanner/rules/debug.js',
      'scanner/engine.js',
    ],
    RULE_SETS: ['vendor', 'vendor-extra', 'generic', 'infrastructure', 'debug'],

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
