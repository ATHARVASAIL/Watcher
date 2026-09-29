/**
 * Watcher — detection helpers.
 *
 * Pure functions shared by the rule sets: entropy, placeholder and identifier
 * heuristics, JWT decoding and hostname classification. No DOM, no network.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.util) return;

  /* ------------------------------------------------------------ entropy */

  /** Shannon entropy in bits per character. */
  function shannon(text) {
    const freq = new Map();
    for (const ch of text) freq.set(ch, (freq.get(ch) || 0) + 1);
    let bits = 0;
    for (const count of freq.values()) {
      const p = count / text.length;
      bits -= p * Math.log2(p);
    }
    return bits;
  }

  /** Number of character classes present: lower, upper, digit, symbol (0–4). */
  const charClasses = (text) =>
    Number(/[a-z]/.test(text)) +
    Number(/[A-Z]/.test(text)) +
    Number(/\d/.test(text)) +
    Number(/[^A-Za-z0-9]/.test(text));

  /* ------------------------------------------------------------ placeholders & shapes */

  // Strong markers ("YOUR_API_KEY_HERE", "<token>", "changeme") are worth reporting as
  // placeholders; weak ones (a bare "password" or "test") are UI labels far more often.
  const STRONG_PLACEHOLDER_RE =
    /^(?:your|my|insert|enter|replace|paste)[\s_-]|^(?:your|insert|enter|replace|paste|put|add|set)[\s_-]?(?:own[\s_-]?)?(?:api|key|token|secret|pass|client|app|access|auth|real|actual|value)|(?:^|[\s_-])(?:here|goes[\s_-]?here)$|^x{3,}$|x{6,}|\*{3,}|•{3,}|^<[^>]*>$|^\[[^\]]*\]$|^\{[^}]*\}$|change[_-]?me|placeholder|dummy|example|sample|redacted|lorem/i;
  const WEAK_PLACEHOLDER_RE =
    /^(?:test|fake\w*|null|undefined|none|todo|tbd|secret|password|passwd|token|api[_-]?key|0{6,})$/i;

  const isStrongPlaceholder = (value) => STRONG_PLACEHOLDER_RE.test(value);
  const isPlaceholder = (value) => STRONG_PLACEHOLDER_RE.test(value) || WEAK_PLACEHOLDER_RE.test(value);

  /** Pure words, identifiers and header names: "accessToken", "X-CSRF-Token", "auth.password.label". */
  const PLAIN_WORDS_RE = /^[A-Za-z]+(?:[\s_\-.:/][A-Za-z]+)*$/;
  /** Code/config shapes: paths, URLs, colours, templates, MIME types, booleans. */
  const NOT_A_SECRET_RE =
    /^(?:\/|\.{1,2}\/|#[0-9a-f]{3,8}$|[#.[^<{%])|:\/\/|\$\{|\{\{|%[sdo]|#\{|\(|^[a-z]+\/[a-z0-9.+-]+$|^(?:true|false|null|undefined|bearer|basic)$/i;
  /** SCREAMING_SNAKE constant names ("HASHED_TOKEN") are identifiers, not values. */
  const CONSTANT_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

  /* ------------------------------------------------------------ key names */

  // Key names that contain a secret-ish word but name something harmless.
  const KEY_DENY_ANYWHERE_RE = /csrf|xsrf|antiforgery|requestverification|nonce|captcha|turnstile/i;
  const KEY_DENY_SUFFIX_RE =
    /(?:storage|cache|store|header|query|param|cookie|field|input|label|placeholder|name|type|kind|url|uri|endpoint|path|route|regexp?|pattern|length|len|min|max|policy|strength|rule|selector|event|error|err|message|msg|hint|text|title|prop|attr|expiry|expires?|expiration|ttl|timeout|lifetime|count|limit|visible|visibility|show|hide|reset|forgot|confirm|update|mode|format|version|prefix|suffix|enabled|required|valid|validation|icon|class|id|provider|manager|service|handler|helper|util|getter|setter)(?:s|key|name|_?id)?$/i;

  const lastKeySegment = (key) =>
    key
      .split(/[.[\]'"]/)
      .filter(Boolean)
      .pop() || key;

  const isDeniedKey = (key) => KEY_DENY_ANYWHERE_RE.test(key) || KEY_DENY_SUFFIX_RE.test(lastKeySegment(key));

  const isPasswordKey = (key) => /passw(?:or)?d|passphrase|pwd/i.test(lastKeySegment(key));

  /** Does this string look like a credential rather than code, config or UI text? */
  function looksSecret(value, key = '') {
    // Compiler/UI tokens often carry edge punctuation: "?NonNullAssertion", "#privateField".
    const core = value.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, '');
    if (NOT_A_SECRET_RE.test(value) || PLAIN_WORDS_RE.test(core) || CONSTANT_NAME_RE.test(core)) {
      return false;
    }
    if (isPasswordKey(key)) return value.length >= 6 && shannon(value) >= 2.0;
    return value.length >= 12 && charClasses(value) >= 2 && shannon(value) >= 3.0;
  }

  /** Walk backwards from a keyword to recover the whole identifier: "config.stripe" + "SecretKey". */
  function keyAt(text, start, keywordPart) {
    let i = start;
    let steps = 0;
    while (i > 0 && steps < 60 && /[A-Za-z0-9_$.-]/.test(text[i - 1])) {
      i--;
      steps++;
    }
    return (text.slice(i, start) + keywordPart).replace(/^[.-]+/, '');
  }

  /* ------------------------------------------------------------ decoding */

  /** Decode base64 or base64url bytes as UTF-8 text; null if invalid. */
  function decodeBase64Text(input) {
    try {
      const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '==='.slice((b64.length + 3) % 4);
      const bin = atob(padded);
      return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    } catch {
      return null;
    }
  }

  /** Decode one base64url JWT segment to an object; null if it is not JSON. */
  function b64urlJson(part) {
    const text = decodeBase64Text(part);
    if (text === null) return null;
    try {
      const value = JSON.parse(text);
      return value && typeof value === 'object' ? value : null;
    } catch {
      return null;
    }
  }

  /** Decode a data: URL body (base64 or percent-encoded). Returns null on failure. */
  function decodeDataUrl(dataUrl) {
    const comma = dataUrl.indexOf(',');
    if (comma === -1) return null;
    const meta = dataUrl.slice(5, comma);
    const body = dataUrl.slice(comma + 1);
    if (/;base64$/i.test(meta)) return decodeBase64Text(body);
    try {
      return decodeURIComponent(body);
    } catch {
      return null;
    }
  }

  /* ------------------------------------------------------------ hosts */

  const INTERNAL_TLDS = new Set([
    'local',
    'localhost',
    'internal',
    'intranet',
    'corp',
    'lan',
    'home',
    'test',
    'invalid',
    'localdomain',
    'priv',
    'private',
  ]);

  const ENV_TOKENS = new Set([
    'dev',
    'devel',
    'develop',
    'development',
    'stage',
    'staging',
    'stg',
    'qa',
    'uat',
    'test',
    'tst',
    'testing',
    'sandbox',
    'sbx',
    'preprod',
    'nonprod',
    'preview',
    'internal',
    'intranet',
    'corp',
    'debug',
    'local',
    'localdev',
    'integration',
  ]);

  /** Public sites whose dev./develop. subdomains appear in library comments and docs links. */
  const PUBLIC_DOC_DOMAINS = new Set([
    'w3.org',
    'whatwg.org',
    'mozilla.org',
    'github.com',
    'github.io',
    'githubusercontent.com',
    'npmjs.com',
    'sentry.dev',
    'sentry.io',
    'google.com',
    'googleapis.com',
    'microsoft.com',
    'apple.com',
    'android.com',
    'chromium.org',
    'webkit.org',
    'stackoverflow.com',
    'wikipedia.org',
    'readthedocs.io',
    'reactjs.org',
    'react.dev',
    'vuejs.org',
    'angular.io',
    'nodejs.org',
    'jquery.com',
    'unicode.org',
    'ietf.org',
    'mdn.dev',
  ]);

  /** Single-label "hosts" that are documentation placeholders or shortlinks, not servers. */
  const DOC_HOST_WORDS = new Set([
    'host',
    'hostname',
    'server',
    'domain',
    'example',
    'yourserver',
    'yourdomain',
    'myserver',
    'ip',
    'address',
    'proxy',
    'url',
    'site',
    'website',
    'your',
    'foo',
    'bar',
    'www',
    'go',
    'myproxy',
    'proxyhost',
    'yourproxy',
  ]);

  /**
   * Classify a hostname. Returns one of: loopback, private, link-local, metadata,
   * internal-name, internal-tld, environment — or null for an ordinary public host.
   */
  function classifyHost(rawHost) {
    const host = rawHost.toLowerCase().replace(/\.$/, '');
    if (host === 'localhost' || host.endsWith('.localhost') || host === '[::1]') return 'loopback';

    if (host.startsWith('[')) {
      if (/^\[f[cd]/.test(host)) return 'private';
      if (/^\[fe[89ab]/.test(host)) return 'link-local';
      return null;
    }

    const ip = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ip) {
      const [a, b] = ip.slice(1).map(Number);
      if (ip.slice(1).some((n) => Number(n) > 255)) return null;
      if (a === 127 || host === '0.0.0.0') return 'loopback';
      if (host === '169.254.169.254') return 'metadata';
      if (a === 169 && b === 254) return 'link-local';
      if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
      return null;
    }

    const labels = host.split('.');
    if (labels.length === 1) return /^[a-z][a-z0-9-]{1,62}$/.test(host) ? 'internal-name' : null;
    if (INTERNAL_TLDS.has(labels[labels.length - 1])) return 'internal-tld';
    if (PUBLIC_DOC_DOMAINS.has(labels.slice(-2).join('.'))) return null;

    // Only look at the subdomain part so "testing-library.com" or "dev.to" don't match.
    const subdomain = labels.slice(0, -2);
    const tokens = subdomain.flatMap((label) => label.split('-'));
    if (tokens.some((t) => ENV_TOKENS.has(t)) || /pre-?prod|non-?prod/.test(subdomain.join('.'))) {
      return 'environment';
    }
    return null;
  }

  const HOST_KINDS = {
    environment: {
      title: 'Non-production host (dev / staging / test)',
      severity: 'low',
      note: 'A staging, dev or test hostname is referenced from this page. It usually means a non-production config shipped in the build, and it maps internal infrastructure for an attacker. Confirm the build uses production environment values and check whether the host is reachable from the internet.',
    },
    'internal-tld': {
      title: 'Internal hostname',
      severity: 'low',
      note: 'Hostname on an internal-only TLD (.local, .internal, .corp …). Reveals internal naming; confirm it is not a leftover from a development config.',
    },
    'internal-name': {
      title: 'Single-label internal hostname',
      severity: 'low',
      note: 'A bare hostname such as http://jenkins:8080 only resolves inside a private network. It reveals internal service names.',
    },
    private: {
      title: 'Private network address',
      severity: 'low',
      note: 'RFC 1918 / ULA address in frontend code. Reveals internal addressing and usually indicates a development config left in the build.',
    },
    'link-local': {
      title: 'Link-local address',
      severity: 'low',
      note: 'Link-local addresses should never appear in a public frontend.',
    },
    metadata: {
      title: 'Cloud metadata endpoint reference',
      severity: 'low',
      note: '169.254.169.254 is the cloud instance-metadata service. There is rarely a legitimate reason for a frontend to reference it; find out why it is here.',
    },
    loopback: {
      title: 'Loopback / dev-server URL',
      severity: 'info',
      note: 'localhost or 127.0.0.1 in a production asset is usually harmless (often from a library), but can indicate a dev build or dev-only feature flag shipped to production.',
    },
  };

  /* ------------------------------------------------------------ client-side storage context */

  /** Web Storage and JS-readable cookies hold runtime session data, not hard-coded secrets. */
  const isClientStore = (source) => source.type === 'storage' || source.type === 'cookie';

  const CLIENT_STORE_NOTES = {
    storage:
      'Anything in localStorage/sessionStorage is readable by any script on this origin, so one XSS leaks it. Prefer HttpOnly, Secure, SameSite cookies for session material.',
    cookie:
      'This cookie is readable through document.cookie, which proves it lacks the HttpOnly flag; an XSS can steal it. Set HttpOnly, Secure and SameSite on session cookies.',
  };

  ns.util = Object.freeze({
    shannon,
    charClasses,
    isPlaceholder,
    isStrongPlaceholder,
    looksSecret,
    keyAt,
    lastKeySegment,
    isDeniedKey,
    isPasswordKey,
    decodeBase64Text,
    b64urlJson,
    decodeDataUrl,
    classifyHost,
    HOST_KINDS: Object.freeze(HOST_KINDS),
    DOC_HOST_WORDS,
    isClientStore,
    CLIENT_STORE_NOTES: Object.freeze(CLIENT_STORE_NOTES),
  });
})();
