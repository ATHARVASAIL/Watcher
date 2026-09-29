/**
 * Watcher — heuristic rules.
 *
 * Keyword + entropy detection for secrets that have no vendor-specific format.
 * Results are marked confidence: 'heuristic' ("needs review" in the UI).
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  ns.ruleSets = ns.ruleSets || {};
  if (ns.ruleSets.generic) return;

  const {
    isPlaceholder,
    isStrongPlaceholder,
    looksSecret,
    keyAt,
    lastKeySegment,
    isDeniedKey,
    isPasswordKey,
    isClientStore,
    CLIENT_STORE_NOTES,
  } = ns.util;

  const STORE_NAMES = { storage: 'Web Storage', cookie: 'a JavaScript-readable cookie' };

  function classifyAssignment({ m, text, value, source }) {
    const keywordPart = m[0].match(/^[A-Za-z0-9_$-]+/)[0];
    const key = keyAt(text, m.index, keywordPart);
    if (isDeniedKey(key)) return false;
    const name = lastKeySegment(key).slice(0, 40);

    if (isStrongPlaceholder(value)) {
      return {
        title: 'Placeholder credential left in source',
        severity: 'info',
        redact: false,
        note: `"${name}" holds a placeholder. Harmless by itself, but in a production build it usually means a feature is misconfigured or a real value is expected here at runtime.`,
      };
    }
    if (isPlaceholder(value) || !looksSecret(value, key)) return false;

    const password = isPasswordKey(key);
    if (isClientStore(source)) {
      const where = STORE_NAMES[source.type];
      return {
        title: password ? `Password stored in ${where}` : `Credential-like value in ${where}`,
        severity: password ? 'medium' : 'low',
        category: 'storage',
        note: password
          ? `A password-like value is persisted client-side where any script on this origin can read it. Never persist passwords in the browser. ${CLIENT_STORE_NOTES[source.type]}`
          : CLIENT_STORE_NOTES[source.type],
      };
    }
    if (password) {
      return {
        title: 'Possible hard-coded password',
        note: `Key "${name}". Hard-coded passwords in frontend code are visible to every visitor. If this is a default or a client-side login check, remove it and authenticate on the server.`,
      };
    }
    return { title: `Possible hard-coded secret ("${name}")` };
  }

  const rules = [
    {
      id: 'generic-secret-assignment',
      title: 'Possible hard-coded secret',
      category: 'credential',
      severity: 'medium',
      confidence: 'heuristic',
      re: /(?:api[_-]?key|secret|token|passw(?:or)?d|passphrase|pwd|auth[_-]?key|access[_-]?key|private[_-]?key|credentials?)[A-Za-z0-9_$-]{0,30}["']?\s{0,5}(?:===?|!==?|:|=)\s{0,5}["'`](?<secret>[^"'`\s\\]{6,256})["'`]/i,
      note: 'A high-entropy string is assigned to a secret-sounding name. Verify whether it is a real credential; if so, rotate it and move it server-side. Build-time env vars (VITE_*, NEXT_PUBLIC_*, REACT_APP_*) are inlined into the bundle, so they are public.',
      check: classifyAssignment,
    },
    {
      id: 'secret-in-query-string',
      title: 'Credential in URL query string',
      category: 'credential',
      severity: 'medium',
      confidence: 'heuristic',
      re: /[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|key)=(?<secret>[^&#\s"'`<>]{8,256})/i,
      note: 'Query-string credentials end up in server logs, browser history and Referer headers. Verify, rotate if real, and send credentials in headers from the backend.',
      check: ({ value, m }) => {
        if (/\$\{|\{\{|%s|^\+/.test(value) || isPlaceholder(value)) return false;
        const param = m[0].toLowerCase();
        const kind = param.includes('pass') || param.includes('pwd') ? 'password' : 'key';
        return looksSecret(value, kind);
      },
    },
  ];

  ns.ruleSets.generic = rules;
})();
