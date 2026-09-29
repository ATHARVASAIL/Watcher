/**
 * Watcher — infrastructure rules.
 *
 * Database endpoints, credentials embedded in URLs and internal / non-production hosts.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  ns.ruleSets = ns.ruleSets || {};
  if (ns.ruleSets.infrastructure) return;

  const { isPlaceholder, classifyHost, HOST_KINDS, DOC_HOST_WORDS } = ns.util;

  const DB_SCHEMES = 'mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|mariadb|rediss?|amqps?|mssql|sqlserver';
  const TEMPLATE_VALUE_RE = /^\$\{|^\{\{|^<|^%|^:/;

  function classifyDatabaseUrl({ value }) {
    const creds = value.match(/^[a-z+]+:\/\/([^/@\s:]{1,64}):([^/@\s]{1,128})@/i);
    const hostMatch = value.match(
      /^[a-z+]+:\/\/(?:[^/@\s]{1,200}@)?([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:.]{2,45}\])/i,
    );
    const isLocal = Boolean(hostMatch) && classifyHost(hostMatch[1]) === 'loopback';
    const isDefaultCreds = Boolean(creds) && creds[1].toLowerCase() === creds[2].toLowerCase(); // guest:guest

    if (isLocal || isDefaultCreds) {
      return {
        title: creds ? 'Local / default database credentials' : 'Local database URL',
        severity: creds ? 'low' : 'info',
        redact: Boolean(creds),
        note: 'Points at a local database or uses vendor-default credentials, typical of docs, examples and dev configs. Not directly exploitable from outside, but confirm it is not a leftover dev config, and never deploy databases with default credentials.',
      };
    }
    if (creds && !isPlaceholder(creds[2]) && !TEMPLATE_VALUE_RE.test(creds[2])) {
      return {
        title: 'Database connection string with credentials',
        severity: 'critical',
        category: 'credential',
        redact: true,
        note: 'Database username and password are in frontend code. Change the password now, restrict network access to the database, and move data access behind an API.',
      };
    }
    return true;
  }

  function classifyInternalUrl({ value, m, env, text }) {
    const host = value.toLowerCase();
    if (host === env.pageHost) return false;
    const kind = classifyHost(host);
    if (!kind) return false;

    // Single-label names are mostly doc examples ("http://host:port") unless a port or a
    // clean URL boundary pins them down ("lodash\.com" inside a regex doc is not a host).
    if (kind === 'internal-name') {
      const next = text[m.index + m[0].length] || '';
      if (DOC_HOST_WORDS.has(host) || (!m.groups.port && !/^(?:$|[/"'`\s])/.test(next))) return false;
    }

    const meta = HOST_KINDS[kind];
    const shown = m.groups.port ? `${host}:${m.groups.port}` : host;
    const verdict = {
      title: meta.title,
      severity: meta.severity,
      note: meta.note,
      value: shown,
      groupKey: `internal-url|${shown}`,
    };
    if (kind === 'internal-name' && !m.groups.port) {
      // "http://jenkins/…" is worth knowing about, but library virtual hosts look the same.
      verdict.severity = 'info';
    }
    if (env.pageIsNonProd && kind !== 'loopback') {
      verdict.severity = 'info';
      verdict.note = `${meta.note} (You are scanning a non-production environment, where references to other non-production hosts are expected.)`;
    }
    return verdict;
  }

  const rules = [
    {
      id: 'db-connection-string',
      title: 'Database endpoint in frontend',
      category: 'infrastructure',
      severity: 'low',
      confidence: 'pattern',
      re: new RegExp(`\\b(?:${DB_SCHEMES}):\\/\\/[^\\s'"\`<>]{3,500}`, 'i'),
      redact: false,
      note: 'Database hosts should not be known to the browser. Confirm the host is not reachable from the internet.',
      check: classifyDatabaseUrl,
    },
    {
      id: 'credentials-in-url',
      title: 'Credentials embedded in URL',
      category: 'credential',
      severity: 'high',
      confidence: 'pattern',
      re: new RegExp(
        `(?<![A-Za-z0-9+.\\-])(?!(?:${DB_SCHEMES})\\b)[a-z][a-z0-9+.\\-]{1,20}:\\/\\/` +
          `(?<user>[^\\/\\s:@'"\`<>]{1,64}):(?<secret>[^\\/\\s@'"\`<>]{1,128})@[A-Za-z0-9.\\-]{1,253}`,
        'i',
      ),
      note: 'A username:password pair is embedded in a URL (http://user:pass@host). Rotate the password and authenticate server-side.',
      check: ({ value, m }) => {
        if (isPlaceholder(value) || isPlaceholder(m.groups.user)) return false;
        if (/^(?:pass(?:word)?|pwd)$/i.test(value)) return false; // docs-style user:password@
        return !TEMPLATE_VALUE_RE.test(value);
      },
    },
    {
      id: 'internal-url',
      title: 'Internal URL',
      category: 'infrastructure',
      severity: 'low',
      confidence: 'pattern',
      re: /\b(?:https?|wss?|ftp):\/\/(?:[^/\s@:'"`<>]{1,64}(?::[^/\s@'"`<>]{0,128})?@)?(?<secret>[A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:.]{2,45}\])(?::(?<port>\d{1,5}))?/i,
      redact: false,
      note: '',
      check: classifyInternalUrl,
    },
  ];

  ns.ruleSets.infrastructure = rules;
})();
