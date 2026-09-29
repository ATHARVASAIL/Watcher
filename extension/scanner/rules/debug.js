/**
 * Watcher — debug-artifact rules.
 *
 * Source maps, credential-related developer comments, console logging of
 * credentials and leftover debugger statements.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  ns.ruleSets = ns.ruleSets || {};
  if (ns.ruleSets.debug) return;

  /** Extend a hit to the end of its line (max 200 chars) so the whole comment is shown. */
  const toEndOfLine = ({ text, m }) => {
    const newline = text.indexOf('\n', m.index);
    const end = Math.min(newline === -1 ? text.length : newline, m.index + 200);
    return { value: text.slice(m.index, end).trim(), start: m.index, end };
  };

  const rules = [
    {
      id: 'source-map-reference',
      title: 'Source map referenced',
      category: 'debug',
      severity: 'info',
      confidence: 'pattern',
      re: /(?:\/\/[#@]|\/\*#)\s{0,5}sourceMappingURL=(?<secret>(?!data:)[^\s*'"`]{1,500})/,
      redact: false,
      note: 'If the .map file is publicly reachable it exposes your original source, comments and internal paths. With "Check source maps" on, the scanner tests this for you.',
    },
    {
      id: 'inline-source-map',
      title: 'Inline source map (original source embedded)',
      category: 'debug',
      severity: 'low',
      confidence: 'pattern',
      re: /(?:\/\/[#@]|\/\*#)\s{0,5}sourceMappingURL=data:application\/json[^,\s]{0,60},/,
      redact: false,
      note: 'The complete original source is embedded in this file as base64, including comments that minification would have removed. Use a production build without inline source maps.',
      check: () => ({ value: 'sourceMappingURL=data:application/json;base64,…' }),
    },
    {
      id: 'sensitive-todo-comment',
      title: 'Comment mentions credentials',
      category: 'debug',
      severity: 'low',
      confidence: 'heuristic',
      re: /(?:\/\/|\/\*|<!--|#)[ \t]{0,10}(?:TODO|FIXME|HACK|XXX)\b[^\n]{0,160}?(?:\bhard[- ]?coded|\bremove (?:this )?(?:before|prior to) (?:release|launch|prod|production|go-?live|deploy)|\b(?:real|actual|prod(?:uction)?|live|default|temp(?:orary)?|admin|master|root|test) (?:passwords?|secrets?|api[ _-]?keys?|tokens?|credentials?)\b|\b(?:passwords?|secrets?|api[ _-]?keys?|tokens?|credentials?) (?:in (?:code|source|plain ?text)|here|below|above)\b|\bplain ?text (?:passwords?|secrets?)|\bdo(?:n'?t| not) commit)/i,
      redact: false,
      note: 'Developer comments shipped to production often describe shortcuts around authentication or secrets. Read it and remove it from the production build.',
      check: toEndOfLine,
    },
    {
      id: 'console-log-sensitive',
      title: 'Credential logged to console',
      category: 'debug',
      severity: 'info',
      confidence: 'heuristic',
      re: /\bconsole\.(?:log|debug|info|trace|dir|table)\([^)\n]{0,120}?\b(?:token|password|passwd|secret|jwt|authorization|apikey|api_key|credential)/i,
      redact: false,
      note: 'Debug logging of credential-bearing values puts them in DevTools and any log-capture tooling. Strip console calls from production builds.',
      check: ({ text, m }) => {
        const close = text.indexOf(')', m.index);
        const end = close === -1 || close - m.index > 200 ? m.index + m[0].length : close + 1;
        return { value: text.slice(m.index, end), start: m.index, end };
      },
    },
    {
      id: 'debugger-statement',
      title: 'debugger statement',
      category: 'debug',
      severity: 'info',
      confidence: 'pattern',
      re: /(?<![A-Za-z0-9_$.])debugger\s{0,5};/,
      redact: false,
      note: 'Pauses execution when DevTools is open. Indicates a debug build or leftover debugging code.',
    },
  ];

  ns.ruleSets.debug = rules;
})();
