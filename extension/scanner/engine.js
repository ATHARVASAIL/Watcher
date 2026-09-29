/**
 * Watcher — scan engine.
 *
 * Pure text analysis: takes a string plus a source descriptor and returns
 * findings. No DOM access, no network, no side effects.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.engine) return;

  const { SEVERITIES, RULE_SETS } = ns.config;

  const CONTEXT_CHARS = 60;
  const MAX_HITS_PER_RULE_PER_SOURCE = 50;
  const MAX_VALUE_CHARS = 400;
  const YIELD_EVERY_CHARS = 200_000; // give the page's main thread a breather on big files
  const MASK = '•';
  const CATEGORIES = new Set(['credential', 'token', 'infrastructure', 'debug', 'storage']);
  const CONFIDENCES = new Set(['pattern', 'heuristic']);

  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

  /* ------------------------------------------------------------ rule registry */

  /** Validate every rule once so a malformed contribution fails loudly in tests, not silently in use. */
  function buildRegistry() {
    const seen = new Set();
    const rules = [];
    for (const setName of RULE_SETS) {
      for (const raw of ns.ruleSets[setName] || []) {
        const rule = { redact: true, ...raw, set: setName };
        const problems = [];
        if (!/^[a-z0-9-]+$/.test(rule.id || '')) problems.push('id must be kebab-case');
        if (seen.has(rule.id)) problems.push('duplicate id');
        if (!rule.title) problems.push('missing title');
        if (!SEVERITIES.includes(rule.severity)) problems.push(`bad severity "${rule.severity}"`);
        if (!CATEGORIES.has(rule.category)) problems.push(`bad category "${rule.category}"`);
        if (!CONFIDENCES.has(rule.confidence)) problems.push(`bad confidence "${rule.confidence}"`);
        if (!(rule.re instanceof RegExp)) problems.push('re must be a RegExp');
        if (rule.check !== undefined && typeof rule.check !== 'function')
          problems.push('check must be a function');
        if (problems.length) throw new Error(`Invalid rule "${rule.id}": ${problems.join(', ')}`);
        seen.add(rule.id);

        // The engine owns the g (global) and d (match indices) flags.
        const flags = [...new Set(`${rule.re.flags}gd`.split(''))].join('');
        rules.push(Object.freeze({ ...rule, regex: new RegExp(rule.re.source, flags) }));
      }
    }
    return Object.freeze(rules);
  }

  const rules = buildRegistry();

  /* ------------------------------------------------------------ formatting helpers */

  function redact(value) {
    if (value.length <= 8) return value.slice(0, 2) + MASK.repeat(Math.max(3, value.length - 2));
    return value.slice(0, 4) + MASK.repeat(Math.min(12, value.length - 8)) + value.slice(-4);
  }

  /** Line/column lookup built lazily, only for sources that have hits. */
  function lineIndex(text) {
    const starts = [0];
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
    return (pos) => {
      let lo = 0;
      let hi = starts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= pos) lo = mid;
        else hi = mid - 1;
      }
      return { line: lo + 1, col: pos - starts[lo] + 1 };
    };
  }

  /**
   * Slice [from, to) of text, masking characters that belong to another redactable
   * hit, so an unrevealed context never leaks a neighbouring secret.
   */
  function maskedSlice(text, from, to, ranges) {
    let out = '';
    let run = 0;
    for (let i = from; i < to; i++) {
      if (ranges.some(([s, e]) => i >= s && i < e)) {
        if (run++ < 6) out += MASK;
      } else {
        run = 0;
        out += text[i];
      }
    }
    return out;
  }

  const collapseWhitespace = (s) => s.replace(/\s+/g, ' ');

  const describeLocation = (source, line, col) =>
    source.lineLabels
      ? source.lineLabels[line - 1] || source.label
      : `line ${line.toLocaleString()}, col ${col.toLocaleString()}`;

  const sourceRef = (source) => ({
    type: source.type,
    label: source.label,
    url: source.url || null,
    parent: source.parent || null,
  });

  /* ------------------------------------------------------------ scanning */

  function runRule(rule, text, source, env, hits) {
    const re = rule.regex;
    re.lastIndex = 0;
    let kept = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const [start, end] = m.indices.groups?.secret ?? m.indices[0];
      const value = text.slice(start, end);

      let verdict = true;
      if (rule.check) {
        try {
          verdict = rule.check({ m, value, text, start, end, source, env });
        } catch {
          verdict = false; // a buggy rule must never break the scan
        }
      }
      if (verdict === false || verdict === null) continue;

      const o = typeof verdict === 'object' ? verdict : {};
      hits.push({
        rule,
        start: o.start ?? start,
        end: o.end ?? end,
        value: o.value ?? value,
        title: o.title ?? rule.title,
        severity: o.severity ?? rule.severity,
        category: o.category ?? rule.category,
        note: o.note ?? rule.note,
        redact: o.redact ?? rule.redact,
        display: o.display,
        groupKey: o.groupKey,
      });
      if (++kept >= MAX_HITS_PER_RULE_PER_SOURCE) break;
    }
  }

  /**
   * Scan one text source.
   * @param {string} text
   * @param {{type: string, label: string, url?: string, parent?: string, lineLabels?: string[]}} source
   * @param {{pageHost: string, pageIsNonProd: boolean, nextId: () => string, signal?: AbortSignal}} env
   * @returns {Promise<object[]>} findings
   */
  async function scanText(text, source, env) {
    const hits = [];
    for (const rule of rules) {
      if (env.signal?.aborted) break;
      runRule(rule, text, source, env, hits);
      if (text.length > YIELD_EVERY_CHARS) await tick();
    }
    if (!hits.length) return [];

    // A vendor-format hit beats a heuristic hit on the same bytes
    // (`token: "ghp_…"` is a GitHub token, not a "possible secret").
    const strong = hits.filter((h) => h.rule.confidence === 'pattern' && h.redact);
    const kept = hits.filter(
      (h) => h.rule.confidence === 'pattern' || !strong.some((s) => h.start < s.end && s.start < h.end),
    );

    const locate = lineIndex(text);
    const maskable = kept.filter((h) => h.redact).map((h) => [h.start, h.end]);

    return kept.map((h) => {
      const { line, col } = locate(h.start);
      const others = maskable.filter(([s, e]) => !(s === h.start && e === h.end));
      let from = Math.max(0, h.start - CONTEXT_CHARS);
      let to = Math.min(text.length, h.end + CONTEXT_CHARS);
      if (source.lineLabels) {
        // Synthetic one-entry-per-line sources (storage, cookies, HTML attributes):
        // never let context bleed into a neighbouring entry.
        from = Math.max(from, text.lastIndexOf('\n', h.start - 1) + 1);
        const lineEnd = text.indexOf('\n', h.end);
        if (lineEnd !== -1) to = Math.min(to, lineEnd);
      }
      const value = h.value.length > MAX_VALUE_CHARS ? `${h.value.slice(0, MAX_VALUE_CHARS)}…` : h.value;
      return {
        id: env.nextId(),
        ruleId: h.rule.id,
        title: h.title,
        severity: h.severity,
        category: h.category,
        confidence: h.rule.confidence,
        note: h.note,
        value,
        redact: h.redact,
        display: h.redact ? h.display || redact(h.value) : value,
        groupKey: h.groupKey || `${h.rule.id}|${h.value}`,
        source: sourceRef(source),
        where: describeLocation(source, line, col),
        line,
        col,
        context: {
          before: collapseWhitespace(text.slice(from, h.start)),
          after: collapseWhitespace(text.slice(h.end, to)),
          beforeMasked: collapseWhitespace(maskedSlice(text, from, h.start, others)),
          afterMasked: collapseWhitespace(maskedSlice(text, h.end, to, others)),
          truncatedBefore: from > 0,
          truncatedAfter: to < text.length,
        },
      };
    });
  }

  /** Findings from structural checks (not regex), e.g. a pre-filled password input. */
  function manualFinding(env, source, where, spec) {
    const redactValue = spec.redact !== false;
    return {
      id: env.nextId(),
      ruleId: spec.ruleId,
      title: spec.title,
      severity: spec.severity,
      category: spec.category,
      confidence: spec.confidence || 'pattern',
      note: spec.note,
      value: spec.value,
      redact: redactValue,
      display: redactValue ? redact(spec.value) : spec.value,
      groupKey: spec.groupKey || `${spec.ruleId}|${spec.value}`,
      source: sourceRef(source),
      where,
      line: null,
      col: null,
      context: null,
    };
  }

  /** Rule metadata for docs and SARIF (no regex objects or functions). */
  const describeRules = () =>
    rules.map(({ id, title, severity, category, confidence, note, set }) => ({
      id,
      title,
      severity,
      category,
      confidence,
      note,
      set,
    }));

  ns.engine = Object.freeze({ scanText, manualFinding, redact, describeRules, ruleCount: rules.length });
})();
