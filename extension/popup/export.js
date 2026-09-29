/**
 * Report builders: JSON, SARIF 2.1.0 and Markdown. Pure functions (no DOM, no
 * chrome.*), unit-tested in Node. Values are masked unless `raw` is true.
 *
 * Every exported string is treated as data from a hostile page: Markdown output
 * escapes HTML and Markdown syntax so a report rendered on GitHub can't inject markup.
 */

const TOOL_NAME = 'Watcher';
const INFO_URI = 'https://github.com/ATHARVASAIL/Watcher';

const cfg = () => globalThis.__WATCHER.config;
const common = () => globalThis.__WATCHER.common;

const shownValue = (f, raw) => (raw || !f.redact ? f.value : f.display);

function shownContext(f, raw) {
  if (!f.context) return null;
  const c = f.context;
  return raw
    ? `${c.before}⟦${f.value}⟧${c.after}`
    : `${c.beforeMasked}⟦${f.redact ? f.display : f.value}⟧${c.afterMasked}`;
}

/* ------------------------------------------------------------ JSON */

export function buildJsonReport(result, { raw = false } = {}) {
  return {
    tool: TOOL_NAME,
    version: result.version,
    exportedAt: new Date().toISOString(),
    valuesMasked: !raw,
    target: { url: result.url, title: result.title },
    scannedAt: new Date(result.startedAt).toISOString(),
    options: result.options,
    stats: result.stats,
    sources: result.sources,
    skipped: result.skipped,
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      category: f.category,
      confidence: f.confidence,
      value: shownValue(f, raw),
      source: f.source,
      where: f.where,
      line: f.line,
      col: f.col,
      context: shownContext(f, raw),
      note: f.note,
    })),
  };
}

/* ------------------------------------------------------------ SARIF */

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };
const FILE_TYPES = new Set(['script-file', 'style-file']);

/**
 * SARIF 2.1.0 log suitable for GitHub code scanning upload.
 * Fingerprints are SHA-256 hashes, so they never carry the secret itself.
 */
export async function buildSarif(result, { raw = false } = {}) {
  const { RANK } = common();
  const rules = new Map();
  for (const f of result.findings) {
    const existing = rules.get(f.ruleId);
    if (!existing || RANK[f.severity] < RANK[existing.severity]) rules.set(f.ruleId, f);
  }
  const ruleList = [...rules.values()].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  const ruleIndex = new Map(ruleList.map((f, i) => [f.ruleId, i]));

  const results = await Promise.all(
    result.findings.map(async (f) => {
      const uri = f.source.url || result.url;
      const physicalLocation = { artifactLocation: { uri } };
      if (FILE_TYPES.has(f.source.type) && f.line) {
        physicalLocation.region = { startLine: f.line, startColumn: f.col };
      }
      return {
        ruleId: f.ruleId,
        ruleIndex: ruleIndex.get(f.ruleId),
        level: SARIF_LEVEL[f.severity],
        message: { text: `${f.title}: ${shownValue(f, raw)} (${f.source.label}, ${f.where})` },
        locations: [
          {
            physicalLocation,
            logicalLocations: [{ fullyQualifiedName: `${f.source.label} › ${f.where}`, kind: f.source.type }],
          },
        ],
        partialFingerprints: { 'watcherGroup/v1': await common().sha256(`${f.groupKey}\u0000${f.where}`) },
        properties: { severity: f.severity, confidence: f.confidence, category: f.category },
      };
    }),
  );

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: result.version,
            informationUri: INFO_URI,
            rules: ruleList.map((f) => ({
              id: f.ruleId,
              name: f.ruleId.replace(/(^|-)([a-z0-9])/g, (_, __, c) => c.toUpperCase()),
              shortDescription: { text: f.title },
              fullDescription: { text: f.note || f.title },
              help: { text: f.note || f.title },
              defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
              properties: {
                'security-severity': SECURITY_SEVERITY[f.severity],
                tags: ['security', f.category, f.confidence],
              },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: !result.stats.cancelled,
            startTimeUtc: new Date(result.startedAt).toISOString(),
            endTimeUtc: new Date(result.finishedAt).toISOString(),
          },
        ],
        originalUriBaseIds: { PAGE: { uri: `${result.origin}/` } },
        properties: { target: result.url, valuesMasked: !raw },
        results,
      },
    ],
  };
}

/* ------------------------------------------------------------ Markdown */

/** Escape text for a GFM table cell: HTML entities, Markdown punctuation, pipes, newlines. */
export function mdEscape(text) {
  return String(text ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_{}[\]()#!|~])/g, '\\$1');
}

export function buildMarkdown(result, { raw = false } = {}) {
  const { SEVERITIES, SEVERITY_LABELS } = cfg();
  const groups = common().groupFindings(result.findings);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const g of groups) counts[g.severity]++;

  const lines = [
    `# Watcher report`,
    '',
    `- **Target:** ${mdEscape(result.url)}`,
    `- **Scanned:** ${new Date(result.startedAt).toISOString()} (${TOOL_NAME} v${mdEscape(result.version)})`,
    `- **Sources:** ${result.stats.sourcesScanned} scanned, ${result.skipped.length} skipped`,
    `- **Values:** ${raw ? '⚠️ unmasked — handle this report as a secret' : 'masked'}`,
    result.stats.cancelled ? '- **Note:** scan stopped early; results are partial' : null,
    '',
    '| Severity | Count |',
    '|---|---|',
    ...SEVERITIES.map((s) => `| ${SEVERITY_LABELS[s]} | ${counts[s]} |`),
    '',
  ].filter((l) => l !== null);

  for (const sev of SEVERITIES) {
    const bucket = groups.filter((g) => g.severity === sev);
    if (!bucket.length) continue;
    lines.push(`## ${SEVERITY_LABELS[sev]} (${bucket.length})`, '');
    lines.push('| Finding | Value | Location(s) | What to do |', '|---|---|---|---|');
    for (const g of bucket) {
      const f = g.head;
      const where = g.items
        .slice(0, 5)
        .map((i) => `${mdEscape(i.source.label)} @ ${mdEscape(i.where)}`)
        .join('<br>');
      const more = g.items.length > 5 ? `<br>… +${g.items.length - 5} more` : '';
      const review = f.confidence === 'heuristic' ? ' _(needs review)_' : '';
      lines.push(
        `| ${mdEscape(f.title)}${review} | ${mdEscape(shownValue(f, raw))} | ${where}${more} | ${mdEscape(f.note)} |`,
      );
    }
    lines.push('');
  }

  if (result.skipped.length) {
    lines.push('## Skipped sources', '');
    for (const s of result.skipped) lines.push(`- ${mdEscape(s.label)}: ${mdEscape(s.reason)}`);
    lines.push('');
  }
  return lines.join('\n');
}
