/**
 * Report builders: JSON masking, SARIF shape, Markdown injection safety.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadScanner, testEnv } from './helpers/scanner.mjs';
import { fake, p } from './helpers/fakes.mjs';

let buildJsonReport;
let buildSarif;
let buildMarkdown;
let mdEscape;
let result;

const HOSTILE = `"><img src=x onerror=alert(1)>|**bold**|[link](javascript:alert(1))`;

before(async () => {
  const { engine } = loadScanner();
  ({ buildJsonReport, buildSarif, buildMarkdown, mdEscape } = await import('../extension/popup/export.js'));

  const secret = `${p('gh', 'p_')}${fake(36)}`;
  const text = `const token = "${secret}";\n// TODO: hardcoded token ${HOSTILE}\n`;
  const findings = await engine.scanText(
    text,
    { type: 'script-file', label: '/app.js', url: 'https://app.acme.io/app.js' },
    testEnv(),
  );
  result = {
    scanId: '00000000-0000-4000-8000-000000000000',
    version: '0.2.0',
    url: 'https://app.acme.io/',
    origin: 'https://app.acme.io',
    title: 'Acme',
    startedAt: Date.UTC(2026, 0, 1),
    finishedAt: Date.UTC(2026, 0, 1, 0, 0, 2),
    options: {},
    stats: { sourcesScanned: 1, bytesScanned: text.length, findingsTruncated: false, cancelled: false },
    sources: [
      {
        type: 'script-file',
        label: '/app.js',
        url: 'https://app.acme.io/app.js',
        bytes: text.length,
        findings: findings.length,
      },
    ],
    skipped: [{ label: HOSTILE, reason: 'test' }],
    findings,
  };
  result.secret = secret;
});

describe('JSON report', () => {
  it('masks secret values by default', () => {
    const json = JSON.stringify(buildJsonReport(result));
    assert.ok(!json.includes(result.secret), 'raw secret leaked into masked export');
    assert.ok(json.includes('"valuesMasked":true'));
  });

  it('includes raw values only when asked', () => {
    const json = JSON.stringify(buildJsonReport(result, { raw: true }));
    assert.ok(json.includes(result.secret));
  });
});

describe('SARIF report', () => {
  it('is a valid-looking SARIF 2.1.0 log', async () => {
    const sarif = await buildSarif(result);
    assert.equal(sarif.version, '2.1.0');
    const run = sarif.runs[0];
    assert.equal(run.tool.driver.name, 'Watcher');
    assert.equal(run.results.length, result.findings.length);
    for (const r of run.results) {
      assert.ok(run.tool.driver.rules[r.ruleIndex].id === r.ruleId);
      assert.ok(['error', 'warning', 'note'].includes(r.level));
      assert.match(r.partialFingerprints['watcherGroup/v1'], /^[0-9a-f]{64}$/);
    }
    const github = run.results.find((r) => r.ruleId === 'github-token');
    assert.equal(github.locations[0].physicalLocation.region.startLine, 1);
    for (const rule of run.tool.driver.rules) assert.match(rule.properties['security-severity'], /^\d+\.\d$/);
  });

  it('never carries the raw secret when masked', async () => {
    assert.ok(!JSON.stringify(await buildSarif(result)).includes(result.secret));
  });
});

describe('Markdown report', () => {
  it('escapes HTML and Markdown from scanned content', () => {
    const md = buildMarkdown(result);
    assert.ok(!md.includes('<img'), 'raw HTML survived');
    assert.ok(!md.includes('](javascript:'), 'markdown link survived');
    assert.ok(!md.includes(result.secret));
    assert.match(md, /# Watcher report/);
  });

  it('mdEscape neutralises table and inline syntax', () => {
    assert.equal(mdEscape('a|b'), 'a\\|b');
    assert.equal(mdEscape('<b>'), '&lt;b&gt;');
    assert.equal(mdEscape('`x`'), '\\`x\\`');
    assert.equal(mdEscape('line1\nline2'), 'line1 line2');
  });
});
