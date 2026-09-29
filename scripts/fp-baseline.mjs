#!/usr/bin/env node
/**
 * False-positive baseline: scan a directory of third-party JS/CSS (e.g. node_modules)
 * and report non-Info findings. Library code should produce (almost) nothing.
 *   node scripts/fp-baseline.mjs node_modules [--verbose]
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { loadScanner, testEnv } from '../tests/helpers/scanner.mjs';

const dir = process.argv[2] || 'node_modules';
const verbose = process.argv.includes('--verbose');
const { engine } = loadScanner();

const files = [];
(function walk(d) {
  for (const name of readdirSync(d)) {
    const path = join(d, name);
    const info = statSync(path);
    if (info.isDirectory()) walk(path);
    else if (/\.(?:m?js|cjs|css)$/.test(name) && info.size > 1000 && info.size < 20_000_000) files.push(path);
  }
})(dir);

let bytes = 0;
const bySeverity = {};
const byRule = {};
const start = performance.now();
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  bytes += text.length;
  for (const f of await engine.scanText(text, { type: 'script-file', label: file }, testEnv())) {
    if (f.severity === 'info') continue;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
    if (verbose)
      console.log(`  [${f.severity}] ${f.ruleId} ${f.display.slice(0, 40)} — ${relative(dir, file)}`);
  }
}
const secs = ((performance.now() - start) / 1000).toFixed(1);
console.log(`${files.length} files, ${(bytes / 1e6).toFixed(1)} MB in ${secs}s`);
console.log('non-info findings by severity:', bySeverity);
console.log('by rule:', byRule);
