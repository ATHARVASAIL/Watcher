#!/usr/bin/env node
/**
 * WCAG 2.x contrast gate for the popup (light and dark themes) and the website.
 * Reads the colour tokens straight from the stylesheets so the check can't drift.
 */
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../extension/popup/popup.css', import.meta.url), 'utf8');

function tokens(block) {
  const out = {};
  for (const [, name, value] of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\b/gi)) out[name] = value;
  return out;
}

const light = tokens(css.match(/:root\s*\{([\s\S]*?)\n\}/)[1]);
const dark = {
  ...light,
  ...tokens(css.match(/prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([\s\S]*?)\}/)[1]),
};

const channel = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const luminance = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => channel(parseInt(hex.slice(i, i + 2), 16) / 255));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

// [foreground token, background token] pairs that carry text.
const PAIRS = [
  ['text', 'bg'],
  ['text', 'surface'],
  ['text', 'surface-2'],
  ['text', 'hero-1'],
  ['text', 'hero-2'],
  ['text-dim', 'bg'],
  ['text-dim', 'surface'],
  ['text-dim', 'surface-2'],
  ['text-dim', 'hero-1'],
  ['text-dim', 'hero-2'],
  ['accent-text', 'accent'],
  ['accent-text', 'accent-2'],
  ['danger-text', 'danger'],
  ['mark-text', 'mark-bg'],
  ['warn', 'bg'],
  ['warn', 'surface'],
  ['error', 'bg'],
  ['on-sev', 'sev-critical'],
  ['on-sev', 'sev-high'],
  ['on-sev', 'sev-medium'],
  ['on-sev', 'sev-low'],
  ['on-sev', 'sev-info'],
];

let failures = 0;
for (const [theme, t] of [
  ['light', light],
  ['dark', dark],
]) {
  for (const [fg, bg] of PAIRS) {
    if (!t[fg] || !t[bg]) {
      console.error(`✗ ${theme}: missing token --${!t[fg] ? fg : bg}`);
      failures++;
      continue;
    }
    const r = ratio(t[fg], t[bg]);
    if (r < 4.5) {
      console.error(`✗ ${theme}: --${fg} on --${bg} = ${r.toFixed(2)}:1 (needs 4.5:1)`);
      failures++;
    }
  }
}
// ------------------------------------------------------------ website (single dark theme)
const siteCss = readFileSync(new URL('../site/assets/css/site.css', import.meta.url), 'utf8');
const site = tokens(siteCss.match(/\n:root\s*\{([\s\S]*?)\n\}/)[1]);
const SITE_PAIRS = [
  ['fg', 'bg'],
  ['fg', 'bg-2'],
  ['fg', 'surface'],
  ['fg', 'surface-2'],
  ['fg', 'code-bg'],
  ['fg-2', 'bg'],
  ['fg-2', 'surface'],
  ['fg-2', 'surface-2'],
  ['muted', 'bg'],
  ['muted', 'bg-2'],
  ['muted', 'surface'],
  ['muted', 'surface-2'],
  ['muted', 'code-bg'],
  ['accent', 'bg'],
  ['accent', 'bg-2'],
  ['accent', 'surface'],
  ['accent', 'code-bg'],
  ['accent-ink', 'accent'],
  ['bg', 'fg'],
  ['heat-2', 'code-bg'],
  ['low', 'code-bg'],
  ['code-fg', 'code-bg'],
  ['code-dim', 'code-bg'],
  ['code-str', 'code-bg'],
  ['code-kw', 'code-bg'],
];
const SEVERITIES = ['crit', 'high', 'med', 'low', 'info'];
const sitePairs = SITE_PAIRS.map(([fg, bg]) => [site[fg], site[bg], `--${fg} on --${bg}`]);
for (const sev of SEVERITIES) sitePairs.push([site['sev-ink'], site[sev], `--sev-ink on --${sev}`]);
for (const [fg, bg, label] of sitePairs) {
  if (!fg || !bg) {
    console.error(`✗ site: missing token for ${label}`);
    failures++;
    continue;
  }
  const r = ratio(fg, bg);
  if (r < 4.5) {
    console.error(`✗ site: ${label} = ${r.toFixed(2)}:1 (needs 4.5:1)`);
    failures++;
  }
}

if (failures) process.exit(1);
console.log(
  `✓ contrast: ${PAIRS.length * 2} popup pairs (light + dark) and ${sitePairs.length} website pairs meet WCAG AA`,
);
