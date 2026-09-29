#!/usr/bin/env node
/**
 * WCAG 2.x contrast gate for the popup, in both light and dark themes.
 * Reads the colour tokens straight from popup.css so the check can't drift.
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
  ['text-dim', 'bg'],
  ['text-dim', 'surface'],
  ['accent-text', 'accent'],
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
if (failures) process.exit(1);
console.log(
  `✓ contrast: ${PAIRS.length * 2} text/background pairs meet WCAG AA (4.5:1) in light and dark themes`,
);
