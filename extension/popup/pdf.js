/**
 * PDF report builder. A small, dependency-free PDF 1.4 writer that uses the standard
 * Helvetica / Courier fonts, so nothing is fetched or embedded. Pure function (no DOM,
 * no chrome.*), unit-tested in Node. Values are masked unless `raw` is true.
 *
 * All page-supplied text is escaped for PDF string syntax and reduced to WinAnsi, so a
 * hostile page cannot inject PDF operators into the report.
 */
import { shownValue, shownContext } from './export.js';

const cfg = () => globalThis.__WATCHER.config;
const common = () => globalThis.__WATCHER.common;

/* ------------------------------------------------------------ page geometry (A4, points) */

const PAGE_W = 595.28;
const PAGE_H = 841.89;
const MARGIN = 46;
const CONTENT_W = PAGE_W - MARGIN * 2;
const FOOTER_H = 34;
const MAX_LOCATIONS = 5;

const COLORS = {
  ink: [0.07, 0.09, 0.15],
  dim: [0.33, 0.37, 0.45],
  line: [0.85, 0.88, 0.93],
  panel: [0.95, 0.96, 0.98],
  band: [0.043, 0.063, 0.118],
  cyan: [0.36, 0.88, 0.94],
  white: [1, 1, 1],
  warn: [0.54, 0.29, 0],
  critical: [0.702, 0.149, 0.118],
  high: [0.71, 0.278, 0.031],
  medium: [0.549, 0.369, 0],
  low: [0.118, 0.439, 0.271],
  info: [0.29, 0.333, 0.396],
};

/* ------------------------------------------------------------ fonts and text */

// Advance widths (1/1000 em) for WinAnsi 32..126, from the Adobe core-font metrics.
const HELV = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
  556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
  500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469,
  556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
  278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELV_BOLD = [
  278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
  556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278,
  556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584,
  556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556,
  333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];
const FONTS = {
  regular: { id: 'F1', base: 'Helvetica', widths: HELV },
  bold: { id: 'F2', base: 'Helvetica-Bold', widths: HELV_BOLD },
  mono: { id: 'F3', base: 'Courier', widths: null },
};

// Unicode → WinAnsi (CP1252) for the characters reports actually use; the rest become '?'.
const WIN_ANSI = new Map([
  [0x20ac, 0x80],
  [0x2026, 0x85],
  [0x2018, 0x91],
  [0x2019, 0x92],
  [0x201c, 0x93],
  [0x201d, 0x94],
  [0x2022, 0x95],
  [0x2013, 0x96],
  [0x2014, 0x97],
  [0x203a, 0x9b],
  [0x2039, 0x8b],
]);
const ASCII_FALLBACK = new Map([
  [0x2192, '->'],
  [0x2190, '<-'],
  [0x27e6, '['],
  [0x27e7, ']'],
  [0x2264, '<='],
  [0x2265, '>='],
  [0x2713, 'v'],
  [0x26a0, '!'],
]);

/** Normalise any string to a sequence of WinAnsi byte values. */
export function toWinAnsi(text) {
  const out = [];
  for (const ch of String(text ?? '')) {
    const cp = ch.codePointAt(0);
    if (cp === 9) out.push(32, 32);
    else if (cp < 32 || cp === 127) out.push(32);
    else if (cp < 127 || (cp >= 0xa0 && cp <= 0xff)) out.push(cp);
    else if (WIN_ANSI.has(cp)) out.push(WIN_ANSI.get(cp));
    else if (ASCII_FALLBACK.has(cp)) for (const c of ASCII_FALLBACK.get(cp)) out.push(c.charCodeAt(0));
    else out.push(63);
  }
  return out;
}

function charWidth(font, code) {
  if (!font.widths) return 600;
  if (code >= 32 && code <= 126) return font.widths[code - 32];
  if (code === 0x95) return 350; // bullet
  if (code === 0x85 || code === 0x97) return 1000;
  return 556;
}

const widthOf = (bytes, font, size) => (bytes.reduce((w, c) => w + charWidth(font, c), 0) / 1000) * size;

/** PDF literal string with (, ) and \ escaped and every non-ASCII byte as an octal escape. */
function pdfString(bytes) {
  let s = '(';
  for (const b of bytes) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) s += `\\${String.fromCharCode(b)}`;
    else if (b < 32 || b > 126) s += `\\${b.toString(8).padStart(3, '0')}`;
    else s += String.fromCharCode(b);
  }
  return `${s})`;
}

/** Greedy word wrap on WinAnsi bytes; words longer than a line are broken by character. */
function wrap(text, font, size, maxWidth) {
  const lines = [];
  for (const paragraph of String(text ?? '').split(/\r?\n/)) {
    const bytes = toWinAnsi(paragraph);
    let line = [];
    let word = [];
    const flushWord = () => {
      if (!word.length) return;
      const candidate = line.length ? [...line, 32, ...word] : word;
      if (widthOf(candidate, font, size) <= maxWidth) {
        line = candidate;
      } else {
        if (line.length) lines.push(line);
        line = [];
        let chunk = [];
        for (const c of word) {
          if (chunk.length && widthOf([...chunk, c], font, size) > maxWidth) {
            lines.push(chunk);
            chunk = [];
          }
          chunk.push(c);
        }
        line = chunk;
      }
      word = [];
    };
    for (const b of bytes) {
      if (b === 32) flushWord();
      else word.push(b);
    }
    flushWord();
    lines.push(line);
  }
  return lines;
}

/* ------------------------------------------------------------ layout */

class Doc {
  constructor() {
    this.pages = [];
    this.newPage();
  }

  newPage() {
    this.ops = [];
    this.pages.push(this.ops);
    this.y = MARGIN;
  }

  /** Start a new page unless `height` more points fit above the footer. */
  ensure(height) {
    if (this.y + height > PAGE_H - MARGIN - FOOTER_H) this.newPage();
  }

  fill(color) {
    this.ops.push(`${color.map((c) => c.toFixed(3)).join(' ')} rg`);
  }

  rect(x, top, w, h, color) {
    this.fill(color);
    this.ops.push(`${x.toFixed(2)} ${(PAGE_H - top - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
  }

  text(bytes, x, baselineTop, font, size, color) {
    this.fill(color);
    this.ops.push(
      `BT /${font.id} ${size} Tf ${x.toFixed(2)} ${(PAGE_H - baselineTop).toFixed(2)} Td ${pdfString(bytes)} Tj ET`,
    );
  }

  /** Write wrapped text at the cursor and advance it. */
  para(
    text,
    { font = FONTS.regular, size = 10, color = COLORS.ink, x = MARGIN, width = CONTENT_W, gap = 1.35 } = {},
  ) {
    const lead = size * gap;
    for (const line of wrap(text, font, size, width)) {
      this.ensure(lead);
      this.text(line, x, this.y + size, font, size, color);
      this.y += lead;
    }
  }

  lines(text, font, size, width) {
    return wrap(text, font, size, width).length;
  }
}

/* ------------------------------------------------------------ report */

function severityCounts(groups) {
  const counts = Object.fromEntries(cfg().SEVERITIES.map((s) => [s, 0]));
  for (const g of groups) counts[g.severity]++;
  return counts;
}

function header(doc, result, raw) {
  doc.rect(0, 0, PAGE_W, 112, COLORS.band);
  doc.rect(0, 112, PAGE_W, 3, COLORS.cyan);
  doc.text(toWinAnsi('Watcher'), MARGIN, 52, FONTS.bold, 26, COLORS.white);
  doc.text(toWinAnsi('Frontend secrets report'), MARGIN, 74, FONTS.regular, 12, COLORS.cyan);
  const stamp = toWinAnsi(`${new Date(result.startedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC`);
  doc.text(stamp, PAGE_W - MARGIN - widthOf(stamp, FONTS.regular, 10), 52, FONTS.regular, 10, COLORS.white);
  const version = toWinAnsi(`Watcher v${result.version}`);
  doc.text(
    version,
    PAGE_W - MARGIN - widthOf(version, FONTS.regular, 10),
    70,
    FONTS.regular,
    10,
    COLORS.cyan,
  );
  doc.y = 138;

  const rows = [
    ['Target', result.url],
    ['Page title', result.title || '-'],
    [
      'Sources',
      `${result.stats.sourcesScanned} scanned, ${result.skipped.length} skipped${
        result.stats.cancelled ? ' - scan stopped early, results are partial' : ''
      }`,
    ],
    ['Values', raw ? 'UNMASKED - handle this report as a secret' : 'masked'],
  ];
  for (const [label, value] of rows) {
    const top = doc.y;
    doc.text(toWinAnsi(label), MARGIN, top + 10, FONTS.bold, 9.5, COLORS.dim);
    doc.para(value, {
      size: 10,
      x: MARGIN + 78,
      width: CONTENT_W - 78,
      color: label === 'Values' && raw ? COLORS.critical : COLORS.ink,
    });
    doc.y = Math.max(doc.y, top + 14) + 2;
  }
}

function summary(doc, groups) {
  const { SEVERITIES, SEVERITY_LABELS } = cfg();
  const counts = severityCounts(groups);
  doc.y += 10;
  const gap = 8;
  const w = (CONTENT_W - gap * (SEVERITIES.length - 1)) / SEVERITIES.length;
  SEVERITIES.forEach((sev, i) => {
    const x = MARGIN + i * (w + gap);
    doc.rect(x, doc.y, w, 54, COLORS[sev]);
    doc.text(toWinAnsi(String(counts[sev])), x + 10, doc.y + 28, FONTS.bold, 20, COLORS.white);
    doc.text(toWinAnsi(SEVERITY_LABELS[sev]), x + 10, doc.y + 45, FONTS.bold, 9, COLORS.white);
  });
  doc.y += 54 + 10;
  const total = groups.length;
  doc.para(
    total
      ? `${total} distinct finding${total === 1 ? '' : 's'}. Treat every Critical or High finding as compromised: rotate it, then remove it from the build and from the repository history.`
      : 'No exposed secrets were found in the sources Watcher could read.',
    { size: 9.5, color: COLORS.dim },
  );
}

const locationLine = (item) => {
  const origin = item.source.parent ? ` <- ${item.source.parent}` : '';
  const where = item.where && item.where !== item.source.label ? ` - ${item.where}` : '';
  return `${item.source.label}${origin}${where}`;
};

function groupBlockHeight(doc, group, raw) {
  const f = group.head;
  const inner = CONTENT_W - 26;
  let h = 24 + doc.lines(`Value: ${shownValue(f, raw)}`, FONTS.mono, 8.5, inner) * 11.5;
  if (f.note) h += doc.lines(f.note, FONTS.regular, 9, inner) * 12.2 + 4;
  for (const item of group.items.slice(0, MAX_LOCATIONS)) {
    h += doc.lines(locationLine(item), FONTS.regular, 8.5, inner - 10) * 11.5 + 2;
    const ctx = shownContext(item, raw);
    if (ctx) h += doc.lines(ctx, FONTS.mono, 7.5, inner - 10) * 10 + 4;
  }
  return h + 22;
}

function findingBlock(doc, group, raw) {
  const { SEVERITY_LABELS } = cfg();
  const f = group.head;
  const color = COLORS[group.severity];
  const x = MARGIN + 14;
  const inner = CONTENT_W - 26;
  const height = Math.min(groupBlockHeight(doc, group, raw), PAGE_H - MARGIN * 2 - FOOTER_H - 20);
  doc.ensure(height);

  const top = doc.y;
  const barStart = doc.pages.length;
  doc.y += 6;

  const label = toWinAnsi(SEVERITY_LABELS[group.severity].toUpperCase());
  const labelW = widthOf(label, FONTS.bold, 7.5) + 12;
  doc.rect(x, doc.y, labelW, 13, color);
  doc.text(label, x + 6, doc.y + 9.5, FONTS.bold, 7.5, COLORS.white);
  const tags = [
    f.confidence === 'heuristic' ? 'needs review' : '',
    group.items.length > 1 ? `${group.items.length} locations` : '',
  ]
    .filter(Boolean)
    .join(' · ');
  const title = toWinAnsi(f.title);
  const titleFits = widthOf(title, FONTS.bold, 11) <= inner - labelW - 8;
  if (titleFits) {
    doc.text(title, x + labelW + 8, doc.y + 10, FONTS.bold, 11, COLORS.ink);
    doc.y += 18;
  } else {
    doc.y += 18;
    doc.para(f.title, { font: FONTS.bold, size: 11, x, width: inner });
  }
  if (tags) doc.para(`${f.ruleId} · ${tags}`, { size: 8, color: COLORS.dim, x, width: inner });
  else doc.para(f.ruleId, { size: 8, color: COLORS.dim, x, width: inner });
  doc.y += 2;
  doc.para(`Value: ${shownValue(f, raw)}`, { font: FONTS.mono, size: 8.5, x, width: inner, gap: 1.35 });
  if (f.note) {
    doc.y += 3;
    doc.para(f.note, { size: 9, color: COLORS.ink, x, width: inner });
  }
  doc.y += 3;
  for (const item of group.items.slice(0, MAX_LOCATIONS)) {
    doc.para(`• ${locationLine(item)}`, { size: 8.5, color: COLORS.dim, x, width: inner });
    const ctx = shownContext(item, raw);
    if (ctx)
      doc.para(ctx, {
        font: FONTS.mono,
        size: 7.5,
        color: COLORS.dim,
        x: x + 10,
        width: inner - 10,
        gap: 1.3,
      });
    doc.y += 2;
  }
  if (group.items.length > MAX_LOCATIONS) {
    doc.para(`+ ${group.items.length - MAX_LOCATIONS} more locations (see the JSON export)`, {
      size: 8.5,
      color: COLORS.dim,
      x,
      width: inner,
    });
  }

  // Severity bar down the left edge (only when the block stayed on one page).
  if (doc.pages.length === barStart) doc.rect(MARGIN, top, 4, doc.y - top + 4, color);
  doc.y += 8;
  doc.rect(MARGIN, doc.y, CONTENT_W, 0.6, COLORS.line);
  doc.y += 10;
}

function footers(doc, result) {
  let host = 'page';
  try {
    host = new URL(result.url).host;
  } catch {
    /* keep default */
  }
  const total = doc.pages.length;
  doc.pages.forEach((ops, i) => {
    doc.ops = ops;
    const top = PAGE_H - MARGIN + 6;
    doc.rect(MARGIN, top - 14, CONTENT_W, 0.6, COLORS.line);
    doc.text(
      toWinAnsi(`Watcher report · ${host} · generated locally, handle as confidential`),
      MARGIN,
      top,
      FONTS.regular,
      8,
      COLORS.dim,
    );
    const page = toWinAnsi(`Page ${i + 1} of ${total}`);
    doc.text(page, PAGE_W - MARGIN - widthOf(page, FONTS.regular, 8), top, FONTS.regular, 8, COLORS.dim);
  });
}

/** Serialise pages into a PDF 1.4 file (ASCII only, so string length equals byte length). */
function serialise(doc, result) {
  const objects = [];
  const add = (body) => objects.push(body) - 1 + 1; // 1-based object numbers
  const catalog = add(null);
  const pagesObj = add(null);
  const fontIds = {};
  for (const font of Object.values(FONTS)) {
    fontIds[font.id] = add(
      `<< /Type /Font /Subtype /Type1 /BaseFont /${font.base} /Encoding /WinAnsiEncoding >>`,
    );
  }
  const fontRes = Object.entries(fontIds)
    .map(([id, n]) => `/${id} ${n} 0 R`)
    .join(' ');
  const kids = [];
  for (const ops of doc.pages) {
    const stream = ops.join('\n');
    const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    kids.push(
      add(
        `<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << ${fontRes} >> >> /Contents ${content} 0 R >>`,
      ),
    );
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R >>`;
  objects[pagesObj - 1] =
    `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`;
  const date = new Date(result.startedAt).toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const info = add(
    `<< /Title ${pdfString(toWinAnsi(`Watcher report: ${result.url}`))} /Producer (Watcher ${String(result.version).replace(/[^\w.-]/g, '')}) /CreationDate (D:${date}Z) >>`,
  );

  let out = '%PDF-1.4\n%âãÏÓ\n'.replace(/[\u0080-ÿ]/g, '~');
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return out;
}

/**
 * Build a PDF report. Returns the file as an ASCII string (safe to wrap in a Blob).
 * @param {object} result  scan result
 * @param {{raw?: boolean}} [opts]
 */
export function buildPdf(result, { raw = false } = {}) {
  const { SEVERITIES, SEVERITY_LABELS } = cfg();
  const groups = common().groupFindings(result.findings);
  const doc = new Doc();
  header(doc, result, raw);
  summary(doc, groups);

  for (const sev of SEVERITIES) {
    const bucket = groups.filter((g) => g.severity === sev);
    if (!bucket.length) continue;
    doc.ensure(90);
    doc.y += 14;
    doc.text(
      toWinAnsi(`${SEVERITY_LABELS[sev]} (${bucket.length})`),
      MARGIN,
      doc.y + 14,
      FONTS.bold,
      15,
      COLORS[sev],
    );
    doc.y += 24;
    doc.rect(MARGIN, doc.y, CONTENT_W, 1.2, COLORS[sev]);
    doc.y += 12;
    for (const g of bucket) findingBlock(doc, g, raw);
  }

  if (result.skipped.length) {
    doc.ensure(60);
    doc.y += 10;
    doc.text(
      toWinAnsi(`Skipped sources (${result.skipped.length})`),
      MARGIN,
      doc.y + 12,
      FONTS.bold,
      13,
      COLORS.ink,
    );
    doc.y += 22;
    for (const s of result.skipped) doc.para(`• ${s.label}: ${s.reason}`, { size: 8.5, color: COLORS.dim });
  }

  footers(doc, result);
  return serialise(doc, result);
}
