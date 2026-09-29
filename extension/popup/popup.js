/**
 * Popup controller: owns UI state, talks to the service worker, renders results.
 */
import { h, clear } from './dom.js';
import { renderSummary, renderCard } from './render.js';
import { buildJsonReport, buildSarif, buildMarkdown } from './export.js';

const { SEVERITIES, DEFAULT_OPTIONS, POPUP_ONLY_OPTIONS, MSG, STORAGE, STALE_AFTER_MS } =
  globalThis.__WATCHER.config;
const { groupFindings } = globalThis.__WATCHER.common;
const triage = globalThis.__WATCHER.triage;

const RESTRICTED_URL =
  /^(?:chrome|edge|brave|opera|vivaldi|about|chrome-extension|devtools|view-source|chrome-search):|^https:\/\/(?:chromewebstore\.google\.com|chrome\.google\.com\/webstore)/i;

const $ = (id) => document.getElementById(id);
const ui = {
  target: $('target'),
  version: $('version'),
  scanBtn: $('scanBtn'),
  exportBtn: $('exportBtn'),
  exportMenu: $('exportMenu'),
  clearBtn: $('clearBtn'),
  status: $('status'),
  progress: $('progress'),
  intro: $('intro'),
  scanning: $('scanning'),
  scanCount: $('scanCount'),
  scanCurrent: $('scanCurrent'),
  allClear: $('allClear'),
  summary: $('summary'),
  results: $('results'),
  optionInputs: [...document.querySelectorAll('input[data-opt]')],
};

const state = {
  tab: null,
  record: null, // { state: 'running' | 'done' | 'error', scanId, startedAt, result?, error? }
  options: { ...DEFAULT_OPTIONS, ...POPUP_ONLY_OPTIONS },
  filters: new Set(SEVERITIES),
  query: '',
  showAccepted: false,
  revealed: new Set(), // group fingerprints revealed in this popup session
  groups: [],
  accepted: new Map(), // fingerprint → accepted-at
  renderedScanId: null,
  countedScanId: null, // scan whose severity counts have already animated in
};

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

const storageKey = () => `${STORAGE.scanPrefix}${state.tab.id}`;
const stripHash = (url) => url.split('#')[0];
const isRunning = (rec) =>
  Boolean(rec) &&
  rec.state === 'running' &&
  Date.now() - (rec.lastProgressAt || rec.startedAt) < STALE_AFTER_MS;

/* ------------------------------------------------------------ options */

async function loadOptions() {
  const stored = (await chrome.storage.local.get(STORAGE.options))[STORAGE.options] || {};
  for (const [key, def] of Object.entries(state.options)) {
    if (typeof stored[key] === typeof def) state.options[key] = stored[key];
  }
  for (const input of ui.optionInputs) input.checked = Boolean(state.options[input.dataset.opt]);
}

function wireOptions() {
  for (const input of ui.optionInputs) {
    input.addEventListener('change', () => {
      state.options[input.dataset.opt] = input.checked;
      chrome.storage.local.set({ [STORAGE.options]: state.options }); // preferences only, never findings
    });
  }
}

/* ------------------------------------------------------------ commands to the service worker */

async function sendCommand(type, extra = {}) {
  try {
    await chrome.runtime.sendMessage({ type, tabId: state.tab.id, ...extra });
  } catch (e) {
    setStatus(`Could not reach the extension background: ${e.message}`, 'error');
  }
}

function onScanButton() {
  if (isRunning(state.record)) {
    ui.scanBtn.disabled = true;
    sendCommand(MSG.CANCEL);
    return;
  }
  state.revealed.clear();
  ui.scanBtn.disabled = true;
  const scannerOptions = Object.fromEntries(Object.keys(DEFAULT_OPTIONS).map((k) => [k, state.options[k]]));
  sendCommand(MSG.START, { options: scannerOptions }); // exportRaw never leaves the popup
}

async function clearResults() {
  state.revealed.clear();
  await chrome.storage.session.remove(storageKey());
  sendCommand(MSG.REFRESH_BADGE);
}

/* ------------------------------------------------------------ export */

function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = h('a');
  link.href = url; // blob: URL created above, not page-controlled
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function exportAs(format) {
  const result = state.record?.result;
  if (!result) return;
  const raw = state.options.exportRaw;
  let host = 'page';
  try {
    host = new URL(result.url).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    /* keep default */
  }
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const base = `watcher-report_${host}_${stamp}`;

  if (format === 'json') {
    download(`${base}.json`, JSON.stringify(buildJsonReport(result, { raw }), null, 2), 'application/json');
  } else if (format === 'sarif') {
    download(
      `${base}.sarif`,
      JSON.stringify(await buildSarif(result, { raw }), null, 2),
      'application/sarif+json',
    );
  } else if (format === 'md') {
    download(`${base}.md`, buildMarkdown(result, { raw }), 'text/markdown');
  }
}

function setMenuOpen(open) {
  ui.exportMenu.hidden = !open;
  ui.exportBtn.setAttribute('aria-expanded', String(open));
  if (open) ui.exportMenu.querySelector('button')?.focus();
}

function wireExportMenu() {
  ui.exportBtn.addEventListener('click', () => setMenuOpen(ui.exportMenu.hidden));
  ui.exportMenu.addEventListener('click', (e) => {
    const format = e.target.closest('button[data-format]')?.dataset.format;
    if (!format) return;
    setMenuOpen(false);
    exportAs(format);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !ui.exportMenu.hidden) {
      setMenuOpen(false);
      ui.exportBtn.focus();
    }
  });
  document.addEventListener('click', (e) => {
    if (!ui.exportMenu.hidden && !e.target.closest('.menu-wrap')) setMenuOpen(false);
  });
}

/* ------------------------------------------------------------ card actions */

async function copyValue(value, button) {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Failed';
  }
  setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

function toggleReveal(group) {
  if (state.revealed.has(group.fp)) state.revealed.delete(group.fp);
  else state.revealed.add(group.fp);
  const card = ui.results.querySelector(`article.card[data-group="${group.fp}"]`); // fp is hex: safe in a selector
  card?.replaceWith(buildCard(group));
}

async function toggleAccepted(group, accepted) {
  const origin = state.record.result.origin;
  await triage.setAccepted(origin, group.fp, accepted);
  state.accepted = await triage.loadAccepted(origin);
  sendCommand(MSG.REFRESH_BADGE);
  renderResultView();
}

/* ------------------------------------------------------------ rendering */

function setStatus(text, kind = '') {
  ui.status.className = `status ${kind}`;
  ui.status.textContent = text;
}

function buildCard(group) {
  return renderCard(group, {
    revealed: state.revealed.has(group.fp),
    accepted: state.accepted.has(group.fp),
    onReveal: toggleReveal,
    onCopy: copyValue,
    onAccept: toggleAccepted,
  });
}

function matchesQuery(group, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  return group.items.some((f) =>
    [f.title, f.ruleId, f.source.label, f.where, f.display, f.category]
      .filter(Boolean)
      .some((text) => String(text).toLowerCase().includes(q)),
  );
}

function renderResultsList() {
  clear(ui.results);
  ui.allClear.hidden = state.groups.length > 0;
  if (!state.groups.length) return;

  const open = state.groups.filter((g) => state.showAccepted || !state.accepted.has(g.fp));
  const visible = open.filter((g) => state.filters.has(g.severity) && matchesQuery(g, state.query));
  visible.forEach((g, i) => {
    const card = buildCard(g);
    card.style.setProperty('--i', String(Math.min(i, 10))); // staggered entrance (CSSOM, not markup)
    ui.results.append(card);
  });

  const hidden = open.length - visible.length;
  if (!visible.length) {
    ui.results.append(h('p', { class: 'empty', text: 'Nothing matches the current filters.' }));
  } else if (hidden) {
    ui.results.append(h('p', { class: 'dim small center', text: `${hidden} more hidden by filters` }));
  }
}

function countOpen() {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  let acceptedCount = 0;
  for (const g of state.groups) {
    if (state.accepted.has(g.fp)) acceptedCount++;
    else counts[g.severity]++;
  }
  return { counts, acceptedCount };
}

/** Summary + list for a finished scan. */
function renderResultView() {
  const result = state.record.result;
  const { counts, acceptedCount } = countOpen();
  const openTotal = Object.values(counts).reduce((a, b) => a + b, 0);
  const navigated = state.tab.url && result.url && stripHash(state.tab.url) !== stripHash(result.url);

  setStatus(
    `${openTotal} open finding${openTotal === 1 ? '' : 's'}${
      acceptedCount ? ` · ${acceptedCount} accepted` : ''
    } · scanned ${new Date(result.startedAt).toLocaleTimeString()}${
      navigated ? ` · results are from ${result.url}` : ''
    }`,
    navigated ? 'warn' : '',
  );

  clear(ui.summary);
  ui.summary.append(
    ...renderSummary(
      result,
      { counts, acceptedCount, filters: state.filters, query: state.query, showAccepted: state.showAccepted },
      {
        onToggleSeverity: (sev) => {
          if (state.filters.has(sev)) state.filters.delete(sev);
          else state.filters.add(sev);
          renderResultView();
        },
        onSearch: (query) => {
          state.query = query;
          renderResultsList(); // keep the search box (and its focus) intact
        },
        onToggleAccepted: (show) => {
          state.showAccepted = show;
          renderResultView();
        },
      },
    )
      .flat()
      .filter(Boolean),
  );
  if (state.countedScanId !== state.renderedScanId) {
    state.countedScanId = state.renderedScanId;
    countUp(ui.summary.querySelectorAll('.tile-count[data-count]'));
  }
  renderResultsList();
}

/** Animate severity counts from 0 (skipped when the user prefers reduced motion). */
function countUp(nodes) {
  if (reducedMotion.matches) return;
  const start = performance.now();
  const DURATION = 550;
  const targets = [...nodes].map((node) => ({ node, to: Number(node.dataset.count) || 0 }));
  const step = (now) => {
    const t = Math.min(1, (now - start) / DURATION);
    const eased = 1 - (1 - t) ** 3;
    for (const { node, to } of targets) node.textContent = String(Math.round(to * eased));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function showPanels({ intro = false, scanning = false, allClear = false } = {}) {
  ui.intro.hidden = !intro;
  ui.scanning.hidden = !scanning;
  ui.allClear.hidden = !allClear;
}

let renderToken = 0;

async function render() {
  const token = ++renderToken;
  const rec = state.record;

  // Prepare grouped results (async hashing) before touching the DOM, so controls and
  // results always change together and a newer render can supersede this one.
  if (rec?.state === 'done' && state.renderedScanId !== rec.scanId) {
    const groups = groupFindings(rec.result.findings);
    const accepted = await triage.annotateGroups(rec.result.origin, groups);
    if (token !== renderToken) return;
    state.groups = groups;
    state.accepted = accepted;
    state.renderedScanId = rec.scanId;
  }

  // No URL means Chrome gave us no access to this tab (internal page, or activeTab not granted).
  const restricted = !state.tab.url || RESTRICTED_URL.test(state.tab.url);
  const running = isRunning(rec);

  ui.scanBtn.disabled = restricted;
  ui.scanBtn.textContent = running ? 'Stop scan' : rec?.state === 'done' ? 'Rescan' : 'Scan this page';
  ui.scanBtn.classList.toggle('danger', running);
  ui.exportBtn.disabled = rec?.state !== 'done';
  if (ui.exportBtn.disabled) setMenuOpen(false);
  ui.clearBtn.disabled = !rec || running;
  document.body.dataset.state = restricted ? 'restricted' : running ? 'running' : rec?.state || 'idle';

  if (restricted) {
    showPanels();
    setStatus(
      state.tab.url
        ? 'This page cannot be scanned (browser-internal page or Web Store).'
        : 'No access to this tab. Browser-internal pages cannot be scanned; on a normal page, click the extension icon while that tab is active.',
      'warn',
    );
    clear(ui.summary);
    clear(ui.results);
    return;
  }

  if (!rec || rec.state !== 'done') {
    clear(ui.summary);
    clear(ui.results);
    state.renderedScanId = null;
    showPanels({ intro: !rec, scanning: running });
    if (!rec) setStatus('');
    else if (rec.state === 'error') setStatus(rec.error || 'Scan failed.', 'error');
    else if (running) {
      setStatus('');
      if (rec.total) {
        ui.progress.value = rec.done / rec.total;
        ui.scanCount.textContent = `Scanning ${rec.done} / ${rec.total} sources`;
      } else {
        ui.progress.removeAttribute('value'); // indeterminate until the first progress update
        ui.scanCount.textContent = 'Starting…';
      }
      ui.scanCurrent.textContent = rec.current || '';
    } else {
      setStatus(
        'The last scan did not finish (the page may have navigated or reloaded). Scan again.',
        'warn',
      );
    }
    return;
  }

  showPanels();
  renderResultView();
}

/* ------------------------------------------------------------ init */

async function init() {
  ui.version.textContent = `v${chrome.runtime.getManifest().version}`;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    setStatus('No active tab.', 'error');
    ui.scanBtn.disabled = true;
    return;
  }
  state.tab = tab;
  try {
    const url = new URL(tab.url);
    ui.target.textContent = url.protocol.startsWith('http') ? url.host + url.pathname : tab.url;
  } catch {
    ui.target.textContent = tab.url || '(no access to this tab)';
  }
  ui.target.title = tab.url || '';

  await loadOptions();
  wireOptions();
  wireExportMenu();

  state.record = (await chrome.storage.session.get(storageKey()))[storageKey()] || null;
  await render();

  ui.scanBtn.addEventListener('click', onScanButton);
  ui.clearBtn.addEventListener('click', clearResults);

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'session' || !(storageKey() in changes)) return;
    state.record = changes[storageKey()].newValue || null;
    render();
  });

  // Re-evaluate staleness while a scan is (supposedly) running.
  setInterval(() => {
    if (state.record?.state === 'running') render();
  }, 5000);
}

init().catch((e) => setStatus(`Popup error: ${e.message}`, 'error'));
