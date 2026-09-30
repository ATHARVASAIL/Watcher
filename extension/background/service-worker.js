/**
 * Watcher — service worker (orchestrator).
 *
 *  - Injects the scanner when the popup asks, so a scan survives the popup closing.
 *  - Relays stop requests to the running scan.
 *  - Stores progress and results in chrome.storage.session (memory only,
 *    cleared when the browser closes) and purges them when the tab closes.
 *  - Shows a per-tab badge with the number of open (non-accepted) findings.
 *  - Never makes network requests: the extension CSP sets connect-src 'none'.
 */
// Static module imports rather than importScripts(): the extension CSP enforces Trusted
// Types, and importScripts() is a Trusted Types sink. These files attach to globalThis.__WATCHER.
import '../shared/common.js';
import '../shared/triage.js';
// DOM-free rule + engine modules, so the worker can scan cookie and network data itself.
import '../scanner/lib/helpers.js';
import '../scanner/rules/vendor.js';
import '../scanner/rules/vendor-extra.js';
import '../scanner/rules/generic.js';
import '../scanner/rules/infrastructure.js';
import '../scanner/rules/debug.js';
import '../scanner/engine.js';

const { MSG, STORAGE, SCANNER_FILES, LIMITS, PROGRESS_WRITE_EVERY_MS, BADGE_COLORS } = self.__WATCHER.config;
const { groupFindings } = self.__WATCHER.common;
const { annotateGroups } = self.__WATCHER.triage;
const engine = self.__WATCHER.engine;

/** Minimal scan env for worker-side passes (no page, so no host-relative classification). */
function workerEnv(url) {
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    /* keep empty */
  }
  let seq = 0;
  return { pageHost: host, pageIsNonProd: false, nextId: () => `sw-${++seq}`, signal: { aborted: false } };
}

// Options for the scan currently running on each tab (so the result handler knows what to augment).
const activeOptions = new Map();
// Active network-capture sessions, keyed by tabId.
const captures = new Map();

const hasPermission = (query) => chrome.permissions.contains(query).catch(() => false);

const POPUP_URL_PREFIX = chrome.runtime.getURL('popup/');
const EXTENSION_ORIGIN = chrome.runtime.getURL('');
const keyFor = (tabId) => `${STORAGE.scanPrefix}${tabId}`;

// Results may contain secrets: only extension pages may read session storage.
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => {});

/* ------------------------------------------------------------ storage (serialised) */

// Serialise all read-modify-writes so a late progress update can never overwrite a result.
let queue = Promise.resolve();
const enqueue = (fn) => (queue = queue.then(fn, fn).catch(() => {}));

async function getRecord(tabId) {
  const key = keyFor(tabId);
  return (await chrome.storage.session.get(key))[key] || null;
}

/* ------------------------------------------------------------ badge */

async function setBadge(tabId, text, color) {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (color) await chrome.action.setBadgeBackgroundColor({ tabId, color });
    if (text && chrome.action.setBadgeTextColor)
      await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
  } catch {
    /* tab closed */
  }
}

async function updateBadge(tabId) {
  const record = await getRecord(tabId);
  if (!record) return setBadge(tabId, '', null);
  if (record.state === 'running') return setBadge(tabId, '…', BADGE_COLORS.running);
  if (record.state !== 'done' || !record.result) return setBadge(tabId, '', null);

  const groups = groupFindings(record.result.findings).filter((g) => g.severity !== 'info');
  const accepted = await annotateGroups(record.result.origin, groups);
  const open = groups.filter((g) => !accepted.has(g.fp));
  if (!open.length) return setBadge(tabId, '✓', BADGE_COLORS.clean);
  return setBadge(tabId, open.length > 99 ? '99+' : String(open.length), BADGE_COLORS[open[0].severity]);
}

/* ------------------------------------------------------------ scan lifecycle */

function friendlyError(e) {
  const msg = String((e && e.message) || e);
  if (/Cannot access a chrome|cannot be scripted|extensions gallery/i.test(msg)) {
    return 'Browser-internal pages and the Web Store cannot be scanned.';
  }
  if (/Cannot access contents of url "file/i.test(msg) || /file:\/\//i.test(msg)) {
    return 'To scan local files, enable "Allow access to file URLs" for this extension in chrome://extensions.';
  }
  if (/Cannot access contents of the page|must request permission/i.test(msg)) {
    return 'No access to this page. Click the extension icon while the page you want to scan is active, then press Scan.';
  }
  if (/No tab with id|Frame with ID 0 was removed|The tab was closed/i.test(msg)) {
    return 'The tab was closed or navigated before the scan could start.';
  }
  return msg.slice(0, 300);
}

function saveFinal(tabId, scanId, record) {
  return enqueue(async () => {
    const key = keyFor(tabId);
    const current = await getRecord(tabId);
    if (current && current.scanId !== scanId) return; // a newer scan replaced this one
    try {
      await chrome.storage.session.set({ [key]: record });
    } catch (e) {
      // Session storage quota is ~10 MB. Retry without context snippets before giving up.
      if (!record.result) throw e;
      const slim = {
        ...record,
        result: {
          ...record.result,
          findings: record.result.findings.slice(0, 1000).map((f) => ({ ...f, context: null })),
          stats: { ...record.result.stats, findingsTruncated: true },
        },
      };
      await chrome.storage.session.set({ [key]: slim }).catch(() =>
        chrome.storage.session.set({
          [key]: {
            state: 'error',
            scanId,
            error: `Could not store results: ${e.message}`,
            finishedAt: Date.now(),
          },
        }),
      );
    }
    await updateBadge(tabId);
  });
}

async function startScan(tabId, options) {
  const scanId = crypto.randomUUID();
  const now = Date.now();
  activeOptions.set(tabId, options);
  await enqueue(async () => {
    await chrome.storage.session.set({
      [keyFor(tabId)]: { state: 'running', scanId, startedAt: now, lastProgressAt: now, done: 0, total: 0 },
    });
    await updateBadge(tabId);
  });
  // Network capture (optional) records API responses while the page runs, so start it first.
  if (options.networkCapture && (await hasPermission({ permissions: ['debugger'] }))) {
    startCapture(tabId, scanId, options).catch(() => {});
  }
  try {
    // 1) Load the scanner into the page's isolated world (idempotent).
    await chrome.scripting.executeScript({ target: { tabId }, world: 'ISOLATED', files: SCANNER_FILES });
    // 2) Kick it off. It returns immediately and reports back by message.
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'ISOLATED',
      func: (opts, id) => globalThis.__WATCHER.start(opts, id),
      args: [options, scanId],
    });
    const res = injection && injection.result;
    if (!res || !res.ok) throw new Error((res && res.error) || 'The scanner did not start.');
  } catch (e) {
    await saveFinal(tabId, scanId, {
      state: 'error',
      scanId,
      error: friendlyError(e),
      finishedAt: Date.now(),
    });
  }
}

async function cancelScan(tabId) {
  const cap = captures.get(tabId);
  if (cap && cap.active) return stopCapture(tabId, 'cancelled'); // ends capture and finalises the held result
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      world: 'ISOLATED',
      func: () => globalThis.__WATCHER?.cancel?.(),
    });
  } catch {
    /* page gone: the stale-record logic in the popup takes over */
  }
}

/* ------------------------------------------------------------ full access: HttpOnly cookies */

/** Scan every cookie for the tab's URL, including HttpOnly ones the page cannot read. */
async function collectCookieFindings(url) {
  if (!chrome.cookies || !(await hasPermission({ permissions: ['cookies'] }))) return [];
  let cookies;
  try {
    cookies = await chrome.cookies.getAll({ url });
  } catch {
    return [];
  }
  const env = workerEnv(url);
  const out = [];
  for (const c of cookies) {
    const flags = [c.httpOnly ? 'HttpOnly' : null, c.secure ? 'Secure' : null].filter(Boolean).join(', ');
    const source = { type: 'cookie-store', label: `cookie ${c.name}${flags ? ` (${flags})` : ''}`, url };
    try {
      out.push(...(await engine.scanText(`${c.name}=${c.value}`, source, env)));
    } catch {
      /* skip one bad cookie */
    }
    if (out.length >= LIMITS.maxFindings) break;
  }
  return out;
}

/* ------------------------------------------------------------ network capture (chrome.debugger) */

const CAPTURE_TYPES = /Document|XHR|Fetch|Script|Manifest/i;
const CAPTURE_MIME = /json|javascript|ecmascript|text|html|xml/i;

async function startCapture(tabId, scanId, options) {
  const target = { tabId };
  const session = { active: true, target, scanId, options, byId: new Map(), bodies: [], pageResult: null };
  captures.set(tabId, session);
  try {
    await chrome.debugger.attach(target, '1.3');
    await chrome.debugger.sendCommand(target, 'Network.enable');
  } catch {
    session.active = false;
    captures.delete(tabId);
    return;
  }
  session.timer = setTimeout(() => stopCapture(tabId, 'timeout').catch(() => {}), LIMITS.networkCaptureMs);
  // Reflect the capture state so the popup can show "capturing… press Stop".
  enqueue(async () => {
    const current = await getRecord(tabId);
    if (current && current.state === 'running' && current.scanId === scanId) {
      await chrome.storage.session.set({
        [keyFor(tabId)]: { ...current, capturing: true, lastProgressAt: Date.now() },
      });
    }
  });
}

chrome.debugger?.onEvent?.addListener((source, method, params) => {
  const s = captures.get(source.tabId);
  if (!s || !s.active) return;
  if (method === 'Network.responseReceived') {
    const { requestId, response, type } = params;
    if (CAPTURE_TYPES.test(type || '') && response) {
      s.byId.set(requestId, { url: response.url || '', mime: response.mimeType || '' });
    }
  } else if (method === 'Network.loadingFinished') {
    const meta = s.byId.get(params.requestId);
    if (!meta) return;
    s.byId.delete(params.requestId);
    if (s.bodies.length >= LIMITS.maxCaptureBodies) return;
    if (!CAPTURE_MIME.test(meta.mime) && !/\.(?:js|mjs|cjs|json|txt|css|map)$/i.test(meta.url)) return;
    chrome.debugger
      .sendCommand(s.target, 'Network.getResponseBody', { requestId: params.requestId })
      .then((r) => {
        if (!r || !r.body || !s.active) return;
        let body = r.body;
        if (r.base64Encoded) {
          try {
            body = atob(body);
          } catch {
            return;
          }
        }
        s.bodies.push({ url: meta.url, mime: meta.mime, text: body.slice(0, LIMITS.maxCaptureBodyBytes) });
      })
      .catch(() => {});
  }
});

// If the user (or Chrome) detaches the debugger, end the session cleanly.
chrome.debugger?.onDetach?.addListener((source) => {
  const s = captures.get(source.tabId);
  if (s && s.active) stopCapture(source.tabId, 'detached').catch(() => {});
});

async function stopCapture(tabId, reason) {
  const s = captures.get(tabId);
  if (!s) return;
  s.active = false;
  clearTimeout(s.timer);
  captures.delete(tabId);
  if (reason !== 'detached') {
    try {
      await chrome.debugger.detach(s.target);
    } catch {
      /* already gone */
    }
  }

  const findings = [];
  for (const b of s.bodies) {
    let label = 'network response';
    try {
      const u = new URL(b.url);
      label = `network: ${u.host}${u.pathname}`.slice(0, 100);
    } catch {
      /* keep default */
    }
    try {
      findings.push(
        ...(await engine.scanText(b.text, { type: 'network', label, url: b.url }, workerEnv(b.url))),
      );
    } catch {
      /* skip one body */
    }
    if (findings.length >= LIMITS.maxFindings) break;
  }

  const result = s.pageResult;
  if (!result) return; // page scan never completed; nothing to finalise
  result.findings.push(...findings.slice(0, Math.max(0, LIMITS.maxFindings - result.findings.length)));
  result.sources.push({
    type: 'network',
    label: `Captured network (${s.bodies.length} response${s.bodies.length === 1 ? '' : 's'})`,
    url: result.url,
    bytes: 0,
    findings: findings.length,
  });
  result.stats = { ...result.stats, networkCaptured: s.bodies.length };
  await saveFinal(tabId, s.scanId, { state: 'done', scanId: s.scanId, finishedAt: Date.now(), result });
}

/* ------------------------------------------------------------ result handling */

async function handleResult(tabId, scanId, result) {
  const opts = activeOptions.get(tabId) || {};
  if (opts.fullAccess) {
    try {
      const extra = await collectCookieFindings(result.url);
      if (extra.length) {
        result.findings.push(...extra.slice(0, Math.max(0, LIMITS.maxFindings - result.findings.length)));
        result.sources.push({
          type: 'cookie-store',
          label: 'HttpOnly cookies (browser cookie store)',
          url: result.url,
          bytes: 0,
          findings: extra.length,
        });
      }
    } catch {
      /* cookies unavailable */
    }
  }
  const cap = captures.get(tabId);
  if (cap && cap.active) {
    cap.pageResult = result; // hold; stopCapture will merge and finalise
    return;
  }
  activeOptions.delete(tabId);
  await saveFinal(tabId, scanId, { state: 'done', scanId, finishedAt: Date.now(), result });
}

const lastProgressWrite = new Map();

function saveProgress(tabId, msg) {
  const now = Date.now();
  if (now - (lastProgressWrite.get(tabId) || 0) < PROGRESS_WRITE_EVERY_MS) return;
  lastProgressWrite.set(tabId, now);
  enqueue(async () => {
    const current = await getRecord(tabId);
    if (!current || current.state !== 'running' || current.scanId !== msg.scanId) return;
    await chrome.storage.session.set({
      [keyFor(tabId)]: {
        ...current,
        lastProgressAt: now,
        done: Number(msg.done) || 0,
        total: Number(msg.total) || 0,
        current: String(msg.current || '').slice(0, 120),
      },
    });
  });
}

/* ------------------------------------------------------------ messaging */

const isFromPopup = (sender) => (sender.url || '').startsWith(POPUP_URL_PREFIX);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg || typeof msg !== 'object') return undefined;

  // Commands from our popup (a content script's sender.url is the web page, so it can't pass this check).
  if (
    msg.type === MSG.START ||
    msg.type === MSG.CANCEL ||
    msg.type === MSG.CAPTURE_STOP ||
    msg.type === MSG.REFRESH_BADGE
  ) {
    if (!isFromPopup(sender) || !Number.isInteger(msg.tabId)) return undefined;
    const task =
      msg.type === MSG.START
        ? startScan(msg.tabId, msg.options && typeof msg.options === 'object' ? msg.options : {})
        : msg.type === MSG.CANCEL
          ? cancelScan(msg.tabId)
          : msg.type === MSG.CAPTURE_STOP
            ? stopCapture(msg.tabId, 'stopped')
            : enqueue(() => updateBadge(msg.tabId));
    task.finally(() => sendResponse({ ok: true }));
    return true; // keep the channel open for the async response
  }

  // Reports from our scanner, running in a tab's top frame.
  if (!sender.tab || sender.frameId !== 0 || typeof msg.scanId !== 'string') return undefined;
  if ((sender.url || '').startsWith(EXTENSION_ORIGIN)) return undefined;
  const tabId = sender.tab.id;

  if (msg.type === MSG.PROGRESS) {
    saveProgress(tabId, msg);
  } else if (msg.type === MSG.RESULT && msg.result && Array.isArray(msg.result.findings)) {
    handleResult(tabId, msg.scanId, msg.result);
  } else if (msg.type === MSG.ERROR) {
    saveFinal(tabId, msg.scanId, {
      state: 'error',
      scanId: msg.scanId,
      error: String(msg.error || 'Unknown scanner error').slice(0, 500),
      finishedAt: Date.now(),
    });
  }
  return undefined;
});

// Results can contain secrets: drop them as soon as the tab is gone.
chrome.tabs.onRemoved.addListener((tabId) => {
  lastProgressWrite.delete(tabId);
  activeOptions.delete(tabId);
  const cap = captures.get(tabId);
  if (cap && cap.active) stopCapture(tabId, 'detached').catch(() => {});
  enqueue(() => chrome.storage.session.remove(keyFor(tabId)));
});
