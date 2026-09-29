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

const { MSG, STORAGE, SCANNER_FILES, PROGRESS_WRITE_EVERY_MS, BADGE_COLORS } = self.__WATCHER.config;
const { groupFindings } = self.__WATCHER.common;
const { annotateGroups } = self.__WATCHER.triage;

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
  await enqueue(async () => {
    await chrome.storage.session.set({
      [keyFor(tabId)]: { state: 'running', scanId, startedAt: now, lastProgressAt: now, done: 0, total: 0 },
    });
    await updateBadge(tabId);
  });
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
  if (msg.type === MSG.START || msg.type === MSG.CANCEL || msg.type === MSG.REFRESH_BADGE) {
    if (!isFromPopup(sender) || !Number.isInteger(msg.tabId)) return undefined;
    const task =
      msg.type === MSG.START
        ? startScan(msg.tabId, msg.options && typeof msg.options === 'object' ? msg.options : {})
        : msg.type === MSG.CANCEL
          ? cancelScan(msg.tabId)
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
    saveFinal(tabId, msg.scanId, {
      state: 'done',
      scanId: msg.scanId,
      finishedAt: Date.now(),
      result: msg.result,
    });
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
  enqueue(() => chrome.storage.session.remove(keyFor(tabId)));
});
