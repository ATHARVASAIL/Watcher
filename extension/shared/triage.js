/**
 * Watcher — triage state (accepted findings).
 *
 * Classic script for extension pages only (popup + service worker). Stores a salted
 * SHA-256 fingerprint per accepted finding group, never the finding or its value.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  if (ns.triage) return;

  const { STORAGE, LIMITS } = ns.config;
  const { fingerprint } = ns.common;

  const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const acceptedKey = (origin) => `${STORAGE.acceptedPrefix}${origin}`;

  /** Per-install random salt so fingerprints cannot be matched across installs. */
  async function getSalt() {
    const stored = (await chrome.storage.local.get(STORAGE.salt))[STORAGE.salt];
    if (typeof stored === 'string' && /^[0-9a-f]{32}$/.test(stored)) return stored;
    const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
    await chrome.storage.local.set({ [STORAGE.salt]: salt });
    return salt;
  }

  /** @returns {Promise<Map<string, number>>} fingerprint → accepted-at timestamp */
  async function loadAccepted(origin) {
    const entry = (await chrome.storage.local.get(acceptedKey(origin)))[acceptedKey(origin)];
    const map = new Map();
    if (entry && entry.v === 1 && entry.fps && typeof entry.fps === 'object') {
      for (const [fp, ts] of Object.entries(entry.fps)) {
        if (/^[0-9a-f]{40}$/.test(fp) && Number.isFinite(ts)) map.set(fp, ts);
      }
    }
    return map;
  }

  async function setAccepted(origin, fp, accepted) {
    const map = await loadAccepted(origin);
    if (accepted) map.set(fp, Date.now());
    else map.delete(fp);
    // Keep the newest entries if the cap is exceeded.
    const entries = [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, LIMITS.maxAcceptedPerOrigin);
    if (entries.length) {
      await chrome.storage.local.set({ [acceptedKey(origin)]: { v: 1, fps: Object.fromEntries(entries) } });
    } else {
      await chrome.storage.local.remove(acceptedKey(origin));
    }
  }

  /** Attach `fp` to each group and return the set of accepted fingerprints for the origin. */
  async function annotateGroups(origin, groups) {
    const salt = await getSalt();
    await Promise.all(
      groups.map(async (g) => {
        g.fp = await fingerprint(salt, origin, g.key);
      }),
    );
    return loadAccepted(origin);
  }

  ns.triage = Object.freeze({ getSalt, loadAccepted, setAccepted, annotateGroups });
})();
