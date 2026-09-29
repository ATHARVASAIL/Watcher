# Architecture

## Components and contexts

| Context                             | Files                                                                             | Can do                                                    |
| ----------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **Popup** (extension page)          | `popup/*.js`, `shared/common.js`, `shared/triage.js`                              | UI, options, exports, accept/reopen; no network (CSP)     |
| **Service worker** (extension page) | `background/service-worker.js` (+ shared, as ES imports)                          | Inject/stop scans, store results, badge; no network (CSP) |
| **Scanner** (page isolated world)   | `shared/common.js`, `scanner/lib`, `scanner/rules/*`, `engine`, `sources`, `scan` | Read the page, re-read its own files, analyse, report     |

The scanner is injected with `chrome.scripting.executeScript` only after the user presses Scan
(permission comes from `activeTab`). Nothing runs on pages the user doesn't scan.

## Scan flow

```
popup ── watcher:start ──▶ service worker ── executeScript(files) ──▶ tab (isolated world)
                                        executeScript(start)        │ inventory → collect → fetch own files
                                                                    │ → rules (engine) → source maps → post-passes
popup ◀── storage.onChanged ── storage.session ◀── watcher:progress / watcher:result
popup ── watcher:cancel ──▶ service worker ── executeScript(cancel) ──▶ AbortController.abort() → partial result
```

- The service worker serialises all `chrome.storage.session` read-modify-writes through one
  promise queue, so a late progress update can never overwrite a finished result, and ignores
  results whose `scanId` no longer matches.
- Progress is throttled at the source (400 ms) and at the store (500 ms). A record with no
  progress for 60 s is shown as interrupted (e.g. the page navigated).

## Scanner pipeline

1. **Inventory** (`sources.inventory`): HTML, Web Storage, cookies, inline scripts/styles, script
   and stylesheet URLs from the DOM **and** the Performance resource timeline (lazy chunks),
   deduplicated; third-party origins skipped unless enabled; file cap.
2. **Collect**: local sources are turned into text. Storage, cookies and HTML use one synthetic
   line per entry plus a `lineLabels` array, so findings point at `localStorage["key"]` or
   `<meta name="api-key"> → content` instead of a meaningless line number.
3. **Fetch** own files: `GET`, `credentials: same-origin`, `cache: force-cache`, 15 s timeout,
   per-file and total byte caps, HTML responses rejected (SPA fallbacks), cancellable.
4. **Rules** (`engine.scanText`): each rule is a bounded regex plus an optional `check()` that
   validates/reclassifies. Vendor-format hits suppress heuristic hits on the same bytes. Each
   finding carries masked and raw context; masked context hides neighbouring secrets and never
   crosses into a neighbouring storage/cookie/attribute entry.
5. **Source maps**: references and `SourceMap` headers are resolved; a reachable map becomes a
   confirmed `source-map-exposed` finding and its `sourcesContent` is scanned (library paths
   such as `node_modules/` skipped).
6. **Post-passes**: pre-filled password inputs; sensitive-named storage keys and session-like
   JS-readable cookies whose values matched no rule.

## Threat model

The scanned page is untrusted. It controls every string the extension displays (values, file
names, storage keys, comments) and may try to attack the extension or poison results.

| Threat                                             | Control                                                                                                                                                                                                         |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS in the popup via hostile page content          | DOM built only with `textContent` + attribute allowlist (`dom.js`); lint bans unsafe sinks; CSP `require-trusted-types-for 'script'` with `trusted-types 'none'` makes any HTML sink throw; `script-src 'self'` |
| Page scripts tampering with the scanner            | Scanner runs in Chrome's isolated world (separate JS globals); the page cannot patch its `RegExp`/`fetch`                                                                                                       |
| Page forging messages to the service worker        | Without `externally_connectable`, pages cannot message the extension; the SW also checks `sender.id`, `sender.frameId`, `sender.url` and message shapes                                                         |
| Scan data leaving the browser                      | Extension pages have `connect-src 'none'`; no remote code; scanner only fetches the page's own origin by default                                                                                                |
| Secrets persisting on disk                         | Results only in `storage.session` (memory), purged on tab close; triage stores salted SHA-256 fingerprints only; exports masked by default                                                                      |
| Scanner changing the page                          | Read-only by construction; e2e asserts zero DOM mutations and unchanged HTML/storage/cookies                                                                                                                    |
| ReDoS from huge minified bundles                   | All backtracking repeats bounded; engine yields between rules; perf test on a ~5 MB hostile input                                                                                                               |
| Permission creep / weakened CSP in a future change | `scripts/check-manifest.mjs` gate in CI and in `npm run build`                                                                                                                                                  |
| Supply chain                                       | Dev-only dependencies, none shipped in the extension; lockfile + `npm audit` in CI; Dependabot; reproducible zip + SHA-256 + build provenance attestation                                                       |

## Data retention

| Data                  | Where                 | Lifetime                                      |
| --------------------- | --------------------- | --------------------------------------------- |
| Scan results          | `storage.session`     | until tab close, Clear, or browser exit       |
| Option toggles        | `storage.local`       | until uninstall                               |
| Accepted fingerprints | `storage.local`       | until reopened / uninstall (max 5,000/origin) |
| Exports               | your downloads folder | your choice                                   |
