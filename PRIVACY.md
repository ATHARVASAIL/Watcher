# Privacy policy

_Last updated: 2026-09-29_

Watcher analyses the web page you are viewing **only when you press Scan**,
and **entirely inside your browser**.

## What the extension accesses

When you start a scan on the active tab, it reads that page's HTML, inline and linked
JavaScript/CSS files and their source maps (from the page's own origin by default),
`localStorage`, `sessionStorage` and cookies visible to `document.cookie`.

## What it stores

- **Scan results** are kept in `chrome.storage.session`: in memory only, never written to disk,
  deleted when you close the tab, press Clear, or close the browser.
- **Option toggles** (which sources to scan) are kept in `chrome.storage.local`.
- **Accepted findings** are kept in `chrome.storage.local` as salted SHA-256 fingerprints.
  The secret values themselves are never stored.

## What it sends

Nothing. The extension has no servers, analytics, telemetry or remote code. Its own pages run
under a Content Security Policy with `connect-src 'none'`, so they cannot make network
requests at all. The only requests made are the scanned page's own files being re-read (normally
from the browser cache) so they can be analysed; third-party files are fetched only if you
enable that option.

Exports (PDF, JSON, SARIF, Markdown) are created locally and saved only where you choose. Values are
masked in exports unless you opt in.

## Contact

Questions: open an issue on the project's GitHub repository.
