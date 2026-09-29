# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-09-29

### Added

- **Redesigned popup**: gradient header with an animated eye, a live scanning view, severity tiles
  that count up, staggered finding cards, an all-clear state; all motion respects reduced-motion.
- **Project website** in `site/`: Calibri typography (self-hosted Carlito fallback), cursor-tracking
  hero eye, scroll-driven story, bento feature grid, magnetic buttons, strict CSP, fully responsive
  and reduced-motion aware, with a GitHub Pages workflow; release assets now include a stable
  `watcher.zip` for its download links.
- **Source-map exposure check**: referenced `.map` files are fetched (same origin); a reachable map
  is reported as confirmed exposure and its original sources are scanned (library paths skipped).
- **JS-readable cookies**: cookies visible to `document.cookie` are scanned; session-like cookies
  are reported as missing HttpOnly (CSRF double-submit cookies excluded).
- **Stop scan** with partial results.
- **Accept / reopen findings** per origin, stored as salted SHA-256 fingerprints only.
- **Exports**: SARIF 2.1.0 (GitHub code scanning) and Markdown, alongside JSON. Masked by default.
- **Per-tab badge** with the number of open findings; **text filter**; keyboard shortcut
  <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd>.
- 17 new vendor rules (55 total): Stripe webhook secrets, Mapbox (public vs secret), Sentry,
  Hugging Face, Groq, xAI, Replicate, DigitalOcean, Vault, Doppler, PyPI, Docker Hub, Atlassian,
  Linear, Postman, Grafana, Firebase FCM server keys, and more.
- Repository tooling: ESLint (incl. `no-unsanitized`), Prettier, manifest security policy gate,
  WCAG contrast gate, generated rules docs, reproducible zip build with SHA-256, CI, CodeQL,
  release workflow with build provenance attestation, Dependabot, issue forms.

### Changed

- **Renamed to Watcher** (previously "Frontend Secrets Auditor"): new eye-and-keyhole icon,
  repository `atharvasail/watcher`, release asset `watcher-vX.Y.Z.zip`, exports `watcher-report_*`.
- Codebase split into modules: `shared/`, `background/`, `scanner/lib`, `scanner/rules/*`,
  `engine`, `sources`, `scan`, and popup `dom`/`render`/`export`.
- The service worker now performs injection, so scans survive the popup closing.
- `sk_live_` / `pk_live_` rules renamed to provider-neutral titles (Stripe and Clerk share the format).
- Context snippets for storage, cookies and HTML attributes never spill into a neighbouring entry.
- Tests moved to `node:test` + Playwright for Node (Python no longer required).

### Security

- Service worker loads shared code with static ES-module imports, because `importScripts()` is a
  Trusted Types sink under the extension CSP.

## [0.1.0] - 2026-09-29

### Added

- Initial MV3 extension: on-demand, read-only scan of inline/linked JS, CSS, HTML and Web Storage;
  38 rules; masked results; JSON export; strict extension CSP with Trusted Types.

[Unreleased]: https://github.com/atharvasail/watcher/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/atharvasail/watcher/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/atharvasail/watcher/releases/tag/v0.1.0
