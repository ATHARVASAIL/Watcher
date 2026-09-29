# Contributing

Thanks for helping improve Watcher. This is a security tool, so the bar is
"correct, safe and tested" rather than "works on my machine".

## Setup

Requirements: Node.js 22.2+ (see `.nvmrc`) and Chrome/Chromium 116+.

```bash
npm ci
npx playwright install chromium   # once, for the end-to-end tests
npm run verify                    # everything CI runs
```

Load `extension/` unpacked in `chrome://extensions` (Developer mode) and use
`npm run serve` for the fixture site at <http://localhost:8765>. `npm run site` previews the project
website from `site/` at <http://localhost:4173>.

## Scripts

| Command                  | What it does                                                            |
| ------------------------ | ----------------------------------------------------------------------- |
| `npm run lint`           | ESLint, including `no-unsanitized` (blocks `innerHTML`-style sinks)     |
| `npm run format`         | Prettier (write); `format:check` in CI                                  |
| `npm test`               | Rule, export and tooling tests (`node:test`)                            |
| `npm run test:e2e`       | Loads the extension in Chromium and scans the fixture site (Playwright) |
| `npm run check:manifest` | Manifest security policy (permissions, CSP, referenced files)           |
| `npm run check:contrast` | WCAG AA contrast of the popup (light and dark) and the website          |
| `npm run docs:rules`     | Regenerates `docs/rules.md` (CI checks it is current)                   |
| `npm run fp-baseline`    | Scans `node_modules` to measure false positives on real library code    |
| `npm run build`          | Reproducible `dist/*.zip` + `.sha256`; refuses to build on policy fail  |

## Adding or changing a detection rule

Rules live in `extension/scanner/rules/` (`vendor.js`, `generic.js`, `infrastructure.js`,
`debug.js`). The engine validates every rule at load time.

```js
{
  id: 'acme-api-key',                 // kebab-case, unique
  title: 'Acme API key',
  category: 'credential',             // credential | token | infrastructure | debug | storage
  severity: 'critical',               // critical | high | medium | low | info (default)
  confidence: 'pattern',              // pattern (vendor format) | heuristic (needs review)
  re: /\bacme_(?:live|test)_[A-Za-z0-9]{32}\b/,
  note: 'What it grants and exactly how to rotate it.',
  // Optional: validate or reclassify. Return false to drop, or an object to override
  // { title, severity, category, note, value, display, redact, groupKey, start, end }.
  check: ({ value, m, text, source, env }) => (value.includes('_test_') ? { severity: 'medium' } : true),
}
```

Rules of thumb:

1. **Severity follows evidence.** Keys that are public by design (Stripe `pk_`, Mapbox `pk.`,
   Supabase `anon`, Google browser keys) are Info/Low with a note on what to verify.
2. **No ReDoS.** Any repeat that can backtrack must be bounded (`{0,40}`, never `*` or `+`
   followed by more pattern). The test suite scans a ~5 MB hostile input with a time limit.
3. **Named group `(?<secret>…)`** marks the sensitive span when the match includes context.
4. **Tests use fake values only**, and anything that matches a real provider format is
   assembled at runtime (`p('gh', 'p_') + fake(36)`) so the repository never trips GitHub push
   protection. Add a case to `tests/rules.test.mjs`, then run `npm run docs:rules`.
5. Check `npm run fp-baseline` does not get noisier.

## Security requirements for code changes

- Popup DOM is built only through `extension/popup/dom.js` (`textContent`, attribute allowlist).
  The CSP enforces Trusted Types, so `innerHTML` throws at runtime as well as failing lint.
- No new permissions, host permissions, content scripts, remote code or network access.
  `scripts/check-manifest.mjs` fails the build otherwise.
- The scanner must stay read-only on the page. The e2e suite asserts zero DOM mutations and
  unchanged HTML, storage and cookies.
- Never persist finding values to `chrome.storage.local`.

## Commits and pull requests

- Small, focused PRs with a clear description; fill in the PR checklist.
- Add an entry under **Unreleased** in `CHANGELOG.md`.
- Releases: bump `version` in both `package.json` and `extension/manifest.json`, move the
  changelog entries under the new version, tag `vX.Y.Z` and push the tag. The release workflow
  verifies, builds, attests and publishes the zip.
