# Security policy

This project is a security tool, so its own security matters. Thank you for helping keep it safe.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository
(`/security/advisories/new`). Include steps to reproduce and, if possible, a minimal page that
triggers the problem. Use fake credentials in any samples.

You can expect an acknowledgement within 7 days. Fixes are released as a new version with a
GitHub Security Advisory crediting the reporter (unless you prefer otherwise).

## What counts as a vulnerability

In scope:

- Script execution or HTML injection in the popup or any extension page (the popup renders
  attacker-controlled page content by design, so this is the primary attack surface).
- Any path by which scan data leaves the browser, or by which the extension makes requests to
  origins other than the scanned page's own origin (third-party fetching is opt-in).
- The scanned page being able to read, alter or forge scan results, or to trigger scans.
- The extension modifying the scanned page (DOM, storage, cookies) or its behaviour.
- Secrets persisted to disk (results are memory-only; triage state is salted hashes).
- Permission or manifest weakening, supply-chain issues in the build/release pipeline.

Out of scope (please open a normal issue instead):

- A secret format the scanner misses, or a false positive.
- Findings on sites you don't own. Only scan applications you are authorised to test.

## Design safeguards

See [docs/architecture.md](docs/architecture.md#threat-model) for the threat model and the
controls that enforce it (strict extension CSP with Trusted Types, isolated-world scanning,
DOM built only via `textContent`, manifest policy checks in CI).
