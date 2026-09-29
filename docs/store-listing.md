# Chrome Web Store listing notes

Copy-ready answers for the Developer Dashboard.

## Single purpose

Scans the frontend of a web application the user is testing (HTML, JavaScript, CSS, source
maps, Web Storage and JavaScript-readable cookies) for accidentally exposed secrets, and shows
the findings locally in the extension popup.

## Permission justifications

| Permission  | Justification                                                                                                                                                  |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `activeTab` | Grants temporary access to the tab only when the user opens the extension, so the scanner can run on that page on request. No access to any other site.        |
| `scripting` | Injects the read-only scanner into the active tab when the user presses Scan, and stops it when the user presses Stop.                                         |
| `storage`   | Keeps scan results in memory-only session storage (cleared when the tab closes), plus the user's option toggles and hashed "accepted finding" markers locally. |

Host permissions: **none**. Remote code: **none**.

## Data usage disclosures

- Collected data types: **none are collected or transmitted.** Page content is analysed
  locally in the browser and never leaves the device.
- Certify: not sold to third parties; not used or transferred for purposes unrelated to the
  single purpose; not used for creditworthiness or lending.

Privacy policy URL: link to `PRIVACY.md` on the repository's default branch.

## Suggested store description

> Watcher finds credentials that shipped to the browser by mistake: API keys
> and tokens in JavaScript bundles and inline scripts, secrets revealed by publicly reachable
> source maps, passwords in HTML and Web Storage, session cookies readable by JavaScript,
> staging/internal URLs and debug leftovers. It knows which keys are public by design (Stripe
> publishable, Supabase anon, Mapbox public, Google browser keys) and rates findings by evidence.
>
> Everything runs locally and only when you click Scan. The extension never modifies the page,
> never sends data anywhere, masks values until you reveal them, and exports JSON, SARIF (for
> GitHub code scanning) or Markdown reports. Only scan applications you own or are authorised
> to test.

## Assets

- Icon: `extension/icons/icon128.png`
- Screenshots: `docs/popup-light.png`, `docs/popup-dark.png` (the store wants 1280×800 or
  640×400; place the popup on a neutral canvas of that size).
