## What does this change?

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `npm run verify` passes locally (lint, format, policy checks, unit + e2e tests, build)
- [ ] New/changed rules have tests in `tests/rules.test.mjs` and `npm run docs:rules` was re-run
- [ ] Every repeat in new regexes that can backtrack is bounded (`{0,40}`, not `*`)
- [ ] Test data uses **fake** values, assembled at runtime where they match a real provider format
- [ ] No new permissions, host permissions, remote code or network access
- [ ] UI changes build DOM through `popup/dom.js` (no `innerHTML`) and keep AA contrast
- [ ] `CHANGELOG.md` updated under "Unreleased"
