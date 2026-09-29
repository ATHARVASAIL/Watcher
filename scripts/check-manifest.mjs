#!/usr/bin/env node
/** Fails CI if the manifest drifts from the extension's security policy. */
import { checkManifest } from './lib/manifest-policy.mjs';

const problems = checkManifest();
if (problems.length) {
  console.error(`Manifest policy violations:\n${problems.map((p) => `  ✗ ${p}`).join('\n')}`);
  process.exit(1);
}
console.log('✓ manifest: MV3, minimal permissions, strict CSP, all referenced files present');
