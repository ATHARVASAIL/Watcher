#!/usr/bin/env node
/** Print the CHANGELOG section for a tag (e.g. v0.2.0) as release notes. */
import { readFileSync } from 'node:fs';

const tag = (process.argv[2] || '').replace(/^v/, '');
const changelog = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
const start = changelog.search(new RegExp(`^## \\[${tag.replace(/\./g, '\\.')}\\]`, 'm'));
if (!tag || start === -1) {
  console.error(`No CHANGELOG entry for ${tag || '(missing tag)'}`);
  process.exit(1);
}
const rest = changelog.slice(start);
const next = rest.slice(1).search(/^## \[/m);
const section = (next === -1 ? rest : rest.slice(0, next + 1)).trim();

console.log(section.split('\n').slice(1).join('\n').trim());
console.log('\n---\n');
console.log('**Install:** download the zip, unzip it, open `chrome://extensions`, enable Developer mode,');
console.log(
  'choose **Load unpacked** and select the unzipped folder. Verify the download with the `.sha256` file',
);
console.log('and the build provenance attestation (`gh attestation verify <zip> --repo <owner>/<repo>`).');
