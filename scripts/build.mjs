#!/usr/bin/env node
/**
 * Package extension/ into dist/watcher-v<version>.zip for the
 * Chrome Web Store / GitHub release. Refuses to build if the manifest policy fails.
 * The archive is reproducible (sorted entries, fixed timestamps); its SHA-256 is printed
 * and written next to it.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createZip } from './lib/zip.mjs';
import { checkManifest, readManifest, EXTENSION, ROOT } from './lib/manifest-policy.mjs';

const problems = checkManifest();
if (problems.length) {
  console.error(
    `Refusing to build — manifest policy violations:\n${problems.map((p) => `  ✗ ${p}`).join('\n')}`,
  );
  process.exit(1);
}

const extDir = fileURLToPath(EXTENSION);
const entries = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name.startsWith('.')) continue; // no dotfiles (e.g. .DS_Store) in the package
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else entries.push({ name: relative(extDir, path).split(sep).join('/'), data: readFileSync(path) });
  }
})(extDir);

const epoch = Number(process.env.SOURCE_DATE_EPOCH);
const zip = createZip(entries, Number.isFinite(epoch) && epoch > 0 ? new Date(epoch * 1000) : undefined);
const { version } = readManifest();
const outDir = fileURLToPath(new URL('dist/', ROOT));
mkdirSync(outDir, { recursive: true });
const file = `watcher-v${version}.zip`;
writeFileSync(join(outDir, file), zip);
const sha = createHash('sha256').update(zip).digest('hex');
writeFileSync(join(outDir, `${file}.sha256`), `${sha}  ${file}\n`);
console.log(
  `✓ dist/${file}  (${entries.length} files, ${(zip.length / 1024).toFixed(1)} KB)\n  sha256 ${sha}`,
);
