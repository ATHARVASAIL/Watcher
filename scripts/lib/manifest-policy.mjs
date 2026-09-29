/**
 * Security policy for the extension manifest. Used by check-manifest.mjs, the build
 * and the tests so a risky manifest change can never ship silently.
 */
import { existsSync, readFileSync } from 'node:fs';
import vm from 'node:vm';

export const ROOT = new URL('../../', import.meta.url);
export const EXTENSION = new URL('extension/', ROOT);

const ALLOWED_PERMISSIONS = ['activeTab', 'scripting', 'storage'];
const FORBIDDEN_KEYS = [
  'host_permissions',
  'optional_host_permissions',
  'optional_permissions',
  'content_scripts',
  'web_accessible_resources',
  'externally_connectable',
  'update_url',
];
const REQUIRED_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
];

export function readManifest() {
  return JSON.parse(readFileSync(new URL('manifest.json', EXTENSION), 'utf8'));
}

/** Scanner file list straight from shared/common.js (single source of truth). */
export function scannerFiles() {
  const sandbox = {};
  sandbox.globalThis = sandbox;
  vm.runInNewContext(readFileSync(new URL('shared/common.js', EXTENSION), 'utf8'), sandbox);
  return [...sandbox.__WATCHER.config.SCANNER_FILES];
}

/** @returns {string[]} list of problems (empty when the manifest is acceptable) */
export function checkManifest(manifest = readManifest()) {
  const problems = [];
  const pkg = JSON.parse(readFileSync(new URL('package.json', ROOT), 'utf8'));

  if (manifest.manifest_version !== 3) problems.push('manifest_version must be 3');
  if (!/^\d+\.\d+\.\d+$/.test(manifest.version)) problems.push('version must be MAJOR.MINOR.PATCH');
  if (manifest.version !== pkg.version)
    problems.push(`version ${manifest.version} != package.json ${pkg.version}`);
  if ((manifest.description || '').length > 132)
    problems.push('description exceeds the 132-character store limit');

  const perms = [...(manifest.permissions || [])].sort();
  if (JSON.stringify(perms) !== JSON.stringify([...ALLOWED_PERMISSIONS].sort())) {
    problems.push(`permissions must be exactly ${ALLOWED_PERMISSIONS.join(', ')} (got ${perms.join(', ')})`);
  }
  for (const key of FORBIDDEN_KEYS) if (key in manifest) problems.push(`"${key}" is not allowed`);

  const csp = manifest.content_security_policy?.extension_pages || '';
  for (const directive of REQUIRED_CSP)
    if (!csp.includes(directive)) problems.push(`CSP missing: ${directive}`);
  if (/unsafe-|https?:|\*/.test(csp))
    problems.push('CSP must not contain unsafe-*, remote origins or wildcards');

  const files = [
    manifest.background?.service_worker,
    manifest.action?.default_popup,
    ...Object.values(manifest.icons || {}),
    ...Object.values(manifest.action?.default_icon || {}),
    ...scannerFiles(),
    'shared/triage.js',
  ].filter(Boolean);
  for (const file of new Set(files)) {
    if (!existsSync(new URL(file, EXTENSION))) problems.push(`missing file: ${file}`);
  }
  return problems;
}
