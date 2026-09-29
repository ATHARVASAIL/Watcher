/**
 * Load the extension's pure scanner modules (config, helpers, rules, engine) into
 * this Node process, exactly as Chrome injects them into a page's isolated world.
 */
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const EXTENSION = new URL('../../extension/', import.meta.url);
const DOM_DEPENDENT = new Set(['scanner/sources.js', 'scanner/scan.js']);

const run = (file) => vm.runInThisContext(readFileSync(new URL(file, EXTENSION), 'utf8'), { filename: file });

export function loadScanner() {
  if (globalThis.__WATCHER?.engine) return globalThis.__WATCHER;
  run('shared/common.js');
  for (const file of globalThis.__WATCHER.config.SCANNER_FILES) {
    if (file !== 'shared/common.js' && !DOM_DEPENDENT.has(file)) run(file);
  }
  return globalThis.__WATCHER;
}

/** Load only the shared config/helpers used by popup modules. */
export function loadShared() {
  if (!globalThis.__WATCHER?.config) run('shared/common.js');
  return globalThis.__WATCHER;
}

let seq = 0;
export const testEnv = (overrides = {}) => ({
  pageHost: 'app.acme.io',
  pageIsNonProd: false,
  nextId: () => `t-${++seq}`,
  ...overrides,
});
