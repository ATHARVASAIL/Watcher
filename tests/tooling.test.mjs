/**
 * Tooling tests: manifest security policy and reproducible packaging.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { inflateRawSync } from 'node:zlib';
import { createZip } from '../scripts/lib/zip.mjs';
import { checkManifest, readManifest } from '../scripts/lib/manifest-policy.mjs';

describe('manifest policy', () => {
  it('the shipped manifest passes', () => {
    assert.deepEqual(checkManifest(), []);
  });

  it('rejects host permissions, content scripts and a weakened CSP', () => {
    const m = readManifest();
    const bad = {
      ...m,
      permissions: [...m.permissions, 'tabs'],
      host_permissions: ['<all_urls>'],
      content_scripts: [{ matches: ['<all_urls>'], js: ['x.js'] }],
      content_security_policy: { extension_pages: "script-src 'self' 'unsafe-eval'; object-src 'self'" },
    };
    const problems = checkManifest(bad).join('\n');
    assert.match(problems, /permissions must be exactly/);
    assert.match(problems, /"host_permissions" is not allowed/);
    assert.match(problems, /"content_scripts" is not allowed/);
    assert.match(problems, /CSP missing: connect-src 'none'/);
    assert.match(problems, /unsafe-/);
  });
});

describe('zip writer', () => {
  const entries = [
    { name: 'b/two.txt', data: Buffer.from('two '.repeat(100)) },
    { name: 'one.txt', data: Buffer.from('1') },
  ];

  it('is reproducible', () => {
    assert.ok(createZip(entries).equals(createZip([...entries].reverse())));
  });

  it('round-trips content', () => {
    const zip = createZip(entries);
    // Walk local file headers.
    let offset = 0;
    const out = {};
    while (zip.readUInt32LE(offset) === 0x04034b50) {
      const method = zip.readUInt16LE(offset + 8);
      const size = zip.readUInt32LE(offset + 18);
      const nameLen = zip.readUInt16LE(offset + 26);
      const name = zip.toString('utf8', offset + 30, offset + 30 + nameLen);
      const body = zip.subarray(offset + 30 + nameLen, offset + 30 + nameLen + size);
      out[name] = (method === 8 ? inflateRawSync(body) : body).toString();
      offset += 30 + nameLen + size;
    }
    assert.equal(out['one.txt'], '1');
    assert.equal(out['b/two.txt'], 'two '.repeat(100));
  });

  it('refuses path traversal', () => {
    assert.throws(() => createZip([{ name: '../evil.js', data: Buffer.from('') }]), /unsafe zip path/);
    assert.throws(() => createZip([{ name: '/abs.js', data: Buffer.from('') }]), /unsafe zip path/);
  });
});
