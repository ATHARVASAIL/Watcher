/**
 * End-to-end tests in real Chromium (Playwright). Loads the extension, scans the
 * fixture site and checks detection, read-only behaviour, popup safety and features.
 *
 *   npm run test:e2e              (needs: npx playwright install chromium)
 *   SCREENSHOT_DIR=docs npm run test:e2e   also refreshes the README screenshots
 *
 * Automation can't click the toolbar icon (which is what grants activeTab), so the
 * suite loads a temporary copy of the extension with host_permissions for the fixture
 * origin. The shipped manifest has none (enforced by scripts/check-manifest.mjs).
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { startServer } from '../test-site/serve.mjs';

const PORT = 8765;
const ORIGIN = `http://localhost:${PORT}`;
const EXTENSION_SRC = fileURLToPath(new URL('../extension', import.meta.url));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(fn, { timeout = 20_000, interval = 150, message = 'condition' } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${message}`);
    await sleep(interval);
  }
}

describe('extension end-to-end', () => {
  let server;
  let context;
  let worker;
  let extensionId;
  let workDir;
  let page;
  let tabId;
  const requests = [];

  const getRecord = (id = tabId) =>
    worker.evaluate(async (key) => (await chrome.storage.session.get(key))[key] || null, `scan:${id}`);

  async function openPopup(forTabId = tabId, colorScheme = 'light') {
    const popup = await context.newPage();
    await popup.emulateMedia({ colorScheme });
    await popup.addInitScript((id) => {
      const realQuery = chrome.tabs.query.bind(chrome.tabs);
      chrome.tabs.query = async () => (await realQuery({})).filter((t) => t.id === id);
    }, forTabId);
    popup.errors = [];
    popup.on('pageerror', (e) => popup.errors.push(String(e)));
    await popup.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    return popup;
  }

  const scanFinished = async (popup) =>
    until(
      () =>
        popup.evaluate(
          () =>
            document.querySelector('#scanBtn').textContent === 'Rescan' &&
            document.querySelector('#results').childElementCount > 0,
        ),
      {
        message: 'scan to finish',
      },
    );

  const tabIdFor = (urlPrefix) =>
    worker.evaluate(
      async (prefix) => (await chrome.tabs.query({})).find((t) => (t.url || '').startsWith(prefix))?.id,
      urlPrefix,
    );

  before(async () => {
    workDir = mkdtempSync(join(tmpdir(), 'watcher-e2e-'));
    const ext = join(workDir, 'extension');
    cpSync(EXTENSION_SRC, ext, { recursive: true });
    const manifestPath = join(ext, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.host_permissions = [`${ORIGIN}/*`];
    writeFileSync(manifestPath, JSON.stringify(manifest));

    server = await startServer({ port: PORT, quiet: true });
    context = await chromium.launchPersistentContext(join(workDir, 'profile'), {
      channel: 'chromium',
      headless: true,
      viewport: { width: 460, height: 900 },
      args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
    });
    worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
    extensionId = new URL(worker.url()).host;

    page = await context.newPage();
    await page.goto(`${ORIGIN}/`);
    await page.waitForTimeout(1200); // seeding + lazy chunk
    tabId = await tabIdFor(ORIGIN);
  });

  after(async () => {
    await context?.close();
    await server?.close();
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  });

  let result;
  let baseline;

  it('loads with the strict manifest CSP accepted', () => {
    assert.match(extensionId, /^[a-p]{32}$/);
    assert.ok(Number.isInteger(tabId));
  });

  it('keeps scanning after the popup closes and stores the result', async () => {
    await page.evaluate(() => {
      window.__mutations = 0;
      new MutationObserver((records) => {
        window.__mutations += records.length;
      }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
    });
    baseline = await page.evaluate(() => ({
      html: document.documentElement.outerHTML,
      storage: JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }),
      cookies: document.cookie,
    }));
    context.on('request', (r) => requests.push(r.url()));

    const popup = await openPopup();
    await popup.click('#scanBtn');
    await popup.close();

    const record = await until(
      async () => {
        const r = await getRecord();
        return r?.state === 'done' && r;
      },
      { message: 'result in session storage' },
    );
    result = record.result;
    assert.ok(result.findings.length > 40, `only ${result.findings.length} findings`);
  });

  it('detects every planted category', () => {
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of [
      'private-key',
      'github-token',
      'live-secret-key',
      'aws-access-key-id',
      'slack-webhook',
      'jwt',
      'db-connection-string',
      'credentials-in-url',
      'hardcoded-authorization-header',
      'prefilled-password-input',
      'secret-in-query-string',
      'generic-secret-assignment',
      'google-api-key',
      'publishable-key',
      'mapbox-token',
      'internal-url',
      'sensitive-todo-comment',
      'console-log-sensitive',
      'source-map-exposed',
      'cookie-not-httponly',
    ]) {
      assert.ok(ids.has(id), `missing ${id}`);
    }
    const titles = result.findings.map((f) => f.title);
    assert.ok(titles.includes('Supabase service_role key'));
    assert.ok(titles.includes('Supabase anon key'));
    assert.ok(titles.includes('JWT in Web Storage'));
    assert.ok(titles.includes('JWT in JavaScript-readable cookie'));
  });

  it('scans original sources from the exposed source map, skipping library code', () => {
    const fromMap = result.findings.filter(
      (f) => f.source.type === 'source-map' && f.ruleId !== 'source-map-exposed',
    );
    assert.ok(
      fromMap.some((f) => f.source.label.startsWith('src/config.ts')),
      'no findings from src/config.ts',
    );
    assert.ok(fromMap.some((f) => f.title === 'Possible hard-coded password'));
    assert.ok(!result.findings.some((f) => /node_modules/.test(f.source.label)), 'library code was scanned');
    assert.ok(!result.findings.some((f) => f.ruleId === 'source-map-reference' && f.value === 'app.js.map'));
    assert.ok(result.skipped.some((s) => /styles\.css\.map/.test(s.label) && /not reachable/.test(s.reason)));
  });

  it('avoids false positives on harmless keys, CSRF tokens and labels', () => {
    const noisy = result.findings.filter(
      (f) =>
        ['Bearer', 'Password', 'auth_token_v2', '8', 'dark'].includes(f.value) ||
        /csrf|xsrf|theme/i.test(f.where || ''),
    );
    assert.deepEqual(
      noisy.map((f) => f.where),
      [],
    );
    assert.ok(
      result.sources.some((s) => s.label === '/chunks/lazy-reports.js'),
      'lazy chunk not found',
    );
    assert.ok(
      result.skipped.some((s) => /vendor\/analytics\.js/.test(s.label)),
      'third-party file not skipped',
    );
  });

  it('is read-only and only talks to the page origin', async () => {
    const current = await page.evaluate(() => ({
      mutations: window.__mutations,
      html: document.documentElement.outerHTML,
      storage: JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }),
      cookies: document.cookie,
    }));
    assert.equal(current.mutations, 0);
    assert.equal(current.html, baseline.html);
    assert.equal(current.storage, baseline.storage);
    assert.equal(current.cookies, baseline.cookies);
    const hosts = new Set(requests.filter((u) => u.startsWith('http')).map((u) => new URL(u).host));
    assert.deepEqual([...hosts], [`localhost:${PORT}`]);
  });

  it('sets a per-tab badge with the open finding count', async () => {
    const text = await worker.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId);
    assert.match(text, /^\d+$/);
  });

  describe('popup', () => {
    let popup;

    before(async () => {
      popup = await openPopup();
      await scanFinished(popup);
    });

    after(async () => {
      if (process.env.SCREENSHOT_DIR) {
        for (const scheme of ['light', 'dark']) {
          const shot = await openPopup(tabId, scheme);
          await scanFinished(shot);
          await shot.screenshot({ path: join(process.env.SCREENSHOT_DIR, `popup-${scheme}.png`) });
          await shot.close();
        }
      }
      await popup?.close();
    });

    it('renders hostile page content as inert text', async () => {
      const dom = await popup.evaluate(() => ({
        images: document.querySelectorAll('img').length,
        scripts: document.querySelectorAll('script').length,
        handlers: [...document.querySelectorAll('*')].filter((el) =>
          [...el.attributes].some((a) => a.name.startsWith('on')),
        ).length,
        canary: document.body.textContent.includes("onerror=alert('popup-xss')"),
      }));
      assert.deepEqual(dom, { images: 0, scripts: 3, handlers: 0, canary: true }, JSON.stringify(dom));
      assert.deepEqual(popup.errors, [], popup.errors.join('\n'));
    });

    it('enforces Trusted Types and blocks network access', async () => {
      const blocked = await popup.evaluate(async (origin) => {
        let html = false;
        let net = false;
        try {
          document.createElement('div').innerHTML = '<b>x</b>';
        } catch {
          html = true;
        }
        try {
          await fetch(origin);
        } catch {
          net = true;
        }
        return { html, net };
      }, ORIGIN);
      assert.deepEqual(blocked, { html: true, net: true });
    });

    it('masks values until revealed', async () => {
      const card = popup.locator('article.card').first();
      assert.match(await card.locator('code.value').innerText(), /•/);
      await card.getByRole('button', { name: 'Reveal' }).click();
      assert.doesNotMatch(await popup.locator('article.card').first().locator('code.value').innerText(), /•/);
      await popup.locator('article.card').first().getByRole('button', { name: 'Hide' }).click();
    });

    it('filters by text', async () => {
      await popup.fill('input.search', 'github');
      const titles = await popup.locator('article.card .card-title').allInnerTexts();
      assert.deepEqual(titles, ['GitHub token']);
      await popup.fill('input.search', '');
    });

    it('exports masked JSON, SARIF and Markdown', async () => {
      const grab = async (format) => {
        await popup.click('#exportBtn');
        const [download] = await Promise.all([
          popup.waitForEvent('download'),
          popup.click(`#exportMenu button[data-format="${format}"]`),
        ]);
        return readFileSync(await download.path(), 'utf8');
      };
      const secrets = result.findings.filter((f) => f.redact && f.value.length > 12).map((f) => f.value);

      const json = await grab('json');
      assert.equal(JSON.parse(json).valuesMasked, true);
      const sarif = await grab('sarif');
      assert.equal(JSON.parse(sarif).version, '2.1.0');
      const md = await grab('md');
      assert.ok(!md.includes('<img'), 'markdown report contains raw HTML');
      for (const s of secrets) {
        const leaks = { json: json.includes(s), sarif: sarif.includes(s), md: md.includes(s) };
        assert.ok(
          !leaks.json && !leaks.sarif && !leaks.md,
          `an export leaked a raw value ${s.slice(0, 6)}… ${JSON.stringify(leaks)}`,
        );
      }
    });

    it('accepts a finding using only a salted hash', async () => {
      const cardsBefore = await popup.locator('article.card').count();
      const badgeBefore = Number(
        await worker.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId),
      );
      await popup.locator('article.card').first().getByRole('button', { name: 'Accept' }).click();
      await until(async () => (await popup.locator('article.card').count()) === cardsBefore - 1, {
        message: 'card hidden',
      });
      assert.match(await popup.locator('.accepted-toggle').innerText(), /Show accepted \(1\)/);

      const local = await worker.evaluate(() => chrome.storage.local.get(null));
      const stored = JSON.stringify(local);
      for (const f of result.findings)
        if (f.redact) assert.ok(!stored.includes(f.value), 'accepted state stores a raw value');
      const entry = local[`accepted:${ORIGIN}`];
      assert.equal(Object.keys(entry.fps).length, 1);
      assert.match(Object.keys(entry.fps)[0], /^[0-9a-f]{40}$/);

      await until(
        async () =>
          Number(await worker.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId)) ===
          badgeBefore - 1,
        { message: 'badge to drop by one' },
      );
    });
  });

  it('stops a running scan and keeps partial results', async () => {
    const slow = await context.newPage();
    await slow.goto(`${ORIGIN}/slow.html`);
    const slowTab = await tabIdFor(`${ORIGIN}/slow.html`);
    const popup = await openPopup(slowTab);
    await popup.click('#scanBtn');
    await until(() => popup.evaluate(() => document.querySelector('#scanBtn').textContent === 'Stop scan'), {
      message: 'Stop button',
    });
    const started = Date.now();
    await popup.click('#scanBtn');
    const record = await until(
      async () => {
        const r = await getRecord(slowTab);
        return r?.state === 'done' && r;
      },
      { message: 'cancelled result' },
    );
    assert.equal(record.result.stats.cancelled, true);
    assert.ok(Date.now() - started < 2_500, 'cancel did not take effect promptly');
    await popup.close();
    await slow.close();
    await until(async () => (await getRecord(slowTab)) === null, {
      message: 'results purged after the tab closed',
    });
  });

  it('refuses browser-internal pages', async () => {
    const internal = await context.newPage();
    await internal.goto('chrome://version');
    const internalTab = await worker.evaluate(
      async () => (await chrome.tabs.query({})).find((t) => !t.url)?.id,
    );
    const popup = await openPopup(internalTab);
    assert.equal(await popup.locator('#scanBtn').isDisabled(), true);
    assert.match(await popup.locator('#status').innerText(), /No access to this tab/);
    await popup.close();
    await internal.close();
  });
});
