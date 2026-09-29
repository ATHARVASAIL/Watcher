/**
 * Rule regression tests (node --test). Every fake credential is generated at runtime.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadScanner, testEnv } from './helpers/scanner.mjs';
import { ALNUM, HEX, UPPER32, fake, jwt, p } from './helpers/fakes.mjs';

const { engine, util } = loadScanner();
const SCRIPT = { type: 'script-file', label: 'bundle.js' };

async function scan(text, source = SCRIPT, env = testEnv()) {
  return engine.scanText(text, source, env);
}

const ids = (findings) => findings.map((f) => f.ruleId);

/** [name, text, rule ids that must fire, rule ids that must NOT fire, optional assertion] */
const CASES = [
  // ---- vendor formats
  [
    'private key',
    `const pem = "${p('-----BEGIN RSA ', 'PRIVATE KEY-----')}\\nMIIE${fake(200)}\\n${p('-----END RSA ', 'PRIVATE KEY-----')}";`,
    ['private-key'],
  ],
  ['AWS key id', `const k="${p('AK', 'IA')}${fake(16, UPPER32)}";`, ['aws-access-key-id']],
  [
    'AWS docs example key → info',
    `k="${p('AKIA', 'IOSFODNN7EXAMPLE')}"`,
    ['aws-access-key-id'],
    [],
    (f) => assert.equal(f[0].severity, 'info'),
  ],
  [
    'AWS secret key',
    `aws_secret_access_key: "${fake(40, `${ALNUM}/+`)}"`,
    ['aws-secret-access-key'],
    ['generic-secret-assignment'],
  ],
  [
    'GitHub token beats heuristic',
    `token: "${p('gh', 'p_')}${fake(36)}"`,
    ['github-token'],
    ['generic-secret-assignment'],
  ],
  ['GitLab token', `t="${p('gl', 'pat-')}${fake(20)}"`, ['gitlab-token']],
  ['npm token', `t="${p('np', 'm_')}${fake(36)}"`, ['npm-token']],
  ['PyPI token', `t="${p('pypi-', 'AgEIcHlwaS5vcmc')}${fake(70)}"`, ['pypi-token']],
  ['Docker Hub token', `t="${p('dckr', '_pat_')}${fake(27)}"`, ['docker-hub-token']],
  ['Slack token', `t="${p('xo', 'xb-')}123456789012-${fake(24)}"`, ['slack-token']],
  [
    'Slack webhook',
    `u="https://hooks.slack.com/${p('serv', 'ices')}/T0${fake(8, UPPER32)}/B0${fake(8, UPPER32)}/${fake(24)}"`,
    ['slack-webhook'],
  ],
  [
    'Discord webhook',
    `u="https://discord.com/api/webhooks/123456789012345678/${fake(68)}"`,
    ['discord-webhook'],
  ],
  ['Telegram bot token', `t="123456789:AA${fake(33)}"`, ['telegram-bot-token']],
  ['Atlassian token', `t="${p('ATATT', '3')}${fake(184)}"`, ['atlassian-api-token']],
  ['Linear key', `t="${p('lin_', 'api_')}${fake(40)}"`, ['linear-api-key']],
  ['Postman key', `t="${p('PM', 'AK-')}${fake(24, HEX)}-${fake(34, HEX)}"`, ['postman-api-key']],
  ['live secret key', `var s='${p('sk_', 'live_')}${fake(24)}'`, ['live-secret-key']],
  ['test secret key', `var s='${p('sk_', 'test_')}${fake(24)}'`, ['test-secret-key']],
  ['publishable key → info', `var s='${p('pk_', 'live_')}${fake(24)}'`, ['publishable-key']],
  ['Stripe webhook secret', `s="${p('wh', 'sec_')}${fake(32)}"`, ['stripe-webhook-secret']],
  ['Shopify token', `t="${p('shp', 'at_')}${fake(32, HEX)}"`, ['shopify-token']],
  ['Square token', `t="${p('sq0', 'atp-')}${fake(22)}"`, ['square-token']],
  ['SendGrid key', `k="${p('S', 'G.')}${fake(22)}.${fake(43)}"`, ['sendgrid-api-key']],
  ['Mailgun key', `k="${p('ke', 'y-')}${fake(32, HEX)}"`, ['mailgun-api-key']],
  ['Mailchimp key', `k="${fake(32, HEX)}-us14"`, ['mailchimp-api-key']],
  ['Twilio SID (heuristic)', `k="${p('S', 'K')}${fake(32, HEX)}"`, ['twilio-api-key']],
  ['OpenAI key', `k="${p('sk-', 'proj-')}${fake(60)}"`, ['openai-api-key']],
  ['Anthropic key', `k="${p('sk-ant-', 'api03-')}${fake(95)}"`, ['anthropic-api-key']],
  ['Groq key', `k="${p('gs', 'k_')}${fake(52)}"`, ['groq-api-key']],
  ['xAI key', `k="${p('xa', 'i-')}${fake(80)}"`, ['xai-api-key']],
  ['Replicate token', `k="${p('r', '8_')}${fake(37)}"`, ['replicate-api-token']],
  ['Hugging Face token', `k="${p('h', 'f_')}${fake(34)}"`, ['huggingface-token']],
  ['Sentry auth token', `k="${p('sntry', 's_')}${fake(80)}"`, ['sentry-auth-token']],
  ['Grafana token', `k="${p('gl', 'sa_')}${fake(32)}_${fake(8, HEX)}"`, ['grafana-token']],
  ['DigitalOcean token', `k="${p('do', 'p_v1_')}${fake(64, HEX)}"`, ['digitalocean-token']],
  ['Vault token', `k="${p('hv', 's.')}${fake(90)}"`, ['vault-token']],
  ['Doppler token', `k="${p('dp.', 'pt.')}${fake(43)}"`, ['doppler-token']],
  ['Google OAuth secret', `s="${p('GOC', 'SPX-')}${fake(28)}"`, ['google-oauth-client-secret']],
  [
    'FCM server key',
    `k="${p('AAAA')}${fake(7)}:${p('APA', '91b')}${fake(134)}"`,
    ['firebase-fcm-server-key'],
  ],
  ['GCP service account', `{"type": "service_account", "project_id": "acme"}`, ['gcp-service-account']],
  [
    'Azure connection string',
    `c="DefaultEndpointsProtocol=https;AccountName=acmestore;AccountKey=${fake(86, `${ALNUM}+/`)}=="`,
    ['azure-storage-connection-string'],
  ],
  [
    'Azure SAS',
    `u="https://acme.blob.core.windows.net/c?sv=2022-11-02&ss=b&sp=rl&se=2027-01-01&sig=${fake(44)}"`,
    ['azure-sas-token'],
  ],
  [
    'Google API key → low',
    `apiKey:"${p('AI', 'za')}${fake(35)}"`,
    ['google-api-key'],
    ['generic-secret-assignment'],
    (f) => assert.equal(f[0].severity, 'low'),
  ],
  [
    'Mapbox secret token',
    `t="${p('sk.', 'eyJ')}${fake(60)}.${fake(22)}"`,
    ['mapbox-token'],
    [],
    (f) => assert.equal(f[0].severity, 'high'),
  ],
  [
    'Mapbox public token → info',
    `t="${p('pk.', 'eyJ')}${fake(60)}.${fake(22)}"`,
    ['mapbox-token'],
    [],
    (f) => assert.equal(f[0].severity, 'info'),
  ],

  // ---- JWT classification
  [
    'JWT generic',
    `const t="${jwt({ sub: 'svc-reporting', role: 'reporter', exp: 4102444800 })}"`,
    ['jwt'],
    [],
    (f) => assert.equal(f[0].severity, 'medium'),
  ],
  [
    'Supabase service_role → critical',
    `createClient(u,"${jwt({ iss: 'supabase', role: 'service_role' })}")`,
    ['jwt'],
    [],
    (f) => assert.equal(f[0].severity, 'critical'),
  ],
  [
    'Supabase anon → info',
    `createClient(u,"${jwt({ iss: 'supabase', role: 'anon' })}")`,
    ['jwt'],
    [],
    (f) => assert.equal(f[0].severity, 'info'),
  ],
  ['not-a-JWT eyJ string', `x="eyJ${fake(20)}.eyJ${fake(20)}.${fake(20)}"`, [], ['jwt']],

  // ---- infrastructure
  [
    'DB URL with credentials → critical',
    `const db="postgres://admin:S3cr3tPw_2024@db.internal.acme.io:5432/prod"`,
    ['db-connection-string'],
    ['credentials-in-url'],
    (f) => assert.equal(f[0].severity, 'critical'),
  ],
  [
    'mongodb+srv credentials',
    `m="mongodb+srv://svc:Hx9pQ2vLz@cluster0.abcd.mongodb.net/app"`,
    ['db-connection-string'],
    ['credentials-in-url'],
  ],
  [
    'default/local DB creds → low',
    `u="amqp://guest:guest@localhost:5672"`,
    ['db-connection-string'],
    [],
    (f) => assert.equal(f[0].severity, 'low'),
  ],
  ['credentials in URL', `fetch("https://deploy:Tr0ub4dor-3@ci.acme.io/api")`, ['credentials-in-url']],
  [
    'docs-style user:password@host ignored',
    `// see https://user:password@host`,
    [],
    ['credentials-in-url', 'internal-url'],
  ],
  ['staging host', `const API="https://api.staging.acme.io/v2/"`, ['internal-url']],
  ['private IP with port', `ws = new WebSocket("ws://10.12.0.44:8081/feed")`, ['internal-url']],
  [
    'public/doc hosts ignored',
    `a="https://www.w3.org/2000/svg";b="https://testing-library.com/x";c="https://dev.to/";d="https://app.acme.io/x";e="https://develop.sentry.dev/x"`,
    [],
    ['internal-url'],
  ],
  ['regex-escaped host ignored', `// => '\\[lodash\\]\\(https://lodash\\.com/\\)'`, [], ['internal-url']],

  // ---- heuristics
  ['client-side password check', `if(pwd==="Adm1n@2024"){login()}`, ['generic-secret-assignment']],
  ['password in JSON', `{"username":"svc","password":"Welcome123"}`, ['generic-secret-assignment']],
  [
    'placeholder → info',
    `const cfg={apiKey:"YOUR_API_KEY_HERE"}`,
    ['generic-secret-assignment'],
    [],
    (f) => assert.equal(f[0].severity, 'info'),
  ],
  [
    'inlined env var',
    `const e={VITE_ANALYTICS_SECRET:"q8Zr2LmX9vT4kP7wN1sE"}`,
    ['generic-secret-assignment'],
  ],
  ['query-string secret', `fetch("/api/x?api_key=${fake(32)}&v=2")`, ['secret-in-query-string']],
  [
    'hard-coded Bearer header',
    `headers:{Authorization:"Bearer ${fake(40)}"}`,
    ['hardcoded-authorization-header'],
    ['generic-secret-assignment'],
  ],
  [
    'hard-coded Basic header decoded',
    `headers:{authorization:"Basic ${Buffer.from('svc:P4ssw0rd!').toString('base64')}"}`,
    ['hardcoded-authorization-header'],
    [],
    (f) => assert.match(f[0].title, /Basic auth/),
  ],

  // ---- false-positive guards
  [
    'i18n labels, csrf tokens, config keys',
    `{password:"Password",confirmPassword:"Confirm password",tokenType:"Bearer",csrfToken:"a8F3kL9mQ2xZ7vB1nR4t",tokenStorageKey:"auth_token_v2",passwordMinLength:"8",resetPasswordUrl:"/reset"}`,
    [],
    ['generic-secret-assignment'],
  ],
  [
    'header names',
    `headers:{"X-CSRF-Token":t, tokenHeader:"X-Auth-Token"}`,
    [],
    ['generic-secret-assignment'],
  ],
  [
    'minified property writes',
    `function a(e,t){return e.token=t,e.password=n,e}var o={type:"password",name:"token"};`,
    [],
    ['generic-secret-assignment'],
  ],
  [
    'compiler tokens with edge punctuation',
    `if(token==="?NonNullAssertion"||token==="#privateFieldName")x()`,
    [],
    ['generic-secret-assignment'],
  ],
  [
    'constant names and templates',
    `const k={secret:"HASHED_TOKEN",token:"%filtered%",apiKey:"\${API_KEY}",password:"{{password}}"}`,
    [],
    ['generic-secret-assignment'],
  ],

  // ---- debug artifacts
  ['source map reference', `x();\n//# sourceMappingURL=main.3f2a.js.map`, ['source-map-reference']],
  [
    'credential TODO',
    `// TODO: remove hardcoded admin password before release\nfoo()`,
    ['sensitive-todo-comment'],
  ],
  [
    'ordinary TODO ignored',
    `// TODO: Remove once the backend is updated to include the minimum password length\n`,
    [],
    ['sensitive-todo-comment'],
  ],
  ['console logging a token', `console.log("token is", accessToken)`, ['console-log-sensitive']],
  ['debugger statement', `if (x) { debugger; }`, ['debugger-statement']],
];

describe('detection rules', () => {
  for (const [name, text, must, mustNot = [], extra] of CASES) {
    it(name, async () => {
      const found = await scan(text);
      const got = ids(found);
      for (const id of must) assert.ok(got.includes(id), `expected ${id}, got [${got.join(', ')}]`);
      for (const id of mustNot) assert.ok(!got.includes(id), `did not expect ${id}, got [${got.join(', ')}]`);
      if (!must.length && !mustNot.length) assert.deepEqual(got, []);
      if (extra) extra(found.filter((f) => must.includes(f.ruleId)));
    });
  }
});

describe('client-side stores', () => {
  const store = (type, key, value) => ({
    text: `${key}="${value}"`,
    source: { type, label: type, lineLabels: [`${type}["${key}"]`] },
  });

  it('JWT in a JS-readable cookie is a storage issue, not a hard-coded token', async () => {
    const { text, source } = store('cookie', 'access_token', jwt({ sub: 'u1', exp: 4102444800 }));
    const [f] = await scan(text, source);
    assert.equal(f.title, 'JWT in JavaScript-readable cookie');
    assert.equal(f.severity, 'low');
    assert.equal(f.where, 'cookie["access_token"]');
  });

  it('opaque token in Web Storage is reported as storage exposure', async () => {
    const { text, source } = store('storage', 'authToken', fake(40));
    const [f] = await scan(text, source);
    assert.equal(f.title, 'Credential-like value in Web Storage');
    assert.equal(f.category, 'storage');
  });

  it('password in Web Storage is medium', async () => {
    const { text, source } = store('storage', 'user_password', 'Summer2024!');
    const [f] = await scan(text, source);
    assert.equal(f.title, 'Password stored in Web Storage');
    assert.equal(f.severity, 'medium');
  });
});

describe('engine guarantees', () => {
  it('masks neighbouring secrets in unrevealed context', async () => {
    const stripe = `${p('sk_', 'live_')}${fake(30)}`;
    const text = `const id="${p('AK', 'IA')}${fake(16, UPPER32)}";const s="${stripe}";`;
    const found = await scan(text);
    const aws = found.find((f) => f.ruleId === 'aws-access-key-id');
    assert.ok(
      !aws.context.afterMasked.includes(stripe.slice(0, 12)),
      'masked context leaked a neighbouring secret',
    );
    assert.ok(aws.context.after.includes(stripe.slice(0, 12)), 'raw context should still hold the text');
    assert.ok(aws.display.includes('•'));
  });

  it('reports line and column', async () => {
    const [f] = await scan(`\n\n  const t = "${p('gh', 'p_')}${fake(36)}";`);
    assert.equal(f.line, 3);
    assert.equal(f.col, 14);
  });

  it('keeps storage context inside one entry', async () => {
    const text = `a="1"\nuser_password="Summer2024!"\ncsrf_token="${fake(32)}"`;
    const source = {
      type: 'storage',
      label: 'localStorage',
      lineLabels: ['a', 'user_password', 'csrf_token'],
    };
    const [f] = await scan(text, source);
    assert.equal(f.where, 'user_password');
    assert.ok(!f.context.after.includes('csrf_token'), 'context bled into the next entry');
    assert.ok(!f.context.before.includes('a="1"'), 'context bled into the previous entry');
  });

  it('uses non-production downgrade only for environment hosts', async () => {
    const found = await scan(`u="https://api.staging.acme.io"`, SCRIPT, testEnv({ pageIsNonProd: true }));
    assert.equal(found[0].severity, 'info');
  });

  it('exposes a valid, unique rule registry', () => {
    const rules = engine.describeRules();
    assert.equal(rules.length, engine.ruleCount);
    assert.equal(new Set(rules.map((r) => r.id)).size, rules.length);
    assert.ok(rules.length >= 45, `expected a full rule set, got ${rules.length}`);
  });

  it('stays linear on hostile input (ReDoS guard)', async () => {
    const chunk =
      'function t(e,n){var r=e.tokenizer||n.passwordPolicy;return r&&(e.secretSauce=r.a),fetch("https://www.w3.org/x?key="+n)}';
    let big = chunk.repeat(Math.ceil(3_000_000 / chunk.length));
    big += `var img="data:image/png;base64,${Buffer.alloc(1_000_000, 7).toString('base64').replace(/A/g, 'eyJ')}";`;
    big += `${'a'.repeat(500_000)}token${'='.repeat(10)}"`;
    const start = performance.now();
    const found = await scan(big);
    const ms = performance.now() - start;
    assert.equal(found.length, 0);
    assert.ok(ms < 5_000, `scan of ${(big.length / 1e6).toFixed(1)} MB took ${ms.toFixed(0)} ms`);
  });

  it('helper classifications', () => {
    assert.equal(util.classifyHost('api.dev.acme.io'), 'environment');
    assert.equal(util.classifyHost('dev.to'), null);
    assert.equal(util.classifyHost('10.0.0.8'), 'private');
    assert.equal(util.classifyHost('169.254.169.254'), 'metadata');
    assert.equal(util.classifyHost('[::1]'), 'loopback');
    assert.equal(util.looksSecret('Welcome123', 'password'), true);
    assert.equal(util.looksSecret('X-CSRF-Token', 'tokenHeader'), false);
    assert.equal(util.isPlaceholder('YOUR_API_KEY_HERE'), true);
  });
});
