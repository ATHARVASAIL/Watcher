// Acme Portal fixture bundle. Every value is fake.
//
// Vendor-format keys (GitHub, Stripe, AWS, ...) are assembled at runtime and
// written into the DOM and Web Storage, so this repository never contains a
// contiguous token string that would trip GitHub push protection.

const API_BASE = 'https://api.staging.acme-corp.io';
const LEGACY_WS = 'ws://192.168.1.50:8081/live';
const DB_URL = 'postgres://app_rw:Pg-S3cure-2024@db.internal.acme-corp.io:5432/portal';

export const auth = {
  serviceAccount: 'svc_portal',
  password: 'Svc-Acct-9x!',
  tokenType: 'Bearer', // not a secret: plain word
  tokenStorageKey: 'auth_token_v2', // not a secret: denied key suffix
  passwordMinLength: '8', // not a secret: denied key suffix
};

export function exportReports() {
  return fetch(`${API_BASE}/reports?api_key=Zx81kLq2Wv7Tn4Rm9Pb3&format=csv`, {
    headers: { Authorization: 'Basic c3ZjX2V4cG9ydDpFeHAwcnQhMjAyNA==' },
  });
}

console.log('token refreshed', localStorage.getItem('auth_token'));

/* ---------------- runtime-seeded fixtures (vendor formats) ---------------- */

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const fake = (prefix, n, alphabet = ALNUM) =>
  prefix +
  Array.from(
    { length: n },
    (_, i) => alphabet[(i * 17 + n * 13 + prefix.length * 7 + 5) % alphabet.length],
  ).join('');
const b64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (payload) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.${fake('', 43)}`;

const seeded = {
  githubToken: fake('gh' + 'p_', 36),
  stripeSecret: fake('sk_' + 'live_', 24),
  stripePublishable: fake('pk_' + 'live_', 24),
  awsAccessKeyId: fake('AK' + 'IA', 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
  googleMapsKey: fake('AI' + 'za', 35),
  mapboxPublicToken: `${fake('pk.' + 'eyJ', 60)}.${fake('', 22)}`,
  slackWebhook:
    `https://hooks.slack.com/` +
    `services/${fake('T0', 8, 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789')}/${fake(
      'B0',
      8,
      'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789',
    )}/${fake('', 24)}`,
  supabaseServiceRole: jwt({
    iss: 'supabase',
    ref: 'acmeportal',
    role: 'service_role',
    iat: 1735689600,
    exp: 2051222400,
  }),
  supabaseAnon: jwt({ iss: 'supabase', ref: 'acmeportal', role: 'anon', iat: 1735689600, exp: 2051222400 }),
  privateKey: `${['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ')}\n${fake('MIIEow', 240)}\n${[
    '-----END',
    'RSA PRIVATE KEY-----',
  ].join(' ')}`,
};

// 1) Inline JSON block, the way SSR frameworks embed config (not executable).
const block = document.createElement('script');
block.type = 'application/json';
block.id = 'seeded-config';
block.textContent = JSON.stringify(seeded, null, 2);
document.getElementById('seeded').append(block);

// 2) Web Storage: a realistic mix of session material and harmless keys.
localStorage.setItem(
  'auth_token',
  jwt({ sub: 'user-1842', role: 'authenticated', exp: Math.floor(Date.now() / 1000) + 3600 }),
);
localStorage.setItem('refresh_token', fake('rt_', 40));
localStorage.setItem('user_password', 'Summer2024!');
localStorage.setItem('theme', 'dark');
localStorage.setItem('csrf_token', fake('', 32));
localStorage.setItem(
  'featureFlags',
  JSON.stringify({ beta: true, payments: { apiKey: seeded.stripeSecret } }),
);
sessionStorage.setItem('debug_session', JSON.stringify({ sessionSecret: fake('', 28), env: 'staging' }));
// Hostile key name: the popup must show it as text, never as markup.
localStorage.setItem(`<img src=x onerror=alert('popup-xss')>_token`, fake('xss_', 30));

// 3) Cookies without HttpOnly: visible to document.cookie, so an XSS could read them.
document.cookie = `session_id=${fake('s_', 32)}; path=/; SameSite=Lax`;
document.cookie = `access_token=${jwt({ sub: 'user-1842', role: 'authenticated', exp: 2051222400 })}; path=/; SameSite=Lax`;
document.cookie = 'theme=dark; path=/; SameSite=Lax'; // harmless
document.cookie = `XSRF-TOKEN=${fake('', 32)}; path=/; SameSite=Lax`; // double-submit CSRF cookie: must be readable

// 4) Lazily loaded chunk: never appears as a <script> tag, only in the resource timeline.
setTimeout(() => import('./chunks/lazy-reports.js'), 200);

export { LEGACY_WS, DB_URL };
//# sourceMappingURL=app.js.map
