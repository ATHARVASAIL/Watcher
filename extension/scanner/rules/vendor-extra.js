/**
 * Watcher — additional vendor credential rules (2025–2026 formats).
 *
 * Distinctive, low-false-positive token prefixes that the core vendor set does
 * not already cover. Same rule shape as scanner/rules/vendor.js.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  ns.ruleSets = ns.ruleSets || {};
  if (ns.ruleSets['vendor-extra']) return;

  const cred = (id, title, severity, re, note, extra = {}) => ({
    id,
    title,
    category: 'credential',
    severity,
    confidence: 'pattern',
    re,
    note,
    ...extra,
  });

  ns.ruleSets['vendor-extra'] = [
    /* ------------------------------------------------------------ AI providers (billable) */
    cred(
      'perplexity-api-key',
      'Perplexity API key',
      'high',
      /\bpplx-[A-Za-z0-9]{40,60}\b/,
      'Billable API access. Revoke it in the Perplexity dashboard and call the API from your backend.',
    ),
    cred(
      'fireworks-api-key',
      'Fireworks AI API key',
      'high',
      /\bfw_[A-Za-z0-9]{24,40}\b/,
      'Billable API access. Revoke it in the Fireworks dashboard and call the API from your backend.',
    ),
    cred(
      'tavily-api-key',
      'Tavily API key',
      'high',
      /\btvly-(?:dev-)?[A-Za-z0-9]{24,48}\b/,
      'Billable search API access. Revoke it in the Tavily dashboard and call the API from your backend.',
    ),
    cred(
      'deepseek-api-key',
      'DeepSeek API key',
      'high',
      /\bsk-[a-f0-9]{32}\b/,
      'Possible DeepSeek API key (billable). If real, revoke it in the DeepSeek platform and proxy calls through your backend.',
      { confidence: 'heuristic' },
    ),

    /* ------------------------------------------------------------ email / messaging */
    cred(
      'resend-api-key',
      'Resend API key',
      'high',
      /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{20,40}\b/,
      'Can send email as your domain. Revoke it in the Resend dashboard and keep it server-side.',
    ),
    cred(
      'postmark-server-token',
      'Postmark server token',
      'high',
      /\bX-Postmark-Server-Token['":\s]{1,4}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
      'Can send email through Postmark. Rotate the server token in the Postmark dashboard.',
      { confidence: 'heuristic' },
    ),

    /* ------------------------------------------------------------ databases & infra platforms */
    cred(
      'planetscale-password',
      'PlanetScale database password',
      'critical',
      /\bpscale_pw_[A-Za-z0-9_.-]{40,}\b/,
      'Direct database credential. Rotate it in PlanetScale and never ship database passwords to the browser.',
    ),
    cred(
      'planetscale-token',
      'PlanetScale service token',
      'critical',
      /\bpscale_tkn_[A-Za-z0-9_.-]{40,}\b/,
      'Service token for the PlanetScale API. Revoke it in the PlanetScale dashboard.',
    ),
    cred(
      'neon-api-key',
      'Neon API key',
      'high',
      /\bnapi_[a-z0-9]{28,48}\b/,
      'Manages your Neon Postgres projects. Revoke it in the Neon console and keep it server-side.',
    ),
    cred(
      'databricks-token',
      'Databricks personal access token',
      'critical',
      /\bdapi[a-f0-9]{32}(?:-\d+)?\b/,
      'Grants access to your Databricks workspace. Revoke it in User Settings → Access tokens.',
    ),

    /* ------------------------------------------------------------ platforms */
    cred(
      'notion-token',
      'Notion integration token',
      'high',
      /\b(?:ntn_[0-9A-Za-z]{40,50}|secret_[A-Za-z0-9]{43})\b/,
      'Grants access to the connected Notion workspace. Revoke it in the Notion integration settings.',
    ),
    cred(
      'vercel-blob-token',
      'Vercel Blob read-write token',
      'high',
      /\bvercel_blob_rw_[A-Za-z0-9]{20,}_[A-Za-z0-9]{20,}\b/,
      'Read-write access to your Vercel Blob store. Rotate it in the Vercel dashboard and keep it server-side.',
    ),
    cred(
      'cloudflare-api-token',
      'Cloudflare API token',
      'high',
      /\bCLOUDFLARE_API_TOKEN['":=\s]{1,4}['"]?[A-Za-z0-9_-]{40}\b/,
      'Manages Cloudflare resources. Roll it in the Cloudflare dashboard (My Profile → API Tokens).',
      { confidence: 'heuristic' },
    ),
    cred(
      'flyio-token',
      'Fly.io access token',
      'high',
      /\bFlyV1 [A-Za-z0-9_,/=+-]{80,}/,
      'Deploys and manages your Fly.io apps. Revoke it with `fly tokens revoke` and issue a scoped token instead.',
      { confidence: 'heuristic' },
    ),
  ];
})();
