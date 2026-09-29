/**
 * Watcher — vendor credential rules.
 *
 * Provider-specific token formats with low false-positive rates.
 * Rule shape and the ReDoS rule are documented in CONTRIBUTING.md.
 */
(() => {
  'use strict';

  const ns = globalThis.__WATCHER;
  ns.ruleSets = ns.ruleSets || {};
  if (ns.ruleSets.vendor) return;

  const { isPlaceholder, b64urlJson, decodeBase64Text, isClientStore, CLIENT_STORE_NOTES } = ns.util;

  /** Build a simple "rotate it" rule without repeating boilerplate. */
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

  /** JWT inspection: claims summary plus context-aware classification. */
  function classifyJwt({ value, source }) {
    const [headerPart, payloadPart] = value.split('.');
    const header = b64urlJson(headerPart);
    const payload = b64urlJson(payloadPart);
    if (!header || !payload || !header.alg) return false; // not actually a JWT

    const claims = [`alg=${String(header.alg).slice(0, 20)}`];
    if (payload.iss) claims.push(`iss=${String(payload.iss).slice(0, 60)}`);
    if (payload.role) claims.push(`role=${String(payload.role).slice(0, 40)}`);
    if (payload.sub) claims.push(`sub=${String(payload.sub).slice(0, 40)}`);
    let expired = false;
    if (typeof payload.exp === 'number') {
      expired = payload.exp * 1000 < Date.now();
      const date = new Date(payload.exp * 1000).toISOString().slice(0, 10);
      claims.push(`exp=${date}${expired ? ' (expired)' : ''}`);
    } else {
      claims.push('no exp claim (never expires)');
    }
    const claimText = `Claims: ${claims.join(', ')}.`;

    if (payload.role === 'service_role') {
      return {
        title: 'Supabase service_role key',
        severity: 'critical',
        note: `Bypasses Row Level Security: full read/write on your database. Rotate the Supabase JWT secret / API keys and use this key only on the server. ${claimText}`,
      };
    }
    if (payload.role === 'anon') {
      return {
        title: 'Supabase anon key',
        severity: 'info',
        note: `Designed to be public. It is only safe if Row Level Security is enabled with correct policies on every exposed table. ${claimText}`,
      };
    }
    if (isClientStore(source)) {
      return {
        title: source.type === 'cookie' ? 'JWT in JavaScript-readable cookie' : 'JWT in Web Storage',
        severity: 'low',
        category: 'storage',
        note: `Likely the current user's session token. ${CLIENT_STORE_NOTES[source.type]} ${claimText}`,
      };
    }
    if (header.alg === 'none') {
      return {
        title: 'Unsigned JWT (alg: none) in source',
        severity: 'medium',
        note: `An unsigned token is hard-coded. Make sure the backend rejects alg=none. ${claimText}`,
      };
    }
    return {
      severity: expired ? 'low' : 'medium',
      note: `A token baked into the build is shared by every visitor and cannot be revoked per user. Find what it authorises and replace it with a per-session token. ${claimText}`,
    };
  }

  const rules = [
    /* ------------------------------------------------------------ keys & cloud */
    cred(
      'private-key',
      'Private key',
      'critical',
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,8000}?-----END[ A-Z]{0,20}PRIVATE KEY(?: BLOCK)?-----)?/,
      'A private key must never reach a browser. Treat it as compromised: revoke and re-issue it, then remove it from the source and the repository history.',
      {
        check: ({ value }) => {
          const header = value.split('-----')[1];
          const label = header ? `-----${header}-----` : 'PRIVATE KEY';
          return { display: `${label} … (${value.length.toLocaleString()} chars)` };
        },
      },
    ),
    cred(
      'aws-access-key-id',
      'AWS access key ID',
      'high',
      /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/,
      'Identifies an IAM credential; the matching secret key is usually close by. Deactivate and rotate it in IAM and review CloudTrail for use. Browsers should get short-lived credentials (e.g. Cognito) instead.',
      {
        check: ({ value }) =>
          isPlaceholder(value)
            ? {
                severity: 'info',
                title: 'AWS documentation example key',
                note: 'This is the example key from AWS documentation, not a live credential.',
              }
            : true,
      },
    ),
    cred(
      'aws-secret-access-key',
      'AWS secret access key',
      'critical',
      /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secretAccessKey)["']?\s{0,5}[:=]\s{0,5}["'`](?<secret>[A-Za-z0-9/+]{40})["'`]/i,
      'Full AWS credential. Deactivate it in IAM immediately, check CloudTrail for misuse, and move AWS access server-side.',
    ),
    cred(
      'google-oauth-client-secret',
      'Google OAuth client secret',
      'critical',
      /\bGOCSPX-[A-Za-z0-9_-]{28}\b/,
      'Client secrets belong on the server. Reset it in Google Cloud Console; public clients should use PKCE without a secret.',
    ),
    cred(
      'gcp-service-account',
      'GCP service-account JSON',
      'high',
      /"type"\s{0,5}:\s{0,5}"service_account"/,
      'A service-account credential file appears to be bundled. If a private_key accompanies it (see Private key findings), delete that key in IAM immediately.',
      { redact: false },
    ),
    cred(
      'firebase-fcm-server-key',
      'Firebase Cloud Messaging server key',
      'critical',
      /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134}\b/,
      'Lets anyone send push notifications to all your users. Delete the legacy server key in the Firebase console and send pushes from the backend.',
    ),
    cred(
      'azure-storage-connection-string',
      'Azure Storage connection string',
      'critical',
      /DefaultEndpointsProtocol=https?;AccountName=[^;"'\s]{3,64};AccountKey=[A-Za-z0-9+/=]{86,90}/,
      'Account-level key for the storage account. Rotate the key in the Azure portal; use short-lived SAS tokens for browsers.',
    ),
    {
      id: 'azure-sas-token',
      title: 'Azure SAS token',
      category: 'token',
      severity: 'medium',
      confidence: 'pattern',
      re: /[?&]sv=\d{4}-\d{2}-\d{2}&[^"'\s<>]{0,400}?\bsig=[A-Za-z0-9%+/=]{20,120}/,
      note: 'Check the se= (expiry) and sp= (permissions) parameters. Long-lived or write-capable SAS tokens should not be hard-coded.',
    },
    cred(
      'digitalocean-token',
      'DigitalOcean token',
      'critical',
      /\bdo[opr]_v1_[a-f0-9]{64}\b/,
      'Full API access to your DigitalOcean account. Revoke it under API → Tokens.',
    ),
    cred(
      'vault-token',
      'HashiCorp Vault token',
      'critical',
      /\bhv[sb]\.[A-Za-z0-9_-]{24,200}\b/,
      'A Vault token can read every secret its policies allow. Revoke it (vault token revoke) and audit its accessor.',
    ),
    cred(
      'doppler-token',
      'Doppler token',
      'critical',
      /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b/,
      'Grants access to the secrets stored in Doppler. Revoke it in the Doppler dashboard.',
    ),

    /* ------------------------------------------------------------ source control & packages */
    cred(
      'github-token',
      'GitHub token',
      'critical',
      /\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{80,255})\b/,
      "Revoke it in GitHub → Settings → Developer settings, then review the audit log for the token's activity.",
    ),
    cred(
      'gitlab-token',
      'GitLab personal access token',
      'critical',
      /\bglpat-[A-Za-z0-9_-]{20,64}\b/,
      'Revoke it in GitLab → Access tokens and review what it could reach.',
    ),
    cred(
      'npm-token',
      'npm access token',
      'critical',
      /\bnpm_[A-Za-z0-9]{36}\b/,
      'Could allow publishing packages as you (supply-chain risk). Revoke it on npmjs.com.',
    ),
    cred(
      'pypi-token',
      'PyPI upload token',
      'critical',
      /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,300}/,
      'Could allow publishing packages as you (supply-chain risk). Revoke it in PyPI account settings.',
    ),
    cred(
      'docker-hub-token',
      'Docker Hub access token',
      'critical',
      /\bdckr_pat_[A-Za-z0-9_-]{27}\b/,
      'Could allow pushing images as you. Revoke it in Docker Hub → Account settings → Security.',
    ),

    /* ------------------------------------------------------------ messaging & collaboration */
    cred(
      'slack-token',
      'Slack token',
      'high',
      /\bxox[abposr]-(?:\d{1,20}-){0,3}[A-Za-z0-9-]{10,200}\b/,
      'Revoke it in the Slack app configuration. Bot/user tokens can read and post workspace messages.',
    ),
    cred(
      'slack-webhook',
      'Slack incoming webhook',
      'high',
      /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/]{20,120}/,
      'Anyone with this URL can post into your Slack channel. Regenerate it and send notifications from the backend.',
    ),
    cred(
      'discord-webhook',
      'Discord webhook',
      'high',
      /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[A-Za-z0-9_-]{20,100}/,
      'Anyone with this URL can post to the channel. Delete and recreate the webhook; call it from the backend.',
    ),
    cred(
      'telegram-bot-token',
      'Telegram bot token',
      'high',
      /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/,
      'Full control of the bot. Revoke it via @BotFather (/revoke).',
    ),
    cred(
      'atlassian-api-token',
      'Atlassian API token',
      'high',
      /\bATATT3[A-Za-z0-9_\-=]{180,190}\b/,
      'Acts as the user in Jira/Confluence. Revoke it at id.atlassian.com → Security → API tokens.',
    ),
    cred(
      'linear-api-key',
      'Linear API key',
      'high',
      /\blin_api_[A-Za-z0-9]{40}\b/,
      'Full access to your Linear workspace as the key owner. Revoke it in Linear → Settings → API.',
    ),
    cred(
      'postman-api-key',
      'Postman API key',
      'high',
      /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/,
      'Exposes your Postman workspaces, collections and environments (which often hold more secrets). Revoke it in Postman settings.',
    ),

    /* ------------------------------------------------------------ payments & commerce */
    cred(
      'live-secret-key',
      'Live secret key (sk_live_ / rk_live_)',
      'critical',
      /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,247}\b/,
      'Server-side secret key in the Stripe (or Clerk) format. For Stripe it grants charges, refunds and customer data. Roll the key in the provider dashboard now.',
    ),
    cred(
      'test-secret-key',
      'Test secret key (sk_test_ / rk_test_)',
      'medium',
      /\b(?:sk|rk)_test_[0-9a-zA-Z]{20,247}\b/,
      'Test mode, so no real money moves, but it exposes your test data and signals that secret keys are being bundled. Roll it and keep secret keys server-side.',
    ),
    {
      id: 'publishable-key',
      title: 'Publishable key (pk_live_ / pk_test_)',
      category: 'token',
      severity: 'info',
      confidence: 'pattern',
      re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,247}\b/,
      note: 'Publishable keys are designed to be public. Only worth a look if the environment is wrong (pk_test on a production site).',
    },
    cred(
      'stripe-webhook-secret',
      'Stripe webhook signing secret',
      'critical',
      /\bwhsec_[A-Za-z0-9]{32,60}\b/,
      'Lets anyone forge webhook events your backend will trust. Roll the signing secret in the Stripe dashboard; it belongs only on the server.',
    ),
    cred(
      'shopify-token',
      'Shopify access token',
      'critical',
      /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/,
      'Admin API access to the store. Rotate it in the Shopify admin.',
    ),
    cred(
      'square-token',
      'Square access token / secret',
      'critical',
      /\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}\b/,
      'Payment API access. Revoke it in the Square developer dashboard.',
    ),

    /* ------------------------------------------------------------ email */
    cred(
      'sendgrid-api-key',
      'SendGrid API key',
      'critical',
      /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
      'Can send email as your domain (phishing risk). Delete the key in SendGrid and send mail from the backend.',
    ),
    cred(
      'mailgun-api-key',
      'Mailgun API key',
      'high',
      /\bkey-[0-9a-f]{32}\b/,
      'Can send email as your domain. Rotate it in Mailgun.',
    ),
    cred(
      'mailchimp-api-key',
      'Mailchimp API key',
      'high',
      /\b[0-9a-f]{32}-us\d{1,2}\b/,
      'Full access to your audience data. Revoke it in Mailchimp → Account → Extras → API keys.',
    ),
    {
      ...cred(
        'twilio-api-key',
        'Possible Twilio API key SID',
        'medium',
        /\bSK[0-9a-f]{32}\b/,
        'Matches the Twilio API-key SID format; the secret is usually nearby. Verify, then revoke it in the Twilio console.',
      ),
      confidence: 'heuristic',
    },

    /* ------------------------------------------------------------ AI providers (billable) */
    cred(
      'openai-api-key',
      'OpenAI API key',
      'critical',
      /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,300}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/,
      'Billable API access. Revoke it in the OpenAI dashboard and proxy model calls through your backend.',
    ),
    cred(
      'anthropic-api-key',
      'Anthropic API key',
      'critical',
      /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120}/,
      'Billable API access. Revoke it in the Anthropic Console and proxy model calls through your backend.',
    ),
    cred(
      'groq-api-key',
      'Groq API key',
      'critical',
      /\bgsk_[A-Za-z0-9]{52}\b/,
      'Billable API access. Revoke it in the Groq console and proxy model calls through your backend.',
    ),
    cred(
      'xai-api-key',
      'xAI API key',
      'critical',
      /\bxai-[A-Za-z0-9]{80}\b/,
      'Billable API access. Revoke it in the xAI console and proxy model calls through your backend.',
    ),
    cred(
      'replicate-api-token',
      'Replicate API token',
      'critical',
      /\br8_[A-Za-z0-9]{37}\b/,
      'Billable API access. Revoke it in Replicate account settings.',
    ),
    cred(
      'huggingface-token',
      'Hugging Face token',
      'high',
      /\bhf_[A-Za-z0-9]{34}\b/,
      'Access to your Hugging Face models, datasets and (with write scope) the ability to push to them. Revoke it in account settings → Access Tokens.',
    ),

    /* ------------------------------------------------------------ observability & maps */
    cred(
      'sentry-auth-token',
      'Sentry auth token',
      'high',
      /\bsntry[su]_[A-Za-z0-9+/=_-]{60,300}/,
      'Auth tokens (not DSNs) grant Sentry API access, e.g. to upload releases and read event data. Revoke it in Sentry → Settings → Auth Tokens. DSNs are public by design.',
    ),
    cred(
      'grafana-token',
      'Grafana token',
      'high',
      /\bglsa_[A-Za-z0-9]{32}_[a-fA-F0-9]{8}\b|\bglc_[A-Za-z0-9+/]{32,400}={0,2}/,
      'Grafana service-account or Cloud token. Revoke it in Grafana administration.',
    ),
    {
      id: 'mapbox-token',
      title: 'Mapbox secret token',
      category: 'credential',
      severity: 'high',
      confidence: 'pattern',
      re: /\b(?<kind>sk|pk)\.eyJ[A-Za-z0-9_-]{20,300}\.[A-Za-z0-9_-]{20,40}\b/,
      note: 'Secret (sk.) Mapbox tokens can have write scopes on your account. Revoke it in the Mapbox account page; browsers should use URL-restricted public (pk.) tokens.',
      check: ({ m }) =>
        m.groups.kind === 'pk'
          ? {
              title: 'Mapbox public token',
              severity: 'info',
              category: 'token',
              note: 'Public (pk.) tokens are meant for browsers. Make sure it is URL-restricted in your Mapbox account so others cannot bill your usage.',
            }
          : true,
    },
    {
      id: 'google-api-key',
      title: 'Google API key',
      category: 'token',
      severity: 'low',
      confidence: 'pattern',
      re: /\bAIza[0-9A-Za-z_-]{35}\b/,
      note: 'Browser keys for Maps / Firebase are public by design, so presence alone is not a leak. The risk is an unrestricted key: confirm HTTP-referrer and API restrictions in Google Cloud Console → Credentials.',
    },

    /* ------------------------------------------------------------ auth material */
    cred(
      'hardcoded-authorization-header',
      'Hard-coded Authorization header',
      'high',
      /\bauthorization["']?\s{0,5}[:=]\s{0,5}["'`](?:Bearer|Basic|Token)\s{1,3}(?<secret>[A-Za-z0-9._~+/=-]{12,2048})["'`]/i,
      'A fixed credential is sent with requests from the browser, so every visitor has it. Issue per-user tokens from your backend instead.',
      {
        check: ({ m, value }) => {
          if (isPlaceholder(value)) return false;
          if (/basic/i.test(m[0])) {
            const decoded = decodeBase64Text(value);
            if (decoded && decoded.includes(':')) {
              return {
                title: 'Hard-coded Basic auth credentials',
                note: 'Decodes to a username:password pair that every visitor can read. Rotate the password and authenticate from the backend.',
              };
            }
          }
          return true;
        },
      },
    ),
    {
      id: 'jwt',
      title: 'Hard-coded JWT',
      category: 'token',
      severity: 'medium',
      confidence: 'pattern',
      re: /\beyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,16000}\.[A-Za-z0-9_-]{8,1500}/,
      note: '',
      check: classifyJwt,
    },
  ];

  ns.ruleSets.vendor = rules;
})();
