// src/controllers/oauthController.js
// ============================================================
//  OAuth 2.0 Controller — fully working for Postman desktop + web
//
//  FIXES applied (v2.1):
//  FIX 1: authorizePost now verifies the DB insert succeeded
//          BEFORE redirecting. Previously a silent Supabase insert
//          failure would redirect with a phantom code that could
//          never be exchanged → INVALID_GRANT.
//
//  FIX 2: token() authorization_code branch now uses maybeSingle()
//          so a missing code returns null (not an error object).
//          This lets us give accurate "not found" vs "already used"
//          error messages and avoids a false INVALID_GRANT when the
//          Supabase .single() throws because 0 rows were returned.
//
//  FIX 3: Validation is done BEFORE marking the code as used.
//          Previously redirect_uri / client_id mismatches could burn
//          the code without issuing tokens, making it unrecoverable.
//
//  FIX 4: authorizePost now checks both `users` AND `api_tester_accounts`
//          so registered testers can log in with their own credentials.
//
//  FIX 5: token endpoint now accepts client credentials via
//          Authorization: Basic base64(client_id:client_secret)
//          in addition to request body — RFC 6749 §2.3.1 compliant.
//          Postman's built-in OAuth2 flow sends Basic Auth by default.
// ============================================================

const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const supabase = require('../utils/db');
const {
  OAUTH_ACCESS_TOKEN_TTL,
  OAUTH_REFRESH_TOKEN_TTL,
  OAUTH_AUTH_CODE_TTL,
  BASE_URL,
} = require('../utils/config');
const { success, error } = require('../utils/response');
const {
  audit, AUDIT_EVENTS,
  generateSecureToken, getClientIp,
  isLocked, recordFailure,
} = require('../utils/authSecurity');

const ISSUER = BASE_URL || 'https://hapi-2115.onrender.com';

// ── Extract client credentials from Basic Auth header OR body ─
// RFC 6749 §2.3.1: clients MAY send credentials via HTTP Basic Auth
// on the token endpoint. Postman's built-in OAuth2 flow does this by
// default ("Send as Basic Auth header" option). Support both methods.
const extractClientCredentials = (req) => {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded  = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
      const colonIdx = decoded.indexOf(':');
      if (colonIdx !== -1) {
        return {
          client_id:     decodeURIComponent(decoded.slice(0, colonIdx)),
          client_secret: decodeURIComponent(decoded.slice(colonIdx + 1)),
        };
      }
    } catch (_) {
      // malformed Basic header — fall through to body
    }
  }
  // Fall back to body fields (works when Postman uses "Send in body")
  return {
    client_id:     req.body.client_id,
    client_secret: req.body.client_secret,
  };
};

// ── Client credential validation ─────────────────────────────
const validateClient = async (clientId, clientSecret) => {
  if (!clientId || !clientSecret) return null;
  const { data } = await supabase
    .from('oauth_clients')
    .select('*')
    .eq('client_id', clientId)
    .single();
  if (!data) return null;
  const buf1 = Buffer.from(data.client_secret);
  const buf2 = Buffer.from(String(clientSecret));
  if (buf1.length !== buf2.length) return null;
  if (!crypto.timingSafeEqual(buf1, buf2)) return null;
  return data;
};

// ── PKCE verification ─────────────────────────────────────────
const verifyCodeChallenge = (verifier, challenge, method) => {
  if (method === 'S256') {
    return crypto.createHash('sha256').update(verifier).digest('base64url') === challenge;
  }
  if (method === 'plain') return verifier === challenge;
  return false;
};

// ── Token response builder ────────────────────────────────────
const buildTokenResponse = async (userId, clientId, scope) => {
  const accessToken  = generateSecureToken('hapi_at');
  const refreshToken = generateSecureToken('hapi_rt');
  const now = Date.now();
  const { data: user } = userId
    ? await supabase.from('users').select('id, name, email, role').eq('id', userId).single()
    : { data: null };
  const atExpiry = new Date(now + OAUTH_ACCESS_TOKEN_TTL * 1000).toISOString();
  await Promise.all([
    supabase.from('oauth_access_tokens').insert({
      token: accessToken, user_id: userId || null,
      client_id: clientId, scope, expires_at: atExpiry,
    }),
    supabase.from('oauth_refresh_tokens').insert({
      token: refreshToken, user_id: userId || null,
      client_id: clientId, scope,
    }),
  ]);
  return {
    access_token: accessToken, token_type: 'Bearer',
    expires_in: OAUTH_ACCESS_TOKEN_TTL,
    refresh_token: refreshToken, scope,
    token_metadata: {
      issued_at: new Date(now).toISOString(), expires_at: atExpiry,
      sub: userId || 'service-account',
      username: user?.email || null, role: user?.role || 'service',
    },
  };
};

// ── Unified user lookup (users table + api_tester_accounts) ──
const lookupUser = async (email) => {
  const normalised = (email || '').toLowerCase().trim();

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('email', normalised)
    .single();

  if (user) return user;

  const { data: tester } = await supabase
    .from('api_tester_accounts')
    .select('*')
    .eq('email', normalised)
    .single();

  if (!tester) return null;

  return {
    id:         tester.id,
    name:       tester.full_name,
    email:      tester.email,
    password:   tester.password,
    role:       tester.role,
    department: tester.organisation || null,
  };
};

// ─────────────────────────────────────────────────────────────
//  GET /api/oauth/.well-known/oauth-authorization-server
// ─────────────────────────────────────────────────────────────
const serverMetadata = (req, res) => res.status(200).json({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/api/oauth/authorize`,
  token_endpoint:         `${ISSUER}/api/oauth/token`,
  revocation_endpoint:    `${ISSUER}/api/oauth/revoke`,
  introspection_endpoint: `${ISSUER}/api/oauth/introspect`,
  jwks_uri: null,
  response_types_supported:             ['code'],
  grant_types_supported:                ['authorization_code', 'client_credentials', 'password', 'refresh_token'],
  token_endpoint_auth_methods_supported:['client_secret_post', 'client_secret_basic'],
  scopes_supported: ['read:patients','write:patients','read:appointments','write:appointments','read:records','write:records','admin'],
  code_challenge_methods_supported: ['S256', 'plain'],
  require_pkce_for_public_clients: true,
  service_documentation: `${ISSUER}/api/docs`,
});

// ─────────────────────────────────────────────────────────────
//  GET /api/oauth/clients
// ─────────────────────────────────────────────────────────────
const listClients = async (req, res) => {
  const { data } = await supabase
    .from('oauth_clients')
    .select('client_id, name, redirect_uris, grant_types, scopes, created_at');
  return success(res, data || [], 'Registered OAuth2 clients.');
};

// ─────────────────────────────────────────────────────────────
//  HTML Login Page builder
// ─────────────────────────────────────────────────────────────
const buildLoginPage = ({ clientName, scope, queryString, loginError }) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>HealthAPI — Authorize</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'DM Sans',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;
         display:flex;align-items:center;justify-content:center;padding:20px;
         background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(79,142,247,.12) 0%,transparent 60%)}
    .card{width:100%;max-width:420px;background:#181c27;border:1px solid #2a2f3e;
          border-radius:20px;padding:40px 36px 36px;box-shadow:0 25px 60px rgba(0,0,0,.5)}
    .logo{display:flex;align-items:center;gap:10px;margin-bottom:28px}
    .logo-icon{width:36px;height:36px;background:linear-gradient(135deg,#4f8ef7,#34d399);
               border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px}
    .logo-text{font-size:18px;font-weight:600;letter-spacing:-.3px}
    .logo-text span{color:#4f8ef7}
    h1{font-size:22px;font-weight:600;letter-spacing:-.5px;margin-bottom:6px}
    .subtitle{font-size:13px;color:#64748b;margin-bottom:24px;line-height:1.5}
    .scope-box{background:rgba(79,142,247,.06);border:1px solid rgba(79,142,247,.2);
               border-radius:10px;padding:12px 14px;margin-bottom:24px;font-size:12px;color:#64748b}
    .scope-box strong{display:block;color:#e2e8f0;font-size:13px;margin-bottom:4px}
    .scope-tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
    .scope-tag{background:rgba(79,142,247,.15);color:#4f8ef7;font-family:'DM Mono',monospace;
               font-size:11px;padding:2px 8px;border-radius:5px}
    .error{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);
           border-radius:10px;padding:10px 14px;margin-bottom:18px;font-size:13px;color:#f87171}
    label{display:block;font-size:12px;font-weight:500;color:#64748b;
          text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
    input{width:100%;background:#0f1117;border:1px solid #2a2f3e;border-radius:12px;
          color:#e2e8f0;font-family:'DM Sans',sans-serif;font-size:14px;
          padding:11px 14px;margin-bottom:16px;outline:none;transition:border-color .15s}
    input:focus{border-color:#4f8ef7}
    input::placeholder{color:#64748b}
    .hint{font-size:11px;color:#64748b;margin-top:-12px;margin-bottom:16px;font-family:'DM Mono',monospace}
    button[type=submit]{width:100%;background:linear-gradient(135deg,#4f8ef7,#6fa8f8);color:#fff;
                        border:none;border-radius:12px;font-family:'DM Sans',sans-serif;font-size:14px;
                        font-weight:600;padding:13px;cursor:pointer;transition:opacity .15s,transform .1s;letter-spacing:.2px}
    button[type=submit]:hover{opacity:.9;transform:translateY(-1px)}
    .divider{text-align:center;font-size:12px;color:#64748b;margin:16px 0;position:relative}
    .divider::before,.divider::after{content:'';position:absolute;top:50%;width:calc(50% - 30px);height:1px;background:#2a2f3e}
    .divider::before{left:0}.divider::after{right:0}
    .creds-grid{display:grid;gap:6px;margin-bottom:20px}
    .cred-row{display:flex;align-items:center;justify-content:space-between;background:#0f1117;
              border:1px solid #2a2f3e;border-radius:8px;padding:8px 12px;font-size:12px;
              cursor:pointer;transition:border-color .15s}
    .cred-row:hover{border-color:#4f8ef7}
    .cred-label{font-weight:500;color:#e2e8f0;font-size:12px}
    .cred-role{font-family:'DM Mono',monospace;font-size:10px;padding:2px 7px;border-radius:4px;
               background:rgba(52,211,153,.12);color:#34d399}
    .footer{margin-top:20px;text-align:center;font-size:11px;color:#64748b}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">🏥</div>
      <div class="logo-text">Health<span>API</span></div>
    </div>
    <h1>Sign in to authorize</h1>
    <p class="subtitle"><strong>${clientName || 'An application'}</strong> is requesting access to your HealthAPI account.</p>
    ${scope ? `<div class="scope-box"><strong>Requested permissions</strong><div class="scope-tags">${scope.split(' ').map(s => `<span class="scope-tag">${s}</span>`).join('')}</div></div>` : ''}
    ${loginError ? `<div class="error">⚠️ ${loginError}</div>` : ''}
    <form method="POST" action="/api/oauth/authorize${queryString}">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" placeholder="admin@healthapi.com" required autocomplete="username"/>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="••••••••" required autocomplete="current-password"/>
      <p class="hint">Use your registered email and password</p>
      <button type="submit">Authorize Access →</button>
    </form>
    <div class="divider">test accounts</div>
    <div class="creds-grid">
      <div class="cred-row" onclick="fillCreds('admin@healthapi.com','Admin@1234')">
        <span class="cred-label">admin@healthapi.com</span><span class="cred-role">admin</span>
      </div>
      <div class="cred-row" onclick="fillCreds('sarah.mehta@healthapi.com','Admin@1234')">
        <span class="cred-label">sarah.mehta@healthapi.com</span><span class="cred-role">doctor</span>
      </div>
      <div class="cred-row" onclick="fillCreds('priya.nair@healthapi.com','Admin@1234')">
        <span class="cred-label">priya.nair@healthapi.com</span><span class="cred-role">nurse</span>
      </div>
    </div>
    <div class="footer">HealthAPI v2.0 · OAuth 2.0 Authorization Server</div>
  </div>
  <script>
    function fillCreds(email, pass){
      document.getElementById('email').value = email;
      document.getElementById('password').value = pass;
    }
  </script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────
//  GET /api/oauth/authorize  — Show login form
// ─────────────────────────────────────────────────────────────
const authorize = async (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, login_error } = req.query;

  if (response_type !== 'code')
    return error(res, 400, 'UNSUPPORTED_RESPONSE_TYPE', 'response_type must be "code".');
  if (!client_id)
    return error(res, 400, 'MISSING_CLIENT_ID', 'client_id is required.');

  const { data: client } = await supabase.from('oauth_clients').select('*').eq('client_id', client_id).single();
  if (!client)
    return error(res, 401, 'INVALID_CLIENT', `No registered OAuth2 client with client_id: ${client_id}.`);

  if (!redirect_uri)
    return error(res, 400, 'MISSING_REDIRECT_URI', 'redirect_uri is required.');
  if (!client.redirect_uris.includes(redirect_uri))
    return error(res, 400, 'INVALID_REDIRECT_URI',
      `redirect_uri '${redirect_uri}' is not registered. Registered: ${client.redirect_uris.join(', ')}`);

  const requestedScopes = (scope || 'read:patients').split(' ').filter(Boolean);
  const invalidScopes   = requestedScopes.filter(s => !client.scopes.includes(s));
  if (invalidScopes.length)
    return error(res, 400, 'INVALID_SCOPE', `Scopes not permitted: ${invalidScopes.join(', ')}`);

  const qs = '?' + new URLSearchParams({
    response_type, client_id, redirect_uri,
    scope: requestedScopes.join(' '),
    ...(state                ? { state }                : {}),
    ...(code_challenge       ? { code_challenge }       : {}),
    ...(code_challenge_method? { code_challenge_method }: {}),
  }).toString();

  return res.status(200).send(buildLoginPage({
    clientName: client.name,
    scope: requestedScopes.join(' '),
    queryString: qs,
    loginError: login_error || null,
  }));
};

// ─────────────────────────────────────────────────────────────
//  POST /api/oauth/authorize  — Process login, issue code, redirect
//
//  FIX 1: The DB insert result is now checked. If Supabase returns
//  an error we do NOT redirect — we show the login page again with
//  an error message. Previously a failed insert silently redirected
//  with a phantom code that could never be exchanged.
// ─────────────────────────────────────────────────────────────
const authorizePost = async (req, res) => {
  const {
    response_type, client_id, redirect_uri, scope,
    state, code_challenge, code_challenge_method,
  } = req.query;
  const { email, password } = req.body;

  const { data: client } = await supabase
    .from('oauth_clients').select('*').eq('client_id', client_id).single();
  if (!client || !client.redirect_uris.includes(redirect_uri))
    return error(res, 400, 'INVALID_CLIENT', 'Invalid client or redirect_uri.');

  const requestedScopes = (scope || 'read:patients').split(' ').filter(Boolean);

  // Helper: rebuild the query-string for error redirects
  const buildQs = (extraParams = {}) =>
    '?' + new URLSearchParams({
      response_type, client_id, redirect_uri,
      scope: requestedScopes.join(' '),
      ...(state                 ? { state }                 : {}),
      ...(code_challenge        ? { code_challenge }        : {}),
      ...(code_challenge_method ? { code_challenge_method } : {}),
      ...extraParams,
    }).toString();

  // ── Unified user lookup ───────────────────────────────────
  const dummyHash = '$2a$10$dummy.hash.to.prevent.timing.attacks.from.user.enumeration.';
  const user = await lookupUser(email);
  const hashToCheck = user ? user.password : dummyHash;
  const valid = await bcrypt.compare(password || '', hashToCheck);

  if (!user || !valid) {
    return res.redirect(302,
      `/api/oauth/authorize${buildQs({ login_error: 'Invalid email or password. Please try again.' })}`
    );
  }

  // ── Issue auth code ───────────────────────────────────────
  const code      = generateSecureToken('hapi_code', 24);
  const expiresAt = new Date(Date.now() + OAUTH_AUTH_CODE_TTL * 1000).toISOString();

  // FIX 1: Check the insert result before redirecting.
  const { error: insertErr } = await supabase.from('oauth_auth_codes').insert({
    code,
    user_id:               user.id,
    client_id,
    scope:                 requestedScopes.join(' '),
    redirect_uri,
    expires_at:            expiresAt,
    code_challenge:        code_challenge        || null,
    code_challenge_method: code_challenge_method || null,
    used:                  false,
  });

  if (insertErr) {
    // DB write failed — do NOT redirect with a phantom code.
    console.error('[OAuth] auth_code insert failed:', insertErr.message);
    return res.redirect(302,
      `/api/oauth/authorize${buildQs({ login_error: 'Server error while generating authorization code. Please try again.' })}`
    );
  }

  audit(AUDIT_EVENTS.OAUTH_TOKEN, {
    clientId: client_id, userId: user.id,
    event: 'auth_code_issued', scope: requestedScopes.join(' '),
  });

  // Redirect to the redirect_uri with the code
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set('code', code);
  if (state) callbackUrl.searchParams.set('state', state);

  return res.redirect(302, callbackUrl.toString());
};

// ─────────────────────────────────────────────────────────────
//  GET /api/oauth/callback  — Self-hosted callback page
// ─────────────────────────────────────────────────────────────
const callbackPage = (req, res) => {
  const { code, state, error: oauthError, error_description } = req.query;

  if (oauthError) {
    return res.status(400).send(`<!DOCTYPE html>
<html><head><title>Authorization Failed</title>
<style>body{font-family:sans-serif;background:#0f1117;color:#f87171;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style>
</head><body><div><h2>❌ Authorization Failed</h2><p>${oauthError}: ${error_description || ''}</p></div></body></html>`);
  }

  return res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>HealthAPI — Authorization Complete</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap');
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'DM Sans',sans-serif;background:#0f1117;color:#e2e8f0;
         min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{width:100%;max-width:480px;background:#181c27;border:1px solid #2a2f3e;
          border-radius:20px;padding:40px 36px}
    .icon{font-size:40px;margin-bottom:16px;text-align:center}
    h1{font-size:20px;font-weight:600;margin-bottom:8px;text-align:center}
    .sub{font-size:13px;color:#64748b;text-align:center;margin-bottom:28px;line-height:1.5}
    .code-block{background:#0f1117;border:1px solid #2a2f3e;border-radius:10px;
                padding:14px 16px;margin-bottom:16px;position:relative}
    .code-label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
    .code-value{font-family:'DM Mono',monospace;font-size:11px;color:#4f8ef7;
                word-break:break-all;line-height:1.5}
    .copy-btn{position:absolute;top:12px;right:12px;background:rgba(79,142,247,.1);
              border:1px solid rgba(79,142,247,.3);color:#4f8ef7;border-radius:6px;
              padding:4px 10px;font-size:11px;cursor:pointer;font-family:'DM Sans',sans-serif}
    .copy-btn:hover{background:rgba(79,142,247,.2)}
    .notice{background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.2);
            border-radius:10px;padding:12px 14px;font-size:12px;color:#34d399;line-height:1.6;
            margin-bottom:16px}
    .postman-notice{background:rgba(255,106,0,.06);border:1px solid rgba(255,106,0,.2);
                    border-radius:10px;padding:12px 14px;font-size:12px;color:#ff9a5c;line-height:1.6}
    strong{color:#e2e8f0}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Authorization successful</h1>
    <p class="sub">You've been authenticated. Postman will now exchange this code for an access token automatically.</p>

    <div class="code-block">
      <div class="code-label">Authorization code</div>
      <div class="code-value" id="code-val">${code || ''}</div>
      <button class="copy-btn" onclick="copyCode()">Copy</button>
    </div>

    ${state ? `<div class="code-block">
      <div class="code-label">State</div>
      <div class="code-value">${state}</div>
    </div>` : ''}

    <div class="notice">
      <strong>Postman desktop:</strong> This window will close automatically as Postman intercepts the redirect. If it doesn't close, copy the code above and paste it into Postman manually.
    </div>

    <div class="postman-notice">
      <strong>Postman web app:</strong> Copy the authorization code above, then go back to Postman and paste it in the "Authorization code" field, then click "Exchange authorization code for tokens".
    </div>
  </div>
  <script>
    function copyCode(){
      const code = document.getElementById('code-val').textContent;
      navigator.clipboard.writeText(code).then(()=>{
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(()=>btn.textContent='Copy', 1500);
      });
    }
  </script>
</body>
</html>`);
};

// ─────────────────────────────────────────────────────────────
//  POST /api/oauth/token  — All 4 grant types
//
//  FIX 2: Uses maybeSingle() so "0 rows" returns null instead of
//          throwing an error. This prevents Supabase's PostgREST
//          "JSON object requested, multiple (or no) rows returned"
//          error from masking the real INVALID_GRANT response.
//
//  FIX 3: ALL validation (expiry, redirect_uri, client_id, PKCE)
//          is done BEFORE the code is marked as used. Previously
//          a redirect_uri mismatch would burn the code without
//          issuing tokens.
// ─────────────────────────────────────────────────────────────
const token = async (req, res) => {
  const { grant_type } = req.body;
  const ip = getClientIp(req);

  // ── authorization_code ────────────────────────────────────
  if (grant_type === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;
    const { client_id, client_secret } = extractClientCredentials(req);

    if (!code || !redirect_uri)
      return error(res, 400, 'MISSING_PARAMS', 'Required fields missing: code, redirect_uri');
    if (!client_id || !client_secret)
      return error(res, 401, 'INVALID_CLIENT',
        'client_id and client_secret are required (via body or Basic Auth header).');

    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');
    if (!client.grant_types.includes('authorization_code'))
      return error(res, 400, 'UNAUTHORIZED_GRANT_TYPE', 'Client not authorized for authorization_code.');

    // ── FIX 2: use maybeSingle() — returns null when 0 rows, ─
    //    no error thrown. .single() throws when row count ≠ 1,
    //    which caused genuine "not found" to surface as a 500.
    const { data: codeRecord, error: codeErr } = await supabase
      .from('oauth_auth_codes')
      .select('*')
      .eq('code', code)
      .maybeSingle();

    // Code not in DB at all — never existed or already deleted
    if (codeErr) {
      console.error('[OAuth] DB error fetching auth code:', codeErr.message);
      return error(res, 500, 'DB_ERROR', 'Database error while validating authorization code.');
    }

    if (!codeRecord) {
      return error(res, 400, 'INVALID_GRANT',
        'Authorization code not found. It may have expired or been used already.');
    }

    // Code was previously marked used — replay attack
    if (codeRecord.used) {
      // Revoke all tokens issued to this client as a security measure
      await Promise.all([
        supabase.from('oauth_auth_codes').delete().eq('code', code),
        supabase.from('oauth_access_tokens').delete().eq('client_id', client_id),
      ]);
      return error(res, 400, 'CODE_REUSE_DETECTED',
        'Authorization code has already been used. All tokens for this client have been revoked for security.');
    }

    // ── FIX 3: Validate ALL constraints BEFORE consuming code ─
    // This ensures a bad request (wrong redirect_uri, expired code,
    // PKCE mismatch) does NOT burn the code. The user can retry.

    if (new Date() > new Date(codeRecord.expires_at)) {
      await supabase.from('oauth_auth_codes').delete().eq('code', code);
      return error(res, 400, 'CODE_EXPIRED',
        'Authorization code has expired. Please restart the authorization flow.');
    }

    if (codeRecord.redirect_uri !== redirect_uri) {
      return error(res, 400, 'REDIRECT_URI_MISMATCH',
        `redirect_uri mismatch. Expected: ${codeRecord.redirect_uri} — Got: ${redirect_uri}`);
    }

    if (codeRecord.client_id !== client_id) {
      return error(res, 400, 'CLIENT_MISMATCH',
        'Authorization code was issued to a different client.');
    }

    if (codeRecord.code_challenge) {
      if (!code_verifier)
        return error(res, 400, 'PKCE_REQUIRED', 'code_verifier is required for PKCE.');
      if (!verifyCodeChallenge(
            code_verifier,
            codeRecord.code_challenge,
            codeRecord.code_challenge_method || 'plain'))
        return error(res, 400, 'PKCE_MISMATCH', 'code_verifier does not match code_challenge.');
    }

    // ── All checks passed — atomically consume & issue tokens ─
    const { error: updateErr } = await supabase
      .from('oauth_auth_codes')
      .update({ used: true })
      .eq('code', code)
      .eq('used', false); // extra guard: only update if still unused (concurrent request safety)

    if (updateErr) {
      console.error('[OAuth] Failed to mark code as used:', updateErr.message);
      return error(res, 500, 'DB_ERROR', 'Database error while consuming authorization code.');
    }

    const tokenData = await buildTokenResponse(
      codeRecord.user_id, client_id, codeRecord.scope);

    audit(AUDIT_EVENTS.OAUTH_TOKEN, {
      ip, clientId: client_id,
      grant: 'authorization_code',
      userId: codeRecord.user_id,
    });

    return success(res, tokenData, 'Token issued via authorization_code.');
  }

  // ── client_credentials ────────────────────────────────────
  if (grant_type === 'client_credentials') {
    const { scope } = req.body;
    const { client_id, client_secret } = extractClientCredentials(req);

    if (!client_id || !client_secret)
      return error(res, 401, 'INVALID_CLIENT',
        'client_id and client_secret are required (via body or Basic Auth header).');

    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');
    if (!client.grant_types.includes('client_credentials'))
      return error(res, 400, 'UNAUTHORIZED_GRANT_TYPE', 'Client not authorized for client_credentials.');

    const requestedScope = (scope || 'read:patients').split(' ').filter(Boolean);
    const invalidScopes  = requestedScope.filter(s => !client.scopes.includes(s));
    if (invalidScopes.length)
      return error(res, 400, 'INVALID_SCOPE', `Scope(s) not permitted: ${invalidScopes.join(', ')}`);

    const accessToken = generateSecureToken('hapi_cc');
    const expiresAt   = new Date(Date.now() + OAUTH_ACCESS_TOKEN_TTL * 1000).toISOString();
    await supabase.from('oauth_access_tokens').insert({
      token: accessToken, user_id: null, client_id,
      scope: requestedScope.join(' '), expires_at: expiresAt,
    });
    audit(AUDIT_EVENTS.OAUTH_TOKEN, { ip, clientId: client_id, grant: 'client_credentials' });
    return res.status(200).json({
      success: true, message: 'Token issued via client_credentials.',
      data: {
        access_token: accessToken, token_type: 'Bearer',
        expires_in: OAUTH_ACCESS_TOKEN_TTL, scope: requestedScope.join(' '),
        note: 'client_credentials does not issue a refresh_token.',
      },
    });
  }

  // ── password ──────────────────────────────────────────────
  if (grant_type === 'password') {
    const { username, password, scope } = req.body;
    const { client_id, client_secret } = extractClientCredentials(req);

    if (!username || !password)
      return error(res, 400, 'MISSING_PARAMS', 'Required fields missing: username, password');
    if (!client_id || !client_secret)
      return error(res, 401, 'INVALID_CLIENT',
        'client_id and client_secret are required (via body or Basic Auth header).');

    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');
    if (!client.grant_types.includes('password'))
      return error(res, 400, 'UNAUTHORIZED_GRANT_TYPE', 'Client not authorized for password grant.');

    const dummyHash = '$2a$10$dummy.hash.to.prevent.timing.attacks.from.user.enumeration.';
    const user = await lookupUser(username);
    const hashToCheck = user ? user.password : dummyHash;
    const valid = await bcrypt.compare(password, hashToCheck);

    if (!user || !valid)
      return error(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.');

    const tokenData = await buildTokenResponse(
      user.id, client_id, scope || 'read:patients read:appointments');
    audit(AUDIT_EVENTS.OAUTH_TOKEN, { ip, clientId: client_id, grant: 'password', userId: user.id });
    return success(res, tokenData, 'Token issued via password grant.');
  }

  // ── refresh_token ─────────────────────────────────────────
  if (grant_type === 'refresh_token') {
    const { refresh_token } = req.body;
    const { client_id, client_secret } = extractClientCredentials(req);

    if (!refresh_token)
      return error(res, 400, 'MISSING_PARAMS', 'Required field missing: refresh_token');
    if (!client_id || !client_secret)
      return error(res, 401, 'INVALID_CLIENT',
        'client_id and client_secret are required (via body or Basic Auth header).');

    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');
    if (!client.grant_types.includes('refresh_token'))
      return error(res, 400, 'UNAUTHORIZED_GRANT_TYPE', 'Client not authorized for refresh_token.');

    const { data: rtRecord } = await supabase
      .from('oauth_refresh_tokens').select('*').eq('token', refresh_token).maybeSingle();
    if (!rtRecord)
      return error(res, 400, 'INVALID_GRANT', 'Refresh token not found or revoked.');
    if (rtRecord.client_id !== client_id)
      return error(res, 400, 'CLIENT_MISMATCH', 'Refresh token was issued to a different client.');

    await supabase.from('oauth_refresh_tokens').delete().eq('token', refresh_token);
    const tokenData = await buildTokenResponse(rtRecord.user_id, client_id, rtRecord.scope);
    audit(AUDIT_EVENTS.OAUTH_TOKEN, {
      ip, clientId: client_id, grant: 'refresh_token', userId: rtRecord.user_id });
    return success(res, { ...tokenData, note: 'Previous refresh_token revoked.' }, 'New tokens issued.');
  }

  return error(res, 400, 'UNSUPPORTED_GRANT_TYPE',
    `grant_type '${grant_type}' is not supported. ` +
    'Supported: authorization_code, client_credentials, password, refresh_token.');
};

// ─────────────────────────────────────────────────────────────
//  POST /api/oauth/revoke
// ─────────────────────────────────────────────────────────────
const revoke = async (req, res) => {
  const { token: tok, token_type_hint } = req.body;
  const { client_id, client_secret } = extractClientCredentials(req);

  if (!tok) return error(res, 400, 'MISSING_PARAMS', 'token is required.');
  const client = await validateClient(client_id, client_secret);
  if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');

  const tables = token_type_hint === 'refresh_token'
    ? ['oauth_refresh_tokens', 'oauth_access_tokens']
    : ['oauth_access_tokens', 'oauth_refresh_tokens'];

  let revoked = false;
  for (const table of tables) {
    const { data, error: dbErr } = await supabase.from(table).delete().eq('token', tok).select('token');
    if (!dbErr && data && data.length > 0) { revoked = true; break; }
  }
  audit(AUDIT_EVENTS.OAUTH_REVOKE, { clientId: client_id, revoked });
  return res.status(200).json({
    success: true, revoked,
    message: revoked
      ? 'Token revoked.'
      : 'Token not found (may already be expired or revoked).',
  });
};

// ─────────────────────────────────────────────────────────────
//  POST /api/oauth/introspect
// ─────────────────────────────────────────────────────────────
const introspect = async (req, res) => {
  const { token: tok } = req.body;
  const { client_id, client_secret } = extractClientCredentials(req);

  if (!tok) return error(res, 400, 'MISSING_PARAMS', 'token is required.');
  const client = await validateClient(client_id, client_secret);
  if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');

  const { data: record } = await supabase
    .from('oauth_access_tokens')
    .select('*, users(email, role, name, department)')
    .eq('token', tok)
    .maybeSingle();

  if (!record || new Date() > new Date(record.expires_at)) {
    if (record) await supabase.from('oauth_access_tokens').delete().eq('token', tok);
    return res.status(200).json({ active: false });
  }
  const u = record.users;
  return res.status(200).json({
    active: true, scope: record.scope, client_id: record.client_id,
    username: u?.email || null, token_type: 'Bearer',
    exp: Math.floor(new Date(record.expires_at).getTime() / 1000),
    iat: Math.floor(new Date(record.created_at).getTime() / 1000),
    sub: record.user_id || 'service-account', iss: ISSUER,
    role: u?.role || 'service', name: u?.name || null, department: u?.department || null,
  });
};

// ─────────────────────────────────────────────────────────────
//  GET /api/auth/apikeys
// ─────────────────────────────────────────────────────────────
const listApiKeys = async (req, res) => {
  const { data } = await supabase
    .from('api_keys').select('key, role, description, created_at');
  return success(res, data || [], 'Available API keys for Basic Auth and X-API-Key testing.');
};

module.exports = {
  listClients, serverMetadata,
  authorize, authorizePost,
  callbackPage,
  token, revoke, introspect,
  listApiKeys,
};