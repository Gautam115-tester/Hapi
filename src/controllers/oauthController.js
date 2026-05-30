// src/controllers/oauthController.js
const crypto   = require('crypto');
const supabase = require('../utils/db');
const { OAUTH_ACCESS_TOKEN_TTL, OAUTH_REFRESH_TOKEN_TTL, OAUTH_AUTH_CODE_TTL, BASE_URL } = require('../utils/config');
const { success, error } = require('../utils/response');

const generateToken = (prefix = 'hapi') => `${prefix}_${crypto.randomBytes(24).toString('hex')}`;

const validateClient = async (clientId, clientSecret) => {
  const { data } = await supabase.from('oauth_clients')
    .select('*').eq('client_id', clientId).eq('client_secret', clientSecret).single();
  return data;
};

// ── GET /api/oauth/clients ────────────────────────────────────
const listClients = async (req, res) => {
  const { data } = await supabase.from('oauth_clients').select('client_id, name, redirect_uris, grant_types, scopes');
  return success(res, data || [], 'Registered OAuth2 clients.');
};

// ── GET /api/oauth/.well-known/oauth-authorization-server ─────
const serverMetadata = (req, res) => {
  return res.status(200).json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/api/oauth/authorize`,
    token_endpoint:         `${BASE_URL}/api/oauth/token`,
    revocation_endpoint:    `${BASE_URL}/api/oauth/revoke`,
    introspection_endpoint: `${BASE_URL}/api/oauth/introspect`,
    grant_types_supported:  ['authorization_code', 'client_credentials', 'password', 'refresh_token'],
    response_types_supported: ['code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: ['read:patients', 'write:patients', 'read:appointments', 'write:appointments', 'read:records', 'admin'],
    code_challenge_methods_supported: ['S256'],
  });
};

// ── GET /api/oauth/authorize ──────────────────────────────────
const authorize = async (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

  if (response_type !== 'code') return error(res, 400, 'UNSUPPORTED_RESPONSE_TYPE', 'response_type must be "code".');

  const { data: client } = await supabase.from('oauth_clients').select('*').eq('client_id', client_id).single();
  if (!client) return error(res, 401, 'INVALID_CLIENT', `No registered client with client_id: ${client_id}`);

  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return error(res, 400, 'INVALID_REDIRECT_URI', `redirect_uri '${redirect_uri}' not registered. Allowed: ${client.redirect_uris.join(', ')}`);
  }

  const requestedScopes = (scope || 'read:patients').split(' ');
  const invalidScopes   = requestedScopes.filter((s) => !client.scopes.includes(s));
  if (invalidScopes.length > 0) return error(res, 400, 'INVALID_SCOPE', `Scope(s) not allowed: ${invalidScopes.join(', ')}`);

  const code      = generateToken('hapi_code');
  const expiresAt = new Date(Date.now() + OAUTH_AUTH_CODE_TTL * 1000).toISOString();

  await supabase.from('oauth_auth_codes').insert({
    code, user_id: 'usr_001', client_id,
    scope: requestedScopes.join(' '), redirect_uri,
    expires_at: expiresAt,
    code_challenge: code_challenge || null,
    code_challenge_method: code_challenge_method || null,
    used: false,
  });

  return res.status(200).json({
    success: true,
    message: 'Authorization code issued. In a real app the user would be redirected.',
    data: {
      code, state: state || null, redirect_uri,
      expiresIn: `${OAUTH_AUTH_CODE_TTL} seconds`,
      note: 'Use this code in POST /api/oauth/token with grant_type=authorization_code',
      simulatedRedirect: `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`,
    },
  });
};

// ── POST /api/oauth/token ─────────────────────────────────────
const token = async (req, res) => {
  const { grant_type } = req.body;

  // ── authorization_code ────────────────────────────────────
  if (grant_type === 'authorization_code') {
    const { code, redirect_uri, client_id, client_secret, code_verifier } = req.body;
    if (!code || !redirect_uri || !client_id || !client_secret) return error(res, 400, 'MISSING_PARAMS', 'Required: code, redirect_uri, client_id, client_secret');

    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'client_id or client_secret is incorrect.');

    const { data: codeRecord, error: codeErr } = await supabase.from('oauth_auth_codes').select('*').eq('code', code).single();
    if (codeErr || !codeRecord) return error(res, 400, 'INVALID_GRANT', 'Authorization code not found or already used.');
    if (codeRecord.used)       { await supabase.from('oauth_auth_codes').delete().eq('code', code); return error(res, 400, 'CODE_REUSE', 'Code already used.'); }
    if (new Date() > new Date(codeRecord.expires_at)) { await supabase.from('oauth_auth_codes').delete().eq('code', code); return error(res, 400, 'CODE_EXPIRED', 'Authorization code expired.'); }
    if (codeRecord.redirect_uri !== redirect_uri) return error(res, 400, 'REDIRECT_MISMATCH', 'redirect_uri mismatch.');
    if (codeRecord.client_id !== client_id)       return error(res, 400, 'CLIENT_MISMATCH',   'Code issued to different client.');

    if (codeRecord.code_challenge) {
      if (!code_verifier) return error(res, 400, 'PKCE_REQUIRED', 'code_verifier required (PKCE).');
      const expected = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (expected !== codeRecord.code_challenge) return error(res, 400, 'PKCE_MISMATCH', 'code_verifier mismatch.');
    }

    await supabase.from('oauth_auth_codes').update({ used: true }).eq('code', code);
    return success(res, await buildTokenResponse(codeRecord.user_id, client_id, codeRecord.scope), 'Token issued via authorization_code.', 200);
  }

  // ── client_credentials ────────────────────────────────────
  if (grant_type === 'client_credentials') {
    const { client_id, client_secret, scope } = req.body;
    if (!client_id || !client_secret) return error(res, 400, 'MISSING_PARAMS', 'Required: client_id, client_secret');
    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'Incorrect client credentials.');
    if (!client.grant_types.includes('client_credentials')) return error(res, 400, 'UNAUTHORIZED_GRANT', 'Client not allowed to use client_credentials.');

    const reqScope = scope || 'read:patients';
    const invalid  = reqScope.split(' ').filter((s) => !client.scopes.includes(s));
    if (invalid.length) return error(res, 400, 'INVALID_SCOPE', `Scopes not permitted: ${invalid.join(', ')}`);

    const accessToken = generateToken('hapi_cc');
    const expiresAt   = new Date(Date.now() + OAUTH_ACCESS_TOKEN_TTL * 1000).toISOString();
    await supabase.from('oauth_access_tokens').insert({ token: accessToken, user_id: null, client_id, scope: reqScope, expires_at: expiresAt });

    return res.status(200).json({ success: true, message: 'Token issued via client_credentials.', data: { access_token: accessToken, token_type: 'Bearer', expires_in: OAUTH_ACCESS_TOKEN_TTL, scope: reqScope } });
  }

  // ── password grant ─────────────────────────────────────────
  if (grant_type === 'password') {
    const { username, password, client_id, client_secret, scope } = req.body;
    if (!username || !password || !client_id || !client_secret) return error(res, 400, 'MISSING_PARAMS', 'Required: username, password, client_id, client_secret');
    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'Incorrect client credentials.');
    if (!client.grant_types.includes('password')) return error(res, 400, 'UNAUTHORIZED_GRANT', 'Client not allowed to use password grant.');

    const { data: user } = await supabase.from('users').select('*').eq('email', username).single();
    if (!user || password !== 'Admin@1234') return error(res, 401, 'INVALID_CREDENTIALS', 'Invalid username or password.');

    const grantedScope = scope || 'read:patients read:appointments';
    return success(res, await buildTokenResponse(user.id, client_id, grantedScope), 'Token issued via password grant.', 200);
  }

  // ── refresh_token ─────────────────────────────────────────
  if (grant_type === 'refresh_token') {
    const { refresh_token, client_id, client_secret } = req.body;
    if (!refresh_token || !client_id || !client_secret) return error(res, 400, 'MISSING_PARAMS', 'Required: refresh_token, client_id, client_secret');
    const client = await validateClient(client_id, client_secret);
    if (!client) return error(res, 401, 'INVALID_CLIENT', 'Incorrect client credentials.');

    const { data: rtRecord } = await supabase.from('oauth_refresh_tokens').select('*').eq('token', refresh_token).single();
    if (!rtRecord) return error(res, 400, 'INVALID_GRANT', 'Refresh token not found or revoked.');
    if (rtRecord.client_id !== client_id) return error(res, 400, 'CLIENT_MISMATCH', 'Token issued to different client.');

    await supabase.from('oauth_refresh_tokens').delete().eq('token', refresh_token);
    return success(res, await buildTokenResponse(rtRecord.user_id, client_id, rtRecord.scope), 'New token issued via refresh_token. Old token revoked.', 200);
  }

  return error(res, 400, 'UNSUPPORTED_GRANT_TYPE', `grant_type '${grant_type}' not supported. Supported: authorization_code, client_credentials, password, refresh_token`);
};

// Helper: persist and return token pair
const buildTokenResponse = async (userId, clientId, scope) => {
  const accessToken  = generateToken('hapi_at');
  const refreshToken = generateToken('hapi_rt');
  const now = Date.now();

  const { data: user } = userId ? await supabase.from('users').select('id, name, role').eq('id', userId).single() : { data: null };

  await Promise.all([
    supabase.from('oauth_access_tokens').insert({ token: accessToken, user_id: userId, client_id: clientId, scope, expires_at: new Date(now + OAUTH_ACCESS_TOKEN_TTL * 1000).toISOString() }),
    supabase.from('oauth_refresh_tokens').insert({ token: refreshToken, user_id: userId, client_id: clientId, scope }),
  ]);

  return { access_token: accessToken, token_type: 'Bearer', expires_in: OAUTH_ACCESS_TOKEN_TTL, refresh_token: refreshToken, scope, user };
};

// ── POST /api/oauth/revoke ────────────────────────────────────
const revoke = async (req, res) => {
  const { token: tok, client_id, client_secret } = req.body;
  if (!tok) return error(res, 400, 'MISSING_PARAMS', 'token is required.');
  const client = await validateClient(client_id, client_secret);
  if (!client) return error(res, 401, 'INVALID_CLIENT', 'Incorrect client credentials.');

  const [{ count: c1 }, { count: c2 }] = await Promise.all([
    supabase.from('oauth_access_tokens').delete().eq('token', tok).select('*', { count: 'exact', head: true }),
    supabase.from('oauth_refresh_tokens').delete().eq('token', tok).select('*', { count: 'exact', head: true }),
  ]);

  return res.status(200).json({ success: true, message: (c1 || c2) ? 'Token revoked successfully.' : 'Token not found.', revoked: !!(c1 || c2) });
};

// ── POST /api/oauth/introspect ────────────────────────────────
const introspect = async (req, res) => {
  const { token: tok, client_id, client_secret } = req.body;
  if (!tok) return error(res, 400, 'MISSING_PARAMS', 'token is required.');
  const client = await validateClient(client_id, client_secret);
  if (!client) return error(res, 401, 'INVALID_CLIENT', 'Incorrect client credentials.');

  const { data: record } = await supabase.from('oauth_access_tokens').select('*, users(email, role)').eq('token', tok).single();
  if (!record || new Date() > new Date(record.expires_at)) return res.status(200).json({ active: false });

  return res.status(200).json({
    active: true, scope: record.scope, client_id: record.client_id, token_type: 'Bearer',
    exp: Math.floor(new Date(record.expires_at).getTime() / 1000),
    sub: record.user_id || 'service-account',
    username: record.users?.email || null,
    role: record.users?.role || null,
  });
};

// ── GET /api/auth/apikeys (admin only) ────────────────────────
const listApiKeys = async (req, res) => {
  const { data } = await supabase.from('api_keys').select('key, role, description, created_at');
  return success(res, data || [], 'Available API keys for Basic Auth testing.');
};

module.exports = { listClients, serverMetadata, authorize, token, revoke, introspect, listApiKeys };