// src/controllers/developerController.js
// ============================================================
//  HealthAPI — API Tester Registration Portal
//
//  Allows testers (lab participants, evaluators, integration
//  partners) to self-register and receive unique OAuth2
//  credentials to access the HealthAPI.
//
//  POST /api/register        — create tester account
//  POST /api/register/login  — login, retrieve credentials
//  GET  /api/register/me     — view my credentials (auth needed)
//  POST /api/register/regenerate — rotate client secret
// ============================================================

const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const jwt      = require('jsonwebtoken');
const supabase = require('../utils/db');
const { JWT_SECRET, JWT_EXPIRES_IN, BASE_URL } = require('../utils/config');
const { success, error } = require('../utils/response');

const ISSUER = BASE_URL || 'https://hapi-2115.onrender.com';

// ── Helpers ───────────────────────────────────────────────────
const generateClientId = (fullName) => {
  const slug = fullName
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 18);
  const rand = crypto.randomBytes(4).toString('hex');
  return `tester_${slug}_${rand}`;
};

const generateClientSecret = () =>
  'hapi_' + crypto.randomBytes(22).toString('hex');

const signToken = (account) =>
  jwt.sign(
    { sub: account.id, email: account.email, name: account.name, type: 'tester' },
    JWT_SECRET,
    { issuer: ISSUER, expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
  );

const buildCredentialBlock = (clientId, clientSecret) => ({
  client_id:     clientId,
  client_secret: clientSecret,
  auth_url:      `${ISSUER}/api/oauth/authorize`,
  token_url:     `${ISSUER}/api/oauth/token`,
  scopes_available: [
    'read:patients',
    'write:patients',
    'read:appointments',
    'write:appointments',
    'read:records',
  ],
});

const buildPostmanBlock = (clientId, clientSecret) => ({
  note:             'Fill these 4 fields in Postman → Authorization → OAuth 2.0 → Configure New Token',
  grant_type:       'Client Credentials',
  access_token_url: `${ISSUER}/api/oauth/token`,
  client_id:         clientId,
  client_secret:     clientSecret,
  scope:            'read:patients write:patients',
  client_authentication: 'Send as Basic Auth header',
});

// ─────────────────────────────────────────────────────────────
//  POST /api/register
//  Anyone testing the HealthAPI registers here.
//  Fields: fullName, email, password, organisation, role
// ─────────────────────────────────────────────────────────────
const register = async (req, res) => {
  const { fullName, email, password, organisation, role } = req.body;

  // ── Field validation ──────────────────────────────────────
  const missing = ['fullName', 'email', 'password', 'organisation', 'role']
    .filter(f => !req.body[f]);
  if (missing.length)
    return error(res, 422, 'VALIDATION_ERROR',
      `Missing required fields: ${missing.join(', ')}`);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return error(res, 422, 'VALIDATION_ERROR', 'A valid email address is required.');

  if (password.length < 6)
    return error(res, 422, 'VALIDATION_ERROR', 'Password must be at least 6 characters.');

  const allowedRoles = ['doctor', 'nurse', 'lab_technician', 'researcher', 'it_administrator', 'auditor'];
  if (!allowedRoles.includes(role))
    return error(res, 422, 'VALIDATION_ERROR',
      `role must be one of: ${allowedRoles.join(', ')}`);

  // ── Duplicate check ───────────────────────────────────────
  const { data: existing } = await supabase
    .from('api_tester_accounts')
    .select('id')
    .eq('email', email.toLowerCase().trim())
    .single();

  if (existing)
    return error(res, 409, 'EMAIL_CONFLICT',
      `An account with email '${email}' already exists. Use POST /api/register/login to retrieve your credentials.`);

  // ── Generate credentials ──────────────────────────────────
  const hashedPassword = await bcrypt.hash(password, 10);
  const clientId       = generateClientId(fullName);
  const clientSecret   = generateClientSecret();

  // ── Save tester account ───────────────────────────────────
  const { data: account, error: dbErr } = await supabase
    .from('api_tester_accounts')
    .insert({
      full_name:     fullName.trim(),
      email:         email.toLowerCase().trim(),
      password:      hashedPassword,
      organisation:  organisation.trim(),
      role,
      client_id:     clientId,
      client_secret: clientSecret,
    })
    .select('id, full_name, email, organisation, role, client_id, created_at')
    .single();

  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);

  // ── Register as live OAuth client ────────────────────────
  await supabase.from('oauth_clients').insert({
    client_id:     clientId,
    client_secret: clientSecret,
    name:          `${fullName.trim()} — ${organisation.trim()}`,
    redirect_uris: ['https://oauth.pstmn.io/v1/callback', 'http://localhost:3000/callback'],
    grant_types:   ['authorization_code', 'client_credentials', 'refresh_token', 'password'],
    scopes:        ['read:patients', 'write:patients', 'read:appointments',
                    'write:appointments', 'read:records', 'admin'],
  });

  const token = signToken({ id: account.id, email: account.email, name: account.full_name });

  return success(res, {
    session_token: token,
    account: {
      full_name:    account.full_name,
      email:        account.email,
      organisation: account.organisation,
      role:         account.role,
      registered_at: account.created_at,
    },
    oauth2_credentials: buildCredentialBlock(clientId, clientSecret),
    postman_setup:      buildPostmanBlock(clientId, clientSecret),
    next_steps: [
      'Copy your client_id and client_secret — client_secret will not be shown again.',
      'In Postman: Authorization tab → OAuth 2.0 → Configure New Token → fill the 4 fields above.',
      'Click Get New Access Token → Use Token → you can now call any HealthAPI endpoint.',
      'Use GET /api/register/me with your session_token to view credentials again anytime.',
    ],
  }, 'Account registered. Your OAuth2 credentials are ready.', 201);
};

// ─────────────────────────────────────────────────────────────
//  POST /api/register/login
// ─────────────────────────────────────────────────────────────
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return error(res, 400, 'MISSING_CREDENTIALS', 'email and password are required.');

  const { data: account } = await supabase
    .from('api_tester_accounts')
    .select('*')
    .eq('email', email.toLowerCase().trim())
    .single();

  const dummy = '$2a$10$dummy.hash.to.prevent.timing.attacks.xxxxxxxxxxxxx';
  const valid = await bcrypt.compare(password, account ? account.password : dummy);

  if (!account || !valid)
    return error(res, 401, 'INVALID_CREDENTIALS', 'Invalid email or password.');

  const token = signToken({ id: account.id, email: account.email, name: account.full_name });

  return success(res, {
    session_token: token,
    account: {
      full_name:    account.full_name,
      email:        account.email,
      organisation: account.organisation,
      role:         account.role,
    },
    oauth2_credentials: buildCredentialBlock(account.client_id, account.client_secret),
    postman_setup:      buildPostmanBlock(account.client_id, account.client_secret),
  }, 'Login successful. Your credentials are below.');
};

// ─────────────────────────────────────────────────────────────
//  GET /api/register/me   (session token required)
// ─────────────────────────────────────────────────────────────
const me = async (req, res) => {
  const { data: account } = await supabase
    .from('api_tester_accounts')
    .select('id, full_name, email, organisation, role, client_id, client_secret, created_at')
    .eq('id', req.tester.id)
    .single();

  if (!account)
    return error(res, 404, 'NOT_FOUND', 'Account not found.');

  return success(res, {
    account: {
      full_name:    account.full_name,
      email:        account.email,
      organisation: account.organisation,
      role:         account.role,
      registered_at: account.created_at,
    },
    oauth2_credentials: buildCredentialBlock(account.client_id, account.client_secret),
    postman_setup:      buildPostmanBlock(account.client_id, account.client_secret),
  }, 'Your HealthAPI credentials.');
};

// ─────────────────────────────────────────────────────────────
//  POST /api/register/regenerate  (session token required)
// ─────────────────────────────────────────────────────────────
const regenerateSecret = async (req, res) => {
  const { data: account } = await supabase
    .from('api_tester_accounts')
    .select('client_id')
    .eq('id', req.tester.id)
    .single();

  if (!account) return error(res, 404, 'NOT_FOUND', 'Account not found.');

  const newSecret = generateClientSecret();

  await Promise.all([
    supabase.from('api_tester_accounts')
      .update({ client_secret: newSecret })
      .eq('id', req.tester.id),
    supabase.from('oauth_clients')
      .update({ client_secret: newSecret })
      .eq('client_id', account.client_id),
  ]);

  return success(res, {
    oauth2_credentials: buildCredentialBlock(account.client_id, newSecret),
    postman_setup:      buildPostmanBlock(account.client_id, newSecret),
    warning: 'Your previous client_secret is now invalid. Update Postman with the new one above.',
  }, 'Client secret regenerated successfully.');
};

module.exports = { register, login, me, regenerateSecret };