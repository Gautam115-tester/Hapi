// src/controllers/developerController.js
// ============================================================
//  HealthAPI — Integration Access Portal
//
//  Healthcare professionals and IT teams register here to
//  obtain OAuth 2.0 credentials for system integration,
//  clinical data access, and API connectivity testing.
//
//  POST /api/register            — register and receive credentials
//  POST /api/register/login      — authenticate and retrieve credentials
//  GET  /api/register/me         — view active credentials
//  POST /api/register/regenerate — rotate client secret
// ============================================================

const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const jwt      = require('jsonwebtoken');
const supabase = require('../utils/db');
const { JWT_SECRET, JWT_EXPIRES_IN, BASE_URL } = require('../utils/config');
const { success, error } = require('../utils/response');

const ISSUER  = BASE_URL || 'https://healthapi.onrender.com';
const API_VER = 'v2.0';

const generateClientId = (fullName) => {
  const slug = fullName
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 18);
  const rand = crypto.randomBytes(4).toString('hex');
  return `hapi_${slug}_${rand}`;
};

const generateClientSecret = () =>
  'hapi_sk_' + crypto.randomBytes(22).toString('hex');

const signToken = (account) =>
  jwt.sign(
    { sub: account.id, email: account.email, name: account.name, type: 'tester' },
    JWT_SECRET,
    { issuer: ISSUER, expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
  );

const roleLabels = {
  doctor:           'Medical Doctor',
  nurse:            'Registered Nurse',
  lab_technician:   'Laboratory Technician',
  researcher:       'Clinical Researcher',
  it_administrator: 'IT Administrator',
  auditor:          'Compliance Auditor',
};

const buildAccessBlock = (clientId, clientSecret) => ({
  client_id:     clientId,
  client_secret: clientSecret,
  authorization_endpoint: `${ISSUER}/api/oauth/authorize`,
  token_endpoint:         `${ISSUER}/api/oauth/token`,
  token_endpoint_auth_method: 'client_secret_basic',
  grant_types_supported:  ['client_credentials', 'authorization_code', 'refresh_token', 'password'],
  scopes_granted: [
    'read:patients',
    'write:patients',
    'read:appointments',
    'write:appointments',
    'read:records',
  ],
  access_token_ttl:  '3600 seconds (1 hour)',
  refresh_token_ttl: '604800 seconds (7 days)',
});

const buildIntegrationGuide = (clientId, clientSecret) => ({
  postman: {
    authorization_type: 'OAuth 2.0',
    grant_type:         'Client Credentials',
    access_token_url:   `${ISSUER}/api/oauth/token`,
    client_id:           clientId,
    client_secret:       clientSecret,
    scope:              'read:patients write:patients read:appointments',
    client_authentication: 'Send as Basic Auth header',
  },
  curl_example: `curl -X POST ${ISSUER}/api/oauth/token \\\n  -H "Content-Type: application/x-www-form-urlencoded" \\\n  -d "grant_type=client_credentials&client_id=${clientId}&client_secret=${clientSecret}&scope=read:patients"`,
});

// ─────────────────────────────────────────────────────────────
//  POST /api/register
// ─────────────────────────────────────────────────────────────
const register = async (req, res) => {
  const { fullName, email, password, organisation, role } = req.body;

  const missing = ['fullName', 'email', 'password', 'organisation', 'role']
    .filter(f => !req.body[f]);
  if (missing.length)
    return error(res, 422, 'VALIDATION_ERROR',
      `Required fields missing: ${missing.join(', ')}.`);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return error(res, 422, 'VALIDATION_ERROR', 'A valid institutional email address is required.');

  if (password.length < 6)
    return error(res, 422, 'VALIDATION_ERROR', 'Password must be at least 6 characters.');

  const allowedRoles = ['doctor', 'nurse', 'lab_technician', 'researcher', 'it_administrator', 'auditor'];
  if (!allowedRoles.includes(role))
    return error(res, 422, 'VALIDATION_ERROR',
      `Invalid role. Accepted values: ${allowedRoles.join(', ')}.`);

  const { data: existing } = await supabase
    .from('api_tester_accounts')
    .select('id')
    .eq('email', email.toLowerCase().trim())
    .single();

  if (existing)
    return error(res, 409, 'ACCOUNT_EXISTS',
      `An access account is already registered under ${email}. Please authenticate via POST /api/register/login.`);

  const hashedPassword = await bcrypt.hash(password, 10);
  const clientId       = generateClientId(fullName);
  const clientSecret   = generateClientSecret();

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

  // Register as live OAuth client — all 4 callback URIs included
  await supabase.from('oauth_clients').insert({
    client_id:     clientId,
    client_secret: clientSecret,
    name:          `${fullName.trim()} · ${organisation.trim()}`,
    redirect_uris: [
      'https://oauth.pstmn.io/v1/callback',
      'http://localhost:3000/callback',
      'http://localhost:3000/api/oauth/callback',
      `${ISSUER}/api/oauth/callback`,
    ],
    grant_types:   ['authorization_code', 'client_credentials', 'refresh_token', 'password'],
    scopes:        ['read:patients', 'write:patients', 'read:appointments',
                    'write:appointments', 'read:records', 'admin'],
  });

  const sessionToken = signToken({
    id: account.id, email: account.email, name: account.full_name,
  });

  return success(res, {
    api:     'HealthAPI',
    version:  API_VER,
    status:  'ACCESS_GRANTED',

    practitioner: {
      name:          account.full_name,
      email:         account.email,
      role:          roleLabels[account.role] || account.role,
      organisation:  account.organisation,
      access_issued: account.created_at,
      account_id:    account.id,
    },

    access_credentials: buildAccessBlock(clientId, clientSecret),

    integration_guide: buildIntegrationGuide(clientId, clientSecret),

    session: {
      token:      sessionToken,
      token_type: 'Bearer',
      expires_in: JWT_EXPIRES_IN,
      usage:      'Use this token in Authorization: Bearer <token> to access GET /api/register/me only. To access patient/appointment data, use the OAuth access token from step below.',
    },

    how_to_access_api: {
      description: 'Use client_credentials grant to get an OAuth access token for all API endpoints',
      step1: {
        method:  'POST',
        url:     `${ISSUER}/api/oauth/token`,
        headers: { 'Content-Type': 'application/json' },
        body: {
          grant_type:    'client_credentials',
          client_id:     clientId,
          client_secret: clientSecret,
          scope:         'read:patients write:patients read:appointments',
        },
      },
      step2: 'Copy access_token from the response',
      step3: `Use it on any endpoint: GET ${ISSUER}/api/patients  →  Authorization: Bearer <access_token>`,
    },

    important_notice: [
      'Store your client_secret securely — treat it like a password.',
      'Do not share or commit your client_secret to version control.',
      'If your client_secret is compromised, rotate it immediately via POST /api/register/regenerate.',
      'Access tokens expire after 1 hour. Use the refresh_token grant to obtain new ones.',
      'All API access is logged and auditable per hospital data governance policy.',
    ],

    endpoints: {
      retrieve_credentials: `GET  ${ISSUER}/api/register/me`,
      rotate_secret:        `POST ${ISSUER}/api/register/regenerate`,
      token_endpoint:       `POST ${ISSUER}/api/oauth/token`,
      api_documentation:    `GET  ${ISSUER}/api/docs`,
    },
  }, 'Access credentials issued. Integration access is now active for your account.', 201);
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
    return error(res, 401, 'INVALID_CREDENTIALS',
      'Authentication failed. Verify your email and password and try again.');

  const sessionToken = signToken({
    id: account.id, email: account.email, name: account.full_name,
  });

  return success(res, {
    api:    'HealthAPI',
    version: API_VER,
    status: 'AUTHENTICATED',

    practitioner: {
      name:         account.full_name,
      email:        account.email,
      role:         roleLabels[account.role] || account.role,
      organisation: account.organisation,
      account_id:   account.id,
    },

    access_credentials: buildAccessBlock(account.client_id, account.client_secret),

    integration_guide: buildIntegrationGuide(account.client_id, account.client_secret),

    session: {
      token:      sessionToken,
      token_type: 'Bearer',
      expires_in: JWT_EXPIRES_IN,
      usage:      'Use this token in Authorization: Bearer <token> to access GET /api/register/me only. To access patient/appointment data, use the OAuth access token from step below.',
    },

    how_to_access_api: {
      description: 'Use client_credentials grant to get an OAuth access token for all API endpoints',
      step1: {
        method:  'POST',
        url:     `${ISSUER}/api/oauth/token`,
        headers: { 'Content-Type': 'application/json' },
        body: {
          grant_type:    'client_credentials',
          client_id:     account.client_id,
          client_secret: account.client_secret,
          scope:         'read:patients write:patients read:appointments',
        },
      },
      step2: 'Copy access_token from the response',
      step3: `Use it on any endpoint: GET ${ISSUER}/api/patients  →  Authorization: Bearer <access_token>`,
    },
  }, 'Authentication successful. Your integration credentials are listed below.');
};

// ─────────────────────────────────────────────────────────────
//  GET /api/register/me
// ─────────────────────────────────────────────────────────────
const me = async (req, res) => {
  const { data: account } = await supabase
    .from('api_tester_accounts')
    .select('id, full_name, email, organisation, role, client_id, client_secret, created_at')
    .eq('id', req.tester.id)
    .single();

  if (!account)
    return error(res, 404, 'ACCOUNT_NOT_FOUND',
      'No access account found for this session. Please re-register.');

  return success(res, {
    api:    'HealthAPI',
    version: API_VER,
    status: 'ACTIVE',

    practitioner: {
      name:          account.full_name,
      email:         account.email,
      role:          roleLabels[account.role] || account.role,
      organisation:  account.organisation,
      access_issued: account.created_at,
      account_id:    account.id,
    },

    access_credentials: buildAccessBlock(account.client_id, account.client_secret),

    integration_guide: buildIntegrationGuide(account.client_id, account.client_secret),

    how_to_access_api: {
      description: 'Use client_credentials grant to get an OAuth access token for all API endpoints',
      step1: {
        method:  'POST',
        url:     `${ISSUER}/api/oauth/token`,
        body: {
          grant_type:    'client_credentials',
          client_id:     account.client_id,
          client_secret: account.client_secret,
          scope:         'read:patients write:patients read:appointments',
        },
      },
      step2: 'Copy access_token from the response',
      step3: `Use it on any endpoint: GET ${ISSUER}/api/patients  →  Authorization: Bearer <access_token>`,
    },
  }, 'Active integration credentials for your account.');
};

// ─────────────────────────────────────────────────────────────
//  POST /api/register/regenerate
// ─────────────────────────────────────────────────────────────
const regenerateSecret = async (req, res) => {
  const { data: account } = await supabase
    .from('api_tester_accounts')
    .select('client_id, full_name, organisation, role')
    .eq('id', req.tester.id)
    .single();

  if (!account)
    return error(res, 404, 'ACCOUNT_NOT_FOUND', 'Account not found.');

  const newSecret = generateClientSecret();
  const rotatedAt = new Date().toISOString();

  await Promise.all([
    supabase.from('api_tester_accounts')
      .update({ client_secret: newSecret })
      .eq('id', req.tester.id),
    supabase.from('oauth_clients')
      .update({ client_secret: newSecret })
      .eq('client_id', account.client_id),
  ]);

  return success(res, {
    api:    'HealthAPI',
    version: API_VER,
    status: 'SECRET_ROTATED',

    practitioner: {
      name:         account.full_name,
      organisation: account.organisation,
      role:         roleLabels[account.role] || account.role,
    },

    access_credentials: buildAccessBlock(account.client_id, newSecret),

    integration_guide: buildIntegrationGuide(account.client_id, newSecret),

    security_notice: {
      rotated_at:      rotatedAt,
      previous_secret: 'INVALIDATED',
      action_required: 'Update your client_secret immediately in all integration configurations.',
    },
  }, 'Client secret rotated. Previous secret has been invalidated immediately.');
};

module.exports = { register, login, me, regenerateSecret };