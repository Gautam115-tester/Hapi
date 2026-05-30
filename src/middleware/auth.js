// src/middleware/auth.js
const jwt      = require('jsonwebtoken');
const { JWT_SECRET } = require('../utils/config');
const supabase = require('../utils/db');

// ─────────────────────────────────────────────────────────────
//  UNIFIED AUTHENTICATE MIDDLEWARE
//  Priority: 1. Basic Auth  2. Bearer JWT  3. Bearer OAuth2
// ─────────────────────────────────────────────────────────────
const authenticate = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';

  if (authHeader.startsWith('Basic '))  return handleBasicAuth(req, res, next, authHeader);
  if (authHeader.startsWith('Bearer ')) return handleBearerAuth(req, res, next, authHeader);

  return res.status(401).json({
    success: false,
    error: {
      code: 'MISSING_AUTH',
      message: 'Authorization header is required.',
      supportedSchemes: ['Basic', 'Bearer (JWT)', 'Bearer (OAuth2 token)'],
    },
  });
};

// ── Basic Auth ────────────────────────────────────────────────
const handleBasicAuth = async (req, res, next, authHeader) => {
  try {
    const base64   = authHeader.split(' ')[1];
    const decoded  = Buffer.from(base64, 'base64').toString('utf-8');
    const colonIdx = decoded.indexOf(':');

    if (colonIdx === -1) {
      return res.status(401).json({ success: false, error: { code: 'BASIC_AUTH_MALFORMED', message: 'Credentials must be base64(username:password).' } });
    }

    const username   = decoded.slice(0, colonIdx);
    const credential = decoded.slice(colonIdx + 1);

    // Try API Key first
    const { data: keyRow } = await supabase
      .from('api_keys')
      .select('*, users(*)')
      .eq('key', credential)
      .single();

    if (keyRow) {
      const u = keyRow.users;
      req.user       = { id: u.id, name: u.name, email: u.email, role: u.role };
      req.authMethod = 'basic-apikey';
      return next();
    }

    // Try password (plain "Admin@1234" accepted for dev convenience)
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', username)
      .single();

    if (!user || credential !== 'Admin@1234') {
      return res.status(401).json({ success: false, error: { code: 'BASIC_AUTH_INVALID', message: 'Invalid username or password.' } });
    }

    req.user       = { id: user.id, name: user.name, email: user.email, role: user.role };
    req.authMethod = 'basic-password';
    return next();
  } catch {
    return res.status(401).json({ success: false, error: { code: 'BASIC_AUTH_ERROR', message: 'Could not decode Basic auth header.' } });
  }
};

// ── Bearer Auth (JWT or OAuth2 opaque) ───────────────────────
const handleBearerAuth = async (req, res, next, authHeader) => {
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: { code: 'MISSING_TOKEN', message: 'Bearer token is empty.' } });

  // Try JWT (3 dot-separated segments)
  if (token.split('.').length === 3) {
    try {
      const decoded  = jwt.verify(token, JWT_SECRET);
      req.user       = { id: decoded.id, name: decoded.name, email: decoded.email, role: decoded.role };
      req.authMethod = 'bearer-jwt';
      return next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ success: false, error: { code: 'TOKEN_EXPIRED', message: 'JWT has expired. Please refresh or log in again.' } });
      }
      // fall through to OAuth2 check
    }
  }

  // Try OAuth2 opaque token
  const { data: oauthRecord } = await supabase
    .from('oauth_access_tokens')
    .select('*, users(*)')
    .eq('token', token)
    .single();

  if (oauthRecord) {
    if (new Date() > new Date(oauthRecord.expires_at)) {
      await supabase.from('oauth_access_tokens').delete().eq('token', token);
      return res.status(401).json({ success: false, error: { code: 'OAUTH_TOKEN_EXPIRED', message: 'OAuth2 access token expired. Use refresh_token.' } });
    }
    const u        = oauthRecord.users;
    req.user       = { id: u.id, name: u.name, email: u.email, role: u.role };
    req.oauthScope = oauthRecord.scope;
    req.authMethod = 'bearer-oauth2';
    return next();
  }

  return res.status(401).json({
    success: false,
    error: { code: 'INVALID_TOKEN', message: 'Token is invalid, expired, or unrecognized.' },
  });
};

// ── Role-Based Access Control ─────────────────────────────────
const authorize = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: { code: 'UNAUTHENTICATED', message: 'Please authenticate first.' } });
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      error: { code: 'FORBIDDEN', message: `Access denied. Required: [${roles.join(', ')}]. Your role: ${req.user.role}` },
    });
  }
  next();
};

module.exports = { authenticate, authorize };