// src/utils/authSecurity.js
// ============================================================
//  Auth Security Utilities
//  Brute-force protection, audit logging, token helpers
//  No DB schema changes — all in-memory for the non-persistent stuff
// ============================================================

const crypto = require('crypto');

// ── Brute-force / lockout store (in-memory) ──────────────────
// Map key: "ip:identifier"  →  { attempts, lockedUntil, firstAttemptAt }
const failStore = new Map();

const LOCKOUT_WINDOW_MS   = 15 * 60 * 1000;  // 15 min
const MAX_ATTEMPTS        = 5;
const LOCKOUT_DURATION_MS = 30 * 60 * 1000;  // 30 min

/**
 * Record a failed auth attempt.
 * @returns { locked: bool, attemptsLeft: number, lockedUntilMs: number|null }
 */
const recordFailure = (ip, identifier) => {
  const key = `${ip}:${identifier}`;
  const now  = Date.now();
  let entry  = failStore.get(key);

  if (entry) {
    // Already locked?
    if (entry.lockedUntil && now < entry.lockedUntil) {
      return { locked: true, attemptsLeft: 0, lockedUntilMs: entry.lockedUntil };
    }
    // Window expired — reset
    if (now - entry.firstAttemptAt > LOCKOUT_WINDOW_MS) {
      entry = { attempts: 0, lockedUntil: null, firstAttemptAt: now };
    }
  } else {
    entry = { attempts: 0, lockedUntil: null, firstAttemptAt: now };
  }

  entry.attempts += 1;

  if (entry.attempts >= MAX_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_DURATION_MS;
    failStore.set(key, entry);
    return { locked: true, attemptsLeft: 0, lockedUntilMs: entry.lockedUntil };
  }

  failStore.set(key, entry);
  return {
    locked:        false,
    attemptsLeft:  MAX_ATTEMPTS - entry.attempts,
    lockedUntilMs: null,
  };
};

/**
 * Check if an IP/identifier is currently locked without recording a new failure.
 */
const isLocked = (ip, identifier) => {
  const key   = `${ip}:${identifier}`;
  const entry = failStore.get(key);
  if (!entry || !entry.lockedUntil) return { locked: false };
  if (Date.now() < entry.lockedUntil) {
    return { locked: true, lockedUntilMs: entry.lockedUntil };
  }
  // Expired — clean up
  failStore.delete(key);
  return { locked: false };
};

/** Clear failures on successful auth */
const clearFailures = (ip, identifier) => {
  failStore.delete(`${ip}:${identifier}`);
};

// ── Audit log (in-memory ring buffer, last 1000 events) ──────
const auditLog = [];
const MAX_AUDIT = 1000;

const AUDIT_EVENTS = {
  LOGIN_SUCCESS:    'auth.login.success',
  LOGIN_FAILURE:    'auth.login.failure',
  LOGOUT:           'auth.logout',
  TOKEN_REFRESH:    'auth.token.refresh',
  TOKEN_EXPIRED:    'auth.token.expired',
  TOKEN_INVALID:    'auth.token.invalid',
  APIKEY_USED:      'auth.apikey.used',
  APIKEY_INVALID:   'auth.apikey.invalid',
  OAUTH_TOKEN:      'auth.oauth.token_issued',
  OAUTH_REVOKE:     'auth.oauth.token_revoked',
  ACCOUNT_LOCKED:   'auth.account.locked',
  UNAUTHORIZED:     'auth.unauthorized',
  FORBIDDEN:        'auth.forbidden',
  BRUTE_FORCE:      'auth.brute_force_detected',
};

const audit = (event, data = {}) => {
  const entry = {
    id:        crypto.randomUUID(),
    event,
    timestamp: new Date().toISOString(),
    ...data,
  };
  auditLog.push(entry);
  if (auditLog.length > MAX_AUDIT) auditLog.shift();

  // In production, ship to SIEM / structured logger here
  if (process.env.NODE_ENV !== 'test') {
    const level = event.includes('failure') || event.includes('invalid') || event.includes('locked')
      ? 'WARN' : 'INFO';
    console.log(`[AUDIT][${level}] ${event}`, JSON.stringify({ ip: data.ip, userId: data.userId, email: data.email }));
  }

  return entry;
};

const getAuditLog = (limit = 50) => auditLog.slice(-Math.min(limit, MAX_AUDIT)).reverse();

// ── Token family tracking (refresh token replay detection) ───
// family → { tokens: Set, revoked: bool }
const tokenFamilies = new Map();

const createFamily = (familyId) => {
  tokenFamilies.set(familyId, { tokens: new Set(), revoked: false });
};

const addToFamily = (familyId, token) => {
  let family = tokenFamilies.get(familyId);
  if (!family) { family = { tokens: new Set(), revoked: false }; tokenFamilies.set(familyId, family); }
  family.tokens.add(token);
};

const isTokenReused = (familyId, token) => {
  const family = tokenFamilies.get(familyId);
  if (!family) return false;
  // If family is revoked — definitely reuse attack
  if (family.revoked) return true;
  // If this token was already rotated out (not the latest) → reuse
  // We track ALL issued tokens in the family; the current valid one is the last added
  const arr = [...family.tokens];
  const latestToken = arr[arr.length - 1];
  return token !== latestToken;
};

const revokeFamilyOnReuse = (familyId) => {
  const family = tokenFamilies.get(familyId);
  if (family) family.revoked = true;
};

// ── Secure random token generation ───────────────────────────
const generateSecureToken = (prefix = 'hapi', bytes = 32) =>
  `${prefix}_${crypto.randomBytes(bytes).toString('hex')}`;

/** Generate a JTI (JWT ID) — used to allow individual token revocation */
const generateJti = () => crypto.randomUUID();

// ── WWW-Authenticate header builders ─────────────────────────
const wwwAuthenticate = {
  bearer:   (realm, error, desc) =>
    `Bearer realm="${realm}", error="${error}", error_description="${desc}"`,
  basic:    (realm) => `Basic realm="${realm}", charset="UTF-8"`,
  combined: (realm) =>
    `Bearer realm="${realm}", Basic realm="${realm}", charset="UTF-8"`,
};

// ── IP extraction (respects Render / reverse-proxy headers) ──
const getClientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.headers['x-real-ip'] ||
  req.connection?.remoteAddress ||
  'unknown';

module.exports = {
  // Brute force
  recordFailure,
  isLocked,
  clearFailures,
  // Audit
  audit,
  getAuditLog,
  AUDIT_EVENTS,
  // Token families
  createFamily,
  addToFamily,
  isTokenReused,
  revokeFamilyOnReuse,
  // Helpers
  generateSecureToken,
  generateJti,
  wwwAuthenticate,
  getClientIp,
};