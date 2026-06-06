// src/utils/authSecurity.js
// ============================================================
//  Auth Security Utilities
//  Brute-force protection, audit logging, token helpers
//  IP removed from lockout key — lockout is per email only
//  Students on different IPs share the same counter
// ============================================================

const crypto = require('crypto');

// ── Brute-force / lockout store (in-memory) ──────────────────
// Map key: "identifier" (email only — NO IP)
const failStore = new Map();

const LOCKOUT_WINDOW_MS   = 5 * 60 * 1000;   // 5 min window
const MAX_ATTEMPTS        = 10;               // 10 attempts before lock
const LOCKOUT_DURATION_MS = 2 * 60 * 1000;   // 2 min lockout only

/**
 * Record a failed auth attempt.
 * ip param kept for signature compatibility — ignored.
 * @returns { locked: bool, attemptsLeft: number, lockedUntilMs: number|null }
 */
const recordFailure = (ip, identifier) => {
  const key = identifier; // EMAIL ONLY, no IP
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
 * Check if an identifier is currently locked without recording a new failure.
 * ip param kept for signature compatibility — ignored.
 */
const isLocked = (ip, identifier) => {
  const key   = identifier; // EMAIL ONLY, no IP
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
  failStore.delete(identifier); // EMAIL ONLY, no IP
};

/** Clear ALL failures — for admin/teaching use via /api/auth/clear-lockout */
const clearAllFailures = () => {
  const count = failStore.size;
  failStore.clear();
  return count;
};

/** Get current lockout status for all tracked identifiers */
const getLockoutStatus = () => {
  const result = [];
  const now = Date.now();
  for (const [key, entry] of failStore.entries()) {
    result.push({
      identifier:   key,
      attempts:     entry.attempts,
      locked:       !!(entry.lockedUntil && now < entry.lockedUntil),
      lockedUntil:  entry.lockedUntil ? new Date(entry.lockedUntil).toISOString() : null,
      secondsLeft:  entry.lockedUntil ? Math.max(0, Math.ceil((entry.lockedUntil - now) / 1000)) : 0,
    });
  }
  return result;
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

  // IP removed from console log
  if (process.env.NODE_ENV !== 'test') {
    const level = event.includes('failure') || event.includes('invalid') || event.includes('locked')
      ? 'WARN' : 'INFO';
    console.log(`[AUDIT][${level}] ${event}`,
      JSON.stringify({ userId: data.userId, email: data.email }));
  }

  return entry;
};

const getAuditLog = (limit = 50) =>
  auditLog.slice(-Math.min(limit, MAX_AUDIT)).reverse();

// ── Token family tracking (refresh token replay detection) ───
// family → { tokens: Set, revoked: bool }
const tokenFamilies = new Map();

const createFamily = (familyId) => {
  tokenFamilies.set(familyId, { tokens: new Set(), revoked: false });
};

const addToFamily = (familyId, token) => {
  let family = tokenFamilies.get(familyId);
  if (!family) {
    family = { tokens: new Set(), revoked: false };
    tokenFamilies.set(familyId, family);
  }
  family.tokens.add(token);
};

const isTokenReused = (familyId, token) => {
  const family = tokenFamilies.get(familyId);
  if (!family) return false;
  if (family.revoked) return true;
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

/** Generate a JTI (JWT ID) */
const generateJti = () => crypto.randomUUID();

// ── WWW-Authenticate header builders ─────────────────────────
const wwwAuthenticate = {
  bearer:   (realm, error, desc) =>
    `Bearer realm="${realm}", error="${error}", error_description="${desc}"`,
  basic:    (realm) => `Basic realm="${realm}", charset="UTF-8"`,
  combined: (realm) =>
    `Bearer realm="${realm}", Basic realm="${realm}", charset="UTF-8"`,
};

// ── IP extraction (kept for compatibility — not used in lockout) ──
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
  clearAllFailures,
  getLockoutStatus,
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