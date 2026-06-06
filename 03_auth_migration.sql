-- ============================================================
--  HealthAPI — Auth Enhancement Migration
--  Run AFTER 02_seed.sql
--  Adds: persistent auth audit log + api_key improvements
--  Does NOT change existing tables (schema preserved as required)
-- ============================================================

-- ── AUTH AUDIT LOG ───────────────────────────────────────────
--  Optional persistent audit trail.
--  The in-memory audit log in authSecurity.js works for demos;
--  run this migration for a persistent, queryable audit trail.
CREATE TABLE IF NOT EXISTS auth_audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event        TEXT NOT NULL,               -- e.g. 'auth.login.success'
  user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
  ip_address   TEXT,
  auth_method  TEXT,                         -- bearer-jwt, basic-password, bearer-oauth2, etc.
  path         TEXT,
  http_method  TEXT,
  client_id    TEXT,                         -- for OAuth events
  jti          TEXT,                         -- JWT ID for revocation tracking
  extra        JSONB DEFAULT '{}',           -- any additional context
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON auth_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event     ON auth_audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_ip        ON auth_audit_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON auth_audit_log(created_at DESC);

-- ── JWT REVOCATION LIST (optional — for invalidating specific JTIs) ──
--  Only needed if you want to revoke individual JWTs before expiry.
--  Since JWTs are short-lived (1h), this is optional.
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti          TEXT PRIMARY KEY,
  user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
  revoked_at   TIMESTAMPTZ DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,   -- remove once past exp (cleanup job)
  reason       TEXT
);

CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_tokens(expires_at);

-- ── Cleanup function: remove expired revoked tokens ──────────
CREATE OR REPLACE FUNCTION cleanup_expired_revoked_tokens()
RETURNS void AS $$
BEGIN
  DELETE FROM revoked_tokens WHERE expires_at < NOW();
  DELETE FROM oauth_access_tokens WHERE expires_at < NOW() - INTERVAL '1 day';
  DELETE FROM oauth_auth_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
  DELETE FROM refresh_tokens WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ── Quick-reference view for active sessions ─────────────────
CREATE OR REPLACE VIEW active_sessions AS
SELECT
  rt.token,
  rt.user_id,
  u.name    AS user_name,
  u.email   AS user_email,
  u.role,
  rt.created_at AS issued_at,
  rt.expires_at,
  (rt.expires_at > NOW()) AS is_valid
FROM refresh_tokens rt
LEFT JOIN users u ON u.id = rt.user_id;

-- ── Quick-reference view for active OAuth tokens ─────────────
CREATE OR REPLACE VIEW active_oauth_tokens AS
SELECT
  at.token,
  at.user_id,
  u.email   AS user_email,
  u.role,
  at.client_id,
  at.scope,
  at.expires_at,
  (at.expires_at > NOW()) AS is_active,
  at.created_at
FROM oauth_access_tokens at
LEFT JOIN users u ON u.id = at.user_id
ORDER BY at.created_at DESC;
