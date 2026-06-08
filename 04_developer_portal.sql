-- ============================================================
--  HealthAPI — API Tester Accounts Table
--  Run in Supabase SQL Editor AFTER 02_seed.sql
--
--  Stores accounts for doctors, nurses, lab technicians,
--  researchers and IT staff who register to test the HealthAPI.
-- ============================================================

CREATE TABLE IF NOT EXISTS api_tester_accounts (
  id             TEXT PRIMARY KEY DEFAULT 'tstr_' || substr(gen_random_uuid()::text, 1, 8),
  full_name      TEXT NOT NULL,
  email          TEXT UNIQUE NOT NULL,
  password       TEXT NOT NULL,
  organisation   TEXT NOT NULL,
  role           TEXT NOT NULL CHECK (role IN (
                   'doctor',
                   'nurse',
                   'lab_technician',
                   'researcher',
                   'it_administrator',
                   'auditor'
                 )),
  client_id      TEXT UNIQUE NOT NULL,
  client_secret  TEXT NOT NULL,
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  updated_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tester_email     ON api_tester_accounts(email);
CREATE INDEX IF NOT EXISTS idx_tester_client_id ON api_tester_accounts(client_id);
CREATE INDEX IF NOT EXISTS idx_tester_role      ON api_tester_accounts(role);
CREATE INDEX IF NOT EXISTS idx_tester_org       ON api_tester_accounts(organisation);

CREATE TRIGGER trg_tester_updated_at
  BEFORE UPDATE ON api_tester_accounts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
