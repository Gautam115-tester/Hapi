-- ============================================================
--  HealthAPI — Supabase PostgreSQL Schema
--  Run this in Supabase SQL Editor (Dashboard → SQL Editor)
-- ============================================================

-- ── Extensions ───────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Drop tables if re-running ────────────────────────────────
DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS oauth_access_tokens CASCADE;
DROP TABLE IF EXISTS oauth_auth_codes CASCADE;
DROP TABLE IF EXISTS medical_records CASCADE;
DROP TABLE IF EXISTS appointments CASCADE;
DROP TABLE IF EXISTS patients CASCADE;
DROP TABLE IF EXISTS doctors CASCADE;
DROP TABLE IF EXISTS wards CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS oauth_clients CASCADE;

-- ── USERS ────────────────────────────────────────────────────
CREATE TABLE users (
  id           TEXT PRIMARY KEY DEFAULT 'usr_' || substr(gen_random_uuid()::text, 1, 8),
  name         TEXT NOT NULL,
  email        TEXT UNIQUE NOT NULL,
  password     TEXT NOT NULL,  -- bcrypt hash
  role         TEXT NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse')),
  department   TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── API KEYS (for Basic Auth: email:apiKey) ──────────────────
CREATE TABLE api_keys (
  id          SERIAL PRIMARY KEY,
  key         TEXT UNIQUE NOT NULL,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        TEXT NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── JWT REFRESH TOKENS ────────────────────────────────────────
CREATE TABLE refresh_tokens (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── OAUTH CLIENTS ────────────────────────────────────────────
CREATE TABLE oauth_clients (
  id             SERIAL PRIMARY KEY,
  client_id      TEXT UNIQUE NOT NULL,
  client_secret  TEXT NOT NULL,
  name           TEXT NOT NULL,
  redirect_uris  TEXT[] NOT NULL,
  grant_types    TEXT[] NOT NULL,
  scopes         TEXT[] NOT NULL,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- ── OAUTH AUTH CODES ─────────────────────────────────────────
CREATE TABLE oauth_auth_codes (
  code                   TEXT PRIMARY KEY,
  user_id                TEXT REFERENCES users(id) ON DELETE CASCADE,
  client_id              TEXT NOT NULL,
  scope                  TEXT,
  redirect_uri           TEXT,
  expires_at             TIMESTAMPTZ NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  used                   BOOLEAN DEFAULT FALSE,
  created_at             TIMESTAMPTZ DEFAULT NOW()
);

-- ── OAUTH ACCESS TOKENS ───────────────────────────────────────
CREATE TABLE oauth_access_tokens (
  token       TEXT PRIMARY KEY,
  user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
  client_id   TEXT NOT NULL,
  scope       TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  token_type  TEXT DEFAULT 'Bearer',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── OAUTH REFRESH TOKENS ──────────────────────────────────────
CREATE TABLE oauth_refresh_tokens (
  token       TEXT PRIMARY KEY,
  user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
  client_id   TEXT NOT NULL,
  scope       TEXT,
  issued_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── DOCTORS ──────────────────────────────────────────────────
CREATE TABLE doctors (
  id                TEXT PRIMARY KEY DEFAULT 'doc_' || substr(gen_random_uuid()::text, 1, 8),
  name              TEXT NOT NULL,
  specialization    TEXT NOT NULL,
  qualification     TEXT,
  experience        INTEGER DEFAULT 0,
  phone             TEXT,
  email             TEXT UNIQUE,
  available_days    TEXT[] DEFAULT '{}',
  consultation_fee  NUMERIC(10,2) DEFAULT 0,
  status            TEXT DEFAULT 'active' CHECK (status IN ('active', 'on_leave', 'inactive')),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ── PATIENTS ─────────────────────────────────────────────────
CREATE TABLE patients (
  id                    TEXT PRIMARY KEY DEFAULT 'pat_' || substr(gen_random_uuid()::text, 1, 8),
  first_name            TEXT NOT NULL,
  last_name             TEXT NOT NULL,
  date_of_birth         DATE NOT NULL,
  age                   INTEGER,
  gender                TEXT CHECK (gender IN ('male', 'female', 'other')),
  blood_group           TEXT CHECK (blood_group IN ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
  phone                 TEXT NOT NULL,
  email                 TEXT UNIQUE NOT NULL,
  street                TEXT,
  city                  TEXT,
  state                 TEXT,
  pincode               TEXT,
  emergency_name        TEXT,
  emergency_relation    TEXT,
  emergency_phone       TEXT,
  medical_history       TEXT[] DEFAULT '{}',
  allergies             TEXT[] DEFAULT '{}',
  current_medications   TEXT[] DEFAULT '{}',
  insurance_id          TEXT,
  status                TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  admitted_at           TIMESTAMPTZ,
  created_at            TIMESTAMPTZ DEFAULT NOW(),
  updated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- ── APPOINTMENTS ─────────────────────────────────────────────
CREATE TABLE appointments (
  id                TEXT PRIMARY KEY DEFAULT 'apt_' || substr(gen_random_uuid()::text, 1, 8),
  patient_id        TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  patient_name      TEXT,
  doctor_id         TEXT NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
  doctor_name       TEXT,
  specialization    TEXT,
  appointment_date  DATE NOT NULL,
  appointment_time  TEXT NOT NULL,
  duration          INTEGER DEFAULT 30,
  type              TEXT DEFAULT 'consultation' CHECK (type IN ('consultation','follow-up','emergency','routine-checkup','lab-review')),
  status            TEXT DEFAULT 'scheduled' CHECK (status IN ('scheduled','confirmed','in-progress','completed','cancelled','no-show')),
  symptoms          TEXT,
  notes             TEXT,
  room_no           TEXT,
  fees              NUMERIC(10,2) DEFAULT 0,
  payment_status    TEXT DEFAULT 'pending' CHECK (payment_status IN ('pending','paid','refunded')),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ── MEDICAL RECORDS ───────────────────────────────────────────
CREATE TABLE medical_records (
  id              TEXT PRIMARY KEY DEFAULT 'rec_' || substr(gen_random_uuid()::text, 1, 8),
  patient_id      TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  appointment_id  TEXT REFERENCES appointments(id) ON DELETE SET NULL,
  doctor_id       TEXT NOT NULL REFERENCES doctors(id),
  doctor_name     TEXT,
  record_type     TEXT DEFAULT 'general',
  title           TEXT,
  description     TEXT,
  diagnosis       TEXT,
  prescription    TEXT[] DEFAULT '{}',
  test_results    JSONB DEFAULT '{}',
  follow_up_date  DATE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── WARDS ────────────────────────────────────────────────────
CREATE TABLE wards (
  id              TEXT PRIMARY KEY DEFAULT 'ward_' || substr(gen_random_uuid()::text, 1, 8),
  name            TEXT NOT NULL,
  total_beds      INTEGER DEFAULT 0,
  available_beds  INTEGER DEFAULT 0,
  floor           INTEGER DEFAULT 1,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes for performance ───────────────────────────────────
CREATE INDEX idx_patients_email   ON patients(email);
CREATE INDEX idx_patients_status  ON patients(status);
CREATE INDEX idx_patients_city    ON patients(city);
CREATE INDEX idx_appointments_patient  ON appointments(patient_id);
CREATE INDEX idx_appointments_doctor   ON appointments(doctor_id);
CREATE INDEX idx_appointments_date     ON appointments(appointment_date);
CREATE INDEX idx_appointments_status   ON appointments(status);
CREATE INDEX idx_records_patient  ON medical_records(patient_id);
CREATE INDEX idx_oauth_at_expires ON oauth_access_tokens(expires_at);
CREATE INDEX idx_oauth_codes_expires ON oauth_auth_codes(expires_at);

-- ── Auto-update updated_at triggers ──────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at        BEFORE UPDATE ON users        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_patients_updated_at     BEFORE UPDATE ON patients     FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_appointments_updated_at BEFORE UPDATE ON appointments FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_records_updated_at      BEFORE UPDATE ON medical_records FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_doctors_updated_at      BEFORE UPDATE ON doctors      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
