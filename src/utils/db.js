// src/utils/db.js — Supabase client (service role — server only)
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY; // service role bypasses RLS

if (!supabaseUrl || !supabaseKey) {
  console.error('❌  SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in environment variables.');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: { persistSession: false },
  db:   { schema: 'public' },
});

module.exports = supabase;