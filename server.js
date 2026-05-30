// server.js — HealthAPI v2.0 (Supabase + Render)
require('dotenv').config();

const express    = require('express');
const morgan     = require('morgan');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { PORT, BASE_URL, NODE_ENV } = require('./src/utils/config');
const util = require('./src/controllers/utilController');

// Routes
const authRoutes        = require('./src/routes/auth');
const oauthRoutes       = require('./src/routes/oauth');
const patientRoutes     = require('./src/routes/patients');
const appointmentRoutes = require('./src/routes/appointments');
const { doctorRouter, recordRouter, wardRouter, simulateRouter, validateRouter, dashRouter } = require('./src/routes/misc');

const app = express();

// ── Security Middleware ───────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.set('trust proxy', 1);

// ── Rate Limiting ─────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 min
  max:      parseInt(process.env.RATE_LIMIT_MAX       || '200',    10),
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests. Please slow down.' } },
  skip: (req) => req.path.startsWith('/api/simulate'), // simulators bypass rate limit
});
app.use(limiter);

// ── Request Parsing ───────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── API Docs ──────────────────────────────────────────────────
app.get('/api/docs', (req, res) => {
  res.json({
    title: 'HealthAPI v2.0 — REST API for API Testing Practice (AP1–AP6)',
    version: '2.0.0',
    baseUrl: BASE_URL,
    database: 'Supabase (PostgreSQL)',
    deployment: 'Render',
    authenticationGuide: {
      '1_BASIC_AUTH': {
        description: 'HTTP Basic — base64(email:password) or base64(email:apiKey)',
        howToInPostman: 'Authorization tab → Basic Auth → email + Admin@1234',
        modes: { password: 'email : Admin@1234', apiKey: 'email : hapi_live_admin_k3yABC123xyz' },
        testEndpoint: 'GET /api/auth/basic-test',
      },
      '2_BEARER_JWT': {
        description: 'JWT Bearer Token from POST /api/auth/login',
        howToInPostman: 'POST /api/auth/login → copy accessToken → Authorization → Bearer Token',
        expiry: '1 hour | refresh with POST /api/auth/refresh',
        testEndpoint: 'GET /api/auth/profile',
      },
      '3_OAUTH2': {
        description: 'OAuth 2.0 — 4 grant types',
        serverMetadata: 'GET /api/oauth/.well-known/oauth-authorization-server',
        clients: [
          { clientId: 'healthapi_client_001', clientSecret: 'healthapi_oauth_secret_XyZ_2025', name: 'Postman Test Client' },
          { clientId: 'healthapi_client_002', clientSecret: 'healthapi_oauth_secret_QwE_2025', name: 'Mobile App Client' },
        ],
        grantTypes: ['authorization_code', 'client_credentials', 'password', 'refresh_token'],
      },
    },
    credentials: {
      note: 'All accounts share the same password',
      password: 'Admin@1234',
      accounts: [
        { email: 'admin@healthapi.com',       role: 'admin'  },
        { email: 'sarah.mehta@healthapi.com', role: 'doctor' },
        { email: 'priya.nair@healthapi.com',  role: 'nurse'  },
      ],
      apiKeys: {
        admin:  'hapi_live_admin_k3yABC123xyz',
        doctor: 'hapi_live_doctor_k3yDEF456uvw',
        nurse:  'hapi_live_nurse_k3yGHI789rst',
      },
    },
    endpoints: {
      'Health & Docs (no auth)':          { 'GET /api/health': 'Server + DB status', 'GET /api/docs': 'This documentation' },
      'Auth (Basic + Bearer JWT)':        { 'POST /api/auth/login': 'Login → JWT', 'POST /api/auth/refresh': 'Refresh token', 'POST /api/auth/logout': 'Invalidate token', 'GET /api/auth/profile': 'My profile', 'GET /api/auth/users': 'List users (admin)', 'GET /api/auth/apikeys': 'List API keys (admin)', 'GET /api/auth/basic-test': 'Test Basic Auth' },
      'OAuth 2.0':                        { 'GET /api/oauth/.well-known/oauth-authorization-server': 'RFC 8414 metadata', 'GET /api/oauth/clients': 'List clients', 'GET /api/oauth/authorize': 'Step 1 — get code', 'POST /api/oauth/token': 'Step 2 — exchange code / all 4 grants', 'POST /api/oauth/revoke': 'Revoke token', 'POST /api/oauth/introspect': 'Inspect token', 'GET /api/oauth/callback': 'Simulated redirect' },
      'Patients':                         { 'GET /api/patients': '?gender,status,bloodGroup,age,ageMin,ageMax,city,search,sortBy,order,page,limit', 'GET /api/patients/:id': 'Get one', 'POST /api/patients': 'Create (doctor/nurse/admin)', 'PUT /api/patients/:id': 'Full update', 'PATCH /api/patients/:id': 'Partial update', 'DELETE /api/patients/:id': 'Delete (admin)', 'GET /api/patients/:id/appointments': 'Patient appointments', 'GET /api/patients/:id/records': 'Patient records' },
      'Appointments':                     { 'GET /api/appointments': '?status,type,doctorId,patientId,date,dateFrom,dateTo,paymentStatus,specialization', 'GET /api/appointments/:id': 'Get one', 'POST /api/appointments': 'Book', 'PUT /api/appointments/:id': 'Update', 'PATCH /api/appointments/:id/status': 'Change status', 'DELETE /api/appointments/:id': 'Delete (admin)' },
      'Doctors':                          { 'GET /api/doctors': '?specialization,status,availableDay', 'GET /api/doctors/:id': 'Get one', 'GET /api/doctors/:id/appointments': 'Doctor schedule' },
      'Medical Records':                  { 'GET /api/records': '?patientId,doctorId,recordType', 'GET /api/records/:id': 'Get one', 'POST /api/records': 'Create (doctor/admin)', 'PUT /api/records/:id': 'Update', 'DELETE /api/records/:id': 'Delete (admin)' },
      'Wards':                            { 'GET /api/wards': 'All wards + bed counts', 'GET /api/wards/:id': 'One ward' },
      'Dashboard':                        { 'GET /api/dashboard': 'Stats overview (doctor/admin)' },
      'Validation (AP3)':                 { 'POST /api/validate/patient': 'Validate patient JSON', 'POST /api/validate/appointment': 'Validate appointment JSON' },
      'Status Code Simulators (AP2)':     { 'GET /api/simulate/{200,201,204,400,401,403,404,409,422,429,500,503}': 'Trigger status codes', 'GET /api/simulate/delay?ms=2000': 'Delayed response' },
    },
    sampleIds: {
      patients:     ['pat_001','pat_002','pat_003','pat_004','pat_005'],
      appointments: ['apt_001','apt_002','apt_003','apt_004','apt_005'],
      doctors:      ['doc_001','doc_002','doc_003','doc_004'],
      records:      ['rec_001','rec_002'],
      wards:        ['ward_001','ward_002','ward_003','ward_004'],
    },
    practiceScenarios: {
      'AP1 — REST Fundamentals':    ['GET /api/health', 'GET /api/docs', 'GET /api/patients', 'GET /api/patients/pat_001', 'POST /api/auth/login'],
      'AP2 — HTTP Methods & Codes': ['GET /api/simulate/200', 'GET /api/simulate/404', 'GET /api/simulate/500', 'GET /api/patients/pat_999', 'POST /api/auth/login (wrong password)'],
      'AP3 — JSON & Validation':    ['POST /api/validate/patient (empty body)', 'POST /api/validate/patient (bad email)', 'POST /api/validate/patient (all correct)', 'POST /api/patients (authenticated)'],
      'AP4 — Auth & Params':        ['GET /api/patients (no token → 401)', 'POST /api/auth/login', 'GET /api/auth/profile', 'GET /api/patients?gender=female&city=Mumbai', 'DELETE /api/patients/pat_001 as nurse → 403'],
      'AP5 — Postman & Newman':     ['Import all endpoints as collection', 'Set {{baseUrl}} env var', 'Use pre-request script for token', 'Run with: newman run collection.json'],
      'AP6 — AI Testing':           ['Generate edge cases with ChatGPT', 'Use Postbot for assertions', 'Test null values / boundary conditions'],
    },
  });
});

// ── Mount Routes ──────────────────────────────────────────────
app.get('/api/health',     util.health);
app.use('/api/auth',         authRoutes);
app.use('/api/oauth',        oauthRoutes);
app.use('/api/patients',     patientRoutes);
app.use('/api/appointments', appointmentRoutes);
app.use('/api/doctors',      doctorRouter);
app.use('/api/records',      recordRouter);
app.use('/api/wards',        wardRouter);
app.use('/api/simulate',     simulateRouter);
app.use('/api/validate',     validateRouter);
app.use('/api/dashboard',    dashRouter);

// ── Root redirect ─────────────────────────────────────────────
app.get('/', (req, res) => res.redirect('/api/docs'));

// ── 404 ───────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: { code: 'ENDPOINT_NOT_FOUND', message: `Cannot ${req.method} ${req.path}. See /api/docs.` } });
});

// ── Global Error Handler ──────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected error occurred.' } });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🏥  HealthAPI v2.0 running at http://localhost:${PORT}`);
  console.log(`📄  Docs      → http://localhost:${PORT}/api/docs`);
  console.log(`❤️   Health   → http://localhost:${PORT}/api/health`);
  console.log(`🗄️   Database → Supabase (${process.env.SUPABASE_URL || 'NOT SET'})\n`);
});

module.exports = app;
