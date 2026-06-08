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
const publicRoutes      = require('./src/routes/public');          // ← NEW: no-auth routes
const { doctorRouter, recordRouter, wardRouter, simulateRouter, validateRouter, dashRouter } = require('./src/routes/misc');
const registerRoutes = require('./src/routes/register');

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
      'Health & Docs (no auth)': {
        'GET /api/health': 'Server + DB status',
        'GET /api/docs':   'This documentation',
      },

      // ── NEW: Public no-auth endpoints ─────────────────────────
      'Public — No Auth Required (all 5 HTTP methods)': {
        note: 'No Authorization header needed. Great for AP1–AP3 fundamentals.',
        'GET    /api/public':                      'Public endpoints overview & usage guide',

        'GET    /api/public/patients':             'List patients (?gender,status,bloodGroup,city,age,ageMin,ageMax,search,sortBy,order,page,limit)',
        'GET    /api/public/patients/:id':         'Get a patient by ID (e.g. pat_001)',
        'POST   /api/public/patients':             'Create a patient — body: firstName,lastName,dateOfBirth,gender,bloodGroup,phone,email,address,emergencyContact,medicalHistory,allergies,currentMedications,insuranceId',
        'PUT    /api/public/patients/:id':         'Full replace — all core fields required',
        'PATCH  /api/public/patients/:id':         'Partial update — send only fields to change',
        'DELETE /api/public/patients/:id':         'Delete a patient',

        'GET    /api/public/doctors':              'List doctors (?specialization,status,availableDay)',
        'GET    /api/public/doctors/:id':          'Get a doctor by ID (e.g. doc_001)',
        'POST   /api/public/doctors':              'Create a doctor — body: name,specialization,qualification,experience,phone,email,availableDays,consultationFee,status',
        'PUT    /api/public/doctors/:id':          'Full replace a doctor',
        'PATCH  /api/public/doctors/:id':          'Partial update a doctor',
        'DELETE /api/public/doctors/:id':          'Delete a doctor',

        'GET    /api/public/appointments':         'List appointments (?status,type,doctorId,patientId,date,dateFrom,dateTo,paymentStatus,specialization,page,limit)',
        'GET    /api/public/appointments/:id':     'Get appointment + embedded patient & doctor (e.g. apt_001)',
        'POST   /api/public/appointments':         'Book appointment — body: patientId,doctorId,appointmentDate,appointmentTime,type,symptoms,notes,fees,duration,roomNo',
        'PUT    /api/public/appointments/:id':     'Full replace — appointmentDate & appointmentTime required',
        'PATCH  /api/public/appointments/:id':     'Partial update (status, notes, fees, roomNo, paymentStatus …)',
        'DELETE /api/public/appointments/:id':     'Delete an appointment (blocked if in-progress)',

        'GET    /api/public/records':              'List medical records (?patientId,doctorId,recordType)',
        'GET    /api/public/records/:id':          'Get a record by ID (e.g. rec_001)',
        'POST   /api/public/records':              'Create a record — body: patientId,doctorId,recordType,title,description,diagnosis,prescription,testResults,followUpDate',
        'PUT    /api/public/records/:id':          'Full replace a record',
        'PATCH  /api/public/records/:id':          'Partial update a record',
        'DELETE /api/public/records/:id':          'Delete a record',
      },
      // ── END public endpoints ──────────────────────────────────

      'Auth (Basic + Bearer JWT)': {
        'POST /api/auth/login': 'Login → JWT', 'POST /api/auth/refresh': 'Refresh token',
        'POST /api/auth/logout': 'Invalidate token', 'GET /api/auth/profile': 'My profile',
        'GET /api/auth/users': 'List users (admin)', 'GET /api/auth/apikeys': 'List API keys (admin)',
        'GET /api/auth/basic-test': 'Test Basic Auth',
      },
      'OAuth 2.0': {
        'GET /api/oauth/.well-known/oauth-authorization-server': 'RFC 8414 metadata',
        'GET /api/oauth/clients': 'List clients',
        'GET /api/oauth/authorize': 'Step 1 — get code',
        'POST /api/oauth/token': 'Step 2 — exchange code / all 4 grants',
        'POST /api/oauth/revoke': 'Revoke token', 'POST /api/oauth/introspect': 'Inspect token',
        'GET /api/oauth/callback': 'Simulated redirect',
      },
      'Patients (auth required)': {
        'GET /api/patients': '?gender,status,bloodGroup,age,ageMin,ageMax,city,search,sortBy,order,page,limit',
        'GET /api/patients/:id': 'Get one', 'POST /api/patients': 'Create (doctor/nurse/admin)',
        'PUT /api/patients/:id': 'Full update', 'PATCH /api/patients/:id': 'Partial update',
        'DELETE /api/patients/:id': 'Delete (admin)',
        'GET /api/patients/:id/appointments': 'Patient appointments',
        'GET /api/patients/:id/records': 'Patient records',
      },
      'Appointments (auth required)': {
        'GET /api/appointments': '?status,type,doctorId,patientId,date,dateFrom,dateTo,paymentStatus,specialization',
        'GET /api/appointments/:id': 'Get one', 'POST /api/appointments': 'Book',
        'PUT /api/appointments/:id': 'Update', 'PATCH /api/appointments/:id/status': 'Change status',
        'DELETE /api/appointments/:id': 'Delete (admin)',
      },
      'Doctors (auth required)': {
        'GET /api/doctors': '?specialization,status,availableDay',
        'GET /api/doctors/:id': 'Get one',
        'GET /api/doctors/:id/appointments': 'Doctor schedule',
      },
      'Medical Records (auth required)': {
        'GET /api/records': '?patientId,doctorId,recordType', 'GET /api/records/:id': 'Get one',
        'POST /api/records': 'Create (doctor/admin)', 'PUT /api/records/:id': 'Update',
        'DELETE /api/records/:id': 'Delete (admin)',
      },
      'Wards': { 'GET /api/wards': 'All wards + bed counts', 'GET /api/wards/:id': 'One ward' },
      'Dashboard': { 'GET /api/dashboard': 'Stats overview (doctor/admin)' },
      'Validation (AP3)': { 'POST /api/validate/patient': 'Validate patient JSON', 'POST /api/validate/appointment': 'Validate appointment JSON' },
      'Status Code Simulators (AP2)': {
        'GET /api/simulate/{200,201,204,400,401,403,404,409,422,429,500,503}': 'Trigger status codes',
        'GET /api/simulate/delay?ms=2000': 'Delayed response',
      },
    },
    sampleIds: {
      patients:     ['pat_001','pat_002','pat_003','pat_004','pat_005'],
      appointments: ['apt_001','apt_002','apt_003','apt_004','apt_005'],
      doctors:      ['doc_001','doc_002','doc_003','doc_004'],
      records:      ['rec_001','rec_002'],
      wards:        ['ward_001','ward_002','ward_003','ward_004'],
    },
    practiceScenarios: {
      'AP1 — REST Fundamentals':    [
        'GET /api/health',
        'GET /api/public             ← start here, no auth needed',
        'GET /api/public/patients',
        'GET /api/public/patients/pat_001',
        'POST /api/auth/login',
      ],
      'AP2 — HTTP Methods & Codes': [
        'GET /api/simulate/200',
        'GET /api/simulate/404',
        'GET /api/simulate/500',
        'GET /api/public/patients/pat_999   ← real 404',
        'DELETE /api/public/appointments/apt_003  ← real 409 (completed)',
        'GET /api/simulate/delay?ms=3000',
      ],
      'AP3 — JSON & Validation': [
        'POST /api/validate/patient (empty body)',
        'POST /api/validate/patient (bad email)',
        'POST /api/public/patients (full JSON, no auth)',
        'PUT  /api/public/patients/pat_001  (full replace)',
        'PATCH /api/public/patients/pat_001 {"phone":"+91-9999999999"}',
        'DELETE /api/public/patients/:id',
      ],
      'AP4 — Auth & Params':        [
        'GET /api/patients (no token → 401)',
        'POST /api/auth/login',
        'GET /api/auth/profile (Bearer token)',
        'GET /api/patients?gender=female&city=Mumbai',
        'DELETE /api/patients/pat_001 as nurse → 403',
      ],
      'AP5 — Postman & Newman':     [
        'Import all endpoints as collection',
        'Set {{baseUrl}} env var',
        'Use pre-request script for token',
        'Run with: newman run collection.json',
      ],
      'AP6 — AI Testing':           [
        'Generate edge cases with ChatGPT',
        'Use Postbot for assertions',
        'Test null values / boundary conditions',
      ],
    },
  });
});

// ── Mount Routes ──────────────────────────────────────────────
app.get('/api/health',       util.health);
app.use('/api/public',       publicRoutes);          // ← NEW: no-auth public CRUD
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
  console.log(`📄  Docs         → http://localhost:${PORT}/api/docs`);
  console.log(`🔓  Public API   → http://localhost:${PORT}/api/public`);
  console.log(`❤️   Health      → http://localhost:${PORT}/api/health`);
  console.log(`🗄️   Database    → Supabase (${process.env.SUPABASE_URL || 'NOT SET'})\n`);
});

app.use('/api/register', registerRoutes);

module.exports = app;