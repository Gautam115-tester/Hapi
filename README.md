# 🏥 HealthAPI v2.0 — Production Setup Guide
> REST API for API Testing Labs (AP1–AP6) | Supabase + Render

---

## 📋 Table of Contents
1. [Architecture Overview](#architecture)
2. [Step 1 — Supabase Setup](#supabase)
3. [Step 2 — Local Development](#local)
4. [Step 3 — Deploy to Render](#render)
5. [Authentication Reference](#auth)
6. [API Endpoint Reference](#endpoints)
7. [Practice Scenarios (AP1–AP6)](#scenarios)

---

## 🏗️ Architecture Overview <a name="architecture"></a>

```
Postman / Newman
      │
      ▼
  Render (Node.js + Express)
  https://healthapi.onrender.com
      │
      ▼
  Supabase (PostgreSQL)
  All data persists across restarts
```

**Tech stack:**
- **Runtime:** Node.js 18+ / Express 4
- **Database:** Supabase (PostgreSQL) — real persistent data
- **Auth:** JWT Bearer + HTTP Basic + OAuth 2.0 (all 4 grant types)
- **Deploy:** Render.com (free tier works fine for labs)
- **Security:** Helmet, CORS, Rate limiting, bcrypt passwords

---

## 📌 Step 1 — Supabase Setup <a name="supabase"></a>

### 1.1 Create a Supabase Project
1. Go to **https://supabase.com** → Sign up / Log in
2. Click **New Project**
3. Fill in:
   - **Project name:** `healthapi`
   - **Database password:** (save this securely)
   - **Region:** Choose nearest (e.g. South Asia)
4. Wait ~2 minutes for setup

### 1.2 Run the Schema
1. In Supabase Dashboard → **SQL Editor**
2. Click **New query**
3. Paste the contents of **`sql/01_schema.sql`** → **Run**
4. You should see: *"Success. No rows returned"*

### 1.3 Run the Seed Data
1. New query in SQL Editor
2. Paste **`sql/02_seed.sql`** → **Run**
3. Verify: go to **Table Editor** → you should see patients, doctors, etc.

### 1.4 Get Your API Keys
1. Supabase Dashboard → **Settings** (gear icon) → **API**
2. Copy:
   - **Project URL** → this is your `SUPABASE_URL`
   - **service_role** key (not anon key!) → this is your `SUPABASE_SERVICE_KEY`

> ⚠️ **Security:** The service_role key bypasses Row Level Security.
> Never expose it in client-side code or commit it to git.

---

## 💻 Step 2 — Local Development <a name="local"></a>

```bash
# 1. Clone / copy this project
cd healthapi-production

# 2. Install dependencies
npm install

# 3. Create .env from template
cp .env.example .env

# 4. Edit .env — fill in your Supabase credentials:
# SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
# SUPABASE_SERVICE_KEY=eyJhbGci...

# 5. Start the server
npm start

# Server runs at: http://localhost:3000
# API Docs at:    http://localhost:3000/api/docs
# Health check:   http://localhost:3000/api/health
```

### Verify Everything Works
```bash
# Health check (should show database: supabase (connected))
curl http://localhost:3000/api/health

# List patients
curl -u admin@healthapi.com:Admin@1234 http://localhost:3000/api/patients

# Login and get JWT
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@healthapi.com","password":"Admin@1234"}'
```

---

## 🚀 Step 3 — Deploy to Render <a name="render"></a>

### 3.1 Push to GitHub
```bash
# In the healthapi-production folder
git init
git add .
git commit -m "HealthAPI v2.0 — Supabase + Render"

# Create a new repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/healthapi.git
git push -u origin main
```

### 3.2 Create Render Service
1. Go to **https://render.com** → Sign up / Log in
2. Click **New** → **Web Service**
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` — settings pre-filled:
   - **Name:** `healthapi`
   - **Build command:** `npm install`
   - **Start command:** `npm start`

### 3.3 Set Environment Variables
In Render Dashboard → your service → **Environment**:

| Key | Value |
|-----|-------|
| `SUPABASE_URL` | `https://xxxx.supabase.co` |
| `SUPABASE_SERVICE_KEY` | `eyJhbGci...` (service role key) |
| `JWT_SECRET` | Any long random string |
| `JWT_REFRESH_SECRET` | Any other long random string |
| `NODE_ENV` | `production` |
| `BASE_URL` | `https://healthapi.onrender.com` (your Render URL) |

Click **Save Changes** → Render auto-redeploys.

### 3.4 Verify Deployment
```
https://healthapi.onrender.com/api/health
https://healthapi.onrender.com/api/docs
```

> 💡 **Free tier note:** Render free tier spins down after 15 min inactivity.
> First request after sleep takes ~30 seconds. Upgrade to Starter ($7/mo) for always-on.

---

## 🔐 Authentication Reference <a name="auth"></a>

### Test Credentials
| Email | Role | Permissions |
|-------|------|-------------|
| `admin@healthapi.com` | admin | Full access |
| `sarah.mehta@healthapi.com` | doctor | Read/Write patients, appointments, records |
| `priya.nair@healthapi.com` | nurse | Read/Write patients & appointments |

**Password for all:** `Admin@1234`

### Method 1 — HTTP Basic Auth
```
Authorization: Basic base64(email:password)
```
In Postman: Authorization tab → Basic Auth → fill email + Admin@1234

**Using API Key:**
```
Authorization: Basic base64(email:apiKey)
```
| Role | API Key |
|------|---------|
| Admin | `hapi_live_admin_k3yABC123xyz` |
| Doctor | `hapi_live_doctor_k3yDEF456uvw` |
| Nurse | `hapi_live_nurse_k3yGHI789rst` |

### Method 2 — Bearer JWT
```bash
# 1. Login
POST /api/auth/login
{ "email": "admin@healthapi.com", "password": "Admin@1234" }

# 2. Copy accessToken from response
# 3. Use in header:
Authorization: Bearer <accessToken>

# Token expires in 1 hour — refresh:
POST /api/auth/refresh
{ "refreshToken": "<refreshToken>" }
```

### Method 3 — OAuth 2.0
```
Client ID:     healthapi_client_001
Client Secret: healthapi_oauth_secret_XyZ_2025
```

**Authorization Code flow (Postman):**
1. Authorization tab → OAuth 2.0
2. Auth URL: `{{baseUrl}}/api/oauth/authorize`
3. Token URL: `{{baseUrl}}/api/oauth/token`
4. Client ID + Secret as above
5. Scopes: `read:patients write:patients`

**Client Credentials (machine-to-machine):**
```bash
POST /api/oauth/token
{ "grant_type": "client_credentials", "client_id": "healthapi_client_001", "client_secret": "healthapi_oauth_secret_XyZ_2025" }
```

---

## 📋 API Endpoint Reference <a name="endpoints"></a>

### Health & Docs (no auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server + DB status |
| GET | `/api/docs` | Full API documentation |

### Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | Login → JWT |
| POST | `/api/auth/refresh` | No | Refresh access token |
| POST | `/api/auth/logout` | No | Invalidate refresh token |
| GET | `/api/auth/profile` | Yes (any) | My profile |
| GET | `/api/auth/basic-test` | Yes | Test Basic Auth |
| GET | `/api/auth/users` | Admin | All users |
| GET | `/api/auth/apikeys` | Admin | Available API keys |

### Patients
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/patients` | Yes | List — supports filters |
| GET | `/api/patients/:id` | Yes | Get one |
| POST | `/api/patients` | Doctor/Nurse/Admin | Create |
| PUT | `/api/patients/:id` | Doctor/Nurse/Admin | Full update |
| PATCH | `/api/patients/:id` | Doctor/Nurse/Admin | Partial update |
| DELETE | `/api/patients/:id` | Admin | Delete |
| GET | `/api/patients/:id/appointments` | Yes | Patient appointments |
| GET | `/api/patients/:id/records` | Yes | Medical records |

**Query Parameters:**
```
?gender=male|female|other
?status=active|inactive
?bloodGroup=O+
?age=34  OR  ?ageMin=20&ageMax=40
?city=Mumbai
?search=rohan          (searches name, email, phone)
?sortBy=age&order=asc
?page=1&limit=10
```

**Sample Patient IDs:** `pat_001` through `pat_005`

**Create Patient Body:**
```json
{
  "firstName": "Riya",
  "lastName": "Kapoor",
  "dateOfBirth": "1998-03-20",
  "gender": "female",
  "bloodGroup": "B+",
  "phone": "+91-9876543000",
  "email": "riya.kapoor@email.com",
  "address": { "street": "101 Marine Drive", "city": "Mumbai", "state": "Maharashtra", "pincode": "400002" },
  "emergencyContact": { "name": "Anil Kapoor", "relation": "Father", "phone": "+91-9876543001" },
  "medicalHistory": ["Migraine"],
  "allergies": ["Pollen"],
  "currentMedications": [],
  "insuranceId": "INS-MH-2024-010"
}
```

### Appointments
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/appointments` | Yes | List — supports filters |
| GET | `/api/appointments/:id` | Yes | Get one (includes patient + doctor) |
| POST | `/api/appointments` | Doctor/Nurse/Admin | Book |
| PUT | `/api/appointments/:id` | Doctor/Nurse/Admin | Update |
| PATCH | `/api/appointments/:id/status` | Doctor/Nurse/Admin | Change status |
| DELETE | `/api/appointments/:id` | Admin | Delete |

**Query Parameters:**
```
?status=scheduled|confirmed|in-progress|completed|cancelled|no-show
?type=consultation|follow-up|emergency|routine-checkup|lab-review
?doctorId=doc_001
?patientId=pat_002
?date=2025-02-05
?dateFrom=2025-01-01&dateTo=2025-12-31
?paymentStatus=pending|paid|refunded
?specialization=Cardiology
```

**Sample Appointment IDs:** `apt_001` through `apt_005`

**Create Appointment:**
```json
{
  "patientId": "pat_001",
  "doctorId": "doc_002",
  "appointmentDate": "2025-03-15",
  "appointmentTime": "11:30",
  "type": "consultation",
  "symptoms": "Persistent headache"
}
```

**Update Status:**
```json
{ "status": "confirmed" }
```
Valid flow: `scheduled → confirmed → in-progress → completed | cancelled | no-show`

### Doctors
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/doctors` | `?specialization=Cardiology&status=active&availableDay=Monday` |
| GET | `/api/doctors/:id` | One doctor |
| GET | `/api/doctors/:id/appointments` | Schedule `?date=2025-02-05&status=confirmed` |

**Sample Doctor IDs:** `doc_001` through `doc_004`

### Medical Records
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/records` | Yes | `?patientId=&doctorId=&recordType=` |
| GET | `/api/records/:id` | Yes | One record |
| POST | `/api/records` | Doctor/Admin | Create |
| PUT | `/api/records/:id` | Doctor/Admin | Update |
| DELETE | `/api/records/:id` | Admin | Delete |

### Status Code Simulators (AP2)
| Endpoint | Returns |
|----------|---------|
| `GET /api/simulate/200` | 200 OK |
| `GET /api/simulate/201` | 201 Created |
| `GET /api/simulate/204` | 204 No Content |
| `GET /api/simulate/400` | 400 Bad Request |
| `GET /api/simulate/401` | 401 Unauthorized |
| `GET /api/simulate/403` | 403 Forbidden |
| `GET /api/simulate/404` | 404 Not Found |
| `GET /api/simulate/409` | 409 Conflict |
| `GET /api/simulate/422` | 422 Validation Error |
| `GET /api/simulate/429` | 429 Rate Limited |
| `GET /api/simulate/500` | 500 Server Error |
| `GET /api/simulate/503` | 503 Service Unavailable |
| `GET /api/simulate/delay?ms=2000` | Delayed response |

---

## 🧪 Practice Scenarios (AP1–AP6) <a name="scenarios"></a>

### AP1 — REST API Fundamentals
```
1. GET /api/health                        → understand server info structure
2. GET /api/docs                          → read API documentation
3. GET /api/patients                      → fetch all patients (paginated)
4. GET /api/patients/pat_001              → get a specific patient
5. POST /api/auth/login                   → understand auth flow
```

### AP2 — HTTP Methods & Status Codes
```
1. GET /api/simulate/200                  → see successful response
2. GET /api/simulate/404                  → see not found error
3. GET /api/simulate/500                  → see server error
4. GET /api/patients/pat_999             → real 404 from the API
5. POST /api/auth/login (wrong password) → real 401
6. DELETE /api/patients/pat_001 as nurse → real 403
7. GET /api/simulate/delay?ms=3000       → timeout testing
```

### AP3 — JSON Handling & Data Validation
```
1. POST /api/validate/patient (empty body)      → see all errors
2. POST /api/validate/patient (bad email)       → see email error
3. POST /api/validate/patient (all correct)     → valid payload
4. POST /api/patients (auth + full JSON)        → create a real patient
5. GET  /api/patients?search=rohan              → JSON response structure
```

### AP4 — Authentication & Parameterization
```
1. GET  /api/patients (no token)                → 401 Unauthorized
2. POST /api/auth/login                         → get token
3. GET  /api/auth/profile (Bearer token)        → use token
4. GET  /api/auth/basic-test (Basic Auth)       → alternative auth
5. GET  /api/patients?gender=female&city=Mumbai → query params
6. GET  /api/patients?page=1&limit=2            → pagination
7. GET  /api/patients?ageMin=30&ageMax=50       → range filter
8. POST /api/oauth/token (client_credentials)   → OAuth2 flow
```

### AP5 — Postman Collections & Newman
```javascript
// Pre-request Script for automatic token injection:
const loginUrl = pm.environment.get('baseUrl') + '/api/auth/login';
pm.sendRequest({
  url: loginUrl,
  method: 'POST',
  header: { 'Content-Type': 'application/json' },
  body: {
    mode: 'raw',
    raw: JSON.stringify({
      email: 'admin@healthapi.com',
      password: 'Admin@1234'
    })
  }
}, (err, res) => {
  const token = res.json().data.accessToken;
  pm.environment.set('token', token);
});

// Run collection with Newman:
// npm install -g newman
// newman run HealthAPI.postman_collection.json \
//   --environment HealthAPI.postman_environment.json \
//   --reporters cli,json \
//   --reporter-json-export results.json
```

**Postman Environment Variables:**
```
baseUrl = https://healthapi.onrender.com
token   = (auto-filled by pre-request script)
patientId = pat_001
doctorId  = doc_001
```

### AP6 — AI-Assisted Testing
```
Prompts for ChatGPT:
1. "Generate 10 edge case test scenarios for POST /api/patients"
2. "What are boundary values for the age filter in GET /api/patients?ageMin=&ageMax="
3. "Write Postman test assertions for a 201 response from POST /api/appointments"

Use Postbot (Postman AI) to:
- Auto-generate assertions from response bodies
- Suggest missing test cases
- Analyze response time patterns
```

---

## 📦 Project Structure

```
healthapi-production/
├── server.js                        # Entry point
├── render.yaml                      # Render deployment config
├── .env.example                     # Environment template
├── sql/
│   ├── 01_schema.sql                # Database schema (run first)
│   └── 02_seed.sql                  # Seed data (run second)
└── src/
    ├── controllers/
    │   ├── authController.js        # Login, refresh, logout
    │   ├── patientController.js     # Patient CRUD
    │   ├── appointmentController.js # Appointment CRUD
    │   ├── oauthController.js       # OAuth 2.0 (all 4 grants)
    │   └── utilController.js        # Doctors, Records, Wards, Simulate, Validate
    ├── routes/
    │   ├── auth.js
    │   ├── patients.js
    │   ├── appointments.js
    │   ├── oauth.js
    │   └── misc.js
    ├── middleware/
    │   ├── auth.js                  # JWT + Basic + OAuth2 verify + RBAC
    │   └── validate.js              # express-validator runner
    └── utils/
        ├── db.js                    # Supabase client
        ├── config.js                # Environment config
        └── response.js              # Standardised response helpers
```

---

## 🔒 Security Checklist

- [x] Passwords stored as bcrypt hashes
- [x] Service role key server-side only (never in client)
- [x] Helmet HTTP security headers
- [x] Rate limiting (200 req / 15 min)
- [x] CORS configured
- [x] Input validation with express-validator
- [x] JWT expiry (1h access, 7d refresh)
- [x] OAuth2 auth codes are single-use + expire in 5 min
- [x] OAuth2 refresh tokens rotate on use
- [x] Role-based access control on all write endpoints

---

## 🌐 Live Deployment URLs (after Render deploy)

```
Docs:      https://healthapi.onrender.com/api/docs
Health:    https://healthapi.onrender.com/api/health
Patients:  https://healthapi.onrender.com/api/patients
OAuth:     https://healthapi.onrender.com/api/oauth/.well-known/oauth-authorization-server
```
