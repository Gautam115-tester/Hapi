-- ============================================================
--  HealthAPI — Seed Data
--  Run AFTER 01_schema.sql
--  Password hash = bcrypt("Admin@1234", cost=10)
-- ============================================================

-- ── USERS ────────────────────────────────────────────────────
INSERT INTO users (id, name, email, password, role, department) VALUES
('usr_001', 'Dr. Admin',         'admin@healthapi.com',       '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin',  'Administration'),
('usr_002', 'Dr. Sarah Mehta',   'sarah.mehta@healthapi.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'doctor', 'Cardiology'),
('usr_003', 'Nurse Priya Nair',  'priya.nair@healthapi.com',  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'nurse',  'General Ward');

-- ── API KEYS ─────────────────────────────────────────────────
INSERT INTO api_keys (key, user_id, role, description) VALUES
('hapi_live_admin_k3yABC123xyz',  'usr_001', 'admin',  'Admin API Key'),
('hapi_live_doctor_k3yDEF456uvw', 'usr_002', 'doctor', 'Doctor API Key'),
('hapi_live_nurse_k3yGHI789rst',  'usr_003', 'nurse',  'Nurse API Key');

-- ── OAUTH CLIENTS ─────────────────────────────────────────────
INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris, grant_types, scopes) VALUES
(
  'healthapi_client_001',
  'healthapi_oauth_secret_XyZ_2025',
  'Postman Test Client',
  ARRAY['https://oauth.pstmn.io/v1/callback', 'http://localhost:3000/api/oauth/callback'],
  ARRAY['authorization_code', 'client_credentials', 'refresh_token', 'password'],
  ARRAY['read:patients', 'write:patients', 'read:appointments', 'write:appointments', 'read:records', 'admin']
),
(
  'healthapi_client_002',
  'healthapi_oauth_secret_QwE_2025',
  'Mobile App Client',
  ARRAY['com.healthapi.app://callback'],
  ARRAY['authorization_code', 'refresh_token'],
  ARRAY['read:patients', 'read:appointments']
);

-- ── DOCTORS ──────────────────────────────────────────────────
INSERT INTO doctors (id, name, specialization, qualification, experience, phone, email, available_days, consultation_fee, status) VALUES
('doc_001', 'Dr. Sarah Mehta',    'Cardiology',       'MBBS, MD (Cardiology)',         12, '+91-9000000001', 'sarah.mehta@healthapi.com',  ARRAY['Monday','Wednesday','Friday'],                              800.00, 'active'),
('doc_002', 'Dr. Rahul Gupta',    'Neurology',        'MBBS, DM (Neurology)',           8, '+91-9000000002', 'rahul.gupta@healthapi.com',   ARRAY['Tuesday','Thursday','Saturday'],                           1000.00, 'active'),
('doc_003', 'Dr. Anjali Rao',     'General Medicine', 'MBBS, MD (General Medicine)',   15, '+91-9000000003', 'anjali.rao@healthapi.com',    ARRAY['Monday','Tuesday','Wednesday','Thursday','Friday'],          500.00, 'active'),
('doc_004', 'Dr. Karan Malhotra', 'Orthopedics',      'MBBS, MS (Orthopedics)',        10, '+91-9000000004', 'karan.malhotra@healthapi.com',ARRAY['Monday','Wednesday','Friday'],                              700.00, 'on_leave');

-- ── PATIENTS ─────────────────────────────────────────────────
INSERT INTO patients (
  id, first_name, last_name, date_of_birth, age, gender, blood_group, phone, email,
  street, city, state, pincode, emergency_name, emergency_relation, emergency_phone,
  medical_history, allergies, current_medications, insurance_id, status, admitted_at
) VALUES
(
  'pat_001','Rohan','Sharma','1990-04-15',34,'male','O+','+91-9876543210','rohan.sharma@email.com',
  '12 MG Road','Mumbai','Maharashtra','400001','Anjali Sharma','Spouse','+91-9876543211',
  ARRAY['Hypertension','Type 2 Diabetes'],
  ARRAY['Penicillin'],
  ARRAY['Metformin 500mg','Amlodipine 5mg'],
  'INS-MH-2024-001','active',NULL
),
(
  'pat_002','Priya','Patel','1985-07-22',39,'female','A+','+91-9123456789','priya.patel@email.com',
  '45 Park Street','Pune','Maharashtra','411001','Raj Patel','Husband','+91-9123456790',
  ARRAY['Asthma'],
  ARRAY['Aspirin','Sulfa drugs'],
  ARRAY['Salbutamol inhaler'],
  'INS-MH-2024-002','active','2025-01-20T08:00:00Z'
),
(
  'pat_003','Arjun','Nair','1978-11-30',46,'male','B-','+91-9988776655','arjun.nair@email.com',
  '7 Lakeview Colony','Nagpur','Maharashtra','440001','Deepa Nair','Wife','+91-9988776656',
  ARRAY['Chronic Kidney Disease Stage 2'],
  ARRAY[]::TEXT[],
  ARRAY['Losartan 50mg','Vitamin D3'],
  'INS-MH-2024-003','inactive',NULL
),
(
  'pat_004','Sneha','Kulkarni','2000-03-08',25,'female','AB+','+91-9765432109','sneha.kulkarni@email.com',
  '3 Rose Garden','Nashik','Maharashtra','422001','Suresh Kulkarni','Father','+91-9765432100',
  ARRAY[]::TEXT[],
  ARRAY['Latex'],
  ARRAY[]::TEXT[],
  'INS-MH-2024-004','active',NULL
),
(
  'pat_005','Vikram','Desai','1965-09-14',59,'male','O-','+91-9654321098','vikram.desai@email.com',
  '22 Shivaji Nagar','Aurangabad','Maharashtra','431001','Meena Desai','Wife','+91-9654321099',
  ARRAY['Coronary Artery Disease','Hypertension','Hyperlipidemia'],
  ARRAY['Codeine'],
  ARRAY['Atorvastatin 40mg','Aspirin 75mg','Bisoprolol 5mg'],
  'INS-MH-2024-005','active','2025-01-18T07:30:00Z'
);

-- ── APPOINTMENTS ─────────────────────────────────────────────
INSERT INTO appointments (id, patient_id, patient_name, doctor_id, doctor_name, specialization,
  appointment_date, appointment_time, duration, type, status, symptoms, notes, room_no, fees, payment_status,
  created_at, updated_at) VALUES
(
  'apt_001','pat_001','Rohan Sharma','doc_001','Dr. Sarah Mehta','Cardiology',
  '2025-02-05','10:00',30,'consultation','confirmed',
  'Chest pain and shortness of breath','Follow-up after ECG','OPD-12',800.00,'paid',
  '2025-01-25T09:00:00Z','2025-01-25T09:00:00Z'
),
(
  'apt_002','pat_002','Priya Patel','doc_003','Dr. Anjali Rao','General Medicine',
  '2025-02-06','14:30',20,'follow-up','scheduled',
  'Recurring asthma attacks','','OPD-05',500.00,'pending',
  '2025-01-26T11:00:00Z','2025-01-26T11:00:00Z'
),
(
  'apt_003','pat_005','Vikram Desai','doc_001','Dr. Sarah Mehta','Cardiology',
  '2025-01-18','09:00',45,'emergency','completed',
  'Severe chest pain radiating to arm','Admitted for observation. ECG and troponin tests ordered.','ICU-02',2500.00,'paid',
  '2025-01-18T07:30:00Z','2025-01-18T10:00:00Z'
),
(
  'apt_004','pat_004','Sneha Kulkarni','doc_002','Dr. Rahul Gupta','Neurology',
  '2025-02-11','11:00',30,'consultation','scheduled',
  'Frequent migraines and dizziness','','OPD-08',1000.00,'pending',
  '2025-01-28T14:00:00Z','2025-01-28T14:00:00Z'
),
(
  'apt_005','pat_003','Arjun Nair','doc_003','Dr. Anjali Rao','General Medicine',
  '2025-01-10','15:00',20,'follow-up','cancelled',
  'Routine check-up','Patient cancelled due to travel','OPD-05',500.00,'refunded',
  '2025-01-05T10:00:00Z','2025-01-09T18:00:00Z'
);

-- ── MEDICAL RECORDS ───────────────────────────────────────────
INSERT INTO medical_records (id, patient_id, appointment_id, doctor_id, doctor_name, record_type,
  title, description, diagnosis, prescription, test_results, follow_up_date, created_at, updated_at) VALUES
(
  'rec_001','pat_001',NULL,'doc_001','Dr. Sarah Mehta','lab_report',
  'Blood Sugar Test',
  'Fasting blood glucose: 126 mg/dL, HbA1c: 7.2%',
  'Type 2 Diabetes - Controlled',
  ARRAY['Metformin 500mg twice daily','Low sugar diet advised'],
  '{"fastingGlucose":"126 mg/dL","HbA1c":"7.2%","totalCholesterol":"195 mg/dL"}',
  '2025-04-01',
  '2024-12-15T10:00:00Z','2024-12-15T10:00:00Z'
),
(
  'rec_002','pat_005','apt_003','doc_001','Dr. Sarah Mehta','discharge_summary',
  'Cardiac Emergency - Discharge Summary',
  'Patient admitted with acute chest pain. Troponin elevated.',
  'NSTEMI (Non-ST Elevation Myocardial Infarction)',
  ARRAY['Aspirin 75mg daily','Clopidogrel 75mg daily','Atorvastatin 80mg'],
  '{"troponinI":"2.4 ng/mL (High)","ECG":"ST depression in V4-V6","echocardiogram":"EF 45%"}',
  '2025-02-18',
  '2025-01-21T12:00:00Z','2025-01-21T12:00:00Z'
);

-- ── WARDS ────────────────────────────────────────────────────
INSERT INTO wards (id, name, total_beds, available_beds, floor) VALUES
('ward_001','General Ward A', 20, 14, 1),
('ward_002','ICU',            10,  3, 2),
('ward_003','Cardiology Ward',15,  8, 3),
('ward_004','Pediatric Ward', 12, 10, 4);
