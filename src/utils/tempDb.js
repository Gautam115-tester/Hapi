// src/utils/tempDb.js
// ============================================================
//  SANDBOX — In-memory store for /api/public routes only.
//  Completely isolated from real Supabase data.
//  Mirrors the exact schema, constraints, and query behaviour
//  of the production PostgreSQL tables so every HTTP method
//  works identically to the authenticated API.
// ============================================================

const { v4: uuid } = require('uuid');

// ── Tiny helpers ──────────────────────────────────────────────
const now     = () => new Date().toISOString();
const shortId = (prefix) => `${prefix}_pub_${uuid().replace(/-/g, '').slice(0, 8)}`;
const calcAge = (dob) =>
  Math.floor((Date.now() - new Date(dob).getTime()) / (365.25 * 24 * 60 * 60 * 1000));

// ── Seed data (same shape as DB rows, isolated IDs) ───────────
const SEED = {
  patients: [
    {
      id: 'pub_pat_001', first_name: 'Rohan', last_name: 'Sharma',
      date_of_birth: '1990-04-15', age: 34, gender: 'male', blood_group: 'O+',
      phone: '+91-9876543210', email: 'rohan.sharma@sandbox.com',
      street: '12 MG Road', city: 'Mumbai', state: 'Maharashtra', pincode: '400001',
      emergency_name: 'Anjali Sharma', emergency_relation: 'Spouse', emergency_phone: '+91-9876543211',
      medical_history: ['Hypertension', 'Type 2 Diabetes'],
      allergies: ['Penicillin'],
      current_medications: ['Metformin 500mg', 'Amlodipine 5mg'],
      insurance_id: 'INS-SANDBOX-001', status: 'active', admitted_at: null,
      created_at: '2024-12-01T08:00:00.000Z', updated_at: '2024-12-01T08:00:00.000Z',
    },
    {
      id: 'pub_pat_002', first_name: 'Priya', last_name: 'Patel',
      date_of_birth: '1985-07-22', age: 39, gender: 'female', blood_group: 'A+',
      phone: '+91-9123456789', email: 'priya.patel@sandbox.com',
      street: '45 Park Street', city: 'Pune', state: 'Maharashtra', pincode: '411001',
      emergency_name: 'Raj Patel', emergency_relation: 'Husband', emergency_phone: '+91-9123456790',
      medical_history: ['Asthma'],
      allergies: ['Aspirin', 'Sulfa drugs'],
      current_medications: ['Salbutamol inhaler'],
      insurance_id: 'INS-SANDBOX-002', status: 'active', admitted_at: '2025-01-20T08:00:00.000Z',
      created_at: '2024-12-02T09:00:00.000Z', updated_at: '2024-12-02T09:00:00.000Z',
    },
    {
      id: 'pub_pat_003', first_name: 'Arjun', last_name: 'Nair',
      date_of_birth: '1978-11-30', age: 46, gender: 'male', blood_group: 'B-',
      phone: '+91-9988776655', email: 'arjun.nair@sandbox.com',
      street: '7 Lakeview Colony', city: 'Nagpur', state: 'Maharashtra', pincode: '440001',
      emergency_name: 'Deepa Nair', emergency_relation: 'Wife', emergency_phone: '+91-9988776656',
      medical_history: ['Chronic Kidney Disease Stage 2'],
      allergies: [],
      current_medications: ['Losartan 50mg', 'Vitamin D3'],
      insurance_id: 'INS-SANDBOX-003', status: 'inactive', admitted_at: null,
      created_at: '2024-12-03T10:00:00.000Z', updated_at: '2024-12-03T10:00:00.000Z',
    },
    {
      id: 'pub_pat_004', first_name: 'Sneha', last_name: 'Kulkarni',
      date_of_birth: '2000-03-08', age: 25, gender: 'female', blood_group: 'AB+',
      phone: '+91-9765432109', email: 'sneha.kulkarni@sandbox.com',
      street: '3 Rose Garden', city: 'Nashik', state: 'Maharashtra', pincode: '422001',
      emergency_name: 'Suresh Kulkarni', emergency_relation: 'Father', emergency_phone: '+91-9765432100',
      medical_history: [],
      allergies: ['Latex'],
      current_medications: [],
      insurance_id: 'INS-SANDBOX-004', status: 'active', admitted_at: null,
      created_at: '2024-12-04T11:00:00.000Z', updated_at: '2024-12-04T11:00:00.000Z',
    },
    {
      id: 'pub_pat_005', first_name: 'Vikram', last_name: 'Desai',
      date_of_birth: '1965-09-14', age: 59, gender: 'male', blood_group: 'O-',
      phone: '+91-9654321098', email: 'vikram.desai@sandbox.com',
      street: '22 Shivaji Nagar', city: 'Aurangabad', state: 'Maharashtra', pincode: '431001',
      emergency_name: 'Meena Desai', emergency_relation: 'Wife', emergency_phone: '+91-9654321099',
      medical_history: ['Coronary Artery Disease', 'Hypertension', 'Hyperlipidemia'],
      allergies: ['Codeine'],
      current_medications: ['Atorvastatin 40mg', 'Aspirin 75mg', 'Bisoprolol 5mg'],
      insurance_id: 'INS-SANDBOX-005', status: 'active', admitted_at: '2025-01-18T07:30:00.000Z',
      created_at: '2024-12-05T12:00:00.000Z', updated_at: '2024-12-05T12:00:00.000Z',
    },
  ],

  doctors: [
    {
      id: 'pub_doc_001', name: 'Dr. Sarah Mehta', specialization: 'Cardiology',
      qualification: 'MBBS, MD (Cardiology)', experience: 12,
      phone: '+91-9000000001', email: 'sarah.mehta@sandbox.com',
      available_days: ['Monday', 'Wednesday', 'Friday'],
      consultation_fee: 800.00, status: 'active',
      created_at: '2024-11-01T08:00:00.000Z', updated_at: '2024-11-01T08:00:00.000Z',
    },
    {
      id: 'pub_doc_002', name: 'Dr. Rahul Gupta', specialization: 'Neurology',
      qualification: 'MBBS, DM (Neurology)', experience: 8,
      phone: '+91-9000000002', email: 'rahul.gupta@sandbox.com',
      available_days: ['Tuesday', 'Thursday', 'Saturday'],
      consultation_fee: 1000.00, status: 'active',
      created_at: '2024-11-02T09:00:00.000Z', updated_at: '2024-11-02T09:00:00.000Z',
    },
    {
      id: 'pub_doc_003', name: 'Dr. Anjali Rao', specialization: 'General Medicine',
      qualification: 'MBBS, MD (General Medicine)', experience: 15,
      phone: '+91-9000000003', email: 'anjali.rao@sandbox.com',
      available_days: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
      consultation_fee: 500.00, status: 'active',
      created_at: '2024-11-03T10:00:00.000Z', updated_at: '2024-11-03T10:00:00.000Z',
    },
    {
      id: 'pub_doc_004', name: 'Dr. Karan Malhotra', specialization: 'Orthopedics',
      qualification: 'MBBS, MS (Orthopedics)', experience: 10,
      phone: '+91-9000000004', email: 'karan.malhotra@sandbox.com',
      available_days: ['Monday', 'Wednesday', 'Friday'],
      consultation_fee: 700.00, status: 'on_leave',
      created_at: '2024-11-04T11:00:00.000Z', updated_at: '2024-11-04T11:00:00.000Z',
    },
  ],

  appointments: [
    {
      id: 'pub_apt_001', patient_id: 'pub_pat_001', patient_name: 'Rohan Sharma',
      doctor_id: 'pub_doc_001', doctor_name: 'Dr. Sarah Mehta', specialization: 'Cardiology',
      appointment_date: '2025-02-05', appointment_time: '10:00', duration: 30,
      type: 'consultation', status: 'confirmed',
      symptoms: 'Chest pain and shortness of breath', notes: 'Follow-up after ECG',
      room_no: 'OPD-12', fees: 800.00, payment_status: 'paid',
      created_at: '2025-01-25T09:00:00.000Z', updated_at: '2025-01-25T09:00:00.000Z',
    },
    {
      id: 'pub_apt_002', patient_id: 'pub_pat_002', patient_name: 'Priya Patel',
      doctor_id: 'pub_doc_003', doctor_name: 'Dr. Anjali Rao', specialization: 'General Medicine',
      appointment_date: '2025-02-06', appointment_time: '14:30', duration: 20,
      type: 'follow-up', status: 'scheduled',
      symptoms: 'Recurring asthma attacks', notes: '',
      room_no: 'OPD-05', fees: 500.00, payment_status: 'pending',
      created_at: '2025-01-26T11:00:00.000Z', updated_at: '2025-01-26T11:00:00.000Z',
    },
    {
      id: 'pub_apt_003', patient_id: 'pub_pat_005', patient_name: 'Vikram Desai',
      doctor_id: 'pub_doc_001', doctor_name: 'Dr. Sarah Mehta', specialization: 'Cardiology',
      appointment_date: '2025-01-18', appointment_time: '09:00', duration: 45,
      type: 'emergency', status: 'completed',
      symptoms: 'Severe chest pain radiating to arm', notes: 'Admitted for observation.',
      room_no: 'ICU-02', fees: 2500.00, payment_status: 'paid',
      created_at: '2025-01-18T07:30:00.000Z', updated_at: '2025-01-18T10:00:00.000Z',
    },
    {
      id: 'pub_apt_004', patient_id: 'pub_pat_004', patient_name: 'Sneha Kulkarni',
      doctor_id: 'pub_doc_002', doctor_name: 'Dr. Rahul Gupta', specialization: 'Neurology',
      appointment_date: '2025-02-11', appointment_time: '11:00', duration: 30,
      type: 'consultation', status: 'scheduled',
      symptoms: 'Frequent migraines and dizziness', notes: '',
      room_no: 'OPD-08', fees: 1000.00, payment_status: 'pending',
      created_at: '2025-01-28T14:00:00.000Z', updated_at: '2025-01-28T14:00:00.000Z',
    },
    {
      id: 'pub_apt_005', patient_id: 'pub_pat_003', patient_name: 'Arjun Nair',
      doctor_id: 'pub_doc_003', doctor_name: 'Dr. Anjali Rao', specialization: 'General Medicine',
      appointment_date: '2025-01-10', appointment_time: '15:00', duration: 20,
      type: 'follow-up', status: 'cancelled',
      symptoms: 'Routine check-up', notes: 'Patient cancelled due to travel',
      room_no: 'OPD-05', fees: 500.00, payment_status: 'refunded',
      created_at: '2025-01-05T10:00:00.000Z', updated_at: '2025-01-09T18:00:00.000Z',
    },
  ],

  records: [
    {
      id: 'pub_rec_001', patient_id: 'pub_pat_001', appointment_id: null,
      doctor_id: 'pub_doc_001', doctor_name: 'Dr. Sarah Mehta', record_type: 'lab_report',
      title: 'Blood Sugar Test',
      description: 'Fasting blood glucose: 126 mg/dL, HbA1c: 7.2%',
      diagnosis: 'Type 2 Diabetes - Controlled',
      prescription: ['Metformin 500mg twice daily', 'Low sugar diet advised'],
      test_results: { fastingGlucose: '126 mg/dL', HbA1c: '7.2%', totalCholesterol: '195 mg/dL' },
      follow_up_date: '2025-04-01',
      created_at: '2024-12-15T10:00:00.000Z', updated_at: '2024-12-15T10:00:00.000Z',
    },
    {
      id: 'pub_rec_002', patient_id: 'pub_pat_005', appointment_id: 'pub_apt_003',
      doctor_id: 'pub_doc_001', doctor_name: 'Dr. Sarah Mehta', record_type: 'discharge_summary',
      title: 'Cardiac Emergency - Discharge Summary',
      description: 'Patient admitted with acute chest pain. Troponin elevated.',
      diagnosis: 'NSTEMI (Non-ST Elevation Myocardial Infarction)',
      prescription: ['Aspirin 75mg daily', 'Clopidogrel 75mg daily', 'Atorvastatin 80mg'],
      test_results: { troponinI: '2.4 ng/mL (High)', ECG: 'ST depression in V4-V6', echocardiogram: 'EF 45%' },
      follow_up_date: '2025-02-18',
      created_at: '2025-01-21T12:00:00.000Z', updated_at: '2025-01-21T12:00:00.000Z',
    },
  ],
};

// ── Deep-clone for clean resets ───────────────────────────────
const clone = (x) => JSON.parse(JSON.stringify(x));

// ── Live stores ───────────────────────────────────────────────
let _patients     = clone(SEED.patients);
let _doctors      = clone(SEED.doctors);
let _appointments = clone(SEED.appointments);
let _records      = clone(SEED.records);

// ─────────────────────────────────────────────────────────────
//  PATIENTS
// ─────────────────────────────────────────────────────────────
const patients = {

  // GET list — mirrors patientController.getAll exactly
  list(q = {}) {
    let rows = [..._patients];

    // Exact-match filters (same as Supabase .eq())
    if (q.gender)     rows = rows.filter(p => p.gender === q.gender.toLowerCase());
    if (q.status)     rows = rows.filter(p => p.status === q.status.toLowerCase());
    if (q.bloodGroup) rows = rows.filter(p => p.blood_group === q.bloodGroup);
    if (q.age)        rows = rows.filter(p => p.age === parseInt(q.age, 10));
    if (q.ageMin)     rows = rows.filter(p => p.age >= parseInt(q.ageMin, 10));
    if (q.ageMax)     rows = rows.filter(p => p.age <= parseInt(q.ageMax, 10));

    // Case-insensitive partial city (ilike %city%)
    if (q.city) {
      const c = q.city.toLowerCase();
      rows = rows.filter(p => p.city?.toLowerCase().includes(c));
    }

    // Full-text search across name / email / phone (ilike %q%)
    if (q.search) {
      const s = q.search.toLowerCase();
      rows = rows.filter(p =>
        p.first_name?.toLowerCase().includes(s) ||
        p.last_name?.toLowerCase().includes(s)  ||
        p.email?.toLowerCase().includes(s)       ||
        p.phone?.includes(s)
      );
    }

    // Sorting — matches sortMap in real controller
    const sortMap = { firstName: 'first_name', lastName: 'last_name', age: 'age', createdAt: 'created_at' };
    const col = sortMap[q.sortBy] || 'created_at';
    const asc = q.order === 'asc';
    rows.sort((a, b) => {
      const av = a[col], bv = b[col];
      if (av < bv) return asc ? -1 : 1;
      if (av > bv) return asc ? 1  : -1;
      return 0;
    });

    // Pagination — same bounds as real controller
    const page  = Math.max(1, parseInt(q.page  || 1,  10));
    const limit = Math.min(50, Math.max(1, parseInt(q.limit || 10, 10)));
    const total = rows.length;
    return { data: rows.slice((page - 1) * limit, page * limit), total, page, limit };
  },

  byId(id) { return _patients.find(p => p.id === id) || null; },

  byEmail(email) { return _patients.find(p => p.email === email) || null; },

  // POST — create
  create(fields) {
    const row = {
      ...fields,
      id: shortId('pat'),
      age: calcAge(fields.date_of_birth),
      created_at: now(),
      updated_at: now(),
    };
    _patients.push(row);
    return row;
  },

  // PUT / PATCH — update (partial: only keys present in `fields` are changed)
  update(id, fields) {
    const i = _patients.findIndex(p => p.id === id);
    if (i === -1) return null;
    // Recalculate age when DOB changes
    if (fields.date_of_birth) fields.age = calcAge(fields.date_of_birth);
    _patients[i] = { ..._patients[i], ...fields, updated_at: now() };
    return _patients[i];
  },

  // DELETE — cascade removes related appointments and their records
  delete(id) {
    const exists = _patients.find(p => p.id === id);
    if (!exists) return false;
    _patients     = _patients.filter(p => p.id !== id);
    // Cascade: find appointments for this patient, collect ids
    const aptIds = _appointments.filter(a => a.patient_id === id).map(a => a.id);
    _appointments = _appointments.filter(a => a.patient_id !== id);
    // Cascade: nullify appointment_id in records, remove records for this patient
    _records = _records
      .filter(r => r.patient_id !== id)
      .map(r => aptIds.includes(r.appointment_id) ? { ...r, appointment_id: null } : r);
    return true;
  },
};

// ─────────────────────────────────────────────────────────────
//  DOCTORS
// ─────────────────────────────────────────────────────────────
const doctors = {

  list(q = {}) {
    let rows = [..._doctors];
    if (q.specialization) {
      const s = q.specialization.toLowerCase();
      rows = rows.filter(d => d.specialization?.toLowerCase().includes(s));
    }
    if (q.status)       rows = rows.filter(d => d.status === q.status);
    if (q.availableDay) rows = rows.filter(d => d.available_days?.includes(q.availableDay));
    rows.sort((a, b) => a.name.localeCompare(b.name));
    return rows;
  },

  byId(id) { return _doctors.find(d => d.id === id) || null; },

  byEmail(email) { return _doctors.find(d => d.email === email) || null; },

  // GET /doctors/:id/appointments — mirrors getDoctorAppointments
  appointmentsFor(id, q = {}) {
    let rows = _appointments.filter(a => a.doctor_id === id);
    if (q.date)   rows = rows.filter(a => a.appointment_date === q.date);
    if (q.status) rows = rows.filter(a => a.status === q.status);
    rows.sort((a, b) => (a.appointment_date < b.appointment_date ? -1 : 1));
    return rows;
  },

  create(fields) {
    const row = { ...fields, id: shortId('doc'), created_at: now(), updated_at: now() };
    _doctors.push(row);
    return row;
  },

  update(id, fields) {
    const i = _doctors.findIndex(d => d.id === id);
    if (i === -1) return null;
    _doctors[i] = { ..._doctors[i], ...fields, updated_at: now() };
    return _doctors[i];
  },

  // DELETE — does NOT cascade appointments (real API doesn't cascade on doctor delete)
  delete(id) {
    const exists = _doctors.find(d => d.id === id);
    if (!exists) return false;
    _doctors = _doctors.filter(d => d.id !== id);
    return true;
  },
};

// ─────────────────────────────────────────────────────────────
//  APPOINTMENTS
// ─────────────────────────────────────────────────────────────
const appointments = {

  list(q = {}) {
    let rows = [..._appointments];

    if (q.status)         rows = rows.filter(a => a.status === q.status);
    if (q.type)           rows = rows.filter(a => a.type === q.type);
    if (q.doctorId)       rows = rows.filter(a => a.doctor_id === q.doctorId);
    if (q.patientId)      rows = rows.filter(a => a.patient_id === q.patientId);
    if (q.paymentStatus)  rows = rows.filter(a => a.payment_status === q.paymentStatus);
    if (q.date)           rows = rows.filter(a => a.appointment_date === q.date);
    if (q.dateFrom)       rows = rows.filter(a => a.appointment_date >= q.dateFrom);
    if (q.dateTo)         rows = rows.filter(a => a.appointment_date <= q.dateTo);
    if (q.specialization) {
      const s = q.specialization.toLowerCase();
      rows = rows.filter(a => a.specialization?.toLowerCase().includes(s));
    }

    // Default sort: appointment_date DESC  (or by appointmentTime)
    const col = q.sortBy === 'appointmentTime' ? 'appointment_time' : 'appointment_date';
    const asc = q.order !== 'desc';
    rows.sort((a, b) => {
      if (a[col] < b[col]) return asc ? -1 : 1;
      if (a[col] > b[col]) return asc ? 1  : -1;
      return 0;
    });

    const page  = Math.max(1, parseInt(q.page  || 1,  10));
    const limit = Math.min(50, Math.max(1, parseInt(q.limit || 10, 10)));
    const total = rows.length;
    return { data: rows.slice((page - 1) * limit, page * limit), total, page, limit };
  },

  byId(id) { return _appointments.find(a => a.id === id) || null; },

  // Slot-conflict check — mirrors the Supabase query in both controllers
  // excludes 'cancelled' and 'completed', optionally skip self (for PUT)
  hasSlotConflict(doctorId, date, time, excludeId = null) {
    return _appointments.some(a =>
      a.doctor_id === doctorId &&
      a.appointment_date === date &&
      a.appointment_time === time &&
      !['cancelled', 'completed'].includes(a.status) &&
      a.id !== excludeId
    );
  },

  create(fields) {
    const row = { ...fields, id: shortId('apt'), status: 'scheduled', created_at: now(), updated_at: now() };
    _appointments.push(row);
    return row;
  },

  update(id, fields) {
    const i = _appointments.findIndex(a => a.id === id);
    if (i === -1) return null;
    _appointments[i] = { ..._appointments[i], ...fields, updated_at: now() };
    return _appointments[i];
  },

  // PATCH status — mirrors updateStatus controller exactly
  updateStatus(id, status) {
    return this.update(id, { status });
  },

  // DELETE — nullify appointment_id in linked records (ON DELETE SET NULL)
  delete(id) {
    const exists = _appointments.find(a => a.id === id);
    if (!exists) return false;
    _appointments = _appointments.filter(a => a.id !== id);
    _records = _records.map(r => r.appointment_id === id ? { ...r, appointment_id: null } : r);
    return true;
  },
};

// ─────────────────────────────────────────────────────────────
//  MEDICAL RECORDS
// ─────────────────────────────────────────────────────────────
const records = {

  list(q = {}) {
    let rows = [..._records];
    if (q.patientId)  rows = rows.filter(r => r.patient_id  === q.patientId);
    if (q.doctorId)   rows = rows.filter(r => r.doctor_id   === q.doctorId);
    if (q.recordType) rows = rows.filter(r => r.record_type === q.recordType);
    // Default: created_at DESC
    rows.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    return rows;
  },

  byId(id) { return _records.find(r => r.id === id) || null; },

  create(fields) {
    const row = { ...fields, id: shortId('rec'), created_at: now(), updated_at: now() };
    _records.push(row);
    return row;
  },

  update(id, fields) {
    const i = _records.findIndex(r => r.id === id);
    if (i === -1) return null;
    _records[i] = { ..._records[i], ...fields, updated_at: now() };
    return _records[i];
  },

  delete(id) {
    const exists = _records.find(r => r.id === id);
    if (!exists) return false;
    _records = _records.filter(r => r.id !== id);
    return true;
  },
};

// ── Sandbox meta ──────────────────────────────────────────────
const reset = () => {
  _patients     = clone(SEED.patients);
  _doctors      = clone(SEED.doctors);
  _appointments = clone(SEED.appointments);
  _records      = clone(SEED.records);
  return { patients: _patients.length, doctors: _doctors.length, appointments: _appointments.length, records: _records.length, message: 'Sandbox reset to original seed data.' };
};

const stats = () => ({
  patients:     _patients.length,
  doctors:      _doctors.length,
  appointments: _appointments.length,
  records:      _records.length,
  note: 'In-memory sandbox. Resets on server restart.',
});

module.exports = { patients, doctors, appointments, records, reset, stats };