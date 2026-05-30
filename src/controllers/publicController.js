// src/controllers/publicController.js
// ============================================================
//  PUBLIC (no-auth) endpoints — for learning all 5 HTTP verbs
//  Prefix: /api/public
//  ⚠️  No authentication required on any route in this file.
//  Perfect for AP1 / AP2 / AP3 practice without token setup.
// ============================================================
const supabase = require('../utils/db');
const { success, error, paginate } = require('../utils/response');

// ── Mappers (same shapes as authenticated endpoints) ──────────
const mapPatient = (p) => ({
  id: p.id,
  firstName: p.first_name,
  lastName: p.last_name,
  dateOfBirth: p.date_of_birth,
  age: p.age,
  gender: p.gender,
  bloodGroup: p.blood_group,
  phone: p.phone,
  email: p.email,
  address: {
    street: p.street || '',
    city: p.city || '',
    state: p.state || '',
    pincode: p.pincode || '',
  },
  emergencyContact: {
    name: p.emergency_name || '',
    relation: p.emergency_relation || '',
    phone: p.emergency_phone || '',
  },
  medicalHistory: p.medical_history || [],
  allergies: p.allergies || [],
  currentMedications: p.current_medications || [],
  insuranceId: p.insurance_id,
  status: p.status,
  admittedAt: p.admitted_at,
  createdAt: p.created_at,
  updatedAt: p.updated_at,
});

const mapDoctor = (d) => ({
  id: d.id,
  name: d.name,
  specialization: d.specialization,
  qualification: d.qualification,
  experience: d.experience,
  phone: d.phone,
  email: d.email,
  availableDays: d.available_days,
  consultationFee: d.consultation_fee,
  status: d.status,
  createdAt: d.created_at,
});

const mapApt = (a) => ({
  id: a.id,
  patientId: a.patient_id,
  patientName: a.patient_name,
  doctorId: a.doctor_id,
  doctorName: a.doctor_name,
  specialization: a.specialization,
  appointmentDate: a.appointment_date,
  appointmentTime: a.appointment_time,
  duration: a.duration,
  type: a.type,
  status: a.status,
  symptoms: a.symptoms,
  notes: a.notes,
  roomNo: a.room_no,
  fees: a.fees,
  paymentStatus: a.payment_status,
  createdAt: a.created_at,
  updatedAt: a.updated_at,
});

const mapRecord = (r) => ({
  id: r.id,
  patientId: r.patient_id,
  appointmentId: r.appointment_id,
  doctorId: r.doctor_id,
  doctorName: r.doctor_name,
  recordType: r.record_type,
  title: r.title,
  description: r.description,
  diagnosis: r.diagnosis,
  prescription: r.prescription,
  testResults: r.test_results,
  followUpDate: r.follow_up_date,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

// ══════════════════════════════════════════════════════════════
//  PUBLIC OVERVIEW
//  GET /api/public
// ══════════════════════════════════════════════════════════════
const overview = (req, res) => {
  return res.status(200).json({
    success: true,
    message: 'HealthAPI — Public endpoints (no authentication required)',
    note: 'These routes expose all 5 HTTP methods so you can practice REST fundamentals without dealing with auth headers.',
    endpoints: {
      patients: {
        'GET    /api/public/patients':          'List all patients (supports filters & pagination)',
        'GET    /api/public/patients/:id':      'Get a single patient by ID',
        'POST   /api/public/patients':          'Create a new patient',
        'PUT    /api/public/patients/:id':      'Full update (replace all fields)',
        'PATCH  /api/public/patients/:id':      'Partial update (only supplied fields)',
        'DELETE /api/public/patients/:id':      'Delete a patient',
      },
      doctors: {
        'GET    /api/public/doctors':           'List all doctors',
        'GET    /api/public/doctors/:id':       'Get a single doctor',
        'POST   /api/public/doctors':           'Create a new doctor',
        'PUT    /api/public/doctors/:id':       'Full update a doctor',
        'PATCH  /api/public/doctors/:id':       'Partial update a doctor',
        'DELETE /api/public/doctors/:id':       'Delete a doctor',
      },
      appointments: {
        'GET    /api/public/appointments':      'List all appointments (supports filters)',
        'GET    /api/public/appointments/:id':  'Get a single appointment',
        'POST   /api/public/appointments':      'Book a new appointment',
        'PUT    /api/public/appointments/:id':  'Full update an appointment',
        'PATCH  /api/public/appointments/:id':  'Partial update (status, notes, fees, etc.)',
        'DELETE /api/public/appointments/:id':  'Delete an appointment',
      },
      records: {
        'GET    /api/public/records':           'List medical records',
        'GET    /api/public/records/:id':       'Get a single record',
        'POST   /api/public/records':           'Create a medical record',
        'PUT    /api/public/records/:id':       'Full update a record',
        'PATCH  /api/public/records/:id':       'Partial update a record',
        'DELETE /api/public/records/:id':       'Delete a record',
      },
    },
    sampleIds: {
      patients:     ['pat_001', 'pat_002', 'pat_003', 'pat_004', 'pat_005'],
      doctors:      ['doc_001', 'doc_002', 'doc_003', 'doc_004'],
      appointments: ['apt_001', 'apt_002', 'apt_003', 'apt_004', 'apt_005'],
      records:      ['rec_001', 'rec_002'],
    },
    queryParamsSupported: {
      patients:     ['gender', 'status', 'bloodGroup', 'city', 'age', 'ageMin', 'ageMax', 'search', 'sortBy', 'order', 'page', 'limit'],
      doctors:      ['specialization', 'status', 'availableDay'],
      appointments: ['status', 'type', 'doctorId', 'patientId', 'date', 'dateFrom', 'dateTo', 'paymentStatus', 'specialization'],
      records:      ['patientId', 'doctorId', 'recordType'],
    },
  });
};


// ══════════════════════════════════════════════════════════════
//  PATIENTS — PUBLIC CRUD
// ══════════════════════════════════════════════════════════════

// GET /api/public/patients
const getPatients = async (req, res) => {
  let query = supabase.from('patients').select('*', { count: 'exact' });

  if (req.query.gender)     query = query.eq('gender',      req.query.gender.toLowerCase());
  if (req.query.status)     query = query.eq('status',      req.query.status.toLowerCase());
  if (req.query.bloodGroup) query = query.eq('blood_group', req.query.bloodGroup);
  if (req.query.city)       query = query.ilike('city',     `%${req.query.city}%`);
  if (req.query.age)        query = query.eq('age',         parseInt(req.query.age, 10));
  if (req.query.ageMin)     query = query.gte('age',        parseInt(req.query.ageMin, 10));
  if (req.query.ageMax)     query = query.lte('age',        parseInt(req.query.ageMax, 10));
  if (req.query.search) {
    const q = req.query.search;
    query = query.or(`first_name.ilike.%${q}%,last_name.ilike.%${q}%,email.ilike.%${q}%,phone.ilike.%${q}%`);
  }

  const sortMap = { firstName: 'first_name', lastName: 'last_name', createdAt: 'created_at', age: 'age' };
  const sortCol = sortMap[req.query.sortBy] || 'created_at';
  const asc = req.query.order === 'asc';
  query = query.order(sortCol, { ascending: asc });

  const page  = Math.max(1, parseInt(req.query.page  || 1,  10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || 10, 10)));
  query = query.range((page - 1) * limit, page * limit - 1);

  const { data, error: dbErr, count } = await query;
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapPatient), 'Patients fetched successfully.', 200, paginate(count || 0, page, limit));
};

// GET /api/public/patients/:id
const getPatientById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('patients').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  return success(res, mapPatient(data), 'Patient fetched successfully.');
};

// POST /api/public/patients
const createPatient = async (req, res) => {
  const {
    firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email,
    address = {}, emergencyContact = {}, medicalHistory = [],
    allergies = [], currentMedications = [], insuranceId,
  } = req.body;

  const required = { firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email };
  const missing  = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) {
    return error(res, 422, 'VALIDATION_ERROR', `Missing required fields: ${missing.join(', ')}`);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return error(res, 422, 'VALIDATION_ERROR', 'Invalid email format.');
  }
  if (!['male', 'female', 'other'].includes(gender)) {
    return error(res, 422, 'VALIDATION_ERROR', "gender must be 'male', 'female', or 'other'.");
  }
  if (!['A+','A-','B+','B-','AB+','AB-','O+','O-'].includes(bloodGroup)) {
    return error(res, 422, 'VALIDATION_ERROR', 'Invalid bloodGroup. Must be one of: A+, A-, B+, B-, AB+, AB-, O+, O-.');
  }

  const { data: existing } = await supabase.from('patients').select('id').eq('email', email).single();
  if (existing) return error(res, 409, 'EMAIL_CONFLICT', `A patient with email '${email}' already exists.`);

  const dob = new Date(dateOfBirth);
  if (isNaN(dob.getTime()) || dob > new Date()) {
    return error(res, 422, 'VALIDATION_ERROR', 'dateOfBirth must be a valid past date (YYYY-MM-DD).');
  }
  const age = Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000));

  const row = {
    first_name: firstName, last_name: lastName, date_of_birth: dateOfBirth, age,
    gender, blood_group: bloodGroup, phone, email,
    street: address.street, city: address.city, state: address.state, pincode: address.pincode,
    emergency_name: emergencyContact.name, emergency_relation: emergencyContact.relation,
    emergency_phone: emergencyContact.phone,
    medical_history: medicalHistory, allergies, current_medications: currentMedications,
    insurance_id: insuranceId || null, status: 'active',
  };

  const { data, error: dbErr } = await supabase.from('patients').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapPatient(data), 'Patient created successfully.', 201);
};

// PUT /api/public/patients/:id   — full replace
const replacePatient = async (req, res) => {
  const { data: existing } = await supabase.from('patients').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const {
    firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email,
    address = {}, emergencyContact = {}, medicalHistory = [],
    allergies = [], currentMedications = [], insuranceId, status,
  } = req.body;

  const required = { firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email };
  const missing  = Object.entries(required).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) {
    return error(res, 422, 'VALIDATION_ERROR', `PUT requires all fields. Missing: ${missing.join(', ')}`);
  }

  const dob = new Date(dateOfBirth);
  const age = isNaN(dob.getTime()) ? 0 : Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000));

  const updates = {
    first_name: firstName, last_name: lastName, date_of_birth: dateOfBirth, age,
    gender, blood_group: bloodGroup, phone, email,
    street: address.street || null, city: address.city || null,
    state: address.state || null, pincode: address.pincode || null,
    emergency_name: emergencyContact.name || null,
    emergency_relation: emergencyContact.relation || null,
    emergency_phone: emergencyContact.phone || null,
    medical_history: medicalHistory, allergies, current_medications: currentMedications,
    insurance_id: insuranceId || null, status: status || 'active',
  };

  const { data, error: dbErr } = await supabase.from('patients').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapPatient(data), 'Patient replaced successfully (full update).');
};

// PATCH /api/public/patients/:id   — partial update
const patchPatient = async (req, res) => {
  const { data: existing } = await supabase.from('patients').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length) return error(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  const updates = {};
  if (b.firstName)   updates.first_name  = b.firstName;
  if (b.lastName)    updates.last_name   = b.lastName;
  if (b.dateOfBirth) {
    updates.date_of_birth = b.dateOfBirth;
    const dob = new Date(b.dateOfBirth);
    updates.age = isNaN(dob.getTime()) ? undefined : Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000));
  }
  if (b.gender)             updates.gender              = b.gender;
  if (b.bloodGroup)         updates.blood_group         = b.bloodGroup;
  if (b.phone)              updates.phone               = b.phone;
  if (b.email)              updates.email               = b.email;
  if (b.address) {
    if (b.address.street)  updates.street  = b.address.street;
    if (b.address.city)    updates.city    = b.address.city;
    if (b.address.state)   updates.state   = b.address.state;
    if (b.address.pincode) updates.pincode = b.address.pincode;
  }
  if (b.emergencyContact) {
    if (b.emergencyContact.name)     updates.emergency_name     = b.emergencyContact.name;
    if (b.emergencyContact.relation) updates.emergency_relation = b.emergencyContact.relation;
    if (b.emergencyContact.phone)    updates.emergency_phone    = b.emergencyContact.phone;
  }
  if (b.medicalHistory)    updates.medical_history    = b.medicalHistory;
  if (b.allergies)         updates.allergies          = b.allergies;
  if (b.currentMedications) updates.current_medications = b.currentMedications;
  if (b.insuranceId !== undefined) updates.insurance_id = b.insuranceId;
  if (b.status)            updates.status             = b.status;

  const { data, error: dbErr } = await supabase.from('patients').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapPatient(data), 'Patient partially updated successfully.');
};

// DELETE /api/public/patients/:id
const deletePatient = async (req, res) => {
  const { data: existing } = await supabase.from('patients').select('id, first_name, last_name').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const { error: dbErr } = await supabase.from('patients').delete().eq('id', req.params.id);
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, { id: existing.id, name: `${existing.first_name} ${existing.last_name}`, deletedAt: new Date().toISOString() }, 'Patient deleted successfully.');
};


// ══════════════════════════════════════════════════════════════
//  DOCTORS — PUBLIC CRUD
// ══════════════════════════════════════════════════════════════

// GET /api/public/doctors
const getDoctors = async (req, res) => {
  let query = supabase.from('doctors').select('*');
  if (req.query.specialization) query = query.ilike('specialization', `%${req.query.specialization}%`);
  if (req.query.status)         query = query.eq('status', req.query.status);
  if (req.query.availableDay)   query = query.contains('available_days', [req.query.availableDay]);

  const { data, error: dbErr } = await query.order('name');
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapDoctor), 'Doctors fetched successfully.');
};

// GET /api/public/doctors/:id
const getDoctorById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('doctors').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);
  return success(res, mapDoctor(data), 'Doctor fetched successfully.');
};

// POST /api/public/doctors
const createDoctor = async (req, res) => {
  const { name, specialization, qualification, experience, phone, email, availableDays, consultationFee, status } = req.body;

  if (!name || !specialization) {
    return error(res, 422, 'VALIDATION_ERROR', 'name and specialization are required.');
  }
  if (email) {
    const { data: existing } = await supabase.from('doctors').select('id').eq('email', email).single();
    if (existing) return error(res, 409, 'EMAIL_CONFLICT', `A doctor with email '${email}' already exists.`);
  }

  const validStatuses = ['active', 'on_leave', 'inactive'];
  const row = {
    name,
    specialization,
    qualification: qualification || null,
    experience: parseInt(experience || 0, 10),
    phone: phone || null,
    email: email || null,
    available_days: availableDays || [],
    consultation_fee: parseFloat(consultationFee || 0),
    status: validStatuses.includes(status) ? status : 'active',
  };

  const { data, error: dbErr } = await supabase.from('doctors').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapDoctor(data), 'Doctor created successfully.', 201);
};

// PUT /api/public/doctors/:id
const replaceDoctor = async (req, res) => {
  const { data: existing } = await supabase.from('doctors').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  const { name, specialization, qualification, experience, phone, email, availableDays, consultationFee, status } = req.body;
  if (!name || !specialization) {
    return error(res, 422, 'VALIDATION_ERROR', 'PUT requires name and specialization at minimum.');
  }

  const updates = {
    name, specialization,
    qualification: qualification || null,
    experience: parseInt(experience || 0, 10),
    phone: phone || null,
    email: email || null,
    available_days: availableDays || [],
    consultation_fee: parseFloat(consultationFee || 0),
    status: status || 'active',
  };

  const { data, error: dbErr } = await supabase.from('doctors').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapDoctor(data), 'Doctor replaced successfully (full update).');
};

// PATCH /api/public/doctors/:id
const patchDoctor = async (req, res) => {
  const { data: existing } = await supabase.from('doctors').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length) return error(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  const updates = {};
  if (b.name)             updates.name             = b.name;
  if (b.specialization)   updates.specialization   = b.specialization;
  if (b.qualification)    updates.qualification    = b.qualification;
  if (b.experience !== undefined) updates.experience = parseInt(b.experience, 10);
  if (b.phone)            updates.phone            = b.phone;
  if (b.email)            updates.email            = b.email;
  if (b.availableDays)    updates.available_days   = b.availableDays;
  if (b.consultationFee !== undefined) updates.consultation_fee = parseFloat(b.consultationFee);
  if (b.status)           updates.status           = b.status;

  const { data, error: dbErr } = await supabase.from('doctors').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapDoctor(data), 'Doctor partially updated successfully.');
};

// DELETE /api/public/doctors/:id
const deleteDoctor = async (req, res) => {
  const { data: existing } = await supabase.from('doctors').select('id, name').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  const { error: dbErr } = await supabase.from('doctors').delete().eq('id', req.params.id);
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, { id: existing.id, name: existing.name, deletedAt: new Date().toISOString() }, 'Doctor deleted successfully.');
};


// ══════════════════════════════════════════════════════════════
//  APPOINTMENTS — PUBLIC CRUD
// ══════════════════════════════════════════════════════════════

// GET /api/public/appointments
const getAppointments = async (req, res) => {
  let query = supabase.from('appointments').select('*', { count: 'exact' });

  if (req.query.status)         query = query.eq('status',           req.query.status);
  if (req.query.type)           query = query.eq('type',             req.query.type);
  if (req.query.doctorId)       query = query.eq('doctor_id',        req.query.doctorId);
  if (req.query.patientId)      query = query.eq('patient_id',       req.query.patientId);
  if (req.query.paymentStatus)  query = query.eq('payment_status',   req.query.paymentStatus);
  if (req.query.date)           query = query.eq('appointment_date', req.query.date);
  if (req.query.dateFrom)       query = query.gte('appointment_date', req.query.dateFrom);
  if (req.query.dateTo)         query = query.lte('appointment_date', req.query.dateTo);
  if (req.query.specialization) query = query.ilike('specialization', `%${req.query.specialization}%`);

  const page  = Math.max(1, parseInt(req.query.page  || 1,  10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || 10, 10)));
  query = query.order('appointment_date', { ascending: false }).range((page - 1) * limit, page * limit - 1);

  const { data, error: dbErr, count } = await query;
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapApt), 'Appointments fetched successfully.', 200, paginate(count || 0, page, limit));
};

// GET /api/public/appointments/:id
const getAppointmentById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('appointments').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id, first_name, last_name, phone, email').eq('id', data.patient_id).single(),
    supabase.from('doctors').select('id, name, specialization, phone, email').eq('id', data.doctor_id).single(),
  ]);

  return success(res, { ...mapApt(data), patient: patient || null, doctor: doctor || null }, 'Appointment fetched successfully.');
};

// POST /api/public/appointments
const createAppointment = async (req, res) => {
  const { patientId, doctorId, appointmentDate, appointmentTime, type, symptoms, notes, fees } = req.body;

  if (!patientId || !doctorId || !appointmentDate || !appointmentTime) {
    return error(res, 422, 'VALIDATION_ERROR', 'Required: patientId, doctorId, appointmentDate (YYYY-MM-DD), appointmentTime (HH:MM).');
  }

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id, first_name, last_name').eq('id', patientId).single(),
    supabase.from('doctors').select('id, name, specialization, consultation_fee, status').eq('id', doctorId).single(),
  ]);

  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return error(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);
  if (doctor.status === 'on_leave') return error(res, 409, 'DOCTOR_UNAVAILABLE', `Dr. ${doctor.name} is currently on leave.`);

  const { data: conflict } = await supabase.from('appointments')
    .select('id')
    .eq('doctor_id', doctorId)
    .eq('appointment_date', appointmentDate)
    .eq('appointment_time', appointmentTime)
    .not('status', 'in', '("cancelled","completed")')
    .maybeSingle();

  if (conflict) return error(res, 409, 'SLOT_CONFLICT', `Dr. ${doctor.name} already has a booking on ${appointmentDate} at ${appointmentTime}.`);

  const validTypes = ['consultation', 'follow-up', 'emergency', 'routine-checkup', 'lab-review'];
  const row = {
    patient_id: patientId,
    patient_name: `${patient.first_name} ${patient.last_name}`,
    doctor_id: doctorId,
    doctor_name: doctor.name,
    specialization: doctor.specialization,
    appointment_date: appointmentDate,
    appointment_time: appointmentTime,
    duration: req.body.duration || 30,
    type: validTypes.includes(type) ? type : 'consultation',
    status: 'scheduled',
    symptoms: symptoms || '',
    notes: notes || '',
    room_no: req.body.roomNo || null,
    fees: fees !== undefined ? fees : doctor.consultation_fee,
    payment_status: 'pending',
  };

  const { data, error: dbErr } = await supabase.from('appointments').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), 'Appointment booked successfully.', 201);
};

// PUT /api/public/appointments/:id
const replaceAppointment = async (req, res) => {
  const { data: existing } = await supabase.from('appointments').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const { appointmentDate, appointmentTime, type, status, symptoms, notes, roomNo, fees, paymentStatus, duration } = req.body;
  if (!appointmentDate || !appointmentTime) {
    return error(res, 422, 'VALIDATION_ERROR', 'PUT requires appointmentDate and appointmentTime at minimum.');
  }

  const validStatuses  = ['scheduled', 'confirmed', 'in-progress', 'completed', 'cancelled', 'no-show'];
  const validTypes     = ['consultation', 'follow-up', 'emergency', 'routine-checkup', 'lab-review'];
  const validPayments  = ['pending', 'paid', 'refunded'];

  const updates = {
    appointment_date: appointmentDate,
    appointment_time: appointmentTime,
    duration: duration || 30,
    type: validTypes.includes(type) ? type : 'consultation',
    status: validStatuses.includes(status) ? status : 'scheduled',
    symptoms: symptoms || '',
    notes: notes || '',
    room_no: roomNo || null,
    fees: fees !== undefined ? fees : 0,
    payment_status: validPayments.includes(paymentStatus) ? paymentStatus : 'pending',
  };

  const { data, error: dbErr } = await supabase.from('appointments').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), 'Appointment replaced successfully (full update).');
};

// PATCH /api/public/appointments/:id
const patchAppointment = async (req, res) => {
  const { data: existing } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length) return error(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  const validStatuses = ['scheduled', 'confirmed', 'in-progress', 'completed', 'cancelled', 'no-show'];
  if (b.status && existing.status === 'completed' && b.status !== 'completed') {
    return error(res, 409, 'INVALID_TRANSITION', 'A completed appointment cannot be reverted to another status.');
  }

  const updates = {};
  if (b.appointmentDate) updates.appointment_date = b.appointmentDate;
  if (b.appointmentTime) updates.appointment_time = b.appointmentTime;
  if (b.duration)        updates.duration         = b.duration;
  if (b.type)            updates.type             = b.type;
  if (b.status && validStatuses.includes(b.status)) updates.status = b.status;
  if (b.symptoms)        updates.symptoms         = b.symptoms;
  if (b.notes)           updates.notes            = b.notes;
  if (b.roomNo)          updates.room_no          = b.roomNo;
  if (b.fees !== undefined) updates.fees          = b.fees;
  if (b.paymentStatus)   updates.payment_status   = b.paymentStatus;

  const { data, error: dbErr } = await supabase.from('appointments').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), 'Appointment partially updated successfully.');
};

// DELETE /api/public/appointments/:id
const deleteAppointment = async (req, res) => {
  const { data: existing } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);
  if (existing.status === 'in-progress') return error(res, 409, 'APPOINTMENT_IN_PROGRESS', 'Cannot delete an appointment that is currently in-progress.');

  await supabase.from('appointments').delete().eq('id', req.params.id);
  return success(res, { id: existing.id, deletedAt: new Date().toISOString() }, 'Appointment deleted successfully.');
};


// ══════════════════════════════════════════════════════════════
//  MEDICAL RECORDS — PUBLIC CRUD
// ══════════════════════════════════════════════════════════════

// GET /api/public/records
const getRecords = async (req, res) => {
  let query = supabase.from('medical_records').select('*');
  if (req.query.patientId)  query = query.eq('patient_id',  req.query.patientId);
  if (req.query.doctorId)   query = query.eq('doctor_id',   req.query.doctorId);
  if (req.query.recordType) query = query.eq('record_type', req.query.recordType);

  const { data, error: dbErr } = await query.order('created_at', { ascending: false });
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapRecord), 'Medical records fetched successfully.');
};

// GET /api/public/records/:id
const getRecordById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('medical_records').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'RECORD_NOT_FOUND', `No medical record found with id: ${req.params.id}`);
  return success(res, mapRecord(data), 'Medical record fetched successfully.');
};

// POST /api/public/records
const createRecord = async (req, res) => {
  const { patientId, doctorId, recordType, title, description, diagnosis, prescription, testResults, followUpDate } = req.body;

  if (!patientId || !doctorId) {
    return error(res, 422, 'VALIDATION_ERROR', 'patientId and doctorId are required.');
  }

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id').eq('id', patientId).single(),
    supabase.from('doctors').select('id, name').eq('id', doctorId).single(),
  ]);
  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return error(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);

  const row = {
    patient_id: patientId,
    appointment_id: req.body.appointmentId || null,
    doctor_id: doctorId,
    doctor_name: doctor.name,
    record_type: recordType || 'general',
    title: title || '',
    description: description || '',
    diagnosis: diagnosis || '',
    prescription: prescription || [],
    test_results: testResults || {},
    follow_up_date: followUpDate || null,
  };

  const { data, error: dbErr } = await supabase.from('medical_records').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapRecord(data), 'Medical record created successfully.', 201);
};

// PUT /api/public/records/:id
const replaceRecord = async (req, res) => {
  const { data: existing } = await supabase.from('medical_records').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'RECORD_NOT_FOUND', `No medical record found with id: ${req.params.id}`);

  const { recordType, title, description, diagnosis, prescription, testResults, followUpDate } = req.body;
  if (!title && !diagnosis) {
    return error(res, 422, 'VALIDATION_ERROR', 'PUT requires at least title or diagnosis.');
  }

  const updates = {
    record_type: recordType || 'general',
    title: title || '',
    description: description || '',
    diagnosis: diagnosis || '',
    prescription: prescription || [],
    test_results: testResults || {},
    follow_up_date: followUpDate || null,
  };

  const { data, error: dbErr } = await supabase.from('medical_records').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapRecord(data), 'Medical record replaced successfully (full update).');
};

// PATCH /api/public/records/:id
const patchRecord = async (req, res) => {
  const { data: existing } = await supabase.from('medical_records').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'RECORD_NOT_FOUND', `No medical record found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length) return error(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  const updates = {};
  if (b.recordType)   updates.record_type   = b.recordType;
  if (b.title)        updates.title         = b.title;
  if (b.description)  updates.description   = b.description;
  if (b.diagnosis)    updates.diagnosis     = b.diagnosis;
  if (b.prescription) updates.prescription  = b.prescription;
  if (b.testResults)  updates.test_results  = b.testResults;
  if (b.followUpDate) updates.follow_up_date = b.followUpDate;

  const { data, error: dbErr } = await supabase.from('medical_records').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapRecord(data), 'Medical record partially updated successfully.');
};

// DELETE /api/public/records/:id
const deleteRecord = async (req, res) => {
  const { data: existing } = await supabase.from('medical_records').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'RECORD_NOT_FOUND', `No medical record found with id: ${req.params.id}`);

  await supabase.from('medical_records').delete().eq('id', req.params.id);
  return success(res, { id: existing.id, deletedAt: new Date().toISOString() }, 'Medical record deleted successfully.');
};


module.exports = {
  overview,
  // Patients
  getPatients, getPatientById, createPatient, replacePatient, patchPatient, deletePatient,
  // Doctors
  getDoctors, getDoctorById, createDoctor, replaceDoctor, patchDoctor, deleteDoctor,
  // Appointments
  getAppointments, getAppointmentById, createAppointment, replaceAppointment, patchAppointment, deleteAppointment,
  // Records
  getRecords, getRecordById, createRecord, replaceRecord, patchRecord, deleteRecord,
};
