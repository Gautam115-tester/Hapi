// src/controllers/patientController.js
const supabase = require('../utils/db');
const { success, error, paginate } = require('../utils/response');

// Helper: map DB row → API shape
const mapPatient = (p) => ({
  id:           p.id,
  firstName:    p.first_name,
  lastName:     p.last_name,
  dateOfBirth:  p.date_of_birth,
  age:          p.age,
  gender:       p.gender,
  bloodGroup:   p.blood_group,
  phone:        p.phone,
  email:        p.email,
  address: {
    street:  p.street  || '',
    city:    p.city    || '',
    state:   p.state   || '',
    pincode: p.pincode || '',
  },
  emergencyContact: {
    name:     p.emergency_name     || '',
    relation: p.emergency_relation || '',
    phone:    p.emergency_phone    || '',
  },
  medicalHistory:      p.medical_history      || [],
  allergies:           p.allergies            || [],
  currentMedications:  p.current_medications  || [],
  insuranceId:         p.insurance_id,
  status:              p.status,
  admittedAt:          p.admitted_at,
  createdAt:           p.created_at,
  updatedAt:           p.updated_at,
});

// ── GET /api/patients ─────────────────────────────────────────
const getAll = async (req, res) => {
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

  // Sorting
  const sortMap = { firstName: 'first_name', lastName: 'last_name', createdAt: 'created_at', age: 'age' };
  const sortCol = sortMap[req.query.sortBy] || 'created_at';
  const asc     = req.query.order === 'asc';
  query = query.order(sortCol, { ascending: asc });

  // Pagination
  const page  = Math.max(1, parseInt(req.query.page  || 1, 10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || 10, 10)));
  query = query.range((page - 1) * limit, page * limit - 1);

  const { data, error: dbErr, count } = await query;
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);

  return success(res, (data || []).map(mapPatient), 'Patients fetched successfully.', 200, paginate(count || 0, page, limit));
};

// ── GET /api/patients/:id ─────────────────────────────────────
const getById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('patients').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  return success(res, mapPatient(data), 'Patient fetched successfully.');
};

// ── POST /api/patients ────────────────────────────────────────
const create = async (req, res) => {
  const { firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email,
          address = {}, emergencyContact = {}, medicalHistory = [],
          allergies = [], currentMedications = [], insuranceId } = req.body;

  // Check email uniqueness
  const { data: existing } = await supabase.from('patients').select('id').eq('email', email).single();
  if (existing) return error(res, 409, 'EMAIL_CONFLICT', `A patient with email '${email}' already exists.`);

  const dob = new Date(dateOfBirth);
  const age = Math.floor((Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000));

  const row = {
    first_name: firstName, last_name: lastName, date_of_birth: dateOfBirth, age,
    gender, blood_group: bloodGroup, phone, email,
    street: address.street, city: address.city, state: address.state, pincode: address.pincode,
    emergency_name: emergencyContact.name, emergency_relation: emergencyContact.relation, emergency_phone: emergencyContact.phone,
    medical_history: medicalHistory, allergies, current_medications: currentMedications,
    insurance_id: insuranceId || null, status: 'active',
  };

  const { data, error: dbErr } = await supabase.from('patients').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapPatient(data), 'Patient created successfully.', 201);
};

// ── PUT /api/patients/:id ─────────────────────────────────────
const update = async (req, res) => {
  const { data: existing, error: findErr } = await supabase.from('patients').select('id').eq('id', req.params.id).single();
  if (findErr || !existing) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const b = req.body;
  const updates = {};
  if (b.firstName)          updates.first_name            = b.firstName;
  if (b.lastName)           updates.last_name             = b.lastName;
  if (b.dateOfBirth) {
    updates.date_of_birth = b.dateOfBirth;
    updates.age = Math.floor((Date.now() - new Date(b.dateOfBirth).getTime()) / (365.25 * 24 * 60 * 60 * 1000));
  }
  if (b.gender)             updates.gender                = b.gender;
  if (b.bloodGroup)         updates.blood_group           = b.bloodGroup;
  if (b.phone)              updates.phone                 = b.phone;
  if (b.email)              updates.email                 = b.email;
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
  if (b.medicalHistory)     updates.medical_history       = b.medicalHistory;
  if (b.allergies)          updates.allergies             = b.allergies;
  if (b.currentMedications) updates.current_medications   = b.currentMedications;
  if (b.insuranceId !== undefined) updates.insurance_id  = b.insuranceId;
  if (b.status)             updates.status               = b.status;

  const { data, error: dbErr } = await supabase.from('patients').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapPatient(data), 'Patient updated successfully.');
};

// ── PATCH /api/patients/:id ───────────────────────────────────
const patch = update; // Same logic — partial fields handled naturally

// ── DELETE /api/patients/:id ──────────────────────────────────
const remove = async (req, res) => {
  const { data: existing, error: findErr } = await supabase.from('patients').select('id, first_name, last_name').eq('id', req.params.id).single();
  if (findErr || !existing) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const { error: dbErr } = await supabase.from('patients').delete().eq('id', req.params.id);
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, { id: existing.id, name: `${existing.first_name} ${existing.last_name}` }, 'Patient deleted successfully.');
};

// ── GET /api/patients/:id/appointments ───────────────────────
const getAppointments = async (req, res) => {
  const { data: patient } = await supabase.from('patients').select('id, first_name, last_name').eq('id', req.params.id).single();
  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const { data, error: dbErr } = await supabase.from('appointments').select('*').eq('patient_id', req.params.id).order('appointment_date', { ascending: false });
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapApt), `Appointments for patient ${patient.first_name} ${patient.last_name}.`);
};

// ── GET /api/patients/:id/records ────────────────────────────
const getMedicalRecords = async (req, res) => {
  const { data: patient } = await supabase.from('patients').select('id, first_name, last_name').eq('id', req.params.id).single();
  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const { data, error: dbErr } = await supabase.from('medical_records').select('*').eq('patient_id', req.params.id).order('created_at', { ascending: false });
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapRecord), `Medical records for patient ${patient.first_name} ${patient.last_name}.`);
};

// ── Internal mappers ──────────────────────────────────────────
const mapApt = (a) => ({
  id: a.id, patientId: a.patient_id, patientName: a.patient_name,
  doctorId: a.doctor_id, doctorName: a.doctor_name, specialization: a.specialization,
  appointmentDate: a.appointment_date, appointmentTime: a.appointment_time,
  duration: a.duration, type: a.type, status: a.status,
  symptoms: a.symptoms, notes: a.notes, roomNo: a.room_no,
  fees: a.fees, paymentStatus: a.payment_status,
  createdAt: a.created_at, updatedAt: a.updated_at,
});
const mapRecord = (r) => ({
  id: r.id, patientId: r.patient_id, appointmentId: r.appointment_id,
  doctorId: r.doctor_id, doctorName: r.doctor_name, recordType: r.record_type,
  title: r.title, description: r.description, diagnosis: r.diagnosis,
  prescription: r.prescription, testResults: r.test_results, followUpDate: r.follow_up_date,
  createdAt: r.created_at, updatedAt: r.updated_at,
});

module.exports = { getAll, getById, create, update, patch, remove, getAppointments, getMedicalRecords };