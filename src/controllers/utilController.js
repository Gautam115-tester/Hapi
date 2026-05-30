// src/controllers/utilController.js
const supabase = require('../utils/db');
const { success, error } = require('../utils/response');

// ── Map helpers ───────────────────────────────────────────────
const mapDoctor = (d) => ({
  id: d.id, name: d.name, specialization: d.specialization,
  qualification: d.qualification, experience: d.experience,
  phone: d.phone, email: d.email,
  availableDays: d.available_days, consultationFee: d.consultation_fee,
  status: d.status, createdAt: d.created_at,
});

const mapRecord = (r) => ({
  id: r.id, patientId: r.patient_id, appointmentId: r.appointment_id,
  doctorId: r.doctor_id, doctorName: r.doctor_name, recordType: r.record_type,
  title: r.title, description: r.description, diagnosis: r.diagnosis,
  prescription: r.prescription, testResults: r.test_results, followUpDate: r.follow_up_date,
  createdAt: r.created_at, updatedAt: r.updated_at,
});

// ═══════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
const health = async (req, res) => {
  // Quick DB ping
  let dbStatus = 'connected';
  try {
    await supabase.from('users').select('id').limit(1);
  } catch {
    dbStatus = 'unreachable';
  }

  return res.status(200).json({
    success: true,
    status: 'UP',
    message: 'HealthAPI server is running.',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
    environment: process.env.NODE_ENV || 'development',
    version: '2.0.0',
    database: `supabase (${dbStatus})`,
    endpoints: {
      auth: '/api/auth', patients: '/api/patients',
      appointments: '/api/appointments', doctors: '/api/doctors',
      records: '/api/records', wards: '/api/wards',
      simulate: '/api/simulate', docs: '/api/docs',
    },
  });
};

// ═══════════════════════════════════════════════════════════════
//  DOCTORS
// ═══════════════════════════════════════════════════════════════
const getDoctors = async (req, res) => {
  let query = supabase.from('doctors').select('*');
  if (req.query.specialization) query = query.ilike('specialization', `%${req.query.specialization}%`);
  if (req.query.status)         query = query.eq('status', req.query.status);
  if (req.query.availableDay)   query = query.contains('available_days', [req.query.availableDay]);

  const { data, error: dbErr } = await query.order('name');
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapDoctor), 'Doctors fetched successfully.');
};

const getDoctorById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('doctors').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);
  return success(res, mapDoctor(data), 'Doctor fetched successfully.');
};

const getDoctorAppointments = async (req, res) => {
  const { data: doctor } = await supabase.from('doctors').select('id, name').eq('id', req.params.id).single();
  if (!doctor) return error(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  let query = supabase.from('appointments').select('*').eq('doctor_id', req.params.id);
  if (req.query.date)   query = query.eq('appointment_date', req.query.date);
  if (req.query.status) query = query.eq('status', req.query.status);
  query = query.order('appointment_date');

  const { data, error: dbErr } = await query;
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, data || [], `Appointments for ${doctor.name}.`);
};

// ═══════════════════════════════════════════════════════════════
//  MEDICAL RECORDS
// ═══════════════════════════════════════════════════════════════
const getRecords = async (req, res) => {
  let query = supabase.from('medical_records').select('*');
  if (req.query.patientId)  query = query.eq('patient_id',  req.query.patientId);
  if (req.query.doctorId)   query = query.eq('doctor_id',   req.query.doctorId);
  if (req.query.recordType) query = query.eq('record_type', req.query.recordType);
  const { data, error: dbErr } = await query.order('created_at', { ascending: false });
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapRecord), 'Medical records fetched successfully.');
};

const getRecordById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('medical_records').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);
  return success(res, mapRecord(data), 'Medical record fetched successfully.');
};

const createRecord = async (req, res) => {
  const { patientId, doctorId, recordType, title, description, diagnosis, prescription, testResults, followUpDate } = req.body;

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id').eq('id', patientId).single(),
    supabase.from('doctors').select('id, name').eq('id', doctorId).single(),
  ]);
  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return error(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);

  const row = {
    patient_id: patientId, appointment_id: req.body.appointmentId || null,
    doctor_id: doctorId, doctor_name: doctor.name,
    record_type: recordType || 'general', title: title || '',
    description: description || '', diagnosis: diagnosis || '',
    prescription: prescription || [], test_results: testResults || {},
    follow_up_date: followUpDate || null,
  };

  const { data, error: dbErr } = await supabase.from('medical_records').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapRecord(data), 'Medical record created successfully.', 201);
};

const updateRecord = async (req, res) => {
  const { data: existing } = await supabase.from('medical_records').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);

  const b = req.body;
  const updates = {};
  if (b.recordType)     updates.record_type   = b.recordType;
  if (b.title)          updates.title         = b.title;
  if (b.description)    updates.description   = b.description;
  if (b.diagnosis)      updates.diagnosis     = b.diagnosis;
  if (b.prescription)   updates.prescription  = b.prescription;
  if (b.testResults)    updates.test_results  = b.testResults;
  if (b.followUpDate)   updates.follow_up_date = b.followUpDate;

  const { data, error: dbErr } = await supabase.from('medical_records').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapRecord(data), 'Medical record updated successfully.');
};

const deleteRecord = async (req, res) => {
  const { data: existing } = await supabase.from('medical_records').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);
  await supabase.from('medical_records').delete().eq('id', req.params.id);
  return success(res, null, 'Medical record deleted successfully.');
};

// ═══════════════════════════════════════════════════════════════
//  WARDS
// ═══════════════════════════════════════════════════════════════
const getWards = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('wards').select('*').order('floor');
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  const mapped = (data || []).map((w) => ({
    id: w.id, name: w.name, totalBeds: w.total_beds,
    availableBeds: w.available_beds, floor: w.floor,
  }));
  return success(res, mapped, 'Wards fetched successfully.');
};

const getWardById = async (req, res) => {
  const { data, error: dbErr } = await supabase.from('wards').select('*').eq('id', req.params.id).single();
  if (dbErr || !data) return error(res, 404, 'WARD_NOT_FOUND', `No ward found with id: ${req.params.id}`);
  return success(res, { id: data.id, name: data.name, totalBeds: data.total_beds, availableBeds: data.available_beds, floor: data.floor }, 'Ward fetched successfully.');
};

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════════
const dashboard = async (req, res) => {
  const today = new Date().toISOString().split('T')[0];

  const [
    { count: totalPatients },
    { count: activePatients },
    { data: aptsData },
    { count: totalDoctors },
    { count: activeDoctors },
    { count: totalRecords },
  ] = await Promise.all([
    supabase.from('patients').select('*', { count: 'exact', head: true }),
    supabase.from('patients').select('*', { count: 'exact', head: true }).eq('status', 'active'),
    supabase.from('appointments').select('status, fees, payment_status, appointment_date'),
    supabase.from('doctors').select('*', { count: 'exact', head: true }),
    supabase.from('doctors').select('*', { count: 'exact', head: true }).eq('status', 'active'),
    supabase.from('medical_records').select('*', { count: 'exact', head: true }),
  ]);

  const apts = aptsData || [];
  const byStatus = (s) => apts.filter((a) => a.status === s).length;
  const sumFees  = (arr) => arr.reduce((acc, a) => acc + (parseFloat(a.fees) || 0), 0);

  return success(res, {
    patients:     { total: totalPatients, active: activePatients, inactive: (totalPatients || 0) - (activePatients || 0) },
    appointments: {
      total: apts.length,
      scheduled:   byStatus('scheduled'),
      confirmed:   byStatus('confirmed'),
      completed:   byStatus('completed'),
      cancelled:   byStatus('cancelled'),
      today:       apts.filter((a) => a.appointment_date === today).length,
    },
    doctors: { total: totalDoctors, active: activeDoctors },
    records: { total: totalRecords },
    revenue: {
      total:     sumFees(apts),
      collected: sumFees(apts.filter((a) => a.payment_status === 'paid')),
      pending:   sumFees(apts.filter((a) => a.payment_status === 'pending')),
    },
    generatedAt: new Date().toISOString(),
  }, 'Dashboard statistics fetched successfully.');
};

// ═══════════════════════════════════════════════════════════════
//  STATUS CODE SIMULATORS (AP2)
// ═══════════════════════════════════════════════════════════════
const simulate200 = (_, res) => res.status(200).json({ success: true,  statusCode: 200, status: 'OK',                   message: 'Request was successful.' });
const simulate201 = (_, res) => res.status(201).json({ success: true,  statusCode: 201, status: 'Created',              message: 'Resource was created successfully.' });
const simulate204 = (_, res) => res.status(204).send();
const simulate400 = (_, res) => res.status(400).json({ success: false, statusCode: 400, status: 'Bad Request',          error: { code: 'BAD_REQUEST', message: 'The server cannot process this request due to malformed syntax.' } });
const simulate401 = (_, res) => res.status(401).json({ success: false, statusCode: 401, status: 'Unauthorized',         error: { code: 'UNAUTHORIZED', message: 'Authentication is required.' } });
const simulate403 = (_, res) => res.status(403).json({ success: false, statusCode: 403, status: 'Forbidden',            error: { code: 'FORBIDDEN', message: 'You do not have permission to access this resource.' } });
const simulate404 = (_, res) => res.status(404).json({ success: false, statusCode: 404, status: 'Not Found',            error: { code: 'NOT_FOUND', message: 'The requested resource could not be found.' } });
const simulate409 = (_, res) => res.status(409).json({ success: false, statusCode: 409, status: 'Conflict',             error: { code: 'CONFLICT', message: 'The request conflicts with current state.' } });
const simulate422 = (_, res) => res.status(422).json({ success: false, statusCode: 422, status: 'Unprocessable Entity', error: { code: 'VALIDATION_ERROR', message: 'Validation failed.', fields: [{ field: 'email', value: 'notanemail', message: 'Must be a valid email.' }, { field: 'dateOfBirth', value: '', message: 'Date of birth is required.' }] } });
const simulate429 = (_, res) => res.status(429).json({ success: false, statusCode: 429, status: 'Too Many Requests',    error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests. Try again in 60 seconds.' }, retryAfter: 60 });
const simulate500 = (_, res) => res.status(500).json({ success: false, statusCode: 500, status: 'Internal Server Error',error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected error occurred.' } });
const simulate503 = (_, res) => res.status(503).json({ success: false, statusCode: 503, status: 'Service Unavailable',  error: { code: 'SERVICE_UNAVAILABLE', message: 'Server temporarily unable to handle requests.' }, retryAfter: 300 });

const simulateDelay = (req, res) => {
  const ms = Math.min(10000, parseInt(req.query.ms || 2000, 10));
  setTimeout(() => success(res, { delayedMs: ms }, `Response deliberately delayed by ${ms}ms.`), ms);
};

// ═══════════════════════════════════════════════════════════════
//  VALIDATION ENDPOINTS (AP3)
// ═══════════════════════════════════════════════════════════════
const validatePatient = (req, res) => {
  const body = req.body;
  const errs = [];

  ['firstName', 'lastName', 'dateOfBirth', 'gender', 'bloodGroup', 'phone', 'email'].forEach((f) => {
    if (!body[f]) errs.push({ field: f, message: `${f} is required.` });
  });
  if (body.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) errs.push({ field: 'email', message: 'Invalid email format.' });
  if (body.gender && !['male', 'female', 'other'].includes(body.gender)) errs.push({ field: 'gender', message: "Gender must be 'male', 'female', or 'other'." });
  const validBG = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'];
  if (body.bloodGroup && !validBG.includes(body.bloodGroup)) errs.push({ field: 'bloodGroup', message: `Blood group must be one of: ${validBG.join(', ')}` });
  if (body.dateOfBirth) {
    const dob = new Date(body.dateOfBirth);
    if (isNaN(dob.getTime())) errs.push({ field: 'dateOfBirth', message: 'Invalid date. Use YYYY-MM-DD.' });
    else if (dob > new Date()) errs.push({ field: 'dateOfBirth', message: 'Date of birth cannot be in the future.' });
  }

  if (errs.length > 0) return res.status(422).json({ success: false, valid: false, message: 'Patient payload has validation errors.', errors: errs });
  return res.status(200).json({ success: true, valid: true, message: 'Patient payload is valid.', receivedFields: Object.keys(body) });
};

const validateAppointment = (req, res) => {
  const body = req.body;
  const errs = [];

  ['patientId', 'doctorId', 'appointmentDate', 'appointmentTime'].forEach((f) => {
    if (!body[f]) errs.push({ field: f, message: `${f} is required.` });
  });
  if (body.appointmentDate && isNaN(new Date(body.appointmentDate).getTime())) errs.push({ field: 'appointmentDate', message: 'Invalid date. Use YYYY-MM-DD.' });
  const validTypes = ['consultation', 'follow-up', 'emergency', 'routine-checkup', 'lab-review'];
  if (body.type && !validTypes.includes(body.type)) errs.push({ field: 'type', message: `type must be one of: ${validTypes.join(', ')}` });

  if (errs.length > 0) return res.status(422).json({ success: false, valid: false, message: 'Appointment payload has validation errors.', errors: errs });
  return res.status(200).json({ success: true, valid: true, message: 'Appointment payload is valid.', receivedFields: Object.keys(body) });
};

module.exports = {
  health,
  getDoctors, getDoctorById, getDoctorAppointments,
  getRecords, getRecordById, createRecord, updateRecord, deleteRecord,
  getWards, getWardById,
  dashboard,
  simulate200, simulate201, simulate204, simulate400, simulate401, simulate403, simulate404,
  simulate409, simulate422, simulate429, simulate500, simulate503, simulateDelay,
  validatePatient, validateAppointment,
};