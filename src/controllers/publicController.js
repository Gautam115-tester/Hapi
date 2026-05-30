// src/controllers/publicController.js
// ============================================================
//  PUBLIC (no-auth) — sandbox controller.
//  Every handler mirrors its counterpart in the real API:
//    patientController  → patients
//    utilController     → doctors + records
//    appointmentController → appointments
//  Same validation rules, same error codes, same response
//  shape. Only difference: reads/writes go to tempDb (memory),
//  not Supabase. "_sandbox: true" is appended to every record.
// ============================================================

const db       = require('../utils/tempDb');
const { paginate } = require('../utils/response');

// ── Response helpers (same shape as utils/response.js) ───────
const ok = (res, data, message, status = 200, meta = null) => {
  const body = { success: true, message, data };
  if (meta) body.meta = meta;
  return res.status(status).json(body);
};
const fail = (res, status, code, message, details = null) => {
  const body = { success: false, error: { code, message } };
  if (details) body.error.details = details;
  return res.status(status).json(body);
};

// ── Allowed value sets (mirror DB CHECK constraints) ─────────
const BLOOD_GROUPS   = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
const GENDERS        = ['male','female','other'];
const APT_TYPES      = ['consultation','follow-up','emergency','routine-checkup','lab-review'];
const APT_STATUSES   = ['scheduled','confirmed','in-progress','completed','cancelled','no-show'];
const PAY_STATUSES   = ['pending','paid','refunded'];
const DOC_STATUSES   = ['active','on_leave','inactive'];
const PAT_STATUSES   = ['active','inactive'];

const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const calcAge = (dob) =>
  Math.floor((Date.now() - new Date(dob).getTime()) / (365.25 * 24 * 60 * 60 * 1000));

// ── Mappers (identical to real controllers) ───────────────────
const mapPatient = (p) => ({
  id:          p.id,
  firstName:   p.first_name,
  lastName:    p.last_name,
  dateOfBirth: p.date_of_birth,
  age:         p.age,
  gender:      p.gender,
  bloodGroup:  p.blood_group,
  phone:       p.phone,
  email:       p.email,
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
  medicalHistory:     p.medical_history     || [],
  allergies:          p.allergies           || [],
  currentMedications: p.current_medications || [],
  insuranceId:        p.insurance_id,
  status:             p.status,
  admittedAt:         p.admitted_at,
  createdAt:          p.created_at,
  updatedAt:          p.updated_at,
  _sandbox:           true,
});

const mapDoctor = (d) => ({
  id:              d.id,
  name:            d.name,
  specialization:  d.specialization,
  qualification:   d.qualification,
  experience:      d.experience,
  phone:           d.phone,
  email:           d.email,
  availableDays:   d.available_days,
  consultationFee: d.consultation_fee,
  status:          d.status,
  createdAt:       d.created_at,
  updatedAt:       d.updated_at,
  _sandbox:        true,
});

const mapApt = (a) => ({
  id:              a.id,
  patientId:       a.patient_id,
  patientName:     a.patient_name,
  doctorId:        a.doctor_id,
  doctorName:      a.doctor_name,
  specialization:  a.specialization,
  appointmentDate: a.appointment_date,
  appointmentTime: a.appointment_time,
  duration:        a.duration,
  type:            a.type,
  status:          a.status,
  symptoms:        a.symptoms,
  notes:           a.notes,
  roomNo:          a.room_no,
  fees:            a.fees,
  paymentStatus:   a.payment_status,
  createdAt:       a.created_at,
  updatedAt:       a.updated_at,
  _sandbox:        true,
});

const mapRecord = (r) => ({
  id:            r.id,
  patientId:     r.patient_id,
  appointmentId: r.appointment_id,
  doctorId:      r.doctor_id,
  doctorName:    r.doctor_name,
  recordType:    r.record_type,
  title:         r.title,
  description:   r.description,
  diagnosis:     r.diagnosis,
  prescription:  r.prescription,
  testResults:   r.test_results,
  followUpDate:  r.follow_up_date,
  createdAt:     r.created_at,
  updatedAt:     r.updated_at,
  _sandbox:      true,
});


// ══════════════════════════════════════════════════════════════
//  OVERVIEW   GET /api/public
// ══════════════════════════════════════════════════════════════
const overview = (req, res) => res.status(200).json({
  success: true,
  message: 'HealthAPI — Public Sandbox (no authentication required)',
  warning: '⚠️  Isolated in-memory sandbox. Completely separate from the real database. Resets on server restart.',
  sampleIds: {
    patients:     ['pub_pat_001','pub_pat_002','pub_pat_003','pub_pat_004','pub_pat_005'],
    doctors:      ['pub_doc_001','pub_doc_002','pub_doc_003','pub_doc_004'],
    appointments: ['pub_apt_001','pub_apt_002','pub_apt_003','pub_apt_004','pub_apt_005'],
    records:      ['pub_rec_001','pub_rec_002'],
  },
  endpoints: {
    'GET    /api/public/patients':             'List (?gender,status,bloodGroup,city,age,ageMin,ageMax,search,sortBy,order,page,limit)',
    'GET    /api/public/patients/:id':         'Single patient',
    'POST   /api/public/patients':             'Create — firstName,lastName,dateOfBirth,gender,bloodGroup,phone,email required',
    'PUT    /api/public/patients/:id':         'Full replace — all required fields must be present',
    'PATCH  /api/public/patients/:id':         'Partial update — any subset of fields',
    'DELETE /api/public/patients/:id':         'Delete (cascades appointments & records)',
    'GET    /api/public/patients/:id/appointments': 'Appointments for a patient',
    'GET    /api/public/patients/:id/records':      'Records for a patient',
    'GET    /api/public/doctors':              'List (?specialization,status,availableDay)',
    'GET    /api/public/doctors/:id':          'Single doctor',
    'POST   /api/public/doctors':             'Create — name,specialization required',
    'PUT    /api/public/doctors/:id':          'Full replace',
    'PATCH  /api/public/doctors/:id':          'Partial update',
    'DELETE /api/public/doctors/:id':          'Delete',
    'GET    /api/public/doctors/:id/appointments': 'Doctor schedule (?date,status)',
    'GET    /api/public/appointments':         'List (?status,type,doctorId,patientId,date,dateFrom,dateTo,paymentStatus,specialization,page,limit)',
    'GET    /api/public/appointments/:id':     'Single appointment with embedded patient + doctor',
    'POST   /api/public/appointments':         'Book — patientId,doctorId,appointmentDate,appointmentTime required',
    'PUT    /api/public/appointments/:id':     'Full replace — appointmentDate,appointmentTime required',
    'PATCH  /api/public/appointments/:id':     'Partial update',
    'PATCH  /api/public/appointments/:id/status': 'Status transition (mirrors /api/appointments/:id/status)',
    'DELETE /api/public/appointments/:id':     'Delete (blocked if in-progress)',
    'GET    /api/public/records':              'List (?patientId,doctorId,recordType)',
    'GET    /api/public/records/:id':          'Single record',
    'POST   /api/public/records':              'Create — patientId,doctorId required',
    'PUT    /api/public/records/:id':          'Full replace',
    'PATCH  /api/public/records/:id':          'Partial update',
    'DELETE /api/public/records/:id':          'Delete',
    'GET    /api/public/sandbox/stats':        'Current record counts',
    'POST   /api/public/sandbox/reset':        'Reset sandbox to seed data',
  },
});

// ── Sandbox utilities ─────────────────────────────────────────
const sandboxStats = (req, res) => ok(res, db.stats(), 'Sandbox stats.');
const sandboxReset = (req, res) => ok(res, db.reset(), 'Sandbox reset to original seed data.');


// ══════════════════════════════════════════════════════════════
//  PATIENTS
//  mirrors: src/controllers/patientController.js
// ══════════════════════════════════════════════════════════════

// GET /api/public/patients
const getPatients = (req, res) => {
  const { data, total, page, limit } = db.patients.list(req.query);
  return ok(res, data.map(mapPatient), 'Patients fetched successfully.', 200, paginate(total, page, limit));
};

// GET /api/public/patients/:id
const getPatientById = (req, res) => {
  const p = db.patients.byId(req.params.id);
  if (!p) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  return ok(res, mapPatient(p), 'Patient fetched successfully.');
};

// GET /api/public/patients/:id/appointments
const getPatientAppointments = (req, res) => {
  const p = db.patients.byId(req.params.id);
  if (!p) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  const { data } = db.appointments.list({ patientId: req.params.id });
  return ok(res, data.map(mapApt), `Appointments for patient ${p.first_name} ${p.last_name}.`);
};

// GET /api/public/patients/:id/records
const getPatientRecords = (req, res) => {
  const p = db.patients.byId(req.params.id);
  if (!p) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  const recs = db.records.list({ patientId: req.params.id });
  return ok(res, recs.map(mapRecord), `Medical records for patient ${p.first_name} ${p.last_name}.`);
};

// POST /api/public/patients
const createPatient = (req, res) => {
  const {
    firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email,
    address = {}, emergencyContact = {},
    medicalHistory = [], allergies = [], currentMedications = [], insuranceId,
  } = req.body;

  // Required-field check (mirrors express-validator rules in patients.js)
  const missing = ['firstName','lastName','dateOfBirth','gender','bloodGroup','phone','email']
    .filter(f => !req.body[f]);
  if (missing.length)
    return fail(res, 422, 'VALIDATION_ERROR', `Missing required fields: ${missing.join(', ')}`);

  // Format validation
  if (!isEmail(email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Valid email is required.');
  if (!GENDERS.includes(gender))
    return fail(res, 422, 'VALIDATION_ERROR', `gender must be one of: ${GENDERS.join(', ')}`);
  if (!BLOOD_GROUPS.includes(bloodGroup))
    return fail(res, 422, 'VALIDATION_ERROR', `bloodGroup must be one of: ${BLOOD_GROUPS.join(', ')}`);

  const dob = new Date(dateOfBirth);
  if (isNaN(dob.getTime()))
    return fail(res, 422, 'VALIDATION_ERROR', 'dateOfBirth must be a valid date (YYYY-MM-DD).');
  if (dob > new Date())
    return fail(res, 422, 'VALIDATION_ERROR', 'dateOfBirth cannot be in the future.');

  // Uniqueness check (mirrors Supabase email unique constraint)
  if (db.patients.byEmail(email))
    return fail(res, 409, 'EMAIL_CONFLICT', `A patient with email '${email}' already exists.`);

  const record = db.patients.create({
    first_name: firstName, last_name: lastName, date_of_birth: dateOfBirth,
    gender, blood_group: bloodGroup, phone, email,
    street: address.street || null, city: address.city || null,
    state: address.state   || null, pincode: address.pincode || null,
    emergency_name: emergencyContact.name     || null,
    emergency_relation: emergencyContact.relation || null,
    emergency_phone: emergencyContact.phone   || null,
    medical_history: medicalHistory, allergies, current_medications: currentMedications,
    insurance_id: insuranceId || null, status: 'active', admitted_at: null,
  });

  return ok(res, mapPatient(record), 'Patient created successfully.', 201);
};

// PUT /api/public/patients/:id  — full replace (all fields required)
const replacePatient = (req, res) => {
  const existing = db.patients.byId(req.params.id);
  if (!existing) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const {
    firstName, lastName, dateOfBirth, gender, bloodGroup, phone, email,
    address = {}, emergencyContact = {},
    medicalHistory = [], allergies = [], currentMedications = [],
    insuranceId, status,
  } = req.body;

  const missing = ['firstName','lastName','dateOfBirth','gender','bloodGroup','phone','email']
    .filter(f => !req.body[f]);
  if (missing.length)
    return fail(res, 422, 'VALIDATION_ERROR', `PUT requires all fields. Missing: ${missing.join(', ')}`);

  if (!isEmail(email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Valid email is required.');
  if (!GENDERS.includes(gender))
    return fail(res, 422, 'VALIDATION_ERROR', `gender must be one of: ${GENDERS.join(', ')}`);
  if (!BLOOD_GROUPS.includes(bloodGroup))
    return fail(res, 422, 'VALIDATION_ERROR', `bloodGroup must be one of: ${BLOOD_GROUPS.join(', ')}`);

  const dob = new Date(dateOfBirth);
  if (isNaN(dob.getTime()))
    return fail(res, 422, 'VALIDATION_ERROR', 'dateOfBirth must be a valid date (YYYY-MM-DD).');

  // Email uniqueness — allow keeping own email
  const clash = db.patients.byEmail(email);
  if (clash && clash.id !== req.params.id)
    return fail(res, 409, 'EMAIL_CONFLICT', `A patient with email '${email}' already exists.`);

  if (status && !PAT_STATUSES.includes(status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${PAT_STATUSES.join(', ')}`);

  const updated = db.patients.update(req.params.id, {
    first_name: firstName, last_name: lastName, date_of_birth: dateOfBirth,
    gender, blood_group: bloodGroup, phone, email,
    street: address.street || null, city: address.city || null,
    state: address.state   || null, pincode: address.pincode || null,
    emergency_name: emergencyContact.name     || null,
    emergency_relation: emergencyContact.relation || null,
    emergency_phone: emergencyContact.phone   || null,
    medical_history: medicalHistory, allergies, current_medications: currentMedications,
    insurance_id: insuranceId || null,
    status: PAT_STATUSES.includes(status) ? status : 'active',
  });

  return ok(res, mapPatient(updated), 'Patient updated successfully.');
};

// PATCH /api/public/patients/:id  — partial update (only supplied fields)
const patchPatient = (req, res) => {
  const existing = db.patients.byId(req.params.id);
  if (!existing) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length)
    return fail(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  // Validate only the fields that are present
  if (b.email && !isEmail(b.email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Valid email is required.');
  if (b.gender && !GENDERS.includes(b.gender))
    return fail(res, 422, 'VALIDATION_ERROR', `gender must be one of: ${GENDERS.join(', ')}`);
  if (b.bloodGroup && !BLOOD_GROUPS.includes(b.bloodGroup))
    return fail(res, 422, 'VALIDATION_ERROR', `bloodGroup must be one of: ${BLOOD_GROUPS.join(', ')}`);
  if (b.status && !PAT_STATUSES.includes(b.status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${PAT_STATUSES.join(', ')}`);
  if (b.dateOfBirth && isNaN(new Date(b.dateOfBirth).getTime()))
    return fail(res, 422, 'VALIDATION_ERROR', 'dateOfBirth must be a valid date (YYYY-MM-DD).');

  if (b.email) {
    const clash = db.patients.byEmail(b.email);
    if (clash && clash.id !== req.params.id)
      return fail(res, 409, 'EMAIL_CONFLICT', `A patient with email '${b.email}' already exists.`);
  }

  const updates = {};
  if (b.firstName)   updates.first_name  = b.firstName;
  if (b.lastName)    updates.last_name   = b.lastName;
  if (b.dateOfBirth) updates.date_of_birth = b.dateOfBirth;   // age recalculated in db.update()
  if (b.gender)      updates.gender      = b.gender;
  if (b.bloodGroup)  updates.blood_group = b.bloodGroup;
  if (b.phone)       updates.phone       = b.phone;
  if (b.email)       updates.email       = b.email;
  if (b.status)      updates.status      = b.status;
  if (b.insuranceId !== undefined) updates.insurance_id = b.insuranceId;
  if (b.admittedAt  !== undefined) updates.admitted_at  = b.admittedAt;
  if (b.address) {
    if (b.address.street  !== undefined) updates.street  = b.address.street;
    if (b.address.city    !== undefined) updates.city    = b.address.city;
    if (b.address.state   !== undefined) updates.state   = b.address.state;
    if (b.address.pincode !== undefined) updates.pincode = b.address.pincode;
  }
  if (b.emergencyContact) {
    if (b.emergencyContact.name     !== undefined) updates.emergency_name     = b.emergencyContact.name;
    if (b.emergencyContact.relation !== undefined) updates.emergency_relation = b.emergencyContact.relation;
    if (b.emergencyContact.phone    !== undefined) updates.emergency_phone    = b.emergencyContact.phone;
  }
  if (b.medicalHistory     !== undefined) updates.medical_history    = b.medicalHistory;
  if (b.allergies          !== undefined) updates.allergies          = b.allergies;
  if (b.currentMedications !== undefined) updates.current_medications = b.currentMedications;

  return ok(res, mapPatient(db.patients.update(req.params.id, updates)), 'Patient updated successfully.');
};

// DELETE /api/public/patients/:id
const deletePatient = (req, res) => {
  const existing = db.patients.byId(req.params.id);
  if (!existing) return fail(res, 404, 'PATIENT_NOT_FOUND', `No patient found with id: ${req.params.id}`);
  db.patients.delete(req.params.id);
  return ok(
    res,
    { id: req.params.id, name: `${existing.first_name} ${existing.last_name}` },
    'Patient deleted successfully.'
  );
};


// ══════════════════════════════════════════════════════════════
//  DOCTORS
//  mirrors: src/controllers/utilController.js  getDoctors / getDoctorById / getDoctorAppointments
//           + publicController create/replace/patch/delete from previous version
// ══════════════════════════════════════════════════════════════

// GET /api/public/doctors
const getDoctors = (req, res) => {
  const data = db.doctors.list(req.query);
  return ok(res, data.map(mapDoctor), 'Doctors fetched successfully.');
};

// GET /api/public/doctors/:id
const getDoctorById = (req, res) => {
  const d = db.doctors.byId(req.params.id);
  if (!d) return fail(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);
  return ok(res, mapDoctor(d), 'Doctor fetched successfully.');
};

// GET /api/public/doctors/:id/appointments  — mirrors getDoctorAppointments
const getDoctorAppointments = (req, res) => {
  const d = db.doctors.byId(req.params.id);
  if (!d) return fail(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);
  const data = db.doctors.appointmentsFor(req.params.id, req.query);
  return ok(res, data.map(mapApt), `Appointments for ${d.name}.`);
};

// POST /api/public/doctors
const createDoctor = (req, res) => {
  const { name, specialization, qualification, experience, phone, email, availableDays, consultationFee, status } = req.body;

  if (!name || !specialization)
    return fail(res, 422, 'VALIDATION_ERROR', 'name and specialization are required.');
  if (email && !isEmail(email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Invalid email format.');
  if (status && !DOC_STATUSES.includes(status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${DOC_STATUSES.join(', ')}`);
  if (email && db.doctors.byEmail(email))
    return fail(res, 409, 'EMAIL_CONFLICT', `A doctor with email '${email}' already exists.`);

  const record = db.doctors.create({
    name, specialization,
    qualification: qualification || null,
    experience: parseInt(experience || 0, 10),
    phone: phone || null,
    email: email || null,
    available_days: availableDays || [],
    consultation_fee: parseFloat(consultationFee || 0),
    status: DOC_STATUSES.includes(status) ? status : 'active',
  });

  return ok(res, mapDoctor(record), 'Doctor created successfully.', 201);
};

// PUT /api/public/doctors/:id
const replaceDoctor = (req, res) => {
  const existing = db.doctors.byId(req.params.id);
  if (!existing) return fail(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  const { name, specialization, qualification, experience, phone, email, availableDays, consultationFee, status } = req.body;
  if (!name || !specialization)
    return fail(res, 422, 'VALIDATION_ERROR', 'PUT requires name and specialization at minimum.');
  if (email && !isEmail(email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Invalid email format.');
  if (status && !DOC_STATUSES.includes(status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${DOC_STATUSES.join(', ')}`);

  if (email) {
    const clash = db.doctors.byEmail(email);
    if (clash && clash.id !== req.params.id)
      return fail(res, 409, 'EMAIL_CONFLICT', `A doctor with email '${email}' already exists.`);
  }

  const updated = db.doctors.update(req.params.id, {
    name, specialization,
    qualification: qualification || null,
    experience: parseInt(experience || 0, 10),
    phone: phone || null,
    email: email || null,
    available_days: availableDays || [],
    consultation_fee: parseFloat(consultationFee || 0),
    status: DOC_STATUSES.includes(status) ? status : 'active',
  });

  return ok(res, mapDoctor(updated), 'Doctor updated successfully.');
};

// PATCH /api/public/doctors/:id
const patchDoctor = (req, res) => {
  const existing = db.doctors.byId(req.params.id);
  if (!existing) return fail(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length)
    return fail(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  if (b.email && !isEmail(b.email))
    return fail(res, 422, 'VALIDATION_ERROR', 'Invalid email format.');
  if (b.status && !DOC_STATUSES.includes(b.status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${DOC_STATUSES.join(', ')}`);
  if (b.email) {
    const clash = db.doctors.byEmail(b.email);
    if (clash && clash.id !== req.params.id)
      return fail(res, 409, 'EMAIL_CONFLICT', `A doctor with email '${b.email}' already exists.`);
  }

  const updates = {};
  if (b.name             !== undefined) updates.name             = b.name;
  if (b.specialization   !== undefined) updates.specialization   = b.specialization;
  if (b.qualification    !== undefined) updates.qualification    = b.qualification;
  if (b.experience       !== undefined) updates.experience       = parseInt(b.experience, 10);
  if (b.phone            !== undefined) updates.phone            = b.phone;
  if (b.email            !== undefined) updates.email            = b.email;
  if (b.availableDays    !== undefined) updates.available_days   = b.availableDays;
  if (b.consultationFee  !== undefined) updates.consultation_fee = parseFloat(b.consultationFee);
  if (b.status           !== undefined) updates.status           = b.status;

  return ok(res, mapDoctor(db.doctors.update(req.params.id, updates)), 'Doctor updated successfully.');
};

// DELETE /api/public/doctors/:id
const deleteDoctor = (req, res) => {
  const existing = db.doctors.byId(req.params.id);
  if (!existing) return fail(res, 404, 'DOCTOR_NOT_FOUND', `No doctor found with id: ${req.params.id}`);
  db.doctors.delete(req.params.id);
  return ok(res, { id: req.params.id, name: existing.name }, 'Doctor deleted successfully.');
};


// ══════════════════════════════════════════════════════════════
//  APPOINTMENTS
//  mirrors: src/controllers/appointmentController.js
// ══════════════════════════════════════════════════════════════

// GET /api/public/appointments
const getAppointments = (req, res) => {
  const { data, total, page, limit } = db.appointments.list(req.query);
  return ok(res, data.map(mapApt), 'Appointments fetched successfully.', 200, paginate(total, page, limit));
};

// GET /api/public/appointments/:id  — includes embedded patient + doctor
const getAppointmentById = (req, res) => {
  const a = db.appointments.byId(req.params.id);
  if (!a) return fail(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const p = db.patients.byId(a.patient_id);
  const d = db.doctors.byId(a.doctor_id);

  return ok(res, {
    ...mapApt(a),
    patient: p ? { id: p.id, firstName: p.first_name, lastName: p.last_name, phone: p.phone, email: p.email } : null,
    doctor:  d ? { id: d.id, name: d.name, specialization: d.specialization, phone: d.phone, email: d.email }  : null,
  }, 'Appointment fetched successfully.');
};

// POST /api/public/appointments  — mirrors appointmentController.create exactly
const createAppointment = (req, res) => {
  const { patientId, doctorId, appointmentDate, appointmentTime, type, symptoms, notes, fees } = req.body;

  // Required fields (mirrors express-validator rules in appointments.js)
  if (!patientId)       return fail(res, 422, 'VALIDATION_ERROR', 'patientId is required.');
  if (!doctorId)        return fail(res, 422, 'VALIDATION_ERROR', 'doctorId is required.');
  if (!appointmentDate) return fail(res, 422, 'VALIDATION_ERROR', 'appointmentDate must be YYYY-MM-DD.');
  if (!appointmentTime || !/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(appointmentTime))
    return fail(res, 422, 'VALIDATION_ERROR', 'appointmentTime must be HH:MM.');

  const patient = db.patients.byId(patientId);
  const doctor  = db.doctors.byId(doctorId);

  if (!patient) return fail(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return fail(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);
  if (doctor.status === 'on_leave')
    return fail(res, 409, 'DOCTOR_UNAVAILABLE', `Dr. ${doctor.name} is on leave.`);

  // Slot conflict — same logic as real API
  if (db.appointments.hasSlotConflict(doctorId, appointmentDate, appointmentTime))
    return fail(res, 409, 'SLOT_CONFLICT',
      `Dr. ${doctor.name} already has an appointment on ${appointmentDate} at ${appointmentTime}.`);

  const record = db.appointments.create({
    patient_id:       patientId,
    patient_name:     `${patient.first_name} ${patient.last_name}`,
    doctor_id:        doctorId,
    doctor_name:      doctor.name,
    specialization:   doctor.specialization,
    appointment_date: appointmentDate,
    appointment_time: appointmentTime,
    duration:         req.body.duration || 30,
    type:             APT_TYPES.includes(type) ? type : 'consultation',
    symptoms:         symptoms || '',
    notes:            notes    || '',
    room_no:          req.body.roomNo || null,
    fees:             fees !== undefined ? fees : doctor.consultation_fee,
    payment_status:   'pending',
  });

  return ok(res, mapApt(record), 'Appointment created successfully.', 201);
};

// PUT /api/public/appointments/:id  — mirrors appointmentController.update
const replaceAppointment = (req, res) => {
  const existing = db.appointments.byId(req.params.id);
  if (!existing) return fail(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const { appointmentDate, appointmentTime, type, status, symptoms, notes, roomNo, fees, paymentStatus, duration } = req.body;

  if (!appointmentDate)
    return fail(res, 422, 'VALIDATION_ERROR', 'appointmentDate is required for PUT.');
  if (!appointmentTime || !/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(appointmentTime))
    return fail(res, 422, 'VALIDATION_ERROR', 'appointmentTime must be HH:MM.');
  if (status && !APT_STATUSES.includes(status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${APT_STATUSES.join(', ')}`);
  if (type && !APT_TYPES.includes(type))
    return fail(res, 422, 'VALIDATION_ERROR', `type must be one of: ${APT_TYPES.join(', ')}`);
  if (paymentStatus && !PAY_STATUSES.includes(paymentStatus))
    return fail(res, 422, 'VALIDATION_ERROR', `paymentStatus must be one of: ${PAY_STATUSES.join(', ')}`);

  // Slot conflict for the new time (excluding self)
  if (db.appointments.hasSlotConflict(existing.doctor_id, appointmentDate, appointmentTime, req.params.id))
    return fail(res, 409, 'SLOT_CONFLICT',
      `Dr. ${existing.doctor_name} already has an appointment on ${appointmentDate} at ${appointmentTime}.`);

  const updated = db.appointments.update(req.params.id, {
    appointment_date: appointmentDate,
    appointment_time: appointmentTime,
    duration:         duration || 30,
    type:             APT_TYPES.includes(type) ? type : 'consultation',
    status:           APT_STATUSES.includes(status) ? status : existing.status,
    symptoms:         symptoms !== undefined ? symptoms : '',
    notes:            notes    !== undefined ? notes    : '',
    room_no:          roomNo   !== undefined ? roomNo   : null,
    fees:             fees     !== undefined ? fees     : existing.fees,
    payment_status:   PAY_STATUSES.includes(paymentStatus) ? paymentStatus : existing.payment_status,
  });

  return ok(res, mapApt(updated), 'Appointment updated successfully.');
};

// PATCH /api/public/appointments/:id  — partial update
const patchAppointment = (req, res) => {
  const existing = db.appointments.byId(req.params.id);
  if (!existing) return fail(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length)
    return fail(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  if (b.type && !APT_TYPES.includes(b.type))
    return fail(res, 422, 'VALIDATION_ERROR', `type must be one of: ${APT_TYPES.join(', ')}`);
  if (b.status && !APT_STATUSES.includes(b.status))
    return fail(res, 422, 'VALIDATION_ERROR', `status must be one of: ${APT_STATUSES.join(', ')}`);
  if (b.paymentStatus && !PAY_STATUSES.includes(b.paymentStatus))
    return fail(res, 422, 'VALIDATION_ERROR', `paymentStatus must be one of: ${PAY_STATUSES.join(', ')}`);

  // Block reverting a completed appointment (same rule as real API)
  if (b.status && existing.status === 'completed' && b.status !== 'completed')
    return fail(res, 409, 'INVALID_TRANSITION', 'A completed appointment cannot be changed back.');

  // Slot conflict if time/date are being changed
  const newDate = b.appointmentDate || existing.appointment_date;
  const newTime = b.appointmentTime || existing.appointment_time;
  if ((b.appointmentDate || b.appointmentTime) &&
      db.appointments.hasSlotConflict(existing.doctor_id, newDate, newTime, req.params.id))
    return fail(res, 409, 'SLOT_CONFLICT',
      `Dr. ${existing.doctor_name} already has an appointment on ${newDate} at ${newTime}.`);

  const updates = {};
  if (b.appointmentDate  !== undefined) updates.appointment_date = b.appointmentDate;
  if (b.appointmentTime  !== undefined) updates.appointment_time = b.appointmentTime;
  if (b.duration         !== undefined) updates.duration         = b.duration;
  if (b.type             !== undefined) updates.type             = b.type;
  if (b.status           !== undefined) updates.status           = b.status;
  if (b.symptoms         !== undefined) updates.symptoms         = b.symptoms;
  if (b.notes            !== undefined) updates.notes            = b.notes;
  if (b.roomNo           !== undefined) updates.room_no          = b.roomNo;
  if (b.fees             !== undefined) updates.fees             = b.fees;
  if (b.paymentStatus    !== undefined) updates.payment_status   = b.paymentStatus;

  return ok(res, mapApt(db.appointments.update(req.params.id, updates)), 'Appointment updated successfully.');
};

// PATCH /api/public/appointments/:id/status  — mirrors updateStatus exactly
const updateAppointmentStatus = (req, res) => {
  const { status } = req.body;
  if (!status || !APT_STATUSES.includes(status))
    return fail(res, 400, 'INVALID_STATUS', `Status must be one of: ${APT_STATUSES.join(', ')}`);

  const existing = db.appointments.byId(req.params.id);
  if (!existing) return fail(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  // Same guard as real API
  if (existing.status === 'completed' && status !== 'completed')
    return fail(res, 409, 'INVALID_TRANSITION', 'A completed appointment cannot be changed back.');

  const updated = db.appointments.updateStatus(req.params.id, status);
  return ok(res, mapApt(updated), `Appointment status updated to '${status}'.`);
};

// DELETE /api/public/appointments/:id
const deleteAppointment = (req, res) => {
  const existing = db.appointments.byId(req.params.id);
  if (!existing) return fail(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);
  if (existing.status === 'in-progress')
    return fail(res, 409, 'APPOINTMENT_IN_PROGRESS', 'Cannot delete an in-progress appointment.');

  db.appointments.delete(req.params.id);
  return ok(res, { id: req.params.id }, 'Appointment deleted successfully.');
};


// ══════════════════════════════════════════════════════════════
//  MEDICAL RECORDS
//  mirrors: src/controllers/utilController.js  getRecords / getRecordById / createRecord / updateRecord / deleteRecord
// ══════════════════════════════════════════════════════════════

// GET /api/public/records
const getRecords = (req, res) => {
  const data = db.records.list(req.query);
  return ok(res, data.map(mapRecord), 'Medical records fetched successfully.');
};

// GET /api/public/records/:id
const getRecordById = (req, res) => {
  const r = db.records.byId(req.params.id);
  if (!r) return fail(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);
  return ok(res, mapRecord(r), 'Medical record fetched successfully.');
};

// POST /api/public/records
const createRecord = (req, res) => {
  const { patientId, doctorId, recordType, title, description, diagnosis, prescription, testResults, followUpDate } = req.body;

  if (!patientId || !doctorId)
    return fail(res, 422, 'VALIDATION_ERROR', 'patientId and doctorId are required.');

  const patient = db.patients.byId(patientId);
  const doctor  = db.doctors.byId(doctorId);
  if (!patient) return fail(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return fail(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);

  const record = db.records.create({
    patient_id:     patientId,
    appointment_id: req.body.appointmentId || null,
    doctor_id:      doctorId,
    doctor_name:    doctor.name,
    record_type:    recordType  || 'general',
    title:          title       || '',
    description:    description || '',
    diagnosis:      diagnosis   || '',
    prescription:   prescription  || [],
    test_results:   testResults   || {},
    follow_up_date: followUpDate  || null,
  });

  return ok(res, mapRecord(record), 'Medical record created successfully.', 201);
};

// PUT /api/public/records/:id  — mirrors updateRecord
const replaceRecord = (req, res) => {
  const existing = db.records.byId(req.params.id);
  if (!existing) return fail(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);

  const { recordType, title, description, diagnosis, prescription, testResults, followUpDate } = req.body;

  // Real API updateRecord doesn't enforce required fields on PUT, but title|diagnosis makes sense
  const updated = db.records.update(req.params.id, {
    record_type:    recordType  || 'general',
    title:          title       || '',
    description:    description || '',
    diagnosis:      diagnosis   || '',
    prescription:   prescription  || [],
    test_results:   testResults   || {},
    follow_up_date: followUpDate  || null,
  });

  return ok(res, mapRecord(updated), 'Medical record updated successfully.');
};

// PATCH /api/public/records/:id  — partial update
const patchRecord = (req, res) => {
  const existing = db.records.byId(req.params.id);
  if (!existing) return fail(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);

  const b = req.body;
  if (!Object.keys(b).length)
    return fail(res, 400, 'EMPTY_BODY', 'PATCH body must contain at least one field to update.');

  const updates = {};
  if (b.recordType    !== undefined) updates.record_type    = b.recordType;
  if (b.title         !== undefined) updates.title          = b.title;
  if (b.description   !== undefined) updates.description    = b.description;
  if (b.diagnosis     !== undefined) updates.diagnosis      = b.diagnosis;
  if (b.prescription  !== undefined) updates.prescription   = b.prescription;
  if (b.testResults   !== undefined) updates.test_results   = b.testResults;
  if (b.followUpDate  !== undefined) updates.follow_up_date = b.followUpDate;

  return ok(res, mapRecord(db.records.update(req.params.id, updates)), 'Medical record updated successfully.');
};

// DELETE /api/public/records/:id
const deleteRecord = (req, res) => {
  const existing = db.records.byId(req.params.id);
  if (!existing) return fail(res, 404, 'RECORD_NOT_FOUND', `No record found with id: ${req.params.id}`);
  db.records.delete(req.params.id);
  return ok(res, null, 'Medical record deleted successfully.');
};


module.exports = {
  overview,
  sandboxStats, sandboxReset,
  // Patients
  getPatients, getPatientById, createPatient, replacePatient, patchPatient, deletePatient,
  getPatientAppointments, getPatientRecords,
  // Doctors
  getDoctors, getDoctorById, createDoctor, replaceDoctor, patchDoctor, deleteDoctor,
  getDoctorAppointments,
  // Appointments
  getAppointments, getAppointmentById, createAppointment, replaceAppointment, patchAppointment,
  updateAppointmentStatus, deleteAppointment,
  // Records
  getRecords, getRecordById, createRecord, replaceRecord, patchRecord, deleteRecord,
};