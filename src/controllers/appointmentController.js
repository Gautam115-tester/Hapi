// src/controllers/appointmentController.js
const supabase = require('../utils/db');
const { success, error, paginate } = require('../utils/response');

const mapApt = (a) => ({
  id: a.id, patientId: a.patient_id, patientName: a.patient_name,
  doctorId: a.doctor_id, doctorName: a.doctor_name, specialization: a.specialization,
  appointmentDate: a.appointment_date, appointmentTime: a.appointment_time,
  duration: a.duration, type: a.type, status: a.status,
  symptoms: a.symptoms, notes: a.notes, roomNo: a.room_no,
  fees: a.fees, paymentStatus: a.payment_status,
  createdAt: a.created_at, updatedAt: a.updated_at,
});

// ── GET /api/appointments ─────────────────────────────────────
const getAll = async (req, res) => {
  let query = supabase.from('appointments').select('*', { count: 'exact' });

  if (req.query.status)        query = query.eq('status',         req.query.status);
  if (req.query.type)          query = query.eq('type',           req.query.type);
  if (req.query.doctorId)      query = query.eq('doctor_id',      req.query.doctorId);
  if (req.query.patientId)     query = query.eq('patient_id',     req.query.patientId);
  if (req.query.paymentStatus) query = query.eq('payment_status', req.query.paymentStatus);
  if (req.query.date)          query = query.eq('appointment_date', req.query.date);
  if (req.query.dateFrom)      query = query.gte('appointment_date', req.query.dateFrom);
  if (req.query.dateTo)        query = query.lte('appointment_date', req.query.dateTo);
  if (req.query.specialization) query = query.ilike('specialization', `%${req.query.specialization}%`);

  const sortCol = req.query.sortBy === 'appointmentTime' ? 'appointment_time' : 'appointment_date';
  const asc     = req.query.order !== 'desc';
  query = query.order(sortCol, { ascending: asc });

  const page  = Math.max(1, parseInt(req.query.page  || 1, 10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || 10, 10)));
  query = query.range((page - 1) * limit, page * limit - 1);

  const { data, error: dbErr, count } = await query;
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, (data || []).map(mapApt), 'Appointments fetched successfully.', 200, paginate(count || 0, page, limit));
};

// ── GET /api/appointments/:id ─────────────────────────────────
const getById = async (req, res) => {
  const { data: apt, error: dbErr } = await supabase.from('appointments').select('*').eq('id', req.params.id).single();
  if (dbErr || !apt) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id, first_name, last_name, phone, email').eq('id', apt.patient_id).single(),
    supabase.from('doctors').select('id, name, specialization, phone, email').eq('id', apt.doctor_id).single(),
  ]);

  return success(res, { ...mapApt(apt), patient: patient || null, doctor: doctor || null }, 'Appointment fetched successfully.');
};

// ── POST /api/appointments ────────────────────────────────────
const create = async (req, res) => {
  const { patientId, doctorId, appointmentDate, appointmentTime, type, symptoms, notes, fees } = req.body;

  const [{ data: patient }, { data: doctor }] = await Promise.all([
    supabase.from('patients').select('id, first_name, last_name').eq('id', patientId).single(),
    supabase.from('doctors').select('id, name, specialization, consultation_fee, status').eq('id', doctorId).single(),
  ]);

  if (!patient) return error(res, 404, 'PATIENT_NOT_FOUND', `Patient '${patientId}' not found.`);
  if (!doctor)  return error(res, 404, 'DOCTOR_NOT_FOUND',  `Doctor '${doctorId}' not found.`);
  if (doctor.status === 'on_leave') return error(res, 409, 'DOCTOR_UNAVAILABLE', `Dr. ${doctor.name} is on leave.`);

  // Slot conflict check
  const { data: conflict } = await supabase.from('appointments')
    .select('id')
    .eq('doctor_id', doctorId)
    .eq('appointment_date', appointmentDate)
    .eq('appointment_time', appointmentTime)
    .not('status', 'in', '("cancelled","completed")')
    .maybeSingle();

  if (conflict) return error(res, 409, 'SLOT_CONFLICT', `Dr. ${doctor.name} already has an appointment on ${appointmentDate} at ${appointmentTime}.`);

  const row = {
    patient_id: patientId, patient_name: `${patient.first_name} ${patient.last_name}`,
    doctor_id: doctorId, doctor_name: doctor.name, specialization: doctor.specialization,
    appointment_date: appointmentDate, appointment_time: appointmentTime,
    duration: req.body.duration || 30,
    type: type || 'consultation', status: 'scheduled',
    symptoms: symptoms || '', notes: notes || '',
    room_no: req.body.roomNo || null,
    fees: fees ?? doctor.consultation_fee,
    payment_status: 'pending',
  };

  const { data, error: dbErr } = await supabase.from('appointments').insert(row).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), 'Appointment created successfully.', 201);
};

// ── PUT /api/appointments/:id ─────────────────────────────────
const update = async (req, res) => {
  const { data: existing } = await supabase.from('appointments').select('id').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);

  const b = req.body;
  const updates = {};
  if (b.appointmentDate) updates.appointment_date = b.appointmentDate;
  if (b.appointmentTime) updates.appointment_time = b.appointmentTime;
  if (b.type)            updates.type            = b.type;
  if (b.status)          updates.status          = b.status;
  if (b.symptoms)        updates.symptoms        = b.symptoms;
  if (b.notes)           updates.notes           = b.notes;
  if (b.roomNo)          updates.room_no         = b.roomNo;
  if (b.fees !== undefined) updates.fees         = b.fees;
  if (b.paymentStatus)   updates.payment_status  = b.paymentStatus;
  if (b.duration)        updates.duration        = b.duration;

  const { data, error: dbErr } = await supabase.from('appointments').update(updates).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), 'Appointment updated successfully.');
};

// ── PATCH /api/appointments/:id/status ───────────────────────
const updateStatus = async (req, res) => {
  const { status } = req.body;
  const allowed = ['scheduled', 'confirmed', 'in-progress', 'completed', 'cancelled', 'no-show'];
  if (!status || !allowed.includes(status)) return error(res, 400, 'INVALID_STATUS', `Status must be one of: ${allowed.join(', ')}`);

  const { data: existing } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);
  if (existing.status === 'completed' && status !== 'completed') {
    return error(res, 409, 'INVALID_TRANSITION', 'A completed appointment cannot be changed back.');
  }

  const { data, error: dbErr } = await supabase.from('appointments').update({ status }).eq('id', req.params.id).select().single();
  if (dbErr) return error(res, 500, 'DB_ERROR', dbErr.message);
  return success(res, mapApt(data), `Appointment status updated to '${status}'.`);
};

// ── DELETE /api/appointments/:id ──────────────────────────────
const remove = async (req, res) => {
  const { data: existing } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).single();
  if (!existing) return error(res, 404, 'APPOINTMENT_NOT_FOUND', `No appointment found with id: ${req.params.id}`);
  if (existing.status === 'in-progress') return error(res, 409, 'APPOINTMENT_IN_PROGRESS', 'Cannot delete an in-progress appointment.');

  await supabase.from('appointments').delete().eq('id', req.params.id);
  return success(res, { id: existing.id }, 'Appointment deleted successfully.');
};

module.exports = { getAll, getById, create, update, updateStatus, remove };