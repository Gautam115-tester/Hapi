// src/routes/public.js
// ============================================================
//  PUBLIC ROUTES — No authentication required
//  Prefix: /api/public
//
//  Methods covered per resource:
//    GET     — list all (with filters) + get by ID
//    POST    — create new resource
//    PUT     — full replace (all fields required)
//    PATCH   — partial update (only supplied fields changed)
//    DELETE  — remove resource
//
//  Resources: patients | doctors | appointments | records
// ============================================================

const router = require('express').Router();
const ctrl   = require('../controllers/publicController');

// ── Overview ──────────────────────────────────────────────────
router.get('/', ctrl.overview);

// ── PATIENTS ──────────────────────────────────────────────────
// GET    /api/public/patients               list + filters + pagination
// GET    /api/public/patients/:id           single patient
// POST   /api/public/patients               create
// PUT    /api/public/patients/:id           full replace
// PATCH  /api/public/patients/:id           partial update
// DELETE /api/public/patients/:id           delete
router.get('/patients',       ctrl.getPatients);
router.get('/patients/:id',   ctrl.getPatientById);
router.post('/patients',      ctrl.createPatient);
router.put('/patients/:id',   ctrl.replacePatient);
router.patch('/patients/:id', ctrl.patchPatient);
router.delete('/patients/:id',ctrl.deletePatient);

// ── DOCTORS ───────────────────────────────────────────────────
// GET    /api/public/doctors                list + filters
// GET    /api/public/doctors/:id            single doctor
// POST   /api/public/doctors                create
// PUT    /api/public/doctors/:id            full replace
// PATCH  /api/public/doctors/:id            partial update
// DELETE /api/public/doctors/:id            delete
router.get('/doctors',        ctrl.getDoctors);
router.get('/doctors/:id',    ctrl.getDoctorById);
router.post('/doctors',       ctrl.createDoctor);
router.put('/doctors/:id',    ctrl.replaceDoctor);
router.patch('/doctors/:id',  ctrl.patchDoctor);
router.delete('/doctors/:id', ctrl.deleteDoctor);

// ── APPOINTMENTS ──────────────────────────────────────────────
// GET    /api/public/appointments           list + filters + pagination
// GET    /api/public/appointments/:id       single (includes patient + doctor)
// POST   /api/public/appointments           book new
// PUT    /api/public/appointments/:id       full replace
// PATCH  /api/public/appointments/:id       partial update (status, notes, fees …)
// DELETE /api/public/appointments/:id       delete
router.get('/appointments',        ctrl.getAppointments);
router.get('/appointments/:id',    ctrl.getAppointmentById);
router.post('/appointments',       ctrl.createAppointment);
router.put('/appointments/:id',    ctrl.replaceAppointment);
router.patch('/appointments/:id',  ctrl.patchAppointment);
router.delete('/appointments/:id', ctrl.deleteAppointment);

// ── MEDICAL RECORDS ───────────────────────────────────────────
// GET    /api/public/records                list + filters
// GET    /api/public/records/:id            single record
// POST   /api/public/records                create
// PUT    /api/public/records/:id            full replace
// PATCH  /api/public/records/:id            partial update
// DELETE /api/public/records/:id            delete
router.get('/records',        ctrl.getRecords);
router.get('/records/:id',    ctrl.getRecordById);
router.post('/records',       ctrl.createRecord);
router.put('/records/:id',    ctrl.replaceRecord);
router.patch('/records/:id',  ctrl.patchRecord);
router.delete('/records/:id', ctrl.deleteRecord);

module.exports = router;
