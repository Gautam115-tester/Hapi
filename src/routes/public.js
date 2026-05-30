// src/routes/public.js
// ============================================================
//  PUBLIC ROUTES — No authentication required.
//  ⚠️  Uses a separate in-memory SANDBOX database.
//      ZERO connection to real Supabase data.
//  Prefix: /api/public
// ============================================================

const router = require('express').Router();
const ctrl   = require('../controllers/publicController');

// ── Overview & sandbox utilities ─────────────────────────────
router.get('/',                    ctrl.overview);
router.get('/sandbox/stats',       ctrl.sandboxStats);
router.post('/sandbox/reset',      ctrl.sandboxReset);

// ── PATIENTS ──────────────────────────────────────────────────
router.get('/patients',        ctrl.getPatients);
router.get('/patients/:id',    ctrl.getPatientById);
router.post('/patients',       ctrl.createPatient);
router.put('/patients/:id',    ctrl.replacePatient);
router.patch('/patients/:id',  ctrl.patchPatient);
router.delete('/patients/:id', ctrl.deletePatient);

// ── DOCTORS ───────────────────────────────────────────────────
router.get('/doctors',         ctrl.getDoctors);
router.get('/doctors/:id',     ctrl.getDoctorById);
router.post('/doctors',        ctrl.createDoctor);
router.put('/doctors/:id',     ctrl.replaceDoctor);
router.patch('/doctors/:id',   ctrl.patchDoctor);
router.delete('/doctors/:id',  ctrl.deleteDoctor);

// ── APPOINTMENTS ──────────────────────────────────────────────
router.get('/appointments',        ctrl.getAppointments);
router.get('/appointments/:id',    ctrl.getAppointmentById);
router.post('/appointments',       ctrl.createAppointment);
router.put('/appointments/:id',    ctrl.replaceAppointment);
router.patch('/appointments/:id',  ctrl.patchAppointment);
router.delete('/appointments/:id', ctrl.deleteAppointment);

// ── MEDICAL RECORDS ───────────────────────────────────────────
router.get('/records',         ctrl.getRecords);
router.get('/records/:id',     ctrl.getRecordById);
router.post('/records',        ctrl.createRecord);
router.put('/records/:id',     ctrl.replaceRecord);
router.patch('/records/:id',   ctrl.patchRecord);
router.delete('/records/:id',  ctrl.deleteRecord);

module.exports = router;