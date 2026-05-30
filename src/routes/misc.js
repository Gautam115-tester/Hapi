// src/routes/misc.js
const { authenticate, authorize } = require('../middleware/auth');
const util = require('../controllers/utilController');

// ── DOCTORS ───────────────────────────────────────────────────
const doctorRouter = require('express').Router();
doctorRouter.use(authenticate);
doctorRouter.get('/',                 util.getDoctors);
doctorRouter.get('/:id',              util.getDoctorById);
doctorRouter.get('/:id/appointments', util.getDoctorAppointments);

// ── RECORDS ───────────────────────────────────────────────────
const recordRouter = require('express').Router();
recordRouter.use(authenticate);
recordRouter.get('/',    util.getRecords);
recordRouter.get('/:id', util.getRecordById);
recordRouter.post('/',   authorize('admin','doctor'), util.createRecord);
recordRouter.put('/:id', authorize('admin','doctor'), util.updateRecord);
recordRouter.delete('/:id', authorize('admin'), util.deleteRecord);

// ── WARDS ─────────────────────────────────────────────────────
const wardRouter = require('express').Router();
wardRouter.use(authenticate);
wardRouter.get('/',    util.getWards);
wardRouter.get('/:id', util.getWardById);

// ── SIMULATE (no auth — AP2 teaching) ────────────────────────
const simulateRouter = require('express').Router();
simulateRouter.get('/200',   util.simulate200);
simulateRouter.get('/201',   util.simulate201);
simulateRouter.get('/204',   util.simulate204);
simulateRouter.get('/400',   util.simulate400);
simulateRouter.get('/401',   util.simulate401);
simulateRouter.get('/403',   util.simulate403);
simulateRouter.get('/404',   util.simulate404);
simulateRouter.get('/409',   util.simulate409);
simulateRouter.get('/422',   util.simulate422);
simulateRouter.get('/429',   util.simulate429);
simulateRouter.get('/500',   util.simulate500);
simulateRouter.get('/503',   util.simulate503);
simulateRouter.get('/delay', util.simulateDelay);

// ── VALIDATE (no auth — AP3 teaching) ────────────────────────
const validateRouter = require('express').Router();
validateRouter.post('/patient',     util.validatePatient);
validateRouter.post('/appointment', util.validateAppointment);

// ── DASHBOARD ─────────────────────────────────────────────────
const dashRouter = require('express').Router();
dashRouter.get('/', authenticate, authorize('admin','doctor'), util.dashboard);

module.exports = { doctorRouter, recordRouter, wardRouter, simulateRouter, validateRouter, dashRouter };