// src/routes/register.js
// ============================================================
//  HealthAPI — Tester Registration Portal Routes
//
//  Public:    POST /api/register           — create account
//             POST /api/register/login     — login
//  Protected: GET  /api/register/me        — view credentials
//             POST /api/register/regenerate — rotate secret
// ============================================================

const router = require('express').Router();
const ctrl   = require('../controllers/developerController');
const { testerAuth } = require('../middleware/testerAuth');

// ── No auth needed ────────────────────────────────────────────
router.post('/',          ctrl.register);
router.post('/login',     ctrl.login);

// ── Session token required ────────────────────────────────────
router.get('/me',         testerAuth, ctrl.me);
router.post('/regenerate',testerAuth, ctrl.regenerateSecret);

module.exports = router;