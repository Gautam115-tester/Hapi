// src/routes/auth.js
// ============================================================
//  Auth Routes
//  POST /api/auth/login              — get JWT tokens
//  POST /api/auth/refresh            — rotate tokens
//  POST /api/auth/logout             — invalidate session
//  GET  /api/auth/profile            — my profile (any auth)
//  GET  /api/auth/users              — list users (admin only)
//  GET  /api/auth/apikeys            — list API keys (admin only)
//  GET  /api/auth/basic-test         — test any auth method
//  GET  /api/auth/audit-log          — auth events (admin only)
//  GET  /api/auth/sessions           — active sessions
//  DELETE /api/auth/sessions         — revoke all sessions
//  POST /api/auth/clear-lockout      — clear all lockouts (no auth needed)
//  GET  /api/auth/lockout-status     — view current lockout state (no auth)
// ============================================================

const router = require('express').Router();
const { body } = require('express-validator');
const { validate }               = require('../middleware/validate');
const { authenticate, authorize } = require('../middleware/auth');
const ctrl      = require('../controllers/authController');
const oauthCtrl = require('../controllers/oauthController');

// ── Public routes (no auth required) ─────────────────────────
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required.'),
    body('password').notEmpty().withMessage('Password required.'),
    validate,
  ],
  ctrl.login
);

router.post('/refresh', ctrl.refreshToken);
router.post('/logout',  ctrl.logout);

// ── Clear lockout — intentionally open, no auth needed ───────
// Students who are locked out can call this without any token
router.post('/clear-lockout',   ctrl.clearLockout);
router.get('/lockout-status',   ctrl.lockoutStatus);

// ── Protected routes ──────────────────────────────────────────
router.get('/profile',    authenticate, ctrl.profile);
router.get('/basic-test', authenticate, ctrl.basicTest);

// ── Admin-only routes ─────────────────────────────────────────
router.get('/users',      authenticate, authorize('admin'), ctrl.listUsers);
router.get('/apikeys',    authenticate, authorize('admin'), oauthCtrl.listApiKeys);
router.get('/audit-log',  authenticate, authorize('admin'), ctrl.auditLogEndpoint);

// ── Session management ────────────────────────────────────────
router.get('/sessions',    authenticate, ctrl.listSessions);
router.delete('/sessions', authenticate, ctrl.revokeSessions);

module.exports = router;