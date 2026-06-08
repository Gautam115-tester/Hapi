// src/routes/oauth.js
const router = require('express').Router();
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const ctrl = require('../controllers/oauthController');

// Server metadata & client listing
router.get('/.well-known/oauth-authorization-server', ctrl.serverMetadata);
router.get('/clients', ctrl.listClients);

// Authorization Code flow
// GET  → renders the HTML login/consent page
// POST → processes the form, issues code, redirects
router.get('/authorize',  ctrl.authorize);
router.post('/authorize', ctrl.authorizePost);

// Token endpoint — all 4 grant types
router.post(
  '/token',
  [body('grant_type').notEmpty().withMessage('grant_type required.'), validate],
  ctrl.token
);

// Revocation & Introspection
router.post('/revoke',
  [body('token').notEmpty().withMessage('token required.'), validate],
  ctrl.revoke
);
router.post('/introspect',
  [body('token').notEmpty().withMessage('token required.'), validate],
  ctrl.introspect
);

// ── Self-hosted callback page ─────────────────────────────────
// This is what Postman navigates to after the user logs in.
// It shows the code AND auto-submits it back to Postman desktop.
// Use THIS as your redirect_uri, not oauth.pstmn.io
router.get('/callback', ctrl.callbackPage);

module.exports = router;