// src/routes/oauth.js
const router = require('express').Router();
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const ctrl = require('../controllers/oauthController');

// ── Server metadata & client listing ─────────────────────────
router.get('/.well-known/oauth-authorization-server', ctrl.serverMetadata);
router.get('/clients', ctrl.listClients);

// ── Authorization Code flow ───────────────────────────────────
// GET  → renders the HTML login/consent page
// POST → processes the submitted login form, issues code, redirects
router.get('/authorize',  ctrl.authorize);
router.post('/authorize', ctrl.authorizePost);   // ← NEW

// ── Token endpoint — all 4 grant types ───────────────────────
router.post(
  '/token',
  [body('grant_type').notEmpty().withMessage('grant_type required.'), validate],
  ctrl.token
);

// ── Revocation & Introspection (RFC 7009 / RFC 7662) ─────────
router.post('/revoke',
  [body('token').notEmpty().withMessage('token required.'), validate],
  ctrl.revoke
);
router.post('/introspect',
  [body('token').notEmpty().withMessage('token required.'), validate],
  ctrl.introspect
);

// ── Callback landing page (for testing redirect_uri flows) ───
router.get('/callback', (req, res) => {
  const { code, state, error: oauthError, error_description } = req.query;

  if (oauthError) {
    return res.status(400).json({
      success: false,
      error: { code: oauthError, message: error_description || 'Authorization failed.' },
    });
  }

  return res.status(200).json({
    success:  true,
    message:  'OAuth callback received. Use the code below to exchange for a token.',
    data: {
      code:    code  || null,
      state:   state || null,
      nextStep: {
        method: 'POST',
        url:    '/api/oauth/token',
        body: {
          grant_type:    'authorization_code',
          code,
          redirect_uri:  'http://localhost:3000/api/oauth/callback',
          client_id:     'healthapi_client_001',
          client_secret: 'healthapi_oauth_secret_XyZ_2025',
        },
      },
    },
  });
});

module.exports = router;