// src/routes/auth.js
const router = require('express').Router();
const { body } = require('express-validator');
const { validate }    = require('../middleware/validate');
const { authenticate, authorize } = require('../middleware/auth');
const ctrl      = require('../controllers/authController');
const oauthCtrl = require('../controllers/oauthController');

router.post('/login',
  [body('email').isEmail().withMessage('Valid email required.'), body('password').notEmpty().withMessage('Password required.'), validate],
  ctrl.login);
router.post('/refresh', ctrl.refreshToken);
router.post('/logout',  ctrl.logout);
router.get('/profile',  authenticate, ctrl.profile);
router.get('/users',    authenticate, authorize('admin'), ctrl.listUsers);
router.get('/apikeys',  authenticate, authorize('admin'), oauthCtrl.listApiKeys);
router.get('/basic-test', authenticate, (req, res) => {
  res.json({ success: true, message: 'Basic Auth successful!', data: { authMethod: req.authMethod, user: req.user } });
});

module.exports = router;