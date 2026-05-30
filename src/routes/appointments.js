// src/routes/appointments.js
const router = require('express').Router();
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const { authenticate, authorize } = require('../middleware/auth');
const ctrl = require('../controllers/appointmentController');

const createRules = [
  body('patientId').notEmpty().withMessage('patientId is required.'),
  body('doctorId').notEmpty().withMessage('doctorId is required.'),
  body('appointmentDate').isISO8601().withMessage('appointmentDate must be YYYY-MM-DD.'),
  body('appointmentTime').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('appointmentTime must be HH:MM.'),
  validate,
];

router.use(authenticate);
router.get('/',               ctrl.getAll);
router.get('/:id',            ctrl.getById);
router.post('/',   authorize('admin','doctor','nurse'), createRules, ctrl.create);
router.put('/:id', authorize('admin','doctor','nurse'), ctrl.update);
router.patch('/:id/status', authorize('admin','doctor','nurse'), ctrl.updateStatus);
router.delete('/:id', authorize('admin'), ctrl.remove);

module.exports = router;