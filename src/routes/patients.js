// src/routes/patients.js
const router = require('express').Router();
const { body } = require('express-validator');
const { validate } = require('../middleware/validate');
const { authenticate, authorize } = require('../middleware/auth');
const ctrl = require('../controllers/patientController');

const createRules = [
  body('firstName').trim().notEmpty().withMessage('firstName is required.'),
  body('lastName').trim().notEmpty().withMessage('lastName is required.'),
  body('dateOfBirth').isISO8601().withMessage('dateOfBirth must be YYYY-MM-DD.'),
  body('gender').isIn(['male','female','other']).withMessage("gender must be 'male', 'female', or 'other'."),
  body('bloodGroup').isIn(['A+','A-','B+','B-','AB+','AB-','O+','O-']).withMessage('Invalid blood group.'),
  body('phone').notEmpty().withMessage('phone is required.'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required.'),
  validate,
];

router.use(authenticate);
router.get('/',                   ctrl.getAll);
router.get('/:id',                ctrl.getById);
router.get('/:id/appointments',   ctrl.getAppointments);
router.get('/:id/records',        ctrl.getMedicalRecords);
router.post('/',   authorize('admin','doctor','nurse'), createRules, ctrl.create);
router.put('/:id', authorize('admin','doctor','nurse'), ctrl.update);
router.patch('/:id', authorize('admin','doctor','nurse'), ctrl.patch);
router.delete('/:id', authorize('admin'), ctrl.remove);

module.exports = router;