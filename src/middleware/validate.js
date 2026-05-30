// src/middleware/validate.js
const { validationResult } = require('express-validator');

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'One or more fields failed validation.',
        fields: errors.array().map((e) => ({ field: e.path, value: e.value, message: e.msg })),
      },
    });
  }
  next();
};

module.exports = { validate };