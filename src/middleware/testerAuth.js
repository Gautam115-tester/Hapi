// src/middleware/testerAuth.js
// ============================================================
//  Protects /api/register/me and /api/register/regenerate
//  Verifies the session token issued by POST /api/register/login
// ============================================================

const jwt = require('jsonwebtoken');
const { JWT_SECRET, BASE_URL } = require('../utils/config');

const ISSUER = BASE_URL || 'https://hapi-2115.onrender.com';

const testerAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: {
        code:    'MISSING_TOKEN',
        message: 'Login first at POST /api/register/login to get your session token.',
      },
    });
  }

  const token = authHeader.slice(7).trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: ISSUER, algorithms: ['HS256'],
    });

    if (decoded.type !== 'tester') {
      return res.status(403).json({
        success: false,
        error: {
          code:    'WRONG_TOKEN_TYPE',
          message: 'Use the session token from POST /api/register/login.',
        },
      });
    }

    req.tester = { id: decoded.sub, email: decoded.email, name: decoded.name };
    return next();

  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    return res.status(401).json({
      success: false,
      error: {
        code:    expired ? 'SESSION_EXPIRED' : 'INVALID_TOKEN',
        message: expired
          ? 'Session expired. Login again at POST /api/register/login.'
          : 'Invalid session token.',
      },
    });
  }
};

module.exports = { testerAuth };