// src/utils/config.js
require('dotenv').config();

module.exports = {
  JWT_SECRET:              process.env.JWT_SECRET              || 'healthapi_jwt_super_secret_key_2025',
  JWT_EXPIRES_IN:          process.env.JWT_EXPIRES_IN          || '1h',
  JWT_REFRESH_SECRET:      process.env.JWT_REFRESH_SECRET      || 'healthapi_refresh_super_secret_key_2025',
  JWT_REFRESH_EXPIRES_IN:  process.env.JWT_REFRESH_EXPIRES_IN  || '7d',
  OAUTH_ACCESS_TOKEN_TTL:  parseInt(process.env.OAUTH_ACCESS_TOKEN_TTL  || '3600',  10),
  OAUTH_REFRESH_TOKEN_TTL: parseInt(process.env.OAUTH_REFRESH_TOKEN_TTL || '604800', 10),
  OAUTH_AUTH_CODE_TTL:     parseInt(process.env.OAUTH_AUTH_CODE_TTL     || '300',   10),
  PORT:     process.env.PORT     || 3000,
  BASE_URL: process.env.BASE_URL || 'http://localhost:3000',
  NODE_ENV: process.env.NODE_ENV || 'development',
};