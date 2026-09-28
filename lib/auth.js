const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_ISSUER = 'sharx-api';
const JWT_AUDIENCE = 'sharx-client';
const JWT_ALGORITHM = 'HS256';

function signAccessToken(user, expiresIn = '1d') {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign(
    { id: user.id, email: user.email, tokenVersion: user.tokenVersion || 0 },
    process.env.JWT_SECRET,
    { expiresIn, issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithm: JWT_ALGORITHM }
  );
}

function hashCode(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function randomCode(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

module.exports = { signAccessToken, hashCode, randomCode, JWT_ISSUER, JWT_AUDIENCE, JWT_ALGORITHM };
