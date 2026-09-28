const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = 'sharx-api';
const JWT_AUDIENCE = 'sharx-client';

module.exports = async function authMiddleware(req, res, next) {
  if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET is not configured.');
    return res.status(503).json({ message: 'Authentication service unavailable' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.slice(7).trim();
  if (!token || token.length > 8192) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (!Number.isInteger(decoded.id) || decoded.id <= 0 || !Number.isInteger(decoded.tokenVersion)) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    // Tokens are not enough on their own: verify the account still exists.
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, name: true, tokenVersion: true },
    });

    if (!user || user.tokenVersion !== decoded.tokenVersion) return res.status(401).json({ message: 'Invalid or expired token' });

    req.user = user;
    req.auth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports.JWT_ISSUER = JWT_ISSUER;
module.exports.JWT_AUDIENCE = JWT_AUDIENCE;
