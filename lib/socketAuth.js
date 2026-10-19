// lib/socketAuth.js — Socket.IO connection auth (same rules as authMiddleware).
//
//  - NO token            -> allowed as a GUEST socket (public features like game
//                           rooms / leaderboard keep working). No private room.
//  - VALID token         -> socket.data.userId = <id from the verified JWT>.
//                           The connection handler joins the private room.
//  - INVALID/EXPIRED/    -> connection refused with { code: "UNAUTHORIZED" }
//    revoked token          so the client can react (log out) instead of
//                           silently staying "connected but deaf".
//  - A live socket is disconnected at the moment its JWT expires.
//
// The user id NEVER comes from anything the client sends besides the token,
// and the token is verified (signature, issuer, audience, tokenVersion, and the
// account must still exist) exactly like HTTP requests.

const jwt = require('jsonwebtoken');
const prisma = require('./prisma');
const { JWT_ISSUER, JWT_AUDIENCE } = require('../middleware/authMiddleware');

const MAX_TIMER_MS = 2 ** 31 - 1;

function reject(next, message = 'unauthorized') {
  const err = new Error(message);
  err.data = { code: 'UNAUTHORIZED' };
  return next(err);
}

async function authenticateSocket(socket, next) {
  try {
    const raw = socket.handshake?.auth?.token;

    if (raw === undefined || raw === null || raw === '') {
      socket.data.userId = null;
      return next();
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) return reject(next, 'unavailable');
    if (typeof raw !== 'string' || raw.length > 8192) return reject(next);

    let decoded;
    try {
      decoded = jwt.verify(raw, secret, {
        algorithms: ['HS256'],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });
    } catch {
      return reject(next);
    }

    if (!Number.isInteger(decoded.id) || decoded.id <= 0 || !Number.isInteger(decoded.tokenVersion)) {
      return reject(next);
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, tokenVersion: true },
    });
    if (!user || user.tokenVersion !== decoded.tokenVersion) return reject(next);

    socket.data.userId = user.id;

    // Drop the socket exactly when the token stops being valid.
    if (decoded.exp) {
      const ms = Math.max(0, decoded.exp * 1000 - Date.now());
      const timer = setTimeout(() => {
        try {
          socket.emit('auth:expired');
          socket.disconnect(true);
        } catch {}
      }, Math.min(ms, MAX_TIMER_MS));
      socket.once('disconnect', () => clearTimeout(timer));
    }

    return next();
  } catch (err) {
    console.error('[socketAuth] error:', err.message);
    const e = new Error('server_error');
    e.data = { code: 'SERVER_ERROR' };
    return next(e);
  }
}

module.exports = { authenticateSocket };
