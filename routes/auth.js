const express = require('express');
const passport = require('passport');
const rateLimit = require('express-rate-limit');
const { randomCode, hashCode, signAccessToken } = require('../lib/auth');
const prisma = require('../lib/prisma');

const router = express.Router();
const oauthLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
const exchangeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const OAUTH_CODE_TTL_MS = 60 * 1000;

function parseCookie(header, name) {
  const match = String(header || '').split(';').map((v) => v.trim()).find((v) => v.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

function issueOAuthState(res) {
  const state = randomCode(24);

  res.cookie('sharx_oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: OAUTH_STATE_TTL_MS,
    path: '/auth',
  });

  return state;
}

function verifyOAuthState(req, res) {
  const expected = parseCookie(req.headers.cookie, 'sharx_oauth_state');
  const supplied = typeof req.query.state === 'string' ? req.query.state : '';
  res.clearCookie('sharx_oauth_state', {
    path: '/auth',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  });
  return Boolean(expected && supplied && expected === supplied);
}

async function createExchangeCode(userId) {
  const raw = randomCode(32);
  await prisma.authExchangeCode.deleteMany({ where: { expiresAt: { lt: new Date() } } });
  await prisma.authExchangeCode.create({
    data: {
      userId,
      codeHash: hashCode(raw),
      expiresAt: new Date(Date.now() + OAUTH_CODE_TTL_MS),
    },
  });
  return raw;
}

router.get('/google', oauthLimiter, (req, res, next) => {
  const state = issueOAuthState(res);
  return passport.authenticate('google', { scope: ['profile', 'email'], state })(req, res, next);
});

router.get(
  '/google/callback', oauthLimiter,
  (req, res, next) => { if (!verifyOAuthState(req, res)) return res.redirect(`${process.env.CLIENT_URL}/login?oauth=state_error`); next(); },
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  async (req, res) => {
    try {
      const code = await createExchangeCode(req.user.id);
      return res.redirect(`${process.env.CLIENT_URL}/auth/callback?code=${encodeURIComponent(code)}`);
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      return res.redirect(`${process.env.CLIENT_URL}/login?oauth=error`);
    }
  }
);

router.get('/microsoft', oauthLimiter, (req, res, next) => {
  const state = issueOAuthState(res);
  return passport.authenticate('microsoft', { state })(req, res, next);
});

router.get(
  '/microsoft/callback', oauthLimiter,
  (req, res, next) => { if (!verifyOAuthState(req, res)) return res.redirect(`${process.env.CLIENT_URL}/login?oauth=state_error`); next(); },
  passport.authenticate('microsoft', { failureRedirect: '/login', session: false }),
  async (req, res) => {
    try {
      const code = await createExchangeCode(req.user.id);
      return res.redirect(`${process.env.CLIENT_URL}/auth/callback?code=${encodeURIComponent(code)}`);
    } catch (error) {
      console.error('Microsoft OAuth callback error:', error);
      return res.redirect(`${process.env.CLIENT_URL}/login?oauth=error`);
    }
  }
);

// One-time exchange. The OAuth credential never becomes a reusable bearer
// token in browser history, logs, or referrer headers.
router.post('/exchange', exchangeLimiter, async (req, res) => {
  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  if (!code || code.length > 200) return res.status(400).json({ error: 'Invalid exchange code.' });

  try {
    const row = await prisma.authExchangeCode.findFirst({
      where: {
        codeHash: hashCode(code),
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (!row) return res.status(400).json({ error: 'Exchange code is invalid or expired.' });

    const claimed = await prisma.authExchangeCode.updateMany({
      where: { id: row.id, usedAt: null, expiresAt: { gt: new Date() } },
      data: { usedAt: new Date() },
    });

    if (claimed.count !== 1) return res.status(400).json({ error: 'Exchange code is invalid or already used.' });

    const user = await prisma.user.findUnique({ where: { id: row.userId }, select: { id: true, email: true, tokenVersion: true } });
    if (!user) return res.status(401).json({ error: 'Account not found.' });

    return res.json({ token: signAccessToken(user, '1d'), user });
  } catch (error) {
    console.error('OAuth exchange error:', error);
    return res.status(500).json({ error: 'Could not complete sign-in.' });
  }
});

module.exports = router;
