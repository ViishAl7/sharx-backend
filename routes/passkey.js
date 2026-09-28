const express = require('express');
const jwt = require('jsonwebtoken');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const prisma = require('../lib/prisma');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const JWT_ISSUER = 'sharx-api';
const JWT_AUDIENCE = 'sharx-client';

function getPasskeyConfig() {
  const rpID = process.env.PASSKEY_RP_ID || (process.env.NODE_ENV === 'production' ? '' : 'localhost');
  const origins = (process.env.PASSKEY_ORIGIN || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:3000'))
    .split(',').map((v) => v.trim()).filter(Boolean);
  if (!rpID || origins.length === 0) {
    const error = new Error('PASSKEY_RP_ID and PASSKEY_ORIGIN must be configured.');
    error.code = 'PASSKEY_NOT_CONFIGURED';
    throw error;
  }
  return { rpID, origins };
}

function signAccessToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '1d', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithm: 'HS256' }
  );
}

// Registration is deliberately authenticated. An email address alone is not
// proof of account ownership and must never be sufficient to attach a new
// passkey to an existing account.
router.use('/register', authMiddleware);

router.post('/register/options', async (req, res) => {
  try {
    const { rpID } = getPasskeyConfig();
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found.' });

    const options = await generateRegistrationOptions({
      rpName: 'SHARX',
      rpID,
      userID: Buffer.from(String(user.id)),
      userName: user.email,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      excludeCredentials: user.passkeyCredentialId
        ? [{ id: user.passkeyCredentialId, type: 'public-key' }]
        : [],
    });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        currentChallenge: options.challenge,
        currentChallengeExpiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
      },
    });

    return res.json(options);
  } catch (err) {
    console.error('Register options error:', err);
    return res.status(err.code === 'PASSKEY_NOT_CONFIGURED' ? 503 : 500).json({ error: 'Could not start passkey registration.' });
  }
});

router.post('/register/verify', async (req, res) => {
  const response = req.body;

  try {
    const { rpID, origins } = getPasskeyConfig();
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found.' });
    if (!user.currentChallenge) return res.status(400).json({ error: 'No pending registration. Start again.' });

    if (!user.currentChallengeExpiresAt || user.currentChallengeExpiresAt < new Date()) {
      await prisma.user.update({ where: { id: user.id }, data: { currentChallenge: null, currentChallengeExpiresAt: null } });
      return res.status(400).json({ error: 'Registration challenge expired. Start again.' });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origins,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      await prisma.user.update({ where: { id: user.id }, data: { currentChallenge: null, currentChallengeExpiresAt: null } });
      return res.status(400).json({ verified: false });
    }

    const credential = verification.registrationInfo.credential;
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passkeyCredentialId: credential.id,
        passkeyPublicKey: Buffer.from(credential.publicKey),
        passkeyCounter: credential.counter,
        currentChallenge: null,
        currentChallengeExpiresAt: null,
      },
    });

    return res.json({ verified: true, token: signAccessToken(user), user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error('Register verify error:', err);
    return res.status(400).json({ error: 'Passkey verification failed.' });
  }
});

router.post('/login/options', async (req, res) => {
  try {
    const { rpID } = getPasskeyConfig();
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: [],
      userVerification: 'required',
    });
    const challengeToken = jwt.sign(
      { challenge: options.challenge, purpose: 'passkey-login' },
      JWT_SECRET,
      { expiresIn: '5m', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithm: 'HS256' }
    );
    return res.json({ ...options, challengeToken });
  } catch (err) {
    console.error('Login options error:', err);
    return res.status(err.code === 'PASSKEY_NOT_CONFIGURED' ? 503 : 500).json({ error: 'Could not start passkey login.' });
  }
});

router.post('/login/verify', async (req, res) => {
  const { challengeToken, ...response } = req.body || {};
  if (!challengeToken) return res.status(400).json({ error: 'Missing login challenge.' });

  let expectedChallenge;
  try {
    const decoded = jwt.verify(challengeToken, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (decoded.purpose !== 'passkey-login' || typeof decoded.challenge !== 'string') throw new Error('Invalid challenge purpose');
    expectedChallenge = decoded.challenge;
  } catch {
    return res.status(400).json({ error: 'Login challenge expired or invalid.' });
  }

  const credentialId = response?.id;
  if (typeof credentialId !== 'string' || credentialId.length < 8 || credentialId.length > 1024) {
    return res.status(400).json({ error: 'Invalid passkey credential.' });
  }

  try {
    const { rpID, origins } = getPasskeyConfig();
    // Never trust userHandle to choose the account. The credential ID is the
    // authenticator-bound identifier and must be the lookup key.
    const user = await prisma.user.findFirst({
      where: { passkeyCredentialId: credentialId },
    });

    if (!user?.passkeyCredentialId || !user.passkeyPublicKey) {
      return res.status(401).json({ error: 'Passkey authentication failed.' });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origins,
      expectedRPID: rpID,
      credential: {
        id: user.passkeyCredentialId,
        publicKey: user.passkeyPublicKey,
        counter: user.passkeyCounter || 0,
      },
    });

    if (!verification.verified) return res.status(401).json({ verified: false });

    await prisma.user.update({
      where: { id: user.id },
      data: { passkeyCounter: verification.authenticationInfo.newCounter },
    });

    return res.json({ verified: true, token: signAccessToken(user), user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error('Login verify error:', err);
    return res.status(401).json({ error: 'Passkey authentication failed.' });
  }
});

module.exports = router;
