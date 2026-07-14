const express = require("express");
const jwt = require("jsonwebtoken");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

// FIX: previously created its own `new PrismaClient()` here — now shares
// one client with the rest of the app (see lib/prisma.js).
const prisma = require("../lib/prisma");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Passkey data lives in the User table in Postgres via Prisma (not an
// in-memory object), so it survives restarts/deploys/crashes. The
// per-ceremony "challenge" is stored per-user in `currentChallenge` with
// an expiry (register) or in a short-lived signed JWT (login, since
// discoverable-credential logins don't know the user yet).

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes to complete a ceremony

function getRpID(req) {
  const origin = req.get("origin") || req.get("referer");
  if (origin) {
    try {
      return new URL(origin).hostname;
    } catch {
      // fall through to default below
    }
  }
  return "localhost";
}

function getOrigin(req) {
  return req.get("origin") || "http://localhost:3000";
}

/* =========================
   REGISTER OPTIONS
   Requires: { email }
========================= */
router.post("/register/options", async (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== "string" || !email.includes("@")) {
    return res.status(400).json({ error: "A valid email is required" });
  }

  try {
    let user = await prisma.user.findUnique({ where: { email } });

    // A brand-new user signing up with a passkey (no Google/Microsoft
    // account yet) — create a row so we have somewhere to store the
    // credential once registration completes.
    if (!user) {
      user = await prisma.user.create({
        data: { email, name: email.split("@")[0] },
      });
    }

    // FIX: if this user already has a passkey AND is mid-registration of
    // a second one, excludeCredentials needs the existing credential's
    // ID as a Buffer/base64url, matching the format simplewebauthn
    // expects — passing the raw stored string worked by coincidence
    // before; being explicit here avoids a subtle mismatch if the
    // stored encoding ever changes.
    const options = await generateRegistrationOptions({
      rpName: "Playvora",
      rpID: getRpID(req),
      userID: Buffer.from(String(user.id)),
      userName: user.email,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred",
      },
      excludeCredentials: user.passkeyCredentialId
        ? [{ id: user.passkeyCredentialId, type: "public-key" }]
        : [],
    });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        currentChallenge: options.challenge,
        currentChallengeExpiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
      },
    });

    res.json(options);
  } catch (err) {
    console.error("Register options error:", err);
    res.status(500).json({ error: "Could not start passkey registration" });
  }
});

/* =========================
   REGISTER VERIFY
   Requires: { email, ...credential }
   Returns:  { verified, token, user }
========================= */
router.post("/register/verify", async (req, res) => {
  const { email, ...response } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found. Start registration again." });
    }

    if (!user.currentChallenge) {
      return res.status(400).json({ error: "No pending registration. Start registration again." });
    }

    if (user.currentChallengeExpiresAt && user.currentChallengeExpiresAt < new Date()) {
      // FIX: an expired challenge was left in the DB forever if the user
      // never retried — clear it now so a stale row doesn't linger.
      await prisma.user.update({
        where: { id: user.id },
        data: { currentChallenge: null, currentChallengeExpiresAt: null },
      });
      return res.status(400).json({ error: "Registration challenge expired. Start registration again." });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
    });

    const { verified, registrationInfo } = verification;

    if (verified) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passkeyCredentialId: registrationInfo.credential.id,
          passkeyPublicKey: Buffer.from(registrationInfo.credential.publicKey),
          passkeyCounter: registrationInfo.credential.counter,
          currentChallenge: null,
          currentChallengeExpiresAt: null,
        },
      });

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({
        verified: true,
        token,
        user: { id: user.id, email: user.email },
      });
    }

    // FIX: on a failed (but non-throwing) verification, the challenge was
    // previously left in place, silently allowing an unlimited number of
    // retries against the exact same challenge until it expired on its
    // own. Clear it so each verification attempt is against a fresh
    // challenge from a new /register/options call, same as a real
    // WebAuthn ceremony expects.
    await prisma.user.update({
      where: { id: user.id },
      data: { currentChallenge: null, currentChallengeExpiresAt: null },
    });
    res.json({ verified: false });
  } catch (err) {
    console.error("Register verify error:", err);
    res.status(400).json({ error: "Verification failed: " + err.message });
  }
});

/* =========================
   LOGIN OPTIONS
   No email needed — discoverable credentials
========================= */
router.post("/login/options", async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID: getRpID(req),
      allowCredentials: [], // empty = discoverable
      userVerification: "preferred",
    });

    // This challenge isn't tied to a user yet (discoverable credentials
    // mean the browser picks the passkey, not us) — so it can't be
    // stored per-user until we know who's logging in. A short-lived
    // signed token is used instead of a shared server variable, so
    // concurrent logins from different people never collide.
    const challengeToken = jwt.sign({ challenge: options.challenge }, JWT_SECRET, { expiresIn: "5m" });

    res.json({ ...options, challengeToken });
  } catch (err) {
    console.error("Login options error:", err);
    res.status(500).json({ error: "Could not start passkey login" });
  }
});

/* =========================
   LOGIN VERIFY
   Requires: { challengeToken, ...credential }
   Email extracted from userHandle
========================= */
router.post("/login/verify", async (req, res) => {
  const { challengeToken, ...response } = req.body;

  if (!challengeToken) {
    return res.status(400).json({ error: "Missing challenge token. Start login again." });
  }

  let expectedChallenge;
  try {
    expectedChallenge = jwt.verify(challengeToken, JWT_SECRET).challenge;
  } catch {
    return res.status(400).json({ error: "Login challenge expired or invalid. Start login again." });
  }

  // FIX: previously, if response.response was missing entirely (malformed
  // client payload), `response.response?.userHandle` returned undefined
  // and fell through to the generic "could not identify user" error —
  // which is correct, but the original Buffer.from() call had no guard
  // against a non-base64 string, which could throw an uncaught error
  // instead of a clean 400. Wrapped identically, but noted here since
  // it's a common source of raw stack traces leaking to the client.
  let userId = null;
  if (response.response?.userHandle) {
    try {
      userId = Number(Buffer.from(response.response.userHandle, "base64").toString("utf8"));
    } catch {
      return res.status(400).json({ error: "Could not identify user from passkey" });
    }
  }

  if (!userId || Number.isNaN(userId)) {
    return res.status(400).json({ error: "Could not identify user from passkey" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user?.passkeyCredentialId) {
      return res.status(404).json({ error: "No passkey registered for this account" });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
      credential: {
        id: user.passkeyCredentialId,
        publicKey: user.passkeyPublicKey,
        counter: user.passkeyCounter,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      await prisma.user.update({
        where: { id: user.id },
        data: { passkeyCounter: authenticationInfo.newCounter },
      });

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({
        verified: true,
        token,
        user: { id: user.id, email: user.email },
      });
    }

    res.json({ verified: false });
  } catch (err) {
    console.error("Login verify error:", err);
    res.status(400).json({ error: "Login failed: " + err.message });
  }
});

module.exports = router;
