const express = require("express");
const jwt = require("jsonwebtoken");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// ⚠️ IN-MEMORY — resets on server restart
// TODO: Move to Prisma later
const users = {};

// ✅ FIX: Get rpID from the browser's Origin header, NOT from req.hostname
// req.hostname = backend IP (192.168.x.x) — WRONG for WebAuthn
// Origin header = frontend URL (localhost:3000) — CORRECT
function getRpID(req) {
  const origin = req.get("origin") || req.get("referer");
  if (origin) {
    try {
      return new URL(origin).hostname; // "localhost" or actual domain
    } catch {}
  }
  return "localhost"; // safe fallback
}

function getOrigin(req) {
  // Use the actual origin the browser sent
  return req.get("origin") || "http://localhost:3000";
}

/* =========================
   REGISTER OPTIONS
   Requires: { email }
========================= */
router.post("/register/options", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = users[email] || { id: email, email };
  users[email] = user;

  const options = await generateRegistrationOptions({
    rpName: "Playvora",
    rpID: getRpID(req),
    userID: Buffer.from(user.id),
    userName: user.email,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
    excludeCredentials: user.passkey
      ? [{ id: user.passkey.credentialID, type: "public-key" }]
      : [],
  });

  user.currentChallenge = options.challenge;
  res.json(options);
});

/* =========================
   REGISTER VERIFY
   Requires: { email, ...credential }
   Returns:  { verified, token, user }
========================= */
router.post("/register/verify", async (req, res) => {
  const { email, ...response } = req.body;
  const user = users[email];

  if (!user) {
    return res.status(404).json({ error: "User not found. Start registration again." });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
    });

    const { verified, registrationInfo } = verification;

    if (verified) {
      user.passkey = {
        credentialID: registrationInfo.credential.id,
        publicKey: registrationInfo.credential.publicKey,
        counter: registrationInfo.credential.counter,
      };

      const token = jwt.sign({ id: email, email }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({
        verified: true,
        token,
        user: { id: email, email },
      });
    }

    res.json({ verified: false });
  } catch (err) {
    console.error("Register verify error:", err);
    res.status(400).json({ error: "Verification failed: " + err.message });
  }
});

/* =========================
   LOGIN OPTIONS
   No email needed — discoverable credentials
   Browser shows all saved passkeys for this site
========================= */
router.post("/login/options", async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: getRpID(req),
    allowCredentials: [], // empty = discoverable
    userVerification: "preferred",
  });

  router._pendingChallenge = options.challenge;
  res.json(options);
});

/* =========================
   LOGIN VERIFY
   Email extracted from userHandle
   Returns: { verified, token, user }
========================= */
router.post("/login/verify", async (req, res) => {
  const response = req.body;

  // Extract email from userHandle (set as userID = email during registration)
  let email = null;
  if (response.response?.userHandle) {
    try {
      email = Buffer.from(response.response.userHandle, "base64").toString("utf8");
    } catch {
      email = response.response.userHandle;
    }
  }

  if (!email) {
    return res.status(400).json({ error: "Could not identify user from passkey" });
  }

  const user = users[email];
  if (!user?.passkey) {
    return res.status(404).json({ error: "No passkey registered for this account" });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: router._pendingChallenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpID(req),
      credential: {
        id: user.passkey.credentialID,
        publicKey: user.passkey.publicKey,
        counter: user.passkey.counter,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      user.passkey.counter = authenticationInfo.newCounter;

      const token = jwt.sign({ id: email, email }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({
        verified: true,
        token,
        user: { id: email, email },
      });
    }

    res.json({ verified: false });
  } catch (err) {
    console.error("Login verify error:", err);
    res.status(400).json({ error: "Login failed: " + err.message });
  }
});

module.exports = router;