// Gaming-Backend/routes/referrals.js
//
// Referral-code generation only.
// Actual referral attachment should happen during signup, before the
// referred account has qualified for a reward.
//
// This file deliberately does NOT create a self-referral row.

const express = require("express");
const crypto = require("crypto");

const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.use(authMiddleware);

function makeCode(userId) {
  return crypto
    .createHash("sha256")
    .update(`SHARX:${userId}`)
    .digest("hex")
    .slice(0, 10)
    .toUpperCase();
}

router.get("/me", async (req, res) => {
  try {
    const code = `SHARX${makeCode(req.user.id)}`;

    return res.json({
      success: true,
      code,
      shareText:
        "Join me on SHARX and play games with my referral code: " +
        code,
    });
  } catch (error) {
    console.error("GET /referrals/me:", error);

    return res.status(500).json({
      success: false,
      error: "Could not load referral information.",
    });
  }
});

module.exports = router;