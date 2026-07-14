const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");

const router = express.Router();

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user.id,
        email: req.user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.redirect(
      `${process.env.CLIENT_URL}/auth/callback?token=${token}`
    );
  }
);

// Microsoft login
router.get("/microsoft",
  passport.authenticate("microsoft")
);

router.get("/microsoft/callback",
  passport.authenticate("microsoft", {
    failureRedirect: "/login",
    session: false,
  }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user.id,
        email: req.user.emails?.[0]?.value || req.user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.redirect(
      `${process.env.CLIENT_URL}/auth/callback?token=${token}`
    );
  }
);

module.exports = router;