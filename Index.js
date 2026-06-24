require('dotenv').config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const http = require("http");
const { Server } = require("socket.io");
const passport = require("passport");
const session = require("express-session");
const { Resend } = require("resend");
const axios = require("axios");
const passkeyRoutes = require("./routes/passkey.js");

const app = express();
const prisma = new PrismaClient();
const resend = new Resend(process.env.RESEND_API_KEY);

const otpStore = new Map();
const server = http.createServer(app);

// ✅ FIX: CORS — mirror origin back so credentials work from any device
const io = new Server(server, {
  cors: {
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      callback(null, origin);
    },
    methods: ["GET", "POST"],
    credentials: true
  },
});

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

// ─────────────────────────────────────────
// EMAIL TEMPLATE
// ─────────────────────────────────────────
function getOtpEmailHtml(otp, userName = "Player") {
  const year = new Date().getFullYear();
  const firstName = userName.split(" ")[0];

  return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>Reset your Sharx password</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body, table, td, p, a, li, blockquote {
  -webkit-text-size-adjust: 100%;
  -ms-text-size-adjust: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif;
}
body {
  background: #f5f5f7;
  color: #1d1c1d;
  margin: 0;
  padding: 0;
  width: 100%;
}
table { border-collapse: collapse; }
img { border: 0; display: block; }
.outer { width: 100%; background: #f5f5f7; }
.content { padding: 48px 0 0; }
.logo {
  font-size: 22px; font-weight: 600; color: #1d1c1d;
  padding: 0 0 40px; display: block; text-align: left; letter-spacing: -0.3px;
}
.heading {
  font-size: 28px; font-weight: 600; color: #1d1c1d;
  line-height: 1.25; letter-spacing: -0.5px; margin-bottom: 16px; text-align: left;
}
.text { font-size: 15px; color: #515154; line-height: 1.5; margin-bottom: 32px; text-align: left; }
.otp-code {
  font-size: 48px; font-weight: 600; color: #1d1c1d; letter-spacing: 8px;
  line-height: 1; display: block; margin-bottom: 8px; text-align: left;
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
}
.otp-hint { font-size: 13px; color: #86868b; margin-bottom: 40px; display: block; text-align: left; }
.divider { border: none; border-top: 1px solid #d2d2d6; margin-bottom: 32px; }
.section-title { font-size: 15px; font-weight: 600; color: #1d1c1d; margin-bottom: 8px; text-align: left; }
.section-text { font-size: 14px; color: #515154; line-height: 1.5; margin-bottom: 28px; text-align: left; }
.security-note { font-size: 13px; color: #86868b; line-height: 1.5; margin-bottom: 48px; text-align: left; }
.footer-td { background: #1d1c1d; padding: 28px 40px 24px; }
.footer-logo { font-size: 16px; font-weight: 600; color: #ffffff; display: block; margin-bottom: 16px; text-align: left; letter-spacing: -0.3px; }
.footer-links { margin-bottom: 12px; text-align: left; }
.footer-links a { font-size: 12px; color: rgba(255,255,255,0.6); text-decoration: none; margin-right: 24px; }
.footer-links a:hover { color: rgba(255,255,255,0.9); text-decoration: underline; }
.footer-copy { font-size: 11px; color: rgba(255,255,255,0.4); line-height: 1.5; margin-top: 12px; text-align: left; }
@media (prefers-color-scheme: dark) {
  body, .outer { background: #1c1c1e !important; }
  .logo { color: #ffffff !important; }
  .heading { color: #ffffff !important; }
  .text { color: #a1a1a6 !important; }
  .otp-code { color: #ffffff !important; }
  .otp-hint { color: #8e8e93 !important; }
  .divider { border-top-color: #3a3a3c !important; }
  .section-title { color: #ffffff !important; }
  .section-text { color: #a1a1a6 !important; }
  .security-note { color: #8e8e93 !important; }
  .footer-td { background: #000000 !important; }
  .footer-logo { color: #ffffff !important; }
  .footer-links a { color: rgba(255,255,255,0.5) !important; }
  .footer-copy { color: rgba(255,255,255,0.3) !important; }
}
@media only screen and (max-width: 600px) {
  .otp-code { font-size: 36px !important; letter-spacing: 6px !important; }
  .heading { font-size: 24px !important; }
  .content { padding: 32px 24px 0 !important; }
  .footer-td { padding: 24px 24px 20px !important; }
  .footer-links a { margin-right: 16px !important; font-size: 11px !important; }
}
</style>
</head>
<body>
<table class="outer" width="100%" cellpadding="0" cellspacing="0" role="presentation">
  <tr>
    <td align="center">
      <table width="100%" style="max-width:560px;" cellpadding="0" cellspacing="0" role="presentation">
        <tr>
          <td class="content" style="padding:48px 40px 0;">
            <div class="logo">Sharx</div>
            <h1 class="heading">Reset your password</h1>
            <p class="text">
              Hi ${firstName},<br><br>
              We received a request to reset the password for your Sharx account.
              Enter the verification code below to continue.
            </p>
            <div class="otp-code">${otp}</div>
            <div class="otp-hint">This code expires in 10 minutes</div>
            <hr class="divider">
            <div class="section-title">Didn't request this?</div>
            <p class="section-text">
              If you didn't request a password reset, you can safely ignore this email.
              Your password will remain unchanged and your account is secure.
            </p>
            <div class="security-note">
              For your security, Sharx will never ask for your password, payment details,
              or verification code via email, phone, or chat.
            </div>
          </td>
        </tr>
        <tr>
          <td class="footer-td">
            <div class="footer-logo">Sharx</div>
            <div class="footer-links">
              <a href="#">Privacy Policy</a>
              <a href="#">Terms of Service</a>
              <a href="#">Support</a>
              <a href="#">Security</a>
            </div>
            <div class="footer-copy">
              © ${year} Sharx. All rights reserved.<br>
              This is an automated message. Please do not reply.
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>`;
}

// ─────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────

// ✅ FIX: Mirror origin back — works from localhost, phone, any IP
// credentials: true is required for passkey (WebAuthn uses session cookies)
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow Postman / mobile with no origin
    callback(null, origin);                   // mirror the request origin back
  },
  credentials: true
}));

app.use(express.json());
app.use(session({ secret: "gaming_secret", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// ✅ FIX: All requires and route registrations AFTER app is initialized
const userRoutes = require("./routes/userRoutes");
const authRoutes = require("./routes/auth");
require("./Controllers/authController");

app.use("/user", userRoutes);
app.use("/auth", authRoutes);
app.use("/passkey", passkeyRoutes);

// ─────────────────────────────────────────
// GAMES ENDPOINT
// ─────────────────────────────────────────
app.get("/games", async (req, res) => {
  try {
    const { page = 1, num = 50 } = req.query;

    const response = await axios.get(
      `https://gamemonetize.com/feed.php?format=0&num=${num}&page=${page}`
    );

    res.json({
      success: true,
      page: parseInt(page),
      num: parseInt(num),
      games: Array.isArray(response.data) ? response.data : response.data,
    });
  } catch (error) {
    console.error("Games fetch error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to fetch games from GameMonetize"
    });
  }
});

// ─────────────────────────────────────────
// SOCKET.IO
// ─────────────────────────────────────────
io.on("connection", (socket) => {
  console.log("User connected 🔥");

  socket.on("joinRoom", (roomId) => {
    socket.join(roomId);
  });

  socket.on("makeMove", ({ roomId, board, player }) => {
    socket.to(roomId).emit("moveMade", { board, player });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected 💤");
  });
});

// ─────────────────────────────────────────
// HELPER
// ─────────────────────────────────────────
function getRank(score) {
  if (score >= 1000) return "Diamond 💎";
  if (score >= 600)  return "Platinum 🔵";
  if (score >= 300)  return "Gold 🟡";
  if (score >= 100)  return "Silver ⚪";
  return "Bronze 🟤";
}

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────
app.get("/", (req, res) => res.send("🎮 Playvora Gaming Server running 🚀"));

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, score: 0 }
    });

    const { password: _, ...userWithoutPassword } = user;
    res.json({ message: "User created successfully", user: userWithoutPassword });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Signup error" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (!user.password) {
      return res.status(400).json({ message: "Please login with Google" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login error" });
  }
});

// FORGOT PASSWORD
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes("@")) {
      return res.status(400).json({ message: "Valid email required" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.json({ message: "OTP sent" }); // don't reveal if email exists

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, expires: Date.now() + 10 * 60 * 1000 });

    await resend.emails.send({
      from: "Playvora <onboarding@resend.dev>",
      to: email,
      subject: "Reset your Playvora password",
      html: getOtpEmailHtml(otp, user.name),
    });

    res.json({ message: "OTP sent" });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Error sending email" });
  }
});

// VERIFY OTP
app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const stored = otpStore.get(email);

    if (!stored) return res.status(400).json({ message: "OTP not found. Request again." });
    if (Date.now() > stored.expires) {
      otpStore.delete(email);
      return res.status(400).json({ message: "OTP expired. Request again." });
    }
    if (stored.otp !== otp) return res.status(400).json({ message: "Invalid OTP." });

    res.json({ message: "OTP verified" });
  } catch (error) {
    console.error("OTP verify error:", error);
    res.status(500).json({ message: "Verification error" });
  }
});

// RESET PASSWORD
app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const stored = otpStore.get(email);

    if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
      return res.status(400).json({ message: "Invalid or expired OTP." });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { email },
      data: { password: hashedPassword }
    });

    otpStore.delete(email);
    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Reset error" });
  }
});

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Token missing" });
  if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ message: "Invalid token format" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// PROFILE
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ message: "User not found" });

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ message: "Error fetching profile" });
  }
});

// PLAY / RECORD MATCH
app.post("/play", authMiddleware, async (req, res) => {
  try {
    const { result, score } = req.body;

    if (typeof score !== "number" || score < 0) {
      return res.status(400).json({ message: "Invalid score" });
    }

    const match = await prisma.match.create({
      data: { result, score, userId: req.user.id }
    });

    await prisma.user.update({
      where: { id: req.user.id },
      data: { score: { increment: score } }
    });

    const players = await prisma.user.findMany({
      orderBy: { score: "desc" },
      take: 10
    });

    io.emit("leaderboardUpdated", players);
    res.json({ message: "Match recorded", match });
  } catch (error) {
    console.error("Play error:", error);
    res.status(500).json({ message: "Game error" });
  }
});

// LEADERBOARD
app.get("/leaderboard", async (req, res) => {
  try {
    const players = await prisma.user.findMany({
      orderBy: { score: "desc" },
      take: 10
    });

    const rankedPlayers = players.map((p, i) => ({
      position: i + 1,
      medal: i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : null,
      name: p.name,
      score: p.score,
      rank: getRank(p.score)
    }));

    res.json(rankedPlayers);
  } catch (error) {
    console.error("Leaderboard error:", error);
    res.status(500).json({ message: "Error fetching leaderboard" });
  }
});

// CONTACT
app.post("/contact", async (req, res) => {
  try {
    const { name, email, message, topic } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ message: "All fields required" });
    }

    await resend.emails.send({
      from: "Playvora <onboarding@resend.dev>",
      to: "vishalxr92@gmail.com",
      subject: `New ${topic || "General"} Message | Playvora`,
      html: `
        <div style="font-family:sans-serif;padding:20px">
          <h2>New Contact Message</h2>
          <p><b>Name:</b> ${name}</p>
          <p><b>Email:</b> ${email}</p>
          <p><b>Topic:</b> ${topic || "General"}</p>
          <p><b>Message:</b></p>
          <div style="background:#f5f5f5;padding:15px;border-radius:10px;">
            ${message}
          </div>
        </div>
      `,
    });

    res.json({ success: true, message: "Message sent successfully" });
  } catch (error) {
    console.error("Contact error:", error);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
});

// ─────────────────────────────────────────
// SERVER START
// ─────────────────────────────────────────
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Playvora Server running on port ${PORT}`);
  console.log(`📱 Local:   http://localhost:${PORT}`);
  console.log(`🌐 Network: http://<your-ip>:${PORT}`);
});