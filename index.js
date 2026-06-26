// ─────────────────────────────────────────────────────────────
//  PLAVORA GAMING SERVER — WITH AD BLOCKER PROXY
//  (FULLY INTEGRATED)
// ─────────────────────────────────────────────────────────────
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const http = require('http');
const { Server } = require('socket.io');
const passport = require('passport');
const session = require('express-session');
const { Resend } = require('resend');
const axios = require('axios');
const { URL } = require('url');               // ✅ Added for ad blocker

// ─── Custom Routes ──────────────────────────────────────────
const passkeyRoutes = require('./routes/passkey');
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/auth');
require('./Controllers/authController'); // side‑effects (passport config)

// ─── Initialise ─────────────────────────────────────────────
const app = express();
const prisma = new PrismaClient();
const resend = new Resend(process.env.RESEND_API_KEY);
const server = http.createServer(app);
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

// ─── OTP Store ──────────────────────────────────────────────
const otpStore = new Map();
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

// ─── CORS (mirror origin) ──────────────────────────────────
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      callback(null, origin);
    },
    credentials: true,
  })
);

// ─── Middleware ─────────────────────────────────────────────
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'gaming_secret',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ─── Socket.IO ──────────────────────────────────────────────
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      callback(null, origin);
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

io.on('connection', (socket) => {
  console.log('User connected 🔥');

  socket.on('joinRoom', (roomId) => {
    socket.join(roomId);
  });

  socket.on('makeMove', ({ roomId, board, player }) => {
    socket.to(roomId).emit('moveMade', { board, player });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected 💤');
  });
});

// ─── Email Template ─────────────────────────────────────────
function getOtpEmailHtml(otp, userName = 'Player') {
  const year = new Date().getFullYear();
  const firstName = userName.split(' ')[0];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reset your Sharx password</title>
  <style>
    /* Full styles omitted for brevity — keep your original */
  </style>
</head>
<body>
  <div style="...">
    <div>Sharx</div>
    <h1>Reset your password</h1>
    <p>Hi ${firstName},<br><br>We received a request to reset the password for your Sharx account. Enter the verification code below to continue.</p>
    <div style="font-size:48px;font-weight:600;letter-spacing:8px;">${otp}</div>
    <div>This code expires in 10 minutes</div>
    <hr>
    <div>Didn't request this?</div>
    <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged and your account is secure.</p>
    <div>For your security, Sharx will never ask for your password, payment details, or verification code via email, phone, or chat.</div>
    <div>
      <div>Sharx</div>
      <div>
        <a href="#">Privacy Policy</a>
        <a href="#">Terms of Service</a>
        <a href="#">Support</a>
        <a href="#">Security</a>
      </div>
      <div>© ${year} Playvora. All rights reserved.<br>This is an automated message. Please do not reply.</div>
    </div>
  </div>
</body>
</html>`;
}

// ─── Auth Middleware ────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ─── Helpers ─────────────────────────────────────────────────
function getRank(score) {
  if (score >= 1000) return 'Diamond 💎';
  if (score >= 600) return 'Platinum 🔵';
  if (score >= 300) return 'Gold 🟡';
  if (score >= 100) return 'Silver ⚪';
  return 'Bronze 🟤';
}

// ─── Routes ──────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => res.send('🎮 Playvora Gaming Server running 🚀'));

// User routes
app.use('/user', userRoutes);
app.use('/auth', authRoutes);
app.use('/passkey', passkeyRoutes);

// ─── Game Fetch (cached) ────────────────────────────────────
const gamesCache = new Map();
const GAME_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

app.get('/games', async (req, res) => {
  try {
    const { page = 1, num = 50 } = req.query;
    const cacheKey = `${page}-${num}`;
    const cached = gamesCache.get(cacheKey);

    if (cached && Date.now() - cached.time < GAME_CACHE_TTL) {
      return res.json(cached.data);
    }

    const response = await axios.get(
      `https://gamemonetize.com/feed.php?format=0&num=${num}&page=${page}`
    );
    const games = Array.isArray(response.data) ? response.data : [];
    gamesCache.set(cacheKey, { data: games, time: Date.now() });
    res.json(games);
  } catch (error) {
    console.error('Games fetch error:', error.message);
    // Fallback to stale cache
    const cacheKey = `${req.query.page || 1}-${req.query.num || 50}`;
    const stale = gamesCache.get(cacheKey);
    if (stale) return res.json(stale.data);
    res.status(500).json({ success: false, message: 'Failed to fetch games' });
  }
});

// ─── Signup ──────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashed, score: 0 },
    });

    const { password: _, ...safeUser } = user;
    res.json({ message: 'User created successfully', user: safeUser });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup error' });
  }
});

// ─── Login ───────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (!user.password) {
      return res.status(400).json({ message: 'Please login with Google' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Wrong password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: '1d',
    });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login error' });
  }
});

// ─── Forgot Password ────────────────────────────────────────
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Valid email required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.json({ message: 'OTP sent' }); // don't reveal existence

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, expires: Date.now() + OTP_EXPIRY_MS });

    await resend.emails.send({
      from: 'Playvora <onboarding@resend.dev>',
      to: email,
      subject: 'Reset your Playvora password',
      html: getOtpEmailHtml(otp, user.name),
    });

    res.json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Error sending email' });
  }
});

// ─── Verify OTP ─────────────────────────────────────────────
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const stored = otpStore.get(email);
    if (!stored) {
      return res.status(400).json({ message: 'OTP not found. Request again.' });
    }
    if (Date.now() > stored.expires) {
      otpStore.delete(email);
      return res.status(400).json({ message: 'OTP expired. Request again.' });
    }
    if (stored.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }
    res.json({ message: 'OTP verified' });
  } catch (error) {
    console.error('OTP verify error:', error);
    res.status(500).json({ message: 'Verification error' });
  }
});

// ─── Reset Password ─────────────────────────────────────────
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const stored = otpStore.get(email);
    if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { email },
      data: { password: hashed },
    });
    otpStore.delete(email);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Reset error' });
  }
});

// ─── Profile ─────────────────────────────────────────────────
app.get('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ message: 'User not found' });
    const { password: _, ...safeUser } = user;
    res.json(safeUser);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

// ─── Play / Record Match ────────────────────────────────────
app.post('/play', authMiddleware, async (req, res) => {
  try {
    const { result, score } = req.body;
    if (typeof score !== 'number' || score < 0) {
      return res.status(400).json({ message: 'Invalid score' });
    }

    const match = await prisma.match.create({
      data: { result, score, userId: req.user.id },
    });

    await prisma.user.update({
      where: { id: req.user.id },
      data: { score: { increment: score } },
    });

    const topPlayers = await prisma.user.findMany({
      orderBy: { score: 'desc' },
      take: 10,
    });
    io.emit('leaderboardUpdated', topPlayers);

    res.json({ message: 'Match recorded', match });
  } catch (error) {
    console.error('Play error:', error);
    res.status(500).json({ message: 'Game error' });
  }
});

// ─── Leaderboard ────────────────────────────────────────────
app.get('/leaderboard', async (req, res) => {
  try {
    const players = await prisma.user.findMany({
      orderBy: { score: 'desc' },
      take: 10,
    });

    const ranked = players.map((p, i) => ({
      position: i + 1,
      medal: i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : null,
      name: p.name,
      score: p.score,
      rank: getRank(p.score),
    }));

    res.json(ranked);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ message: 'Error fetching leaderboard' });
  }
});

// ─── Contact ─────────────────────────────────────────────────
app.post('/contact', async (req, res) => {
  try {
    const { name, email, message, topic } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ message: 'All fields required' });
    }

    await resend.emails.send({
      from: 'Playvora <onboarding@resend.dev>',
      to: 'vishalxr92@gmail.com',
      subject: `New ${topic || 'General'} Message | Playvora`,
      html: `
        <div style="font-family:sans-serif;padding:20px">
          <h2>New Contact Message</h2>
          <p><b>Name:</b> ${name}</p>
          <p><b>Email:</b> ${email}</p>
          <p><b>Topic:</b> ${topic || 'General'}</p>
          <p><b>Message:</b></p>
          <div style="background:#f5f5f5;padding:15px;border-radius:10px;">
            ${message}
          </div>
        </div>
      `,
    });

    res.json({ success: true, message: 'Message sent successfully' });
  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ════════════════════════════════════════════════════════════════
//  🚫 AD BLOCKER PROXY — ROUTES & MIDDLEWARE
//  (Placed after all other routes, before server start)
// ════════════════════════════════════════════════════════════════

// ─── Ad domains blocklist ───────────────────────────────────
// NOTE: gamemonetize.com is deliberately NOT in here — that's your own
// game source (html5.gamemonetize.com etc.), blocking it would have
// blocked every single game from loading through the proxy.
const AD_DOMAINS = new Set([
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'adnxs.com', 'rubiconproject.com', 'openx.net', 'pubmatic.com',
  'criteo.com', 'taboola.com', 'outbrain.com', 'revcontent.com',
  'advertising.com', 'yieldmo.com', 'smartadserver.com', 'appnexus.com',
  'adsafeprotected.com', 'moatads.com', 'scorecardresearch.com',
  'quantserve.com', 'amazon-adsystem.com', 'media.net',
  'sharethrough.com', 'teads.tv', '33across.com', 'indexexchange.com',
  'sovrn.com', 'lijit.com', 'undertone.com', 'conversantmedia.com',
  'flashtalking.com', 'exoclick.com', 'trafficjunky.com',
  'cpmstar.com', 'popads.net', 'popcash.net', 'propellerads.com',
  'hilltopads.net', 'adcash.com', 'clickadu.com', 'zeropark.com',
  'adsterra.com', 'admaven.com', 'mgid.com', 'revolutiontt.net',
  'juicyads.com', 'ero-advertising.com', 'adcolony.com',
  'unityads.unity3d.com', 'ads.mopub.com', 'superawesome.com',
  'chartboost.com', 'vungle.com', 'applovin.com', 'ironsrc.com',
]);

function isAdDomain(hostname) {
  if (!hostname) return false;
  for (const ad of AD_DOMAINS) {
    if (hostname === ad || hostname.endsWith('.' + ad)) return true;
  }
  return false;
}

// ─── Game Proxy Route ────────────────────────────────────────
// Frontend use: fetch('/proxy/game?url=https://game.example.com/game/')
app.get('/proxy/game', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).send('URL required');
  }

  // Express already URL-decodes query params once, so `url` here is
  // already the real game URL. Decoding it AGAIN can corrupt URLs that
  // legitimately contain a `%` in their own query string — so we try
  // the plain value first, and only fall back to a manual decode.
  let targetUrl;
  try {
    targetUrl = new URL(url);
  } catch {
    try {
      targetUrl = new URL(decodeURIComponent(url));
    } catch {
      return res.status(400).send('Invalid URL');
    }
  }

  // Block direct ad domain access
  if (isAdDomain(targetUrl.hostname)) {
    return res.status(204).send('');
  }

  try {
    const response = await axios.get(targetUrl.toString(), {
      timeout: 10000,
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': targetUrl.origin,
      },
      maxRedirects: 5,
    });

    const contentType = response.headers['content-type'] || 'text/html';

    // ─── HEADERS ───────────────────────────────────────────
    // Permissive on purpose so embedded games (which load assets from all
    // over the place) keep working. The actual ad-blocking happens via the
    // injected script below + the domain check above — NOT via this CSP.
    // We deliberately do NOT set X-Frame-Options here: "ALLOWALL" is not a
    // real value and modern browsers treat unrecognised values as DENY,
    // which would silently block your own iframe from rendering anything.
    res.set({
      'Content-Type': contentType,
      'Content-Security-Policy': [
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
        "script-src * 'unsafe-inline' 'unsafe-eval' blob: data:",
        "connect-src * data: blob:",
        "frame-src * data: blob:",
        "img-src * data: blob:",
      ].join('; '),
      'Cache-Control': 'public, max-age=300',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET',
    });

    // HTML content: inject ad-blocking JavaScript
    if (contentType.includes('text/html')) {
      let html = Buffer.from(response.data).toString('utf-8');

      const adBlockScript = `<script>
(function() {
  var AD_DOMAINS = ${JSON.stringify([...AD_DOMAINS])};
  function isAd(url) {
    try {
      var h = new URL(url, location.href).hostname;
      return AD_DOMAINS.some(function(d){ return h===d||h.endsWith('.'+d); });
    } catch(e){ return false; }
  }
  // Block fetch
  var _fetch = window.fetch;
  window.fetch = function(input, init) {
    var url = typeof input==='string' ? input : (input&&input.url)||'';
    if(isAd(url)) return Promise.reject(new Error('Blocked'));
    return _fetch.apply(this, arguments);
  };
  // Block XHR
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, url) {
    if(isAd(String(url))) { this._sharxBlocked=true; return; }
    return _open.apply(this, arguments);
  };
  var _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function() {
    if(this._sharxBlocked) return;
    return _send.apply(this, arguments);
  };
  // Block window.open (popups)
  var _wopen = window.open;
  window.open = function(url) {
    if(url && isAd(String(url))) return null;
    return _wopen && _wopen.apply(this, arguments);
  };
  // Remove ad elements
  function removeAds() {
    document.querySelectorAll('iframe,script,ins').forEach(function(el) {
      var src = el.src || el.getAttribute('src') || '';
      if(src && isAd(src)) el.remove();
    });
  }
  new MutationObserver(removeAds).observe(document.documentElement, {childList:true, subtree:true});
  document.addEventListener('DOMContentLoaded', removeAds);
})();
</script>`;

      if (html.includes('<head>')) {
        html = html.replace('<head>', '<head>' + adBlockScript);
      } else if (html.includes('<html>')) {
        html = html.replace('<html>', '<html>' + adBlockScript);
      } else {
        html = adBlockScript + html;
      }

      // Set base URL for relative resources
      if (!html.includes('<base ')) {
        const baseTag = `<base href="${targetUrl.origin}${targetUrl.pathname.replace(/[^/]*$/, '')}">`;
        if (html.includes('<head>')) {
          html = html.replace('<head>', '<head>' + baseTag);
        }
      }

      return res.send(html);
    }

    // Non-HTML content (JS, CSS, images) directly serve
    res.send(Buffer.from(response.data));

  } catch (error) {
    console.error('Proxy error:', error.message);
    // On failure, redirect to original URL as fallback
    res.redirect(targetUrl.toString());
  }
});

// ─── Ad domain blocker — direct resource requests ────────────
// If any request's referer is an ad domain, return 204 (no content)
app.use((req, res, next) => {
  const referer = req.headers.referer || '';
  try {
    if (referer) {
      const ref = new URL(referer);
      if (isAdDomain(ref.hostname)) {
        return res.status(204).send('');
      }
    }
  } catch {}
  next();
});

// ════════════════════════════════════════════════════════════════
//  🚀 START SERVER
// ════════════════════════════════════════════════════════════════

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Playvora Server running on port ${PORT}`);
  console.log(`📱 Local:   http://localhost:${PORT}`);
  console.log(`🌐 Network: http://<your-ip>:${PORT}`);
});