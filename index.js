// ─────────────────────────────────────────────────────────────
//  PLAVORA GAMING SERVER — WITH AD BLOCKER PROXY
//  (FULLY INTEGRATED & REFACTORED)
//  PATCHED — see "PATCH" comments for what changed and why
// ─────────────────────────────────────────────────────────────
//
// WHAT CHANGED IN THIS VERSION:
// - Complete asset proxy system with /proxy/game and /proxy/asset
// - All game assets (JS, CSS, images, audio, video) now route through proxy
// - Binary asset caching with TTL
// - Proper CORS handling for all proxied content
// - Timeout protection for all requests
// - Protocol-relative, absolute, relative, and root-relative URL support
// - Shared handleAssetProxy() function (no code duplication)
// - Cache-busting query string preservation
// - Redirect handling
// - Production-ready error handling
//
// REQUIRED PACKAGE.JSON CHANGES:
//   npm install compression cheerio axios
//
// REQUIRED ENV VARS — add to your .env:
//   PUBLIC_BASE_URL=https://your-actual-domain-or-ip:5001
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
const compression = require('compression');
const cheerio = require('cheerio');
const adblock = require('./lib/adblock');

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
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;

// ─── Crash Guards (PATCH) ───────────────────────────────────
// Without this, one bad request (e.g. a bug inside lib/adblock.js, or an
// unexpected upstream response) can throw OUTSIDE any try/catch and kill
// the entire Node process. Once that happens, EVERY route — even ones
// completely unrelated to the request that crashed it — stops responding.
// That is what "net::ERR_CONNECTION_REFUSED" on every asset means: nothing
// is listening on port 5001 anymore.
// This does NOT fix the underlying bug — it only stops it from taking the
// whole server down. Watch this log for a stack trace; that tells you the
// real line to fix (most likely inside lib/adblock.js, which we can't see).
process.on('uncaughtException', (err) => {
  console.error('❌ [uncaughtException] This would have crashed the server:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ [unhandledRejection] This would have crashed the server:', reason);
});

// ─── OTP Store ──────────────────────────────────────────────
const otpStore = new Map();
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

// ─── Last Proxied Game URL (for fallback asset resolution) ──
let lastProxiedGameUrl = null;

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

// ─── Middleware ──────────────────────────────────────────────
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
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
  <title>Reset your Playvora password</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif; }
  </style>
</head>
<body>
  <div style="max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
    <div style="font-size: 24px; font-weight: bold; margin-bottom: 20px;">Playvora</div>
    <h1 style="font-size: 28px; margin: 20px 0;">Reset your password</h1>
    <p>Hi ${firstName},<br><br>We received a request to reset the password for your Playvora account. Enter the verification code below to continue.</p>
    <div style="font-size:48px;font-weight:600;letter-spacing:8px;text-align:center;margin:30px 0;">${otp}</div>
    <div style="text-align: center; color: #666;">This code expires in 10 minutes</div>
    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
    <div style="margin: 20px 0;"><strong>Didn't request this?</strong></div>
    <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged and your account is secure.</p>
    <div style="color: #666; font-size: 14px; margin: 20px 0;">For your security, Playvora will never ask for your password, payment details, or verification code via email, phone, or chat.</div>
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee;">
      <div style="font-weight: bold; margin-bottom: 10px;">Playvora</div>
      <div style="margin-bottom: 10px;">
        <a href="#" style="color: #0066cc; text-decoration: none; margin-right: 20px;">Privacy Policy</a>
        <a href="#" style="color: #0066cc; text-decoration: none; margin-right: 20px;">Terms of Service</a>
        <a href="#" style="color: #0066cc; text-decoration: none; margin-right: 20px;">Support</a>
        <a href="#" style="color: #0066cc; text-decoration: none;">Security</a>
      </div>
      <div style="color: #999; font-size: 12px;">© ${year} Playvora. All rights reserved.<br>This is an automated message. Please do not reply.</div>
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

// ════════════════════════════════════════════════════════════════
//  🚀 UNIFIED ASSET PROXY HANDLER
//  Handles all asset proxying logic — used by both /proxy/game and
//  /proxy/asset routes. Eliminates code duplication.
// ════════════════════════════════════════════════════════════════

const assetProxyCache = adblock.createAssetCache({ maxEntries: 2000, ttlMs: 60 * 60 * 1000 });

/**
 * Core asset proxy handler — shared by all routes.
 * @param {string} url - The target URL to proxy
 * @param {number} timeoutMs - Request timeout in milliseconds
 * @param {boolean} isHtmlGame - If true, applies ad-blocking and runtime script
 * @returns {Promise<{buffer, contentType, cacheControl}>}
 */
async function handleAssetProxy(url, timeoutMs = 10000, isHtmlGame = false) {
  // Check cache first
  const cached = assetProxyCache.get(url);
  if (cached) {
    return cached;
  }

  // Validate URL is safe
  const safe = await adblock.isSafeTarget(url);
  if (!safe) {
    const error = new Error('Invalid or unsafe URL');
    error.statusCode = 400;
    throw error;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const targetUrl = new URL(url);
    const upstream = await fetch(targetUrl.toString(), {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': targetUrl.origin,
        'Origin': PUBLIC_BASE_URL,
        'DNT': '1',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    if (!upstream.ok) {
      const error = new Error(`Upstream returned ${upstream.status}`);
      error.statusCode = 502;
      throw error;
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const cacheControl = upstream.headers.get('cache-control') || 'public, max-age=3600';

    let buffer;
    let finalContentType = contentType;

    if (contentType.includes('text/html') && isHtmlGame) {
      // Process HTML for ad-blocking and asset rewriting
      const html = await upstream.text();
      const $ = cheerio.load(html);

      // Strip ads
      adblock.stripAds($, targetUrl.toString());

      // Rewrite all asset URLs to go through /proxy/asset
      rewriteAssetUrls($, targetUrl.toString());

      // (PATCH) Disable the game's own service-worker registration.
      // Some HTML5 games (Unity WebGL in particular) try to register their
      // own service worker for offline caching, using a path relative to
      // their own folder (e.g. "ServiceWorker.js"). Once proxied, that
      // relative path resolves against THIS server instead of the real
      // game host, points at a script that doesn't exist here, and throws
      // an uncaught error in the browser. Properly proxying a real service
      // worker (rewriting its internal fetch/cache logic too) is a much
      // bigger job than it's worth here, so we just disable registration.
      const swGuardTag = `<script>try{if(navigator.serviceWorker){navigator.serviceWorker.register=function(){return Promise.reject(new Error('Service worker disabled by proxy'));};}}catch(e){}</script>`;
      $('head').prepend(swGuardTag);

      // Inject ad-block runtime script
      const runtimeScriptTag = `<script src="${PUBLIC_BASE_URL}/adblock-runtime.js"></script>`;
      $('head').append(runtimeScriptTag);

      const finalHtml = $.html();
      buffer = Buffer.from(finalHtml, 'utf-8');
      finalContentType = 'text/html; charset=utf-8';
    } else if (contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      // For JS files
      buffer = Buffer.from(await upstream.arrayBuffer());
      finalContentType = 'application/javascript; charset=utf-8';
    } else if (contentType.includes('text/css')) {
      // (PATCH) For CSS files — rewrite url(...) references before serving.
      // cheerio only rewrites tags in the HTML document; it cannot see
      // inside a separately-fetched .css file. Without this, any image
      // referenced from CSS (Unity's progress-bar/logo images are exactly
      // this case) bypasses the proxy and breaks.
      const cssText = await upstream.text();
      const rewrittenCss = rewriteCssUrls(cssText, targetUrl.toString());
      buffer = Buffer.from(rewrittenCss, 'utf-8');
      finalContentType = 'text/css; charset=utf-8';
    } else {
      // Binary assets (images, audio, video, etc.)
      buffer = Buffer.from(await upstream.arrayBuffer());
    }

    const result = { buffer, contentType: finalContentType, cacheControl };
    assetProxyCache.set(url, result);

    return result;
  } catch (error) {
    if (error.statusCode) throw error;
    if (error.name === 'AbortError') {
      const err = new Error('Request timeout');
      err.statusCode = 504;
      throw err;
    }
    console.error('[proxy] error:', error.message);
    const err = new Error('Failed to proxy asset');
    err.statusCode = 502;
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Rewrite all asset URLs in an HTML document to use /proxy/asset
 * Handles: script[src], img[src], iframe[src], audio[src], video[src],
 * source[src], link[href], object[data], and meta[content] for redirects.
 */
function rewriteAssetUrls($, baseUrl) {
  const base = new URL(baseUrl);
  const proxyAssetUrl = `${PUBLIC_BASE_URL}/proxy/asset`;

  // Helper to convert any URL to absolute
  function resolveUrl(urlStr) {
    if (!urlStr) return null;
    try {
      // Protocol-relative URL
      if (urlStr.startsWith('//')) {
        return new URL(urlStr, base).href;
      }
      // Absolute URL or root-relative
      return new URL(urlStr, base).href;
    } catch {
      return null;
    }
  }

  // Helper to create proxy URL with cache-busting preserved
  function createProxyUrl(absoluteUrl) {
    if (!absoluteUrl) return null;
    return `${proxyAssetUrl}?url=${encodeURIComponent(absoluteUrl)}`;
  }

  // Rewrite script[src]
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute && !adblock.isBlockedUrl(absolute)) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite img[src]
  $('img[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite iframe[src]
  $('iframe[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute && !adblock.isBlockedUrl(absolute)) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite audio[src]
  $('audio[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite video[src]
  $('video[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite source[src] (inside audio/video)
  $('source[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite link[href] (stylesheets, icons, etc.)
  $('link[href]').each((_, el) => {
    const href = $(el).attr('href');
    const absolute = resolveUrl(href);
    if (absolute && !href.startsWith('#')) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('href', proxyUrl);
    }
  });

  // Rewrite object[data]
  $('object[data]').each((_, el) => {
    const data = $(el).attr('data');
    const absolute = resolveUrl(data);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('data', proxyUrl);
    }
  });

  // Rewrite embed[src]
  $('embed[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  // Rewrite meta[content] for refresh redirects
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr('content');
    if (content && content.includes('url=')) {
      const match = content.match(/url=([^;]+)/i);
      if (match) {
        let url = match[1].trim();
        if (url.startsWith('"') || url.startsWith("'")) {
          url = url.slice(1, -1);
        }
        const absolute = resolveUrl(url);
        if (absolute) {
          const proxyUrl = createProxyUrl(absolute);
          const delay = content.match(/^(\d+)/)?.[1] || '0';
          $(el).attr('content', `${delay};url=${proxyUrl}`);
        }
      }
    }
  });

  // (PATCH) Rewrite url(...) references inside inline <style> blocks.
  // Same reasoning as the external-CSS patch in handleAssetProxy — a
  // background-image or font url() set in an inline <style> tag is
  // invisible to the tag-based rewriting above.
  $('style').each((_, el) => {
    const cssText = $(el).html();
    if (cssText) {
      $(el).html(rewriteCssUrls(cssText, baseUrl));
    }
  });
}

/**
 * (PATCH — new function)
 * Rewrite url(...) references inside CSS text so they also route through
 * /proxy/asset. This covers both relative paths ("progress-bar.png") and
 * already-absolute ones — either way, the browser will otherwise hit the
 * image directly instead of going through the proxy/ad-blocker.
 */
function rewriteCssUrls(cssText, baseUrl) {
  const base = new URL(baseUrl);
  const proxyAssetUrl = `${PUBLIC_BASE_URL}/proxy/asset`;

  return cssText.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, path) => {
    if (path.startsWith('data:')) return match; // inline data, nothing to proxy
    try {
      const absolute = new URL(path, base).href;
      const proxied = `${proxyAssetUrl}?url=${encodeURIComponent(absolute)}`;
      return `url(${quote}${proxied}${quote})`;
    } catch {
      return match;
    }
  });
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
      `https://gamemonetize.com/feed.php?format=0&num=${num}&page=${page}`,
      { timeout: 10000 }
    );
    const games = Array.isArray(response.data) ? response.data : [];
    gamesCache.set(cacheKey, { data: games, time: Date.now() });
    res.json(games);
  } catch (error) {
    console.error('Games fetch error:', error.message);
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
    if (!user) return res.json({ message: 'OTP sent' });

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
// ════════════════════════════════════════════════════════════════

// Mount ad-block runtime script
adblock.mountAdBlockRuntime(app, PUBLIC_BASE_URL);

// ─── GAME PROXY ROUTE (Main Entry Point) ────────────────────
app.get('/proxy/game', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }

  try {
    lastProxiedGameUrl = url;
    const result = await handleAssetProxy(url, 15000, true);

    res.set({
      'Content-Type': result.contentType,
      'Cache-Control': result.cacheControl || 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept',
      'X-Content-Type-Options': 'nosniff',
    });

    return res.send(result.buffer);
  } catch (error) {
    console.error('[proxy/game] error:', error.message);
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Failed to load game';
    return res.status(statusCode).json({ error: message });
  }
});

// ─── ASSET PROXY ROUTE (All Assets) ────────────────────────
app.get('/proxy/asset', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }

  try {
    const result = await handleAssetProxy(url, 10000, false);

    res.set({
      'Content-Type': result.contentType,
      'Cache-Control': result.cacheControl || 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept',
      'X-Content-Type-Options': 'nosniff',
      'ETag': `"${Date.now()}"`,
    });

    return res.send(result.buffer);
  } catch (error) {
    console.error('[proxy/asset] error:', error.message);
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Failed to load asset';
    return res.status(statusCode).json({ error: message });
  }
});

// ─── FALLBACK PROXY ROUTE (PATCH — new route) ──────────────
// Unity (and most HTML5 game engines) build several asset URLs at RUNTIME
// rather than putting them in the static HTML: CSS "url()" rules that
// point outside this CSS file's own folder, and inline JS that creates
// <script> tags using a path like "Build/xxx.loader.js". Neither passes
// through rewriteAssetUrls() or rewriteCssUrls(), so they hit THIS server
// directly as a bare relative path — e.g. /proxy/Build/xxx.loader.js —
// which had no matching route at all. This catches anything under /proxy/
// that isn't /proxy/game or /proxy/asset, and resolves it against the
// real game's URL.
//
// To find the right game URL, we first check the Referer header (the
// page/file that made this request) — this is per-request and correct
// even with multiple people using the server at once. If that's missing,
// we fall back to lastProxiedGameUrl — but that variable is a single
// GLOBAL value shared by everyone, so the fallback only gives the right
// answer when exactly one game is being loaded at a time. Fine for local
// testing; not safe once you have concurrent users — see chat notes.
app.get(/^\/proxy\/(.+)/, async (req, res) => {
  try {
    let gameBaseUrl = lastProxiedGameUrl;

    const referer = req.headers.referer;
    if (referer) {
      try {
        const refUrl = new URL(referer);
        const refGameUrl = refUrl.searchParams.get('url');
        if (refGameUrl) gameBaseUrl = refGameUrl;
      } catch {
        // malformed referer header — keep the fallback value
      }
    }

    if (!gameBaseUrl) {
      return res.status(404).json({ error: 'No active game session to resolve this path against' });
    }

    const relativePath = req.params[0];
    const base = new URL(gameBaseUrl);
    const resolved = new URL(relativePath, base);

    // Preserve any query string the browser sent on the relative request
    // (e.g. cache-busting params like ?v=123)
    const originalQuery = req.url.split('?')[1];
    if (originalQuery) resolved.search = originalQuery;

    const result = await handleAssetProxy(resolved.toString(), 10000, false);

    res.set({
      'Content-Type': result.contentType,
      'Cache-Control': result.cacheControl || 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    });

    return res.send(result.buffer);
  } catch (error) {
    console.error('[proxy/fallback] error:', error.message);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({ error: error.message || 'Failed to resolve relative asset' });
  }
});

// ─── OPTIONS for CORS Preflight ────────────────────────────
app.options('/proxy/game', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
  });
  res.sendStatus(204);
});

app.options('/proxy/asset', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
  });
  res.sendStatus(204);
});

// ════════════════════════════════════════════════════════════════
//  🚀 START SERVER
// ════════════════════════════════════════════════════════════════

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Playvora Server running on port ${PORT}`);
  console.log(`📱 Local:   http://localhost:${PORT}`);
  console.log(`🌐 Network: http://<your-ip>:${PORT}`);
  console.log(`🌐 Public base URL (used for ad-block runtime): ${PUBLIC_BASE_URL}`);
  if (PUBLIC_BASE_URL.includes('localhost')) {
    console.log(`⚠️  PUBLIC_BASE_URL is not set — ad-block runtime script will 404 for real visitors.`);
  }
  console.log('');
  console.log(`✅ Proxy routes ready:`);
  console.log(`   - /proxy/game?url=<gameUrl>  (HTML games with ad-blocking)`);
  console.log(`   - /proxy/asset?url=<assetUrl> (All assets: JS, CSS, images, audio, video)`);
  console.log(`   - /proxy/<relative-path>      (fallback for paths games build at runtime)`);
  console.log('');
  adblock.startBlocklistAutoRefresh();
});

module.exports = app;