// ─────────────────────────────────────────────────────────────
//  PLAVORA GAMING SERVER — MERGED (AUTH + GAMES + AD-BLOCK PROXY)
//  One Node process: login/database (Gaming-Backend) + the multi-page
//  games fetch + proxy system (formerly the standalone server.js).
//
//  HARDENED VERSION — fixes applied on top of the original merge:
//   1. CRASH FIX: `app.use(cookieParser())` was called before `app` was
//      defined (ReferenceError — the server could never start at all).
//   2. Single shared PrismaClient (lib/prisma.js) instead of 4 separate
//      connection pools across index.js / authController / userController
//      / passkey routes — prevents exhausting Postgres's connection limit.
//   3. Added helmet for baseline security headers.
//   4. CORS now uses an explicit allow-list (ALLOWED_ORIGINS env var)
//      instead of reflecting every incoming Origin header.
//   5. Added rate limiting on auth endpoints (login/signup/forgot-password/
//      verify-otp/reset-password) to blunt brute-force and OTP-spam abuse.
//   6. SESSION_SECRET now required in production (was silently falling
//      back to a hardcoded default string).
//   7. Input validation tightened (email format, contact form HTML
//      escaping to prevent stored/reflected HTML injection in admin
//      inbox, score bounds, pagination bounds).
//   8. OTP store now actually cleans up expired entries instead of
//      growing forever in memory.
// ─────────────────────────────────────────────────────────────

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const passport = require('passport');
const session = require('express-session');
const { Resend } = require('resend');
const compression = require('compression');
const cheerio = require('cheerio');
const { Readable } = require('stream');
const cookieParser = require('cookie-parser');

const adblock = require('./lib/adblock');
const prisma = require('./lib/prisma');

// ─── Custom Routes ──────────────────────────────────────────
const passkeyRoutes = require('./routes/passkey');
const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/auth');
require('./Controllers/authController'); // side-effects (passport config)

// ─── Required env vars — fail fast with a clear message ────
// FIX: previously a missing JWT_SECRET meant jwt.sign()/jwt.verify() would
// throw at request time with a confusing low-level error ("secretOrPrivateKey
// must have a value"), for every single request that touched auth, forever,
// until someone noticed. Check it once at startup instead.
const REQUIRED_ENV = ['JWT_SECRET', 'DATABASE_URL'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error('   The server cannot start safely without these. Set them in your .env file.');
  process.exit(1);
}

// FIX: SESSION_SECRET used to silently fall back to a hardcoded string
// ('gaming_secret') if unset. That's fine for local dev but a real
// security risk in production (anyone who reads this source knows the
// session-signing secret). Now it's required outright in production and
// only falls back to a dev-only value with a loud warning otherwise.
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('❌ SESSION_SECRET must be set in production. Refusing to start with an insecure default.');
  process.exit(1);
}
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_only_insecure_session_secret_change_me';
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET not set — using an insecure development-only default. Set SESSION_SECRET before deploying.');
}

// ─── Initialise ─────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // needed for correct req.ip / rate-limiting behind a reverse proxy (Render, Railway, nginx, etc.)

const resend = new Resend(process.env.RESEND_API_KEY);
const server = http.createServer(app);
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;

// ─── Crash Guards ───────────────────────────────────
// Without this, one bad request (e.g. a bug inside lib/adblock.js, or an
// unexpected upstream response) can throw OUTSIDE any try/catch and kill
// the entire Node process. Once that happens, EVERY route — even ones
// completely unrelated to the request that crashed it — stops responding.
// That is what "net::ERR_CONNECTION_REFUSED" on every asset means: nothing
// is listening on the port anymore.
// This does NOT fix the underlying bug — it only stops it from taking the
// whole server down. Watch this log for a stack trace; that tells you the
// real line to fix.
process.on('uncaughtException', (err) => {
  console.error('❌ [uncaughtException] This would have crashed the server:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ [unhandledRejection] This would have crashed the server:', reason);
});

// ─── OTP Store ──────────────────────────────────────────────
const otpStore = new Map();
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

// FIX: otpStore is an in-memory Map that only ever grew — expired entries
// were left in place until the SAME email requested another OTP. A steady
// trickle of different emails requesting password resets (or being
// targeted by an attacker enumerating emails) meant unbounded memory
// growth over the server's lifetime. Sweep expired entries periodically.
const otpCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [email, entry] of otpStore.entries()) {
    if (now > entry.expires) otpStore.delete(email);
  }
}, 5 * 60 * 1000);
otpCleanupTimer.unref?.();

// ─── Last Proxied Game URL (for fallback asset resolution) ──
let lastProxiedGameUrl = null;

// ─── CORS ───────────────────────────────────────────────────
// FIX: the original config reflected ANY incoming Origin header back with
// credentials: true — this is functionally "allow every website on the
// internet to make authenticated requests," which defeats the purpose of
// CORS entirely for an app that issues auth tokens/cookies. Now it uses an
// explicit allow-list. Set ALLOWED_ORIGINS in .env as a comma-separated
// list (e.g. "https://playvora.com,https://www.playvora.com"). Falls back
// to allowing localhost origins only, so local dev keeps working even if
// the env var isn't set yet.
const configuredOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const DEFAULT_DEV_ORIGINS = [/^http:\/\/localhost(:\d+)?$/, /^http:\/\/127\.0\.0\.1(:\d+)?$/];

function isAllowedOrigin(origin) {
  if (configuredOrigins.includes(origin)) return true;
  return DEFAULT_DEV_ORIGINS.some((re) => re.test(origin));
}

if (configuredOrigins.length === 0) {
  console.warn('⚠️  ALLOWED_ORIGINS is not set — only localhost origins will be allowed for CORS. Set ALLOWED_ORIGINS in .env before deploying (e.g. "https://yourdomain.com").');
}

const corsOptionsDelegate = (origin, callback) => {
  if (!origin) return callback(null, true); // same-origin / server-to-server / curl requests have no Origin header
  if (isAllowedOrigin(origin)) return callback(null, true);
  console.warn(`[CORS] Blocked request from disallowed origin: ${origin}`);
  return callback(null, false);
};

app.use(
  cors({
    origin: corsOptionsDelegate,
    credentials: true,
  })
);

// ─── Security headers ───────────────────────────────────────
// FIX: no security headers at all previously. helmet's defaults cover the
// common baseline (X-Content-Type-Options, X-Frame-Options, etc).
// contentSecurityPolicy is disabled because this server proxies and
// serves arbitrary third-party game HTML/JS/CSS/wasm through /proxy/* —
// a strict default CSP would break those games; the ad-block + SSRF-guard
// layers in lib/adblock.js are the actual defense for that surface.
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false, // games/assets are intentionally served cross-origin
    crossOriginEmbedderPolicy: false,
  })
);

// ─── Middleware ──────────────────────────────────────────────
app.use(cookieParser());
app.use(compression({
  filter: (req, res) => {
    // /proxy/* is mostly images, audio, wasm, video (already compressed)
    // plus streamed binary responses — gzipping any of that again just
    // burns CPU for no size win, and the extra pass adds latency games
    // don't need. Everything else (API JSON, etc.) still compresses.
    if (req.path.startsWith('/proxy/')) return false;
    return compression.filter(req, res);
  },
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ─── Rate limiting on auth-sensitive endpoints ──────────────
// FIX: /login, /signup, /forgot-password, /verify-otp, /reset-password had
// zero rate limiting — an attacker could brute-force passwords/OTPs or
// spam-trigger OTP emails at unlimited speed. These limits are per-IP.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' },
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // OTP requests/verifications are more sensitive — tighter limit
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' },
});

// ─── Socket.IO ──────────────────────────────────────────────
const io = new Server(server, {
  cors: {
    origin: corsOptionsDelegate,
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

io.on('connection', (socket) => {
  console.log('User connected 🔥');

  socket.on('joinRoom', (roomId) => {
    // FIX: roomId was joined with no validation — a non-string or absurd
    // value could be used to probe internal behavior. Cheap guard, no
    // behavior change for legitimate callers.
    if (typeof roomId !== 'string' || roomId.length === 0 || roomId.length > 100) return;
    socket.join(roomId);
  });

  socket.on('makeMove', ({ roomId, board, player } = {}) => {
    if (typeof roomId !== 'string' || roomId.length === 0 || roomId.length > 100) return;
    socket.to(roomId).emit('moveMade', { board, player });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected 💤');
  });
});

// ─── Email Template ─────────────────────────────────────────
// FIX: escape the user's own name before interpolating it into HTML —
// previously a user whose display name contained HTML (e.g. from a
// Google/Microsoft profile name, or a signup form with no server-side
// sanitization elsewhere) could inject markup into their own password
// reset email. Low severity (it's their own inbox) but free to fix.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getOtpEmailHtml(otp, userName = 'Player') {
  const year = new Date().getFullYear();
  const firstName = escapeHtml(String(userName).split(' ')[0]);
  const safeOtp = escapeHtml(otp);

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
    <div style="font-size:48px;font-weight:600;letter-spacing:8px;text-align:center;margin:30px 0;">${safeOtp}</div>
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

// ─── Validation helpers ─────────────────────────────────────
// FIX: signup/forgot-password previously only checked `email.includes('@')`
// (or nothing at all for signup) — accepting garbage like "a@" or "@@@".
// A real regex catches the obviously-invalid cases without being an
// overengineered RFC 5322 validator (which nothing needs).
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(email) {
  return typeof email === 'string' && EMAIL_RE.test(email);
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

    // Upstream has started responding — the "did they even answer" risk is
    // over. Clear the abort timer here so a large-but-progressing wasm/data
    // download (which can take well over timeoutMs to fully arrive) isn't
    // killed mid-transfer. Only a genuinely non-responding upstream will
    // still hit the timeout, right here, before this point.
    clearTimeout(timeoutId);

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    let cacheControl = upstream.headers.get('cache-control') || 'public, max-age=3600';

    let buffer;
    let finalContentType = contentType;

    if (contentType.includes('text/html') && isHtmlGame) {
      // Process HTML for ad-blocking and asset rewriting
      const html = await upstream.text();
      const $ = cheerio.load(html);

      // Strip ads
      adblock.stripAds($, targetUrl.toString(), PUBLIC_BASE_URL);

      // Rewrite all asset URLs to go through /proxy/asset
      rewriteAssetUrls($, targetUrl.toString());

      // Disable the game's own service-worker registration.
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
      // This HTML has proxy links baked in using the CURRENT PUBLIC_BASE_URL.
      // Never let the browser cache it long-term — if that value ever
      // changes (or was wrong on an earlier run), a cached copy would keep
      // replaying broken links indefinitely instead of picking up the fix.
      cacheControl = 'no-cache';
    } else if (contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      // For JS files
      buffer = Buffer.from(await upstream.arrayBuffer());
      finalContentType = 'application/javascript; charset=utf-8';
    } else if (contentType.includes('text/css')) {
      // For CSS files — rewrite url(...) references before serving.
      // cheerio only rewrites tags in the HTML document; it cannot see
      // inside a separately-fetched .css file. Without this, any image
      // referenced from CSS (Unity's progress-bar/logo images are exactly
      // this case) bypasses the proxy and breaks.
      const cssText = await upstream.text();
      const rewrittenCss = rewriteCssUrls(cssText, targetUrl.toString());
      buffer = Buffer.from(rewrittenCss, 'utf-8');
      finalContentType = 'text/css; charset=utf-8';
      // Same reasoning as the HTML branch above — this CSS also has
      // PUBLIC_BASE_URL-based proxy links baked into it.
      cacheControl = 'no-cache';
    } else {
      // Binary assets (images, audio, video, wasm, etc.) — these need no
      // text transformation, so stream them straight through instead of
      // buffering first. Buffering means: wait for the FULL download,
      // THEN send the FULL thing to the browser — for a 30-50MB Unity
      // .wasm/.data file that's roughly double the wait for no reason.
      // Streaming lets bytes reach the browser as they arrive from
      // upstream. Not cached in assetProxyCache (nothing to cache once
      // it's been piped through rather than collected into a buffer) —
      // an acceptable trade-off since large files are the ones this
      // change targets, and browsers still cache them via Cache-Control.
      return {
        stream: Readable.fromWeb(upstream.body),
        contentType: finalContentType,
        cacheControl,
      };
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
    console.error('[proxy] error for', url, '-', error.message);
    const err = new Error('Failed to proxy asset');
    err.statusCode = 502;
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Send a handleAssetProxy() result — whether it's a full buffer (html/css/js,
 * or a cache hit) or a stream (binary passthrough). Headers must already be
 * set on `res` before calling this.
 */
function sendProxyResult(result, res) {
  if (result.stream) {
    result.stream.on('error', (err) => {
      console.error('[proxy] stream error:', err.message);
      if (!res.headersSent) {
        res.status(502).end();
      } else {
        res.end();
      }
    });
    return result.stream.pipe(res);
  }
  return res.send(result.buffer);
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
      // Protocol-relative URL, absolute URL, or root-relative — all resolve
      // correctly against `base` via the URL constructor.
      return new URL(urlStr, base).href;
    } catch {
      return null;
    }
  }

  // Helper to create proxy URL with cache-busting preserved
  function createProxyUrl(absoluteUrl) {
    if (!absoluteUrl) return null;
    // Already one of our own proxy links (e.g. stripAds rewrote it first) —
    // wrapping it again would produce ?url=<another proxy URL>, which then
    // fails isSafeTarget for pointing back at our own localhost.
    if (absoluteUrl.startsWith(proxyAssetUrl)) return absoluteUrl;
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
    if (absolute && href && !href.startsWith('#')) {
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

  // Rewrite url(...) references inside inline <style> blocks.
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
    if (path.startsWith(proxyAssetUrl)) return match; // already one of our own proxy links
    try {
      const absolute = new URL(path, base).href;
      if (absolute.startsWith(proxyAssetUrl)) return `url(${quote}${absolute}${quote})`;
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

// ════════════════════════════════════════════════════════════════
//  🎮 GAMES — multi-page parallel fetch, cached, filterable
//  Fetches up to 6 GameMonetize pages in PARALLEL, dedupes by title,
//  caches the full list once, then paginates + filters in memory.
// ════════════════════════════════════════════════════════════════

let gamesDataCache = {};
let gamesFetchInFlight = null;
const GAMES_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

async function fetchGameMonetizePage(p, attempt = 1) {
  const MAX_ATTEMPTS = 3;
  try {
    const url = `https://gamemonetize.com/feed.php?format=0&num=500&page=${p}`;
    const res = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0'
      }
    });
    const text = await res.text();
    if (text.trim().startsWith('<')) {
      // GameMonetize's feed.php returned an HTML page instead of JSON —
      // in practice this means their feed API itself is erroring right
      // now (a 500 error page is HTML), not that this page has zero
      // games. Retry a couple times (a plain 500 is often transient)
      // before giving up, and log clearly either way.
      if (attempt < MAX_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 1500 * attempt));
        return fetchGameMonetizePage(p, attempt + 1);
      }
      console.error(
        `GameMonetize page ${p}: upstream returned non-JSON (HTTP ${res.status}) after ${MAX_ATTEMPTS} attempts — feed.php is likely down/erroring on GameMonetize's own side right now, not a bug here. Response start: ${text.slice(0, 150).replace(/\s+/g, ' ')}`
      );
      return { page: p, games: [], stop: true };
    }

    // FIX: JSON.parse() on a malformed-but-not-HTML response (truncated
    // body, unexpected upstream change) used to throw and be caught by
    // the outer catch, but only AFTER already consuming a retry attempt
    // silently as a generic error with no useful log context. Now it's
    // handled explicitly with a clear message.
    let json;
    try {
      json = JSON.parse(text);
    } catch (parseErr) {
      if (attempt < MAX_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 1500 * attempt));
        return fetchGameMonetizePage(p, attempt + 1);
      }
      console.error(`GameMonetize page ${p}: failed to parse JSON after ${MAX_ATTEMPTS} attempts:`, parseErr.message);
      return { page: p, games: [], stop: true, errored: true };
    }

    if (!Array.isArray(json) || json.length === 0) return { page: p, games: [], stop: true };

    const games = json
      // FIX: entries missing a title or url are filtered out here (not
      // just later in fetchAllGames' de-dupe step) so `id` below never
      // becomes the literal string "gm_undefined" for multiple different
      // broken entries, which would collide with each other under the
      // same fake id.
      .filter(g => g && g.title && g.url)
      .map(g => ({
        id: `gm_${g.id || g.title}`,
        title: g.title,
        thumb: g.thumb,
        url: g.url,
        category: g.category || 'Other',
        source: 'gamemonetize'
      }));

    console.log(`GameMonetize page ${p}: ${games.length} games`);
    return { page: p, games, stop: json.length < 500 };
  } catch (e) {
    if (attempt < MAX_ATTEMPTS) {
      await new Promise((r) => setTimeout(r, 1500 * attempt));
      return fetchGameMonetizePage(p, attempt + 1);
    }
    console.error(`GameMonetize page ${p} error after ${MAX_ATTEMPTS} attempts:`, e.message);
    return { page: p, games: [], stop: true, errored: true };
  }
}

async function fetchGameMonetize() {
  const totalPages = 6;
  const pageNums = Array.from({ length: totalPages }, (_, i) => i + 1);

  const results = await Promise.all(pageNums.map(fetchGameMonetizePage));

  // Preserve "stop at first short/empty/error page" behavior: keep games
  // only from pages before (and including) the first one that signaled
  // stop, in page order — even though they resolved out of order.
  results.sort((a, b) => a.page - b.page);

  const allGames = [];
  for (const r of results) {
    allGames.push(...r.games);
    if (r.stop) break;
  }

  return allGames;
}

async function fetchAllGames() {
  console.log('Fetching all games from all sources...');

  const gamemonetize = await fetchGameMonetize();
  let allGames = [...gamemonetize];

  const seen = new Set();
  const unique = allGames.filter(g => {
    if (!g.title || !g.url) return false;
    const key = g.title.toLowerCase().trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  console.log(`Total unique games: ${unique.length}`);
  return unique;
}

async function getGames() {
  if (gamesDataCache.allGames && Date.now() - gamesDataCache.allGames.time < GAMES_CACHE_TTL) {
    return gamesDataCache.allGames.data;
  }
  if (!gamesFetchInFlight) {
    gamesFetchInFlight = fetchAllGames()
      .then(games => {
        // Only cache real, non-empty results. An empty list almost always
        // means GameMonetize's own feed API was erroring during this
        // fetch — caching that for 10 minutes would keep serving "0
        // games" long after they recover. Leaving it uncached means the
        // next request just tries again fresh.
        if (games.length > 0) {
          gamesDataCache.allGames = { data: games, time: Date.now() };
        }
        gamesFetchInFlight = null;
        return games;
      })
      .catch(err => {
        gamesFetchInFlight = null;
        throw err;
      });
  }
  return gamesFetchInFlight;
}

// If getGames() (or any upstream call) hangs, callers get a clean 504
// instead of an open connection that never resolves.
function withTimeout(ms, label) {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(504).json({ error: `${label} timed out` });
      }
    }, ms);
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));
    next();
  };
}

// Games list rarely changes within the cache window, safe to let
// browsers/CDNs cache it briefly client-side too.
const GAMES_CLIENT_CACHE_SECONDS = 60;

app.get('/games', withTimeout(15000, 'Games request'), async (req, res) => {
  // FIX: parseInt(req.query.page) with no bounds allowed page=0, negative
  // pages (producing a negative `start` index — .slice(-50, 0) silently
  // returns an empty array, not an error, which looked like "no games"
  // for a bogus but easy-to-send query), or absurdly large pages that
  // just always return []. Clamp to a sane minimum of 1.
  let page = parseInt(req.query.page, 10);
  if (!Number.isFinite(page) || page < 1) page = 1;

  const category = typeof req.query.category === 'string' ? req.query.category.slice(0, 100) : '';
  const PER_PAGE = 50;

  try {
    let games = await getGames();

    if (category && category !== 'All') {
      games = games.filter(g => g.category?.toLowerCase() === category.toLowerCase());
    }

    const start = (page - 1) * PER_PAGE;
    const paginated = games.slice(start, start + PER_PAGE);

    if (!res.headersSent) {
      res.set('Cache-Control', `public, max-age=${GAMES_CLIENT_CACHE_SECONDS}`);
      res.json(paginated);
    }
  } catch (e) {
    console.error('Games error:', e.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to load games' });
    }
  }
});

app.get('/categories', withTimeout(15000, 'Categories request'), async (req, res) => {
  try {
    const games = await getGames();
    const cats = [...new Set(games.map(g => g.category).filter(Boolean))].sort();
    if (!res.headersSent) {
      res.set('Cache-Control', `public, max-age=${GAMES_CLIENT_CACHE_SECONDS}`);
      res.json(['All', ...cats]);
    }
  } catch (e) {
    console.error('Categories error:', e.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to load categories' });
    }
  }
});

app.get('/stats', (req, res) => {
  res.set('Cache-Control', 'no-store'); // stats should always be live
  res.json({
    totalGames: gamesDataCache.allGames?.data?.length || 0,
    cacheAge: gamesDataCache.allGames ? Math.round((Date.now() - gamesDataCache.allGames.time) / 1000) + 's' : 'no cache',
    adblock: adblock.getBlocklistStatus(),
  });
});

// ─── Signup ──────────────────────────────────────────────────
app.post('/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ message: 'Name is required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'A valid email is required' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name: name.trim(), email, password: hashed, score: 0 },
    });

    const { password: _, ...safeUser } = user;
    res.json({ message: 'User created successfully', user: safeUser });
  } catch (error) {
    // FIX: a race condition (two signups with the same email landing at
    // almost the same time) could slip past the findUnique check above
    // and hit Prisma's own unique-constraint error (P2002) instead of the
    // friendly "User already exists" message. Handle it explicitly.
    if (error.code === 'P2002') {
      return res.status(400).json({ message: 'User already exists' });
    }
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup error' });
  }
});

// ─── Login ───────────────────────────────────────────────────
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    // FIX: previously "User not found" vs "Wrong password" were distinct
    // messages — this lets an attacker enumerate which emails have
    // accounts at all by trying logins and reading the error message.
    // Both cases now return the same generic message.
    if (!user || !user.password) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid email or password' });

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
app.post('/forgot-password', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Valid email required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    // Same response whether or not the account exists, so this endpoint
    // can't be used to enumerate registered emails.
    if (!user) return res.json({ message: 'If that account exists, an OTP has been sent' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, expires: Date.now() + OTP_EXPIRY_MS });

    await resend.emails.send({
      from: 'Playvora <onboarding@resend.dev>',
      to: email,
      subject: 'Reset your Playvora password',
      html: getOtpEmailHtml(otp, user.name),
    });

    res.json({ message: 'If that account exists, an OTP has been sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Error sending email' });
  }
});

// ─── Verify OTP ─────────────────────────────────────────────
app.post('/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }
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
app.post('/reset-password', otpLimiter, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    const stored = otpStore.get(email);
    if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
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
    // FIX: if the user row was deleted between OTP verification and this
    // call, prisma.user.update() throws P2025 — that used to fall
    // through to a generic 500 "Reset error" instead of a clear message.
    if (error.code === 'P2025') {
      return res.status(400).json({ message: 'Account no longer exists' });
    }
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
    // FIX: `typeof score !== 'number'` doesn't catch NaN or Infinity
    // (both pass typeof === 'number'), and there was no upper bound at
    // all — a client could submit score: 999999999999 and have it
    // permanently added to their total. Added a sane cap; adjust
    // MAX_SCORE_PER_MATCH to whatever your actual game's scoring allows.
    const MAX_SCORE_PER_MATCH = 100000;
    if (
      typeof score !== 'number' ||
      !Number.isFinite(score) ||
      score < 0 ||
      score > MAX_SCORE_PER_MATCH
    ) {
      return res.status(400).json({ message: 'Invalid score' });
    }
    if (typeof result !== 'string' || result.length === 0 || result.length > 50) {
      return res.status(400).json({ message: 'Invalid result' });
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
      select: { id: true, name: true, score: true, avatar: true },
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
      select: { name: true, score: true }, // FIX: was fetching full user rows (incl. password hash) into memory unnecessarily before mapping
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
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many messages sent. Please try again later.' },
});

app.post('/contact', contactLimiter, async (req, res) => {
  try {
    const { name, email, message, topic } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ message: 'All fields required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'A valid email is required' });
    }
    if (String(message).length > 5000) {
      return res.status(400).json({ message: 'Message is too long' });
    }

    // FIX: name/email/topic/message were interpolated directly into the
    // outgoing HTML email with no escaping — a submitter could inject
    // arbitrary HTML/markup (or attempt phishing-style content) into the
    // email your team reads in their inbox. Escape everything from the
    // request body before it goes into HTML.
    const safeName = escapeHtml(name);
    const safeEmail = escapeHtml(email);
    const safeTopic = escapeHtml(topic || 'General');
    const safeMessage = escapeHtml(message).replace(/\n/g, '<br>');

    await resend.emails.send({
      from: 'Playvora <onboarding@resend.dev>',
      to: process.env.CONTACT_INBOX_EMAIL || 'vishalxr92@gmail.com',
      subject: `New ${safeTopic} Message | Playvora`,
      html: `
        <div style="font-family:sans-serif;padding:20px">
          <h2>New Contact Message</h2>
          <p><b>Name:</b> ${safeName}</p>
          <p><b>Email:</b> ${safeEmail}</p>
          <p><b>Topic:</b> ${safeTopic}</p>
          <p><b>Message:</b></p>
          <div style="background:#f5f5f5;padding:15px;border-radius:10px;">
            ${safeMessage}
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

  // If the frontend ever sends a game object whose `url` field is missing,
  // `${gameUrl}` in a template literal silently becomes the *string*
  // "undefined" — not a real error, just a broken value that used to sail
  // straight through and surface later as a confusing 502 deep in an
  // asset request. Catch it right here instead.
  if (!url || url === 'undefined' || url === 'null') {
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

    return sendProxyResult(result, res);
  } catch (error) {
    console.error('[proxy/game] error for', url, '-', error.message);
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Failed to load game';
    return res.status(statusCode).json({ error: message });
  }
});

// ─── ASSET PROXY ROUTE (All Assets) ────────────────────────
app.get('/proxy/asset', async (req, res) => {
  let { url } = req.query;

  if (!url || url === 'undefined' || url === 'null') {
    return res.status(400).json({ error: 'URL required' });
  }

  // Backstop: unwrap a double-proxied link (?url=<our own /proxy/asset
  // link>) instead of failing on it. The idempotency guards in
  // rewriteAssetUrls/rewriteCssUrls should prevent new ones from being
  // created, but this covers any other source of a pre-wrapped link.
  const selfProxyPrefix = `${PUBLIC_BASE_URL}/proxy/asset?url=`;
  if (url.startsWith(selfProxyPrefix)) {
    try {
      url = decodeURIComponent(url.slice(selfProxyPrefix.length));
    } catch {
      // malformed encoding — fall through and let isSafeTarget reject it
    }
  }

  try {
    // 45s — Unity's .wasm/.data files regularly run 10-50+MB. The 504s
    // that used to show up in the console were OUR timeout firing, not
    // the upstream actually failing — cutting the fetch off before a big
    // file finished downloading, then handing Unity a JSON error body
    // instead of the real binary (that's also what caused the "expected
    // magic word" wasm compile error — Unity tried to parse our
    // {"error":...} JSON as wasm).
    const result = await handleAssetProxy(url, 45000, false);

    res.set({
      'Content-Type': result.contentType,
      'Cache-Control': result.cacheControl || 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept',
      'X-Content-Type-Options': 'nosniff',
      'ETag': `"${Date.now()}"`,
    });

    return sendProxyResult(result, res);
  } catch (error) {
    console.error('[proxy/asset] error for', url, '-', error.message);
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Failed to load asset';
    return res.status(statusCode).json({ error: message });
  }
});

// ─── FALLBACK PROXY ROUTE ──────────────────────────────────
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
// testing; not safe once you have concurrent users — the Referer check
// above is what actually protects concurrent sessions.
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

    if (!gameBaseUrl || gameBaseUrl === 'undefined' || gameBaseUrl === 'null') {
      return res.status(404).json({ error: 'No active game session to resolve this path against' });
    }

    const relativePath = req.params[0];
    const base = new URL(gameBaseUrl);
    const resolved = new URL(relativePath, base);

    // Preserve any query string the browser sent on the relative request
    // (e.g. cache-busting params like ?v=123)
    const originalQuery = req.url.split('?')[1];
    if (originalQuery) resolved.search = originalQuery;

    const result = await handleAssetProxy(resolved.toString(), 45000, false);

    res.set({
      'Content-Type': result.contentType,
      'Cache-Control': result.cacheControl || 'public, max-age=3600',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    });

    return sendProxyResult(result, res);
  } catch (error) {
    console.error('[proxy/fallback] error for', req.originalUrl, '-', error.message);
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

// ─── 404 handler ────────────────────────────────────────────
// FIX: previously any unmatched route outside /proxy/* fell through with
// Express's default plain-text 404, which is inconsistent with the JSON
// error shape every other route in this app returns.
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─── Final error handler ────────────────────────────────────
// FIX: no app-level error-handling middleware existed. A synchronous
// throw inside a route not wrapped in try/catch would be caught by
// Express itself, but returned an HTML stack-trace page by default —
// leaking internal file paths/stack traces to clients in production.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('❌ [unhandled route error]', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
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
  console.log(`✅ Games routes ready:`);
  console.log(`   - /games?page=&category=      (paginated, multi-page GameMonetize fetch)`);
  console.log(`   - /categories                  (list of available categories)`);
  console.log(`   - /stats                       (games cache + adblock status)`);
  console.log('');
  console.log(`✅ Proxy routes ready:`);
  console.log(`   - /proxy/game?url=<gameUrl>  (HTML games with ad-blocking)`);
  console.log(`   - /proxy/asset?url=<assetUrl> (All assets: JS, CSS, images, audio, video)`);
  console.log(`   - /proxy/<relative-path>      (fallback for paths games build at runtime)`);
  console.log('');
  adblock.startBlocklistAutoRefresh();

  // Warm the games cache immediately instead of waiting for the first
  // real visitor to eat the ~1-2s cold-fetch cost.
  getGames()
    .then(games => console.log(`🎮 Preloaded ${games.length} games successfully!`))
    .catch(err => console.error('❌ Failed to preload games:', err.message));
});

module.exports = app;
