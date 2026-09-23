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
const REQUIRED_ENV = ['JWT_SECRET', 'DATABASE_URL'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error('   The server cannot start safely without these. Set them in your .env file.');
  process.exit(1);
}

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
app.set('trust proxy', 1);

const resend = new Resend(process.env.RESEND_API_KEY);
const server = http.createServer(app);
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;

// ─── Crash Guards ───────────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('❌ [uncaughtException] This would have crashed the server:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ [unhandledRejection] This would have crashed the server:', reason);
});

// ─── OTP Store ──────────────────────────────────────────────
const otpStore = new Map();
const OTP_EXPIRY_MS = 10 * 60 * 1000;

const otpCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [email, entry] of otpStore.entries()) {
    if (now > entry.expires) otpStore.delete(email);
  }
}, 5 * 60 * 1000);
otpCleanupTimer.unref?.();

// ─── Last Proxied Game URL ──────────────────────────────────
let lastProxiedGameUrl = null;

// ─── CORS ───────────────────────────────────────────────────
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
  console.warn('⚠️  ALLOWED_ORIGINS is not set — only localhost origins will be allowed for CORS. Set ALLOWED_ORIGINS in .env before deploying.');
}

const corsOptionsDelegate = (origin, callback) => {
  if (!origin) return callback(null, true);
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
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

// ─── Middleware ──────────────────────────────────────────────
app.use(cookieParser());
app.use(compression({
  filter: (req, res) => {
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

// ─── Rate limiting ──────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again later.' },
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
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
// ════════════════════════════════════════════════════════════════

const assetProxyCache = adblock.createAssetCache({ maxEntries: 2000, ttlMs: 60 * 60 * 1000 });

async function handleAssetProxy(url, timeoutMs = 10000, isHtmlGame = false) {
  const cached = assetProxyCache.get(url);
  if (cached) {
    return cached;
  }

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

    clearTimeout(timeoutId);

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    let cacheControl = upstream.headers.get('cache-control') || 'public, max-age=3600';

    let buffer;
    let finalContentType = contentType;

    if (contentType.includes('text/html') && isHtmlGame) {
      const html = await upstream.text();
      const $ = cheerio.load(html);

      adblock.stripAds($, targetUrl.toString(), PUBLIC_BASE_URL);
      rewriteAssetUrls($, targetUrl.toString());

      const swGuardTag = `<script>try{if(navigator.serviceWorker){navigator.serviceWorker.register=function(){return Promise.reject(new Error('Service worker disabled by proxy'));};}}catch(e){}</script>`;
      $('head').prepend(swGuardTag);

      const runtimeScriptTag = `<script src="${PUBLIC_BASE_URL}/adblock-runtime.js"></script>`;
      $('head').append(runtimeScriptTag);

      const finalHtml = $.html();
      buffer = Buffer.from(finalHtml, 'utf-8');
      finalContentType = 'text/html; charset=utf-8';
      cacheControl = 'no-cache';
    } else if (contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      buffer = Buffer.from(await upstream.arrayBuffer());
      finalContentType = 'application/javascript; charset=utf-8';
    } else if (contentType.includes('text/css')) {
      const cssText = await upstream.text();
      const rewrittenCss = rewriteCssUrls(cssText, targetUrl.toString());
      buffer = Buffer.from(rewrittenCss, 'utf-8');
      finalContentType = 'text/css; charset=utf-8';
      cacheControl = 'no-cache';
    } else {
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

function rewriteAssetUrls($, baseUrl) {
  const base = new URL(baseUrl);
  const proxyAssetUrl = `${PUBLIC_BASE_URL}/proxy/asset`;

  function resolveUrl(urlStr) {
    if (!urlStr) return null;
    try {
      return new URL(urlStr, base).href;
    } catch {
      return null;
    }
  }

  function createProxyUrl(absoluteUrl) {
    if (!absoluteUrl) return null;
    if (absoluteUrl.startsWith(proxyAssetUrl)) return absoluteUrl;
    return `${proxyAssetUrl}?url=${encodeURIComponent(absoluteUrl)}`;
  }

  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute && !adblock.isBlockedUrl(absolute)) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('img[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('iframe[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute && !adblock.isBlockedUrl(absolute)) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('audio[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('video[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('source[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

  $('link[href]').each((_, el) => {
    const href = $(el).attr('href');
    const absolute = resolveUrl(href);
    if (absolute && href && !href.startsWith('#')) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('href', proxyUrl);
    }
  });

  $('object[data]').each((_, el) => {
    const data = $(el).attr('data');
    const absolute = resolveUrl(data);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('data', proxyUrl);
    }
  });

  $('embed[src]').each((_, el) => {
    const src = $(el).attr('src');
    const absolute = resolveUrl(src);
    if (absolute) {
      const proxyUrl = createProxyUrl(absolute);
      $(el).attr('src', proxyUrl);
    }
  });

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

  $('style').each((_, el) => {
    const cssText = $(el).html();
    if (cssText) {
      $(el).html(rewriteCssUrls(cssText, baseUrl));
    }
  });
}

function rewriteCssUrls(cssText, baseUrl) {
  const base = new URL(baseUrl);
  const proxyAssetUrl = `${PUBLIC_BASE_URL}/proxy/asset`;

  return cssText.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, path) => {
    if (path.startsWith('data:')) return match;
    if (path.startsWith(proxyAssetUrl)) return match;
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
app.get('/', (req, res) => res.send('🎮 Playvora Gaming Server running 🚀'));

app.use('/user', userRoutes);
app.use('/auth', authRoutes);
app.use('/passkey', passkeyRoutes);

// ════════════════════════════════════════════════════════════════
//  🎮 GAMES — multi-page parallel fetch, cached, filterable
// ════════════════════════════════════════════════════════════════

let gamesDataCache = {};
let gamesFetchInFlight = null;
const GAMES_CACHE_TTL = 10 * 60 * 1000;

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
      if (attempt < MAX_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 1500 * attempt));
        return fetchGameMonetizePage(p, attempt + 1);
      }
      console.error(
        `GameMonetize page ${p}: upstream returned non-JSON (HTTP ${res.status}) after ${MAX_ATTEMPTS} attempts — feed.php is likely down/erroring on GameMonetize's own side right now, not a bug here. Response start: ${text.slice(0, 150).replace(/\s+/g, ' ')}`
      );
      return { page: p, games: [], stop: true };
    }

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
      .filter(g => g && g.title && g.url)
      .map((g, idx) => ({
        id: `gm_${g.id || g.title}`,
        title: g.title,
        thumb: g.thumb,
        video: g.video || null,
        url: g.url,
        category: g.category || 'Other',
        description: g.description || '',
        instructions: g.instructions || '',
        tags: g.tags || '',
        source: 'gamemonetize',
        feedRank: (p - 1) * 500 + idx,
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

  const results = [];
  for (const page of pageNums) {
    const result = await fetchGameMonetizePage(page);
    results.push(result);
    if (page < totalPages) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  results.sort((a, b) => a.page - b.page);

  const allGames = [];
  let feedEnded = false;

  for (const r of results) {
    if (r.errored) {
      console.warn(`GameMonetize page ${r.page}: skipped after repeated errors, continuing to next page`);
      continue;
    }

    allGames.push(...r.games);

    if (r.stop && !r.errored) {
      feedEnded = true;
      break;
    }
  }

  if (!feedEnded) {
    console.log('GameMonetize: reached end of configured page range without a natural feed end');
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

const GAMES_CLIENT_CACHE_SECONDS = 60;

app.get('/games', withTimeout(15000, 'Games request'), async (req, res) => {
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

app.get('/games/trending', withTimeout(15000, 'Trending request'), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 12, 50);

  try {
    const games = await getGames();
    const trending = [...games]
      .sort((a, b) => (a.feedRank ?? 0) - (b.feedRank ?? 0))
      .slice(0, limit);

    if (!res.headersSent) {
      res.set('Cache-Control', `public, max-age=${GAMES_CLIENT_CACHE_SECONDS}`);
      res.json(trending);
    }
  } catch (e) {
    console.error('Trending error:', e.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to load trending games' });
    }
  }
});

app.get("/games/:id", async (req, res) => {
  try {
    const games = await getGames();

    console.log("Requested ID:", req.params.id);
    console.log("Games length:", games.length);

    const game = games.find((g) => g.id === req.params.id);

    console.log("Found:", !!game);

    if (!game) {
      console.log("First 5 IDs:", games.slice(0, 5).map(g => g.id));
      return res.status(404).json({
        error: "Game not found",
      });
    }

    res.json(game);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Failed to load game",
    });
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
  res.set('Cache-Control', 'no-store');
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
      select: { name: true, score: true },
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

const CONTACT_REASONS = new Set([
  'General question',
  'Account or login issue',
  'Report a broken game',
  'Report inappropriate content',
  'Bug or technical problem',
  'Feedback or suggestion',
  'Business inquiry',
  'Game submission',
  'Other',
]);

app.post('/contact', contactLimiter, async (req, res) => {
  try {
    const { name, email, message, topic, game, website } = req.body || {};

    // Honeypot: real users never fill this hidden field.
    if (typeof website === 'string' && website.trim()) {
      return res.json({ success: true, message: 'Message sent successfully' });
    }

    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ success: false, message: 'Name is required' });
    }
    if (name.trim().length > 80) {
      return res.status(400).json({ success: false, message: 'Name is too long' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'A valid email is required' });
    }
    if (email.length > 120) {
      return res.status(400).json({ success: false, message: 'Email is too long' });
    }
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }
    if (message.trim().length < 4) {
      return res.status(400).json({ success: false, message: 'Message is too short' });
    }
    if (message.length > 2000) {
      return res.status(400).json({ success: false, message: 'Message is too long' });
    }
    if (typeof topic !== 'string' || !CONTACT_REASONS.has(topic)) {
      return res.status(400).json({ success: false, message: 'Invalid contact topic' });
    }
    if (typeof game !== 'undefined' && game !== null && String(game).length > 200) {
      return res.status(400).json({ success: false, message: 'Game information is too long' });
    }

    if (!process.env.RESEND_API_KEY) {
      console.error('[contact] RESEND_API_KEY is not configured');
      return res.status(503).json({ success: false, message: 'Contact service is temporarily unavailable' });
    }

    const safeName = escapeHtml(name.trim());
    const safeEmail = escapeHtml(email.trim());
    const safeTopic = escapeHtml(topic);
    const safeGame = escapeHtml(String(game || '').trim());
    const safeMessage = escapeHtml(message.trim()).replace(/\n/g, '<br>');
    const inbox = process.env.CONTACT_INBOX_EMAIL || 'vishalxr92@gmail.com';
    const from = process.env.CONTACT_FROM_EMAIL || 'SHARX <onboarding@resend.dev>';

    const result = await resend.emails.send({
      from,
      to: inbox,
      replyTo: email.trim(),
      subject: `SHARX Contact — ${topic}`,
      text: [
        `Name: ${name.trim()}`,
        `Email: ${email.trim()}`,
        `Topic: ${topic}`,
        game ? `Game: ${String(game).trim()}` : '',
        '',
        message.trim(),
      ].filter(Boolean).join('\n'),
      html: `
        <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:680px;margin:0 auto;padding:24px;color:#1B2A41;background:#FFFDF7;">
          <div style="border:1px solid #1B2A41;border-radius:18px;padding:24px;background:#ffffff;">
            <h2 style="margin:0 0 20px;font-size:24px;">New SHARX Contact Message</h2>
            <p><strong>Name:</strong> ${safeName}</p>
            <p><strong>Email:</strong> ${safeEmail}</p>
            <p><strong>Topic:</strong> ${safeTopic}</p>
            ${safeGame ? `<p><strong>Game:</strong> ${safeGame}</p>` : ''}
            <div style="margin-top:20px;padding:16px;border-radius:12px;background:#FFF7E8;border:1px solid #1B2A41;">
              <strong>Message</strong>
              <div style="margin-top:10px;line-height:1.65;">${safeMessage}</div>
            </div>
            <p style="margin:20px 0 0;color:#6b7280;font-size:12px;">Reply to this email to respond directly to the sender.</p>
          </div>
        </div>
      `,
    });

    if (result?.error) {
      console.error('[contact] Resend error:', result.error);
      return res.status(502).json({ success: false, message: 'Failed to send message' });
    }

    return res.json({ success: true, message: 'Message sent successfully' });
  } catch (error) {
    console.error('[contact] Send error:', error?.message || error);
    return res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// ════════════════════════════════════════════════════════════════
//  🚫 AD BLOCKER PROXY
// ════════════════════════════════════════════════════════════════

adblock.mountAdBlockRuntime(app, PUBLIC_BASE_URL);

app.get('/proxy/game', async (req, res) => {
  const { url } = req.query;

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

app.get('/proxy/asset', async (req, res) => {
  let { url } = req.query;

  if (!url || url === 'undefined' || url === 'null') {
    return res.status(400).json({ error: 'URL required' });
  }

  const selfProxyPrefix = `${PUBLIC_BASE_URL}/proxy/asset?url=`;
  if (url.startsWith(selfProxyPrefix)) {
    try {
      url = decodeURIComponent(url.slice(selfProxyPrefix.length));
    } catch {}
  }

  try {
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

app.get(/^\/proxy\/(.+)/, async (req, res) => {
  try {
    let gameBaseUrl = lastProxiedGameUrl;

    const referer = req.headers.referer;
    if (referer) {
      try {
        const refUrl = new URL(referer);
        const refGameUrl = refUrl.searchParams.get('url');
        if (refGameUrl) gameBaseUrl = refGameUrl;
      } catch {}
    }

    if (!gameBaseUrl || gameBaseUrl === 'undefined' || gameBaseUrl === 'null') {
      return res.status(404).json({ error: 'No active game session to resolve this path against' });
    }

    const relativePath = req.params[0];
    const base = new URL(gameBaseUrl);
    const resolved = new URL(relativePath, base);

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
//  🎬 GAME PREVIEW VIDEO — Puppeteer-based (Render compatible)
//  Only generates for top ~100 games to save memory + storage.
//  Uses ffmpeg-static so no system ffmpeg install is needed.
// ════════════════════════════════════════════════════════════════

const puppeteer = require('puppeteer');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');
const fs = require('fs');
const path = require('path');
const os = require('os');

if (ffmpegPath) {
  ffmpeg.setFfmpegPath(ffmpegPath);
}

const PREVIEW_DIR = process.env.PREVIEW_DIR || path.join(__dirname, 'public', 'previews');
try {
  fs.mkdirSync(PREVIEW_DIR, { recursive: true });
} catch (err) {
  console.warn('[preview] could not create PREVIEW_DIR:', err.message);
}

// Prevent concurrent recordings of the same game
const previewJobsInFlight = new Map();

// Rate limit: max 5 preview generations per minute per IP
const previewLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many preview requests. Please try again later.' },
});

app.get('/preview/:gameId', previewLimiter, async (req, res) => {
  const { gameId } = req.params;

  // Sanitize gameId to prevent path traversal
  if (!/^[a-zA-Z0-9_-]+$/.test(gameId)) {
    return res.status(400).json({ error: 'Invalid game ID' });
  }

  const videoPath = path.join(PREVIEW_DIR, `${gameId}.mp4`);

  // Serve cached preview if exists
  if (fs.existsSync(videoPath)) {
    res.set('Cache-Control', 'public, max-age=86400');
    return res.sendFile(videoPath);
  }

  // If a recording is already in progress for this game, wait for it
  if (previewJobsInFlight.has(gameId)) {
    try {
      await previewJobsInFlight.get(gameId);
      if (fs.existsSync(videoPath)) {
        res.set('Cache-Control', 'public, max-age=86400');
        return res.sendFile(videoPath);
      }
    } catch {}
    return res.status(500).json({ error: 'Preview generation failed' });
  }

  // Only generate for top 100 games (saves memory + storage)
  const games = await getGames();
  const game = games.find((g) => g.id === gameId);
  if (!game || !game.url) {
    return res.status(404).json({ error: 'Game not found' });
  }
  if (typeof game.feedRank === 'number' && game.feedRank >= 100) {
    // Non-top games: 404 so frontend falls back to image hover
    return res.status(404).json({ error: 'Preview not available for this game' });
  }

  // Start new recording job
  const job = (async () => {
    const executablePath =
      process.env.PUPPETEER_EXECUTABLE_PATH ||
      (typeof puppeteer.executablePath === 'function' ? puppeteer.executablePath() : undefined);

    const browser = await puppeteer.launch({
      headless: 'new',
      executablePath,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--single-process',
        '--no-zygote',
      ],
    });

    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 640, height: 480, deviceScaleFactor: 1 });

      const client = await page.createCDPSession();
      const frames = [];

      await client.send('Page.startScreencast', {
        format: 'jpeg',
        quality: 55,
        maxWidth: 640,
        maxHeight: 480,
      });

      client.on('Page.screencastFrame', async (frame) => {
        frames.push(frame.data);
        try {
          await client.send('Page.screencastFrameAck', {
            sessionId: frame.sessionId,
          });
        } catch {}
      });

      // Load the game through our own proxy
      const proxyUrl = `${PUBLIC_BASE_URL}/proxy/game?url=${encodeURIComponent(game.url)}`;
      await page.goto(proxyUrl, {
        waitUntil: 'domcontentloaded',
        timeout: 20000,
      });

      // Record for ~4 seconds
      await new Promise((r) => setTimeout(r, 4000));

      await client.send('Page.stopScreencast');
      await browser.close();

      if (frames.length < 10) {
        throw new Error('Not enough frames recorded');
      }

      // Write frames to temp dir
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `sharx-preview-${gameId}-`));

      frames.forEach((data, i) => {
        fs.writeFileSync(
          path.join(tempDir, `frame-${String(i).padStart(5, '0')}.jpg`),
          Buffer.from(data, 'base64')
        );
      });

      // Convert frames to MP4 (10 fps)
      await new Promise((resolve, reject) => {
        ffmpeg()
          .input(path.join(tempDir, 'frame-%05d.jpg'))
          .inputFPS(10)
          .outputOptions([
            '-c:v libx264',
            '-pix_fmt yuv420p',
            '-movflags +faststart',
            '-preset veryfast',
            '-crf 30',
          ])
          .size('640x480')
          .output(videoPath)
          .on('end', resolve)
          .on('error', reject)
          .run();
      });

      // Cleanup temp frames
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {}

      return true;
    } catch (err) {
      try {
        await browser.close();
      } catch {}
      throw err;
    }
  })();

  previewJobsInFlight.set(gameId, job);

  try {
    await job;
    previewJobsInFlight.delete(gameId);
    res.set('Cache-Control', 'public, max-age=86400');
    return res.sendFile(videoPath);
  } catch (err) {
    previewJobsInFlight.delete(gameId);
    console.error('[preview] failed for', gameId, '-', err.message);
    return res.status(500).json({ error: 'Preview generation failed' });
  }
});

// ════════════════════════════════════════════════════════════════
//  404 + FINAL ERROR HANDLER — MUST BE LAST
// ════════════════════════════════════════════════════════════════

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

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
  console.log(`🌐 Public base URL (used for ad-block runtime): ${PUBLIC_BASE_URL}`);
  if (PUBLIC_BASE_URL.includes('localhost')) {
    console.log(`⚠️  PUBLIC_BASE_URL is not set — ad-block runtime script will 404 for real visitors.`);
  }
  console.log('');
  console.log(`✅ Games routes ready:`);
  console.log(`   - /games?page=&category=      (paginated, multi-page GameMonetize fetch)`);
  console.log(`   - /games/trending              (top games by feedRank)`);
  console.log(`   - /categories                  (list of available categories)`);
  console.log(`   - /stats                       (games cache + adblock status)`);
  console.log('');
  console.log(`✅ Proxy routes ready:`);
  console.log(`   - /proxy/game?url=<gameUrl>   (HTML games with ad-blocking)`);
  console.log(`   - /proxy/asset?url=<assetUrl> (All assets)`);
  console.log(`   - /proxy/<relative-path>      (fallback for runtime paths)`);
  console.log('');
  console.log(`✅ Preview routes ready:`);
  console.log(`   - /preview/:gameId            (Puppeteer screen recording → MP4)`);
  console.log(`     Only top 100 games are supported (feedRank < 100).`);
  console.log('');
  adblock.startBlocklistAutoRefresh();

  getGames()
    .then(games => console.log(`🎮 Preloaded ${games.length} games successfully!`))
    .catch(err => console.error('❌ Failed to preload games:', err.message));
});

module.exports = app;