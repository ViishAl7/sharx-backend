/**
 * src/lib/adblock.js — Sharx Ad-Block library (SERVER SIDE)
 * ----------------------------------------------------------------
 * This is the module server.js requires as `./src/lib/adblock`. It is
 * the counterpart to the CLIENT-side runtime (src/lib/adblock.js in the
 * React app) that gets injected into every proxied game's iframe — the
 * two live in different projects and do different jobs:
 *
 *   CLIENT runtime (React app): patches XHR/fetch/window.open *inside*
 *   the game's own iframe once it's already loaded in the browser.
 *
 *   THIS server module: runs *before* the game HTML ever reaches the
 *   browser — it strips known ad tags out of the proxied HTML, blocks
 *   known ad-domain requests at the proxy layer, guards the proxy
 *   against being used as an open SSRF relay, and caches proxied
 *   assets so repeat game loads are fast.
 *
 * Exports used by server.js:
 *   - isBlockedUrl(url)                 → boolean
 *   - isSafeTarget(url)                 → Promise<boolean>
 *   - stripAds($, baseUrl, publicBase)  → mutates + returns cheerio $
 *   - createAssetCache(opts)            → { get(key), set(key, val) }
 *   - mountAdBlockRuntime(app, base)    → registers /adblock-runtime.js
 *   - getBlocklistStatus()             → object for /stats
 *   - startBlocklistAutoRefresh()       → begins periodic refresh
 */

const dns = require('dns').promises;
const net = require('net');

/* ─────────────────────────────────────────────────────────────
   AD DOMAIN BLOCKLIST
   Mirrors the client runtime's list, plus a few extra networks
   commonly seen wrapping free HTML5 game embeds.
───────────────────────────────────────────────────────────── */
const STATIC_AD_DOMAINS = [
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'adnxs.com', 'rubiconproject.com', 'openx.net', 'pubmatic.com',
  'criteo.com', 'taboola.com', 'outbrain.com', 'revcontent.com',
  'advertising.com', 'yieldmo.com', 'smartadserver.com', 'appnexus.com',
  'adsafeprotected.com', 'moatads.com', 'scorecardresearch.com',
  'chartbeat.com', 'quantserve.com', 'amazon-adsystem.com',
  'media.net', 'sharethrough.com', 'teads.tv', '33across.com',
  'indexexchange.com', 'sovrn.com', 'lijit.com', 'undertone.com',
  'conversantmedia.com', 'flashtalking.com', 'mopub.com',
  'adsymptotic.com', 'adtech.de', 'adverticum.net', 'adform.net',
  'adhigh.net', 'adpilot.de', 'adroll.com', 'adzerk.net',
  'exoclick.com', 'trafficjunky.com', 'traffichaus.com',
  'cpmstar.com', 'kontera.com', 'viglink.com', 'skimlinks.com',
  'popads.net', 'popcash.net', 'propellerads.com',
  'hilltopads.net', 'adcash.com', 'clickadu.com', 'zeropark.com',
  'plugrush.com', 'adsterra.com', 'admaven.com',
  // extra networks frequently seen wrapping free game embeds
  'juicyads.com', 'adskeeper.co.uk', 'mgid.com', 'bidvertiser.com',
  'contentad.net', 'adsco.re', 'monetizemore.com', 'ezoic.net',
  'yllix.com', 'a-ads.com', 'coinzilla.com', 'exdynsrv.com',
  'gnezz.com', 'trafficfactory.biz',
];

let adDomains = new Set(STATIC_AD_DOMAINS);
let blocklistUpdatedAt = Date.now();
let blocklistSource = 'static';
let refreshTimer = null;

function hostnameOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

function isBlockedUrl(url) {
  const hostname = hostnameOf(url);
  if (!hostname) return false;
  for (const domain of adDomains) {
    if (hostname === domain || hostname.endsWith(`.${domain}`)) return true;
  }
  return false;
}

/* ─────────────────────────────────────────────────────────────
   SSRF GUARD
   /proxy/game and /proxy/asset fetch whatever URL a client sends.
   Without this, the proxy could be pointed at localhost, internal
   metadata endpoints (169.254.169.254), or private-network IPs.
   isSafeTarget rejects non-http(s) protocols, obviously-private
   hostnames, and — since a hostname can resolve to a private IP even
   when it looks public (DNS rebinding) — resolves the hostname and
   checks the actual IPs too.
───────────────────────────────────────────────────────────── */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:')) return true; // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
  if (lower.startsWith('::ffff:')) return isPrivateIPv4(lower.split(':').pop());
  return false;
}

function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true; // not a recognizable IP → treat as unsafe
}

function isPrivateHostname(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '0.0.0.0' || h.endsWith('.local') || h.endsWith('.internal')) {
    return true;
  }
  if (net.isIP(h)) return isPrivateIp(h);
  return false;
}

async function isSafeTarget(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  if (isPrivateHostname(parsed.hostname)) return false;

  // Resolve DNS and re-check the actual IP(s) so a public-looking
  // hostname can't rebind to an internal address after the fact.
  try {
    const addresses = await dns.lookup(parsed.hostname, { all: true });
    if (addresses.length === 0) return false;
    if (addresses.some((a) => isPrivateIp(a.address))) return false;
  } catch {
    // Can't resolve it — treat as unsafe rather than letting it through.
    return false;
  }

  return true;
}

/* ─────────────────────────────────────────────────────────────
   stripAds
   Runs against a cheerio-loaded copy of the proxied game HTML.
   1. Removes tags that point at known ad domains, or that carry
      common ad-container markers.
   2. Rewrites every remaining asset-bearing URL (script/img/link/
      audio/video/source) to route through our own /proxy/asset,
      so the browser never talks to the game's origin directly —
      this both keeps ad-blocking enforced server-side for every
      asset (not just the ones present in the initial HTML) and
      avoids cross-origin/CORS failures for fonts and XHR-loaded
      assets the game's bundle requests later.
   3. Strips inline popup triggers and meta-refresh redirects,
      the two most common non-network ad vectors.
───────────────────────────────────────────────────────────── */
function resolveAgainst(maybeRelative, baseUrl) {
  if (!maybeRelative || maybeRelative.startsWith('data:') || maybeRelative.startsWith('blob:')) {
    return null;
  }
  try {
    return new URL(maybeRelative, baseUrl).href;
  } catch {
    return null;
  }
}

const AD_CONTAINER_SELECTOR = [
  '[id*="google_ads" i]', '[class*="google-ad" i]', '[id*="banner_ad" i]',
  '[class*="ad-container" i]', '[class*="ad-banner" i]', '[id*="ad-slot" i]',
  'ins.adsbygoogle', '[class*="advertisement" i]',
].join(', ');

function stripAds($, baseUrl, publicBaseUrl) {
  // 1. Drop elements whose src/href points straight at a known ad host.
  $('script[src], iframe[src], img[src], link[href]').each((_, el) => {
    const node = $(el);
    const raw = node.attr('src') || node.attr('href');
    const abs = resolveAgainst(raw, baseUrl);
    if (abs && isBlockedUrl(abs)) node.remove();
  });

  // 2. Drop generic ad-container markup even when it has no src yet
  //    (e.g. a div a third-party ad script would later inject into).
  $(AD_CONTAINER_SELECTOR).remove();

  // 3. Rewrite everything else so it's served through our own proxy.
  const REWRITE_TARGETS = [
    ['script', 'src'],
    ['img', 'src'],
    ['source', 'src'],
    ['audio', 'src'],
    ['video', 'src'],
    ['link', 'href'],
  ];

  REWRITE_TARGETS.forEach(([tag, attr]) => {
    $(`${tag}[${attr}]`).each((_, el) => {
      const node = $(el);
      const raw = node.attr(attr);
      const abs = resolveAgainst(raw, baseUrl);
      if (!abs) return;
      if (isBlockedUrl(abs)) {
        node.remove();
        return;
      }
      node.attr(attr, `${publicBaseUrl}/proxy/asset?url=${encodeURIComponent(abs)}`);
    });
  });

  // 4. Neutralize inline popup triggers and forced redirects.
  $('[onclick*="window.open" i]').removeAttr('onclick');
  $('meta[http-equiv="refresh" i]').remove();

  return $;
}

/* ─────────────────────────────────────────────────────────────
   Asset cache
   Small in-memory TTL + LRU cache so repeat loads of the same
   game (by the same or different players) skip re-fetching
   already-seen assets from the origin.
───────────────────────────────────────────────────────────── */
function createAssetCache({ maxEntries = 1000, ttlMs = 60 * 60 * 1000 } = {}) {
  const store = new Map(); // key -> { value, expiresAt }

  function get(key) {
    const entry = store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      store.delete(key);
      return null;
    }
    // Bump recency for LRU: delete + re-set moves it to the end.
    store.delete(key);
    store.set(key, entry);
    return entry.value;
  }

  function set(key, value) {
    if (store.size >= maxEntries) {
      const oldestKey = store.keys().next().value;
      if (oldestKey !== undefined) store.delete(oldestKey);
    }
    store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  return { get, set };
}

/* ─────────────────────────────────────────────────────────────
   Client-side ad-block runtime
   This is the script injected into every proxied game page via
   <script src="{PUBLIC_BASE_URL}/adblock-runtime.js">. It runs
   inside the game's iframe itself (once the browser has already
   loaded it) and blocks ad requests / popups the game's own JS
   tries to make directly, as a second layer behind stripAds().
───────────────────────────────────────────────────────────── */
function buildRuntimeScript() {
  const domainList = JSON.stringify(Array.from(adDomains));
  return `
(function() {
  'use strict';
  var AD_DOMAINS = ${domainList};

  function hostnameOf(url) {
    try { return new URL(url, window.location.href).hostname; } catch (e) { return ''; }
  }
  function isAdHost(hostname) {
    return AD_DOMAINS.some(function (d) { return hostname === d || hostname.endsWith('.' + d); });
  }

  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (isAdHost(hostnameOf(url))) { this._blocked = true; return; }
    return origOpen.apply(this, arguments);
  };
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    if (this._blocked) return;
    return origSend.apply(this, arguments);
  };

  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      if (isAdHost(hostnameOf(url))) return Promise.reject(new Error('Blocked by Sharx'));
      return origFetch.apply(this, arguments);
    };
  }

  var origWinOpen = window.open;
  window.open = function (url) {
    if (!url || isAdHost(hostnameOf(url))) return null;
    return origWinOpen.apply(this, arguments);
  };

  var origWrite = document.write;
  document.write = function (str) {
    if (typeof str === 'string' && AD_DOMAINS.some(function (d) { return str.indexOf(d) !== -1; })) return;
    return origWrite.apply(document, arguments);
  };

  function sweep(root) {
    root.querySelectorAll('script[src], iframe[src]').forEach(function (node) {
      if (isAdHost(hostnameOf(node.src))) node.remove();
    });
    root.querySelectorAll('[onclick]').forEach(function (node) {
      if (/window\\.open/i.test(node.getAttribute('onclick') || '')) node.removeAttribute('onclick');
    });
    root.querySelectorAll('meta[http-equiv="refresh"]').forEach(function (node) { node.remove(); });
  }
  sweep(document);

  var observer = new MutationObserver(function (mutations) {
    mutations.forEach(function (m) {
      m.addedNodes.forEach(function (node) {
        if (node.nodeType !== 1) return;
        if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
          if (isAdHost(hostnameOf(node.src))) { node.remove(); return; }
        }
        if (node.hasAttribute && node.hasAttribute('onclick') && /window\\.open/i.test(node.getAttribute('onclick'))) {
          node.removeAttribute('onclick');
        }
        try {
          var style = window.getComputedStyle(node);
          if ((style.position === 'fixed' || style.position === 'absolute') && parseInt(style.zIndex || 0, 10) > 9000) {
            var rect = node.getBoundingClientRect();
            var src = node.src || '';
            if (rect.width > 200 && rect.height > 200 && AD_DOMAINS.some(function (d) { return src.indexOf(d) !== -1; })) {
              node.remove();
            }
          }
        } catch (e) {}
        if (node.querySelectorAll) sweep(node);
      });
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  console.log('[Sharx] Ad blocker active');
})();
`;
}

function mountAdBlockRuntime(app, publicBaseUrl) {
  app.get('/adblock-runtime.js', (req, res) => {
    res.set('Content-Type', 'application/javascript; charset=utf-8');
    // Safe to cache a while — the runtime only changes on deploy, and
    // getBlocklistStatus()/startBlocklistAutoRefresh() below don't
    // mutate the domain list at request time.
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(buildRuntimeScript());
  });
}

/* ─────────────────────────────────────────────────────────────
   Blocklist status / refresh
   The list is static for now (no external feed configured), but
   these are wired up so /stats has something real to report and
   so a future remote blocklist source is a one-line change away.
───────────────────────────────────────────────────────────── */
function getBlocklistStatus() {
  return {
    domainCount: adDomains.size,
    source: blocklistSource,
    updatedAt: new Date(blocklistUpdatedAt).toISOString(),
    autoRefresh: !!refreshTimer,
  };
}

function startBlocklistAutoRefresh(intervalMs = 6 * 60 * 60 * 1000) {
  if (refreshTimer) return; // idempotent — don't stack intervals on hot-reload

  refreshTimer = setInterval(() => {
    // No external feed wired up yet, so this just re-stamps the static
    // list as "checked" rather than actually fetching anything. Swap
    // the body of this callback for a real fetch + merge when/if an
    // external blocklist source is added.
    blocklistUpdatedAt = Date.now();
    blocklistSource = 'static';
  }, intervalMs);

  refreshTimer.unref?.(); // don't keep the process alive just for this
}

module.exports = {
  isBlockedUrl,
  isSafeTarget,
  stripAds,
  createAssetCache,
  mountAdBlockRuntime,
  getBlocklistStatus,
  startBlocklistAutoRefresh,
};