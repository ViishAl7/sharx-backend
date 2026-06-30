/**
 * routes/gameProxy.js
 * ----------------------------------------------------------------
 * This is the real ad-blocker. A cross-origin iframe cannot have JS
 * injected into it (browser security — no real website allows that).
 * So instead: fetch the game's HTML on OUR server, strip out the ad
 * <script>/<iframe> tags, and serve it back from our own domain.
 * That makes the frontend's iframe "same-origin", so the
 * AD_BLOCK_SCRIPT can actually run inside it.
 *
 * IMPORTANT — how to mount this (this is what was causing your 404):
 * Your frontend calls:
 *     `${API_BASE}/proxy/game?url=...`
 * So in your main server file (server.js / app.js / index.js), mount
 * this router with NO prefix:
 *     app.use(require("./routes/gameProxy"));
 *
 * Do NOT write app.use("/api", require("./routes/gameProxy")) unless
 * you also change the frontend to call `${API_BASE}/api/proxy/game`.
 * Whichever side you pick, both sides must match exactly, or you get
 * the same 404 you just had.
 * ----------------------------------------------------------------
 */

const express = require("express");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const router = express.Router();

// NOTE: I removed these lines that were in your original file:
//   const passkeyRoutes = require('./routes/passkey');
//   const userRoutes = require('./routes/userRoutes');
//   const authRoutes = require('./routes/auth');
// They were never used anywhere in this file. Worse — if any one of
// those paths is wrong, `require()` throws at server startup and your
// ENTIRE server crashes, not just this one route. Those belong in your
// main server file where they're actually mounted, not here.

// Known ad / tracker domains.
// Keep this list identical to the AD_DOMAINS array in the frontend's
// AD_BLOCK_SCRIPT. Better long-term fix: move this list into one shared
// JSON file both sides import, so they can never drift apart.
const AD_DOMAINS = [
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "adnxs.com", "rubiconproject.com", "openx.net", "pubmatic.com",
  "criteo.com", "taboola.com", "outbrain.com", "revcontent.com",
  "advertising.com", "yieldmo.com", "smartadserver.com", "appnexus.com",
  "adsafeprotected.com", "moatads.com", "scorecardresearch.com",
  "chartbeat.com", "quantserve.com", "amazon-adsystem.com",
  "media.net", "sharethrough.com", "teads.tv", "33across.com",
  "indexexchange.com", "sovrn.com", "lijit.com", "undertone.com",
  "conversantmedia.com", "flashtalking.com", "mopub.com",
  "adsymptotic.com", "adtech.de", "adform.net", "adzerk.net",
  "exoclick.com", "trafficjunky.com", "traffichaus.com",
  "popads.net", "popcash.net", "propellerads.com", "hilltopads.net",
  "adcash.com", "clickadu.com", "zeropark.com", "plugrush.com",
  "adsterra.com", "admaven.com",
];

function isAdUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return AD_DOMAINS.some((d) => hostname === d || hostname.endsWith("." + d));
  } catch {
    return false;
  }
}

/* ──────────────────────────────────────────────────────────────
   SSRF protection (SSRF = a user tricks your server into fetching
   an internal/private address instead of a real game URL)
   ────────────────────────────────────────────────────────────── */

// Checks if an IP address belongs to your own machine, your private
// network, or a cloud "metadata" service (these endpoints can leak
// cloud account credentials if reached — this is a real, common attack).
function isPrivateOrReservedIp(ip) {
  // IPv4
  if (/^127\./.test(ip)) return true;                        // loopback (the machine itself)
  if (/^10\./.test(ip)) return true;                         // private network
  if (/^192\.168\./.test(ip)) return true;                   // private network
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;     // private network
  if (/^169\.254\./.test(ip)) return true;                   // covers 169.254.169.254, the cloud metadata address on AWS/GCP/Azure
  if (ip === "0.0.0.0") return true;

  // IPv6
  if (ip === "::1") return true;                              // loopback
  if (/^fe80:/i.test(ip)) return true;                        // link-local
  if (/^fc00:/i.test(ip) || /^fd00:/i.test(ip)) return true;  // unique-local (covers AWS's IPv6 metadata address)

  return false;
}

// Your original isSafeTarget() only checked the hostname text itself.
// Problem: an attacker can register a normal-looking public domain
// name that simply resolves (via DNS) to an internal IP like
// 169.254.169.254. The hostname looks fine; the real destination isn't.
// This is called "DNS rebinding." Fix: actually resolve the hostname
// and check the real IP too, not just the text.
async function isSafeTarget(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (!["http:", "https:"].includes(parsed.protocol)) return false;

  const hostname = parsed.hostname.toLowerCase();
  if (["localhost", "127.0.0.1", "0.0.0.0", "::1"].includes(hostname)) return false;
  if (isPrivateOrReservedIp(hostname)) return false; // covers the case where someone passes a raw IP

  try {
    const records = await dns.lookup(hostname, { all: true });
    if (records.some((r) => isPrivateOrReservedIp(r.address))) return false;
  } catch {
    // Couldn't resolve it at all — treat as unsafe rather than guessing
    return false;
  }

  return true;
}

// Same ad-blocking runtime the frontend injects — duplicated here so it
// lands inside the proxied page's <head> before anything else on that
// page gets a chance to run.
const AD_BLOCK_RUNTIME = `
(function(){
  var AD_DOMAINS=${JSON.stringify(AD_DOMAINS)};
  function hostOf(u){try{return new URL(u,window.location.href).hostname;}catch(e){return '';}}
  function isAd(h){return AD_DOMAINS.some(function(d){return h===d||h.endsWith('.'+d);});}
  var oOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){if(isAd(hostOf(u))){this._b=true;return;}return oOpen.apply(this,arguments);};
  var oSend=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send=function(){if(this._b)return;return oSend.apply(this,arguments);};
  var oFetch=window.fetch;
  if(oFetch){window.fetch=function(i){var u=typeof i==='string'?i:(i&&i.url)||'';if(isAd(hostOf(u)))return Promise.reject(new Error('blocked'));return oFetch.apply(this,arguments);};}
  var oWinOpen=window.open;
  window.open=function(u){if(!u||isAd(hostOf(u)))return null;return oWinOpen.apply(this,arguments);};
  console.log('[Sharx Proxy] Ad blocker active');
})();
`;

router.get("/proxy/game", async (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).send("Missing url parameter");
  }

  const safe = await isSafeTarget(targetUrl);
  if (!safe) {
    return res.status(400).send("Invalid or unsafe URL");
  }

  // Hard timeout on the upstream fetch. Without this, one slow or dead
  // game host can hang this request indefinitely, tying up a server
  // worker the whole time.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const upstream = await fetch(targetUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SharxProxy/1.0)" },
      signal: controller.signal,
      redirect: "follow",
    });

    if (!upstream.ok) {
      return res.status(502).send(`Upstream returned ${upstream.status}`);
    }

    const contentType = upstream.headers.get("content-type") || "";

    // Non-HTML assets (the game's own JS, CSS, images) get passed
    // straight through — ad-stripping only applies to HTML pages.
    if (!contentType.includes("text/html")) {
      res.set("Content-Type", contentType);
      const buf = await upstream.arrayBuffer();
      return res.send(Buffer.from(buf));
    }

    const html = await upstream.text();
    const $ = cheerio.load(html);
    const base = new URL(targetUrl);

    // 1) Remove ad/tracker <script> and <iframe> tags
    $("script[src], iframe[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (!src) return;
      try {
        if (isAdUrl(new URL(src, base).href)) $(el).remove();
      } catch {}
    });

    // 2) Remove popup-triggering inline onclick="window.open(...)" handlers
    $("[onclick]").each((_, el) => {
      const onclick = $(el).attr("onclick") || "";
      if (/window\.open/i.test(onclick)) $(el).removeAttr("onclick");
    });

    // 3) Remove meta-refresh redirect ads (an old malvertising trick)
    $('meta[http-equiv="refresh"]').remove();

    // 4) Rewrite relative src/href to absolute, so the game's own assets still load
    $("[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src && !/^([a-z]+:)?\/\//i.test(src) && !src.startsWith("data:")) {
        try { $(el).attr("src", new URL(src, base).href); } catch {}
      }
    });
    $("[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href && !/^([a-z]+:)?\/\//i.test(href) && !href.startsWith("#")) {
        try { $(el).attr("href", new URL(href, base).href); } catch {}
      }
    });

    // 5) Inject our ad-block runtime first in <head>, before anything else runs
    $("head").prepend(`<script>${AD_BLOCK_RUNTIME}</script>`);

    res.set("Content-Type", "text/html; charset=utf-8");
    res.send($.html());
  } catch (err) {
    console.error("[Sharx Proxy] failed:", err.message);
    if (err.name === "AbortError") {
      return res.status(504).send("Game host took too long to respond");
    }
    res.status(502).send("Could not load game");
  } finally {
    clearTimeout(timeoutId);
  }
});

module.exports = router;