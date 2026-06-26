/**
 * routes/gameProxy.js
 * ────────────────────────────────────────────────────────────
 * Bhai yahi hai REAL ad-blocker. Cross-origin iframe ke andar
 * JS inject nahi ho sakta (browser security rule, koi bhi
 * website yeh allow nahi karti) — isliye game ko apne server
 * se fetch karke, ad <script>/<iframe> tags nikaal ke, apne
 * domain se serve karo. Phir frontend ka iframe "same-origin"
 * ban jaata hai aur AD_BLOCK_SCRIPT andar chal jaati hai.
 *
 * Setup:
 *   npm install express cheerio
 *   app.use("/api", require("./routes/gameProxy"));
 *   (Node 18+ already has global fetch — node-fetch nahi chahiye)
 * ────────────────────────────────────────────────────────────
 */

const express = require("express");
const cheerio = require("cheerio");
const router = express.Router();

// Known ad / tracker domains — yahi list frontend wali AD_BLOCK_SCRIPT
// me bhi hai, dono jagah sync rakhna (ek shared file me daal sakte ho).
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

// SSRF guard — kabhi bhi apne internal network ko proxy mat hone do
function isSafeTarget(rawUrl) {
  try {
    const { protocol, hostname } = new URL(rawUrl);
    if (!["http:", "https:"].includes(protocol)) return false;
    if (["localhost", "127.0.0.1", "0.0.0.0", "::1"].includes(hostname)) return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

// Same runtime that frontend injects — yahan bhi rakha hai taaki proxy ke
// through aane wale HTML ke <head> me sabse pehle hi block ho jaaye.
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

  if (!targetUrl || !isSafeTarget(targetUrl)) {
    return res.status(400).send("Invalid or unsafe URL");
  }

  try {
    const upstream = await fetch(targetUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SharxProxy/1.0)" },
    });
    const contentType = upstream.headers.get("content-type") || "";

    // Non-HTML assets (js, css, images served relative to the game) ko
    // seedha pass-through karo, ad-stripping sirf HTML pe lagti hai.
    if (!contentType.includes("text/html")) {
      res.set("Content-Type", contentType);
      const buf = await upstream.arrayBuffer();
      return res.send(Buffer.from(buf));
    }

    const html = await upstream.text();
    const $ = cheerio.load(html);
    const base = new URL(targetUrl);

    // 1) Ad/tracker <script> aur <iframe> tags hata do
    $("script[src], iframe[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (!src) return;
      try {
        if (isAdUrl(new URL(src, base).href)) $(el).remove();
      } catch {}
    });

    // 2) Popup-triggering inline onclick="window.open(...)" hata do
    $("[onclick]").each((_, el) => {
      const onclick = $(el).attr("onclick") || "";
      if (/window\.open/i.test(onclick)) $(el).removeAttr("onclick");
    });

    // 3) Meta-refresh redirect ads (malvertising ka purana trick) hata do
    $('meta[http-equiv="refresh"]').remove();

    // 4) Relative src/href ko absolute karo taaki game ke assets load ho
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

    // 5) Apna ad-block runtime sabse pehle <head> me daal do (DOMContentLoaded se pehle chale)
    $("head").prepend(`<script>${AD_BLOCK_RUNTIME}</script>`);

    res.set("Content-Type", "text/html; charset=utf-8");
    res.send($.html());
  } catch (err) {
    console.error("[Sharx Proxy] failed:", err.message);
    res.status(502).send("Could not load game");
  }
});

module.exports = router;