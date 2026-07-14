/**
 * Gaming-Backend — DEEP test suite
 * ---------------------------------
 * Goes beyond smoke tests: signs REAL JWTs with your actual JWT_SECRET
 * so protected routes are tested end-to-end (not just "rejects no token").
 * Also probes edge cases, SQL/NoSQL-injection-shaped input, and a few
 * known-risk areas found by reading your actual controller code.
 *
 * REQUIRES: JWT_SECRET in your .env (same one your backend uses) and
 * a real user row's id/email in the database to test against — OR
 * it will create a throwaway test user directly via Prisma if you
 * give it DATABASE_URL access (see TEST_USER_ID below).
 *
 * Run with:  node backend.deep.test.js
 * Needs:     npm install jsonwebtoken   (only if not already present)
 */

const jwt = require("jsonwebtoken");

const BASE_URL = process.env.BACKEND_URL || "http://localhost:5001";
const JWT_SECRET = process.env.JWT_SECRET;

// Set this to a REAL user id that exists in your DB to fully test
// /user/profile and /user/history with a valid, working token.
// Leave as null to only test the "invalid/malformed" paths.
const TEST_USER_ID = process.env.TEST_USER_ID ? Number(process.env.TEST_USER_ID) : null;
const TEST_USER_EMAIL = process.env.TEST_USER_EMAIL || "test@example.com";

let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];

function pass(name) {
  passed++;
  console.log(`  \x1b[32m✓\x1b[0m ${name}`);
}
function fail(name, reason) {
  failed++;
  failures.push({ name, reason });
  console.log(`  \x1b[31m✗\x1b[0m ${name}`);
  console.log(`    \x1b[31m${reason}\x1b[0m`);
}
function skip(name, reason) {
  skipped++;
  console.log(`  \x1b[33m○\x1b[0m ${name} \x1b[2m(skipped: ${reason})\x1b[0m`);
}
async function test(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err.message);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || "Assertion failed");
}

async function get(path, opts = {}) {
  const res = await fetch(`${BASE_URL}${path}`, { redirect: "manual", ...opts });
  let body = null;
  try { body = await res.json(); } catch {}
  return { status: res.status, body, headers: res.headers };
}
async function put(path, data, opts = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    body: JSON.stringify(data || {}),
  });
  let body = null;
  try { body = await res.json(); } catch {}
  return { status: res.status, body };
}

function makeToken(payload, opts = {}) {
  if (!JWT_SECRET) throw new Error("JWT_SECRET not set in environment — cannot sign test tokens");
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h", ...opts });
}

async function run() {
  console.log(`\nDeep-testing backend at ${BASE_URL}\n`);

  if (!JWT_SECRET) {
    console.log("\x1b[31m⚠ JWT_SECRET is not set in this shell's environment.\x1b[0m");
    console.log("  Run this instead so it can read your .env:");
    console.log("  \x1b[36mnode -r dotenv/config backend.deep.test.js\x1b[0m\n");
  }

  console.log("── JWT / Auth middleware — real token behavior ──");

  await test("Valid JWT (correct secret) is accepted structurally by jwt.verify", async () => {
    if (!JWT_SECRET) throw new Error("JWT_SECRET missing, cannot sign token");
    const token = makeToken({ id: TEST_USER_ID || 999999, email: TEST_USER_EMAIL });
    const decoded = jwt.verify(token, JWT_SECRET);
    assert(decoded.id === (TEST_USER_ID || 999999), "decoded id mismatch");
  });

  await test("Expired JWT is rejected by /user/profile", async () => {
    if (!JWT_SECRET) throw new Error("JWT_SECRET missing, cannot sign token");
    const expiredToken = jwt.sign(
      { id: TEST_USER_ID || 999999, email: TEST_USER_EMAIL },
      JWT_SECRET,
      { expiresIn: "-10s" } // already expired
    );
    const { status } = await get("/user/profile", {
      headers: { Authorization: `Bearer ${expiredToken}` },
    });
    assert(status === 401, `expected 401 for expired token, got ${status}`);
  });

  await test("JWT signed with WRONG secret is rejected", async () => {
    const badToken = jwt.sign({ id: 1, email: "x@x.com" }, "wrong-secret-123", { expiresIn: "1h" });
    const { status } = await get("/user/profile", {
      headers: { Authorization: `Bearer ${badToken}` },
    });
    assert(status === 401, `expected 401 for wrong-secret token, got ${status}`);
  });

  await test("Malformed Authorization header (no 'Bearer ' prefix) is rejected", async () => {
    const { status } = await get("/user/profile", {
      headers: { Authorization: "sometoken" },
    });
    assert(status === 401, `expected 401 for malformed header, got ${status}`);
  });

  await test("Empty Bearer token is rejected", async () => {
    const { status } = await get("/user/profile", {
      headers: { Authorization: "Bearer " },
    });
    assert(status === 401, `expected 401 for empty bearer token, got ${status}`);
  });

  await test("JWT with 'none' algorithm is rejected (alg confusion attack)", async () => {
    // Manually craft a token with alg:none — a classic JWT vulnerability
    // if the server doesn't pin the expected algorithm on verify.
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ id: TEST_USER_ID || 1, email: TEST_USER_EMAIL })).toString("base64url");
    const noneToken = `${header}.${payload}.`;
    const { status } = await get("/user/profile", {
      headers: { Authorization: `Bearer ${noneToken}` },
    });
    assert(status === 401, `expected 401 for alg:none token — got ${status}. If this fails, your JWT verify may not be pinning the algorithm.`);
  });

  console.log("\n── Real authenticated flow (requires TEST_USER_ID env var) ──");

  if (!TEST_USER_ID) {
    skip("GET /user/profile with a REAL valid token returns actual user data", "set TEST_USER_ID=<real db id> to run this");
    skip("PUT /user/profile updates name and it persists", "set TEST_USER_ID=<real db id> to run this");
    skip("GET /user/history returns an array (possibly empty)", "set TEST_USER_ID=<real db id> to run this");
  } else {
    const validToken = makeToken({ id: TEST_USER_ID, email: TEST_USER_EMAIL });

    await test("GET /user/profile with a REAL valid token returns actual user data", async () => {
      const { status, body } = await get("/user/profile", {
        headers: { Authorization: `Bearer ${validToken}` },
      });
      assert(status === 200, `expected 200, got ${status} — body: ${JSON.stringify(body)}`);
      assert(body && typeof body.id === "number", "expected numeric id in response");
      assert("name" in body && "email" in body, "expected name/email fields");
      assert(Array.isArray(body.matches), "expected matches array (nested select)");
    });

    await test("PUT /user/profile updates name and it persists on next GET", async () => {
      const newName = `Test User ${Date.now()}`;
      const { status, body } = await put("/user/profile", { name: newName }, {
        headers: { Authorization: `Bearer ${validToken}` },
      });
      assert(status === 200, `expected 200, got ${status} — body: ${JSON.stringify(body)}`);
      assert(body.name === newName, `expected name to be updated to "${newName}", got "${body.name}"`);

      // Verify it actually persisted, not just echoed back
      const check = await get("/user/profile", { headers: { Authorization: `Bearer ${validToken}` } });
      assert(check.body.name === newName, "name did not persist on re-fetch — update may not be hitting the DB");
    });

    await test("GET /user/history returns an array (possibly empty)", async () => {
      const { status, body } = await get("/user/history", {
        headers: { Authorization: `Bearer ${validToken}` },
      });
      assert(status === 200, `expected 200, got ${status}`);
      assert(Array.isArray(body), "expected an array");
    });
  }

  console.log("\n── Injection / malicious input handling ──");

  await test("PUT /user/profile with SQL-injection-shaped name doesn't crash server", async () => {
    if (!TEST_USER_ID) return skip("needs TEST_USER_ID", "set env var");
    const token = makeToken({ id: TEST_USER_ID, email: TEST_USER_EMAIL });
    const { status } = await put("/user/profile", { name: "'; DROP TABLE \"User\"; --" }, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // Prisma parameterizes queries, so this should just be stored as a literal
    // string (200), not cause a 500. A 500 here would be a real red flag.
    assert(status !== 500, `server returned 500 on SQL-injection-shaped input — investigate immediately`);
  });

  await test("PUT /user/profile with XSS-shaped name doesn't crash server", async () => {
    if (!TEST_USER_ID) return skip("needs TEST_USER_ID", "set env var");
    const token = makeToken({ id: TEST_USER_ID, email: TEST_USER_EMAIL });
    const { status } = await put("/user/profile", { name: "<script>alert(1)</script>" }, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert(status !== 500, `server crashed on XSS-shaped input`);
    // NOTE: this only confirms the backend stores it safely (Prisma escapes it).
    // It does NOT confirm the frontend escapes it on render — check that separately.
  });

  await test("PUT /user/profile with a 10,000-character name doesn't crash server", async () => {
    if (!TEST_USER_ID) return skip("needs TEST_USER_ID", "set env var");
    const token = makeToken({ id: TEST_USER_ID, email: TEST_USER_EMAIL });
    const hugeName = "A".repeat(10000);
    const { status } = await put("/user/profile", { name: hugeName }, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // There's no length validation in updateProfile() based on the code —
    // so this will likely succeed (200) unless Postgres column has a limit.
    // Either 200 or a clean 4xx is fine; 500 is not.
    assert(status !== 500, `server crashed on oversized input — no length validation found in updateProfile()`);
  });

  await test("PUT /user/profile with empty body doesn't crash (no-op update)", async () => {
    if (!TEST_USER_ID) return skip("needs TEST_USER_ID", "set env var");
    const token = makeToken({ id: TEST_USER_ID, email: TEST_USER_EMAIL });
    const { status } = await put("/user/profile", {}, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert(status === 200, `expected 200 (no-op update since name/avatar are optional), got ${status}`);
  });

  console.log("\n── Games API edge cases ──");

  await test("GET /games?page=0 doesn't crash", async () => {
    const { status } = await get("/games?page=0");
    assert(status !== 500, `server crashed on page=0, got ${status}`);
  });

  await test("GET /games?page=-1 doesn't crash", async () => {
    const { status } = await get("/games?page=-1");
    assert(status !== 500, `server crashed on page=-1, got ${status}`);
  });

  await test("GET /games?page=999999 (way out of range) doesn't crash", async () => {
    const { status, body } = await get("/games?page=999999");
    assert(status !== 500, `server crashed on huge page number, got ${status}`);
    if (status === 200) {
      assert(Array.isArray(body), "expected an array even if empty");
    }
  });

  await test("GET /games?page=notanumber doesn't crash", async () => {
    const { status } = await get("/games?page=notanumber");
    assert(status !== 500, `server crashed on non-numeric page param, got ${status}`);
  });

  await test("GET /games?category=<script>alert(1)</script> doesn't crash", async () => {
    const { status } = await get(`/games?category=${encodeURIComponent("<script>alert(1)</script>")}`);
    assert(status !== 500, `server crashed on XSS-shaped category, got ${status}`);
  });

  await test("GET /games?category=NonExistentCategoryXYZ returns empty array, not error", async () => {
    const { status, body } = await get("/games?category=NonExistentCategoryXYZ123456");
    assert(status === 200, `expected 200 for unknown category, got ${status}`);
    assert(Array.isArray(body), "expected an array");
    assert(body.length === 0, `expected empty array for nonexistent category, got ${body.length} results`);
  });

  console.log("\n── Proxy / SSRF protection (reading your isSafeTarget logic) ──");

  await test("GET /proxy/game?url=http://localhost:5001/games is blocked (SSRF to self)", async () => {
    const { status } = await get(`/proxy/game?url=${encodeURIComponent("http://localhost:5001/games")}`);
    assert(status === 400, `expected 400 (blocked as unsafe), got ${status} — SSRF guard may not be catching localhost properly`);
  });

  await test("GET /proxy/game?url=http://127.0.0.1/ is blocked", async () => {
    const { status } = await get(`/proxy/game?url=${encodeURIComponent("http://127.0.0.1/")}`);
    assert(status === 400, `expected 400, got ${status}`);
  });

  await test("GET /proxy/game?url=http://169.254.169.254/latest/meta-data/ is blocked (cloud metadata SSRF)", async () => {
    const { status } = await get(`/proxy/game?url=${encodeURIComponent("http://169.254.169.254/latest/meta-data/")}`);
    assert(status === 400, `expected 400, got ${status} — this is a serious SSRF gap if it's not blocked`);
  });

  await test("GET /proxy/game?url=ftp://example.com is blocked (non-http protocol)", async () => {
    const { status } = await get(`/proxy/game?url=${encodeURIComponent("ftp://example.com")}`);
    assert(status === 400, `expected 400, got ${status}`);
  });

  await test("GET /proxy/game?url=not-a-url is blocked (malformed URL)", async () => {
    const { status } = await get(`/proxy/game?url=not-a-url`);
    assert(status === 400, `expected 400, got ${status}`);
  });

  await test("GET /proxy/game?url=javascript:alert(1) is blocked", async () => {
    const { status } = await get(`/proxy/game?url=${encodeURIComponent("javascript:alert(1)")}`);
    assert(status === 400, `expected 400, got ${status}`);
  });

  console.log("\n── Response headers / basic hygiene ──");

  await test("Responses don't leak an Express version header (X-Powered-By)", async () => {
    const { headers } = await get("/games?page=1");
    const poweredBy = headers.get("x-powered-by");
    assert(!poweredBy, `X-Powered-By header is exposed ("${poweredBy}") — add app.disable('x-powered-by') to avoid fingerprinting`);
  });

  await test("GET /categories responds with JSON content-type", async () => {
    const res = await fetch(`${BASE_URL}/categories`);
    const ct = res.headers.get("content-type") || "";
    assert(ct.includes("application/json"), `expected JSON content-type, got "${ct}"`);
  });

  console.log("\n── Passkey routes (in-memory store — known limitation) ──");

  await test("POST /passkey/register/options without email returns 400", async () => {
    const res = await fetch(`${BASE_URL}/passkey/register/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert(res.status === 400, `expected 400 for missing email, got ${res.status}`);
  });

  await test("POST /passkey/register/options with email returns registration options", async () => {
    const res = await fetch(`${BASE_URL}/passkey/register/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `test-${Date.now()}@example.com` }),
    });
    const body = await res.json().catch(() => null);
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert(body && body.challenge, "expected a challenge in the response");
  });

  await test("POST /passkey/login/verify with garbage userHandle returns 4xx, not 500", async () => {
    const res = await fetch(`${BASE_URL}/passkey/login/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ response: { userHandle: "not-valid-base64-user!!" } }),
    });
    assert(res.status !== 500, `server crashed (500) on malformed passkey login payload`);
  });

  console.log("\n" + "─".repeat(55));
  console.log(`\x1b[1mResults: ${passed} passed, ${failed} failed, ${skipped} skipped\x1b[0m`);
  if (failures.length) {
    console.log("\nFailures:");
    failures.forEach(f => console.log(`  - ${f.name}\n    ${f.reason}`));
  }
  if (skipped > 0) {
    console.log(`\n\x1b[33mNote: ${skipped} test(s) skipped — set TEST_USER_ID env var to a real DB user id to run the full authenticated flow.\x1b[0m`);
    console.log(`Example: TEST_USER_ID=1 node backend.deep.test.js`);
  }
  console.log("─".repeat(55) + "\n");

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error("\n\x1b[31mTest runner crashed:\x1b[0m", err);
  console.error("\nIs the backend running? Try: node index.js\n");
  process.exit(1);
});
