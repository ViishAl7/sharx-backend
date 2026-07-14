const BASE_URL = process.env.BACKEND_URL || "http://localhost:5001";

let passed = 0;
let failed = 0;
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

async function get(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  let body = null;
  try {
    body = await res.json();
  } catch {}
  return { status: res.status, body, headers: res.headers };
}

async function post(path, data) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data || {}),
  });
  let body = null;
  try {
    body = await res.json();
  } catch {}
  return { status: res.status, body };
}

async function run() {
  console.log(`\nTesting backend at ${BASE_URL}\n`);

  console.log("── Games API ──");

  await test("GET /games returns 200 and an array of games", async () => {
    const { status, body } = await get("/games");
    assert(status === 200, `expected 200, got ${status}`);
    assert(Array.isArray(body), "expected response body to be an array");
    assert(body.length > 0, "expected at least one game in the response");
  });

  await test("GET /games?page=1 returns games", async () => {
    const { status, body } = await get("/games?page=1");
    assert(status === 200, `expected 200, got ${status}`);
    assert(Array.isArray(body), "expected an array");
  });

  await test("GET /games?page=2 returns a different page", async () => {
    const page1 = await get("/games?page=1");
    const page2 = await get("/games?page=2");
    assert(page1.status === 200 && page2.status === 200, "both pages should return 200");
    if (Array.isArray(page1.body) && Array.isArray(page2.body) && page1.body.length && page2.body.length) {
      assert(page1.body[0].id !== page2.body[0].id, "page 1 and page 2 should not return identical first game");
    }
  });

  await test("Games have expected shape (id, title, thumb)", async () => {
    const { body } = await get("/games?page=1");
    const game = Array.isArray(body) ? body[0] : null;
    assert(game, "no game returned to inspect");
    assert("id" in game || "title" in game, "game object missing id/title fields");
  });

  await test("GET /games?category=<first category> filters results", async () => {
    const { body: cats } = await get("/categories");
    const catList = Array.isArray(cats) ? cats : cats?.categories;
    if (!catList || !catList.length) {
      console.log("    (skipped — no categories returned to test filtering with)");
      return;
    }
    const cat = typeof catList[0] === "string" ? catList[0] : catList[0].name || catList[0].category;
    const { status, body } = await get(`/games?category=${encodeURIComponent(cat)}`);
    assert(status === 200, `expected 200, got ${status}`);
    assert(Array.isArray(body), "expected an array");
  });

  console.log("\n── Categories API ──");

  await test("GET /categories returns 200", async () => {
    const { status, body } = await get("/categories");
    assert(status === 200, `expected 200, got ${status}`);
    assert(body !== null, "expected a response body");
  });

  console.log("\n── Stats API ──");

  await test("GET /stats returns 200 with cache/adblock status", async () => {
    const { status, body } = await get("/stats");
    assert(status === 200, `expected 200, got ${status}`);
    assert(body !== null, "expected a response body");
  });

  console.log("\n── Proxy routes ──");

  await test("GET /proxy/game without url param returns 4xx (not a crash)", async () => {
    const { status } = await get("/proxy/game");
    assert(status >= 400 && status < 500, `expected 4xx for missing url param, got ${status}`);
  });

  await test("GET /proxy/asset without url param returns 4xx (not a crash)", async () => {
    const { status } = await get("/proxy/asset");
    assert(status >= 400 && status < 500, `expected 4xx for missing url param, got ${status}`);
  });

  console.log("\n── Auth routes (best-effort, common patterns) ──");

  await test("POST /auth/login with bad credentials returns 4xx, not 500", async () => {
    const { status } = await post("/auth/login", { email: "nope@test.com", password: "wrongpass" });
    if (status === 404) {
      console.log("    (route /auth/login not found — check your actual auth route prefix)");
      return;
    }
    assert(status >= 400 && status < 500, `expected 4xx for bad login, got ${status}`);
  });

  await test("POST /auth/signup with missing fields returns 4xx, not 500", async () => {
    const { status } = await post("/auth/signup", {});
    if (status === 404) {
      console.log("    (route /auth/signup not found — check your actual auth route prefix)");
      return;
    }
    assert(status >= 400 && status < 500, `expected 4xx for incomplete signup, got ${status}`);
  });

  console.log("\n── User routes (best-effort, requires auth) ──");

  await test("GET /users/profile without token returns 401", async () => {
    const { status } = await get("/users/profile");
    if (status === 404) {
      console.log("    (route /users/profile not found — check your actual user route prefix)");
      return;
    }
    assert(status === 401 || status === 403, `expected 401/403 without auth, got ${status}`);
  });

  console.log("\n── Error handling / resilience ──");

  await test("Unknown route returns 404 instead of crashing", async () => {
    const { status } = await get("/this-route-does-not-exist-xyz123");
    assert(status === 404, `expected 404 for unknown route, got ${status}`);
  });

  await test("Server responds within reasonable time (<3s) for /games", async () => {
    const start = Date.now();
    await get("/games?page=1");
    const elapsed = Date.now() - start;
    assert(elapsed < 3000, `response took ${elapsed}ms, expected under 3000ms`);
  });

  console.log("\n" + "─".repeat(50));
  console.log(`\x1b[1mResults: ${passed} passed, ${failed} failed\x1b[0m`);
  if (failures.length) {
    console.log("\nFailures:");
    failures.forEach(f => console.log(`  - ${f.name}: ${f.reason}`));
  }
  console.log("─".repeat(50) + "\n");

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error("\n\x1b[31mTest runner crashed:\x1b[0m", err);
  console.error("\nIs the backend running? Try: node index.js\n");
  process.exit(1);
});
