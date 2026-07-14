// lib/prisma.js
// ─────────────────────────────────────────────────────────────
// SINGLE shared PrismaClient for the entire app.
//
// FIX: the project previously created FOUR separate `new PrismaClient()`
// instances (index.js, Controllers/authController.js,
// Controllers/userController.js, routes/passkey.js). Each PrismaClient
// opens its own connection pool to Postgres. On a free/small Postgres
// tier (often a 10-20 connection limit), four pools from ONE running
// process can exhaust the limit by itself before a single real user
// shows up — new queries then hang or fail with
// "too many connections" / "connection pool timeout".
//
// Every file in this project now does:
//   const prisma = require('../lib/prisma');
// instead of creating its own client.
// ─────────────────────────────────────────────────────────────

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'production' ? ['error', 'warn'] : ['error', 'warn'],
});

// Graceful shutdown: without this, redeploys / restarts (or ctrl+C locally)
// can leave the Postgres connection pool in a half-closed state until it
// times out on its own, instead of closing it immediately and cleanly.
async function shutdown(signal) {
  console.log(`\n${signal} received — closing Prisma connection...`);
  try {
    await prisma.$disconnect();
  } finally {
    process.exit(0);
  }
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = prisma;
