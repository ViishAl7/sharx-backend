
import "dotenv/config";

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import cookie from "@fastify/cookie";

import authRoutes from "./modules/auth/auth.routes.js";
import postsRoutes from "./modules/posts/posts.routes.js";
import commentsRoutes from "./modules/comments/comments.routes.js";
import feedbackRoutes from "./modules/feedback/feedback.routes.js";

import {
  checkDatabaseConnection,
  disconnectDatabase
} from "./lib/database.js";

const app = Fastify({
  logger: true,
  trustProxy: false
});

const host = process.env.HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? 4100);

// Security headers
await app.register(helmet);

// CORS
await app.register(cors, {
  origin: process.env.FRONTEND_ORIGIN ?? "http://localhost:3000",
  credentials: true
});

// Rate limiting
await app.register(rateLimit, {
  max: 100,
  timeWindow: 60_000
});

// Cookie support
await app.register(cookie);

// Authentication routes
await app.register(authRoutes, {
  prefix: "/api/v1/auth"
});

// Posts routes
await app.register(postsRoutes, {
  prefix: "/api/v1/posts"
});

// Comments and replies routes
await app.register(commentsRoutes, {
  prefix: "/api/v1/posts"
});

// Feedback routes
await app.register(feedbackRoutes, {
  prefix: "/api/v1/feedback"
});

// Health check
app.get("/health", async () => ({
  status: "ok",
  service: "sharx-community",
  timestamp: new Date().toISOString()
}));

// Database readiness check
app.get("/ready", async (_request, reply) => {
  const databaseReady = await checkDatabaseConnection();

  if (!databaseReady) {
    return reply.code(503).send({
      status: "not_ready",
      service: "sharx-community",
      database: "unavailable"
    });
  }

  return {
    status: "ready",
    service: "sharx-community",
    database: "connected"
  };
});

// Graceful database disconnection
app.addHook("onClose", async () => {
  await disconnectDatabase();
});

// Start server
try {
  await app.listen({ host, port });

  app.log.info(
    `SHARX Community API running at http://${host}:${port}`
  );
} catch (error) {
  app.log.error(error);
  await disconnectDatabase();
  process.exit(1);
}
