import Fastify from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loginCommunityUser: vi.fn(),
  rotateRefreshSession: vi.fn(),
  revokeRefreshSession: vi.fn(),
  createAccessToken: vi.fn(),
  verifyAccessToken: vi.fn(),
  getPrisma: vi.fn(),
  registerCommunityUser: vi.fn(),
  createEmailVerificationToken: vi.fn(),
  createEmailVerificationTokenForEmail: vi.fn(),
  verifyEmailToken: vi.fn(),
  sendCommunityEmail: vi.fn()
}));

vi.mock("../src/modules/auth/auth.login.js", () => ({
  loginCommunityUser: mocks.loginCommunityUser,
  InvalidCredentialsError: class InvalidCredentialsError extends Error {},
  AccountUnavailableError: class AccountUnavailableError extends Error {}
}));

vi.mock("../src/modules/auth/auth.sessions.js", () => ({
  rotateRefreshSession: mocks.rotateRefreshSession,
  revokeRefreshSession: mocks.revokeRefreshSession
}));

vi.mock("../src/modules/auth/auth.jwt.js", () => ({
  createAccessToken: mocks.createAccessToken,
  verifyAccessToken: mocks.verifyAccessToken
}));

vi.mock("../src/lib/database.js", () => ({
  getPrisma: mocks.getPrisma
}));

vi.mock("../src/modules/auth/auth.signup.js", () => ({
  registerCommunityUser: mocks.registerCommunityUser,
  SignupConflictError: class SignupConflictError extends Error {}
}));

vi.mock("../src/modules/auth/auth.verification.js", () => ({
  createEmailVerificationToken: mocks.createEmailVerificationToken,
  createEmailVerificationTokenForEmail: mocks.createEmailVerificationTokenForEmail,
  verifyEmailToken: mocks.verifyEmailToken
}));

vi.mock("../src/modules/auth/auth.email.js", () => ({
  sendCommunityEmail: mocks.sendCommunityEmail
}));


import authRoutes from "../src/modules/auth/auth.routes.js";

async function buildTestApp() {
  const app = Fastify({ logger: false });

  await app.register(cookie);
  await app.register(rateLimit);

  await app.register(authRoutes, {
    prefix: "/api/v1/auth"
  });

  await app.ready();

  return app;
}

describe("Community authentication routes", () => {
  let app: Awaited<ReturnType<typeof buildTestApp>>;

  beforeEach(async () => {
    process.env.FRONTEND_ORIGIN = "http://localhost:3000";

    vi.clearAllMocks();

    mocks.registerCommunityUser.mockResolvedValue({
      id: "user-123",
      username: "vishal_rohilla"
    });

    mocks.createEmailVerificationToken.mockResolvedValue({
      token: "A".repeat(43)
    });

    mocks.createEmailVerificationTokenForEmail.mockResolvedValue(null);
    mocks.sendCommunityEmail.mockResolvedValue(undefined);

    app = await buildTestApp();
  });

  afterEach(async () => {
    await app.close();
  });


  it("creates an account and sends an email verification link", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/signup",
      headers: {
        origin: "http://localhost:3000"
      },
      payload: {
        email: "vishal@example.com",
        username: "vishal_rohilla",
        password: "StrongPassword123"
      }
    });

    expect(response.statusCode).toBe(201);
    expect(mocks.registerCommunityUser).toHaveBeenCalledOnce();
    expect(mocks.createEmailVerificationToken).toHaveBeenCalledWith("user-123");
    expect(mocks.sendCommunityEmail).toHaveBeenCalledOnce();

    const email = mocks.sendCommunityEmail.mock.calls[0][0];

    expect(email.to).toBe("vishal@example.com");
    expect(email.text).toContain("http://localhost:3000/verify-email?token=");
    expect(response.body).not.toContain("A".repeat(43));
  });

  it("rejects signup requests from an untrusted origin", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/signup",
      headers: {
        origin: "http://evil.example"
      },
      payload: {
        email: "vishal@example.com",
        username: "vishal_rohilla",
        password: "StrongPassword123"
      }
    });

    expect(response.statusCode).toBe(403);
    expect(mocks.registerCommunityUser).not.toHaveBeenCalled();
  });

  it("verifies an account using a valid email token", async () => {
    mocks.verifyEmailToken.mockResolvedValue(true);

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/verify-email",
      headers: {
        origin: "http://localhost:3000"
      },
      payload: {
        token: "A".repeat(43)
      }
    });

    expect(response.statusCode).toBe(200);
    expect(mocks.verifyEmailToken).toHaveBeenCalledWith("A".repeat(43));
  });

  it("rejects an invalid email verification token", async () => {
    mocks.verifyEmailToken.mockResolvedValue(false);

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/verify-email",
      headers: {
        origin: "http://localhost:3000"
      },
      payload: {
        token: "A".repeat(43)
      }
    });

    expect(response.statusCode).toBe(400);
    expect(mocks.verifyEmailToken).toHaveBeenCalledOnce();
  });


  it("resends verification email for a pending account", async () => {
    mocks.createEmailVerificationTokenForEmail.mockResolvedValue({
      token: "B".repeat(43)
    });

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/resend-verification",
      headers: { origin: "http://localhost:3000" },
      payload: { email: "Vishal@Example.com" }
    });

    expect(response.statusCode).toBe(200);
    expect(mocks.createEmailVerificationTokenForEmail)
      .toHaveBeenCalledWith("vishal@example.com");
    expect(mocks.sendCommunityEmail).toHaveBeenCalledOnce();
    expect(mocks.sendCommunityEmail.mock.calls[0][0].text)
      .toContain("token=B".repeat(0) + "B".repeat(43));
    expect(response.body).not.toContain("B".repeat(43));
  });

  it("returns a generic response for an unknown email", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/resend-verification",
      headers: { origin: "http://localhost:3000" },
      payload: { email: "unknown@example.com" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("If your account requires verification");
    expect(mocks.sendCommunityEmail).not.toHaveBeenCalled();
  });

  it("returns a generic response when resend email delivery fails", async () => {
    mocks.createEmailVerificationTokenForEmail.mockResolvedValue({
      token: "C".repeat(43)
    });
    mocks.sendCommunityEmail.mockRejectedValue(new Error("Email service unavailable"));

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/resend-verification",
      headers: { origin: "http://localhost:3000" },
      payload: { email: "vishal@example.com" }
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain("If your account requires verification");
  });

  it("rejects login requests from an untrusted origin", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      headers: {
        origin: "http://evil.example"
      },
      payload: {}
    });

    expect(response.statusCode).toBe(403);
    expect(mocks.loginCommunityUser).not.toHaveBeenCalled();
  });

  it("rejects invalid login payloads", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      headers: {
        origin: "http://localhost:3000"
      },
      payload: {}
    });

    expect(response.statusCode).toBe(400);
    expect(mocks.loginCommunityUser).not.toHaveBeenCalled();
  });

  it("rejects refresh requests without a refresh cookie", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/refresh",
      headers: {
        origin: "http://localhost:3000"
      }
    });

    expect(response.statusCode).toBe(401);
    expect(mocks.rotateRefreshSession).not.toHaveBeenCalled();
  });

  it("allows logout without an existing refresh cookie", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: {
        origin: "http://localhost:3000"
      }
    });

    expect(response.statusCode).toBe(204);
    expect(mocks.revokeRefreshSession).not.toHaveBeenCalled();
  });

  it("rejects /me requests without a Bearer token", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/auth/me"
    });

    expect(response.statusCode).toBe(401);
    expect(mocks.verifyAccessToken).not.toHaveBeenCalled();
  });
});
