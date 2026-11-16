import { describe, expect, it } from "vitest";

import {
  signupSchema,
  loginSchema
} from "../src/modules/auth/auth.schemas.js";

import {
  hashPassword,
  verifyPassword,
  generateOpaqueToken,
  hashOpaqueToken
} from "../src/modules/auth/auth.crypto.js";

import {
  createAccessToken,
  verifyAccessToken
} from "../src/modules/auth/auth.jwt.js";

import {
  createRefreshToken,
  parseRefreshToken
} from "../src/modules/auth/auth.refresh-token.js";

describe("Authentication validation", () => {
  it("normalizes email and username", () => {
    const result = signupSchema.parse({
      email: "TEST@Example.com",
      username: "Test_User",
      password: "StrongPassword123"
    });

    expect(result.email).toBe("test@example.com");
    expect(result.username).toBe("test_user");
  });

  it("rejects weak passwords", () => {
    expect(
      signupSchema.safeParse({
        email: "test@example.com",
        username: "test_user",
        password: "short"
      }).success
    ).toBe(false);
  });

  it("rejects invalid usernames", () => {
    expect(
      signupSchema.safeParse({
        email: "test@example.com",
        username: "invalid username",
        password: "StrongPassword123"
      }).success
    ).toBe(false);
  });

  it("rejects unexpected login fields", () => {
    expect(
      loginSchema.safeParse({
        email: "test@example.com",
        password: "StrongPassword123",
        admin: true
      }).success
    ).toBe(false);
  });
});

describe("Password security", () => {
  it("hashes and verifies passwords", async () => {
    const hash = await hashPassword("StrongPassword123");

    expect(hash).not.toBe("StrongPassword123");
    expect(await verifyPassword(hash, "StrongPassword123")).toBe(true);
    expect(await verifyPassword(hash, "WrongPassword123")).toBe(false);
  });
});

describe("Token security", () => {
  it("generates cryptographically random opaque tokens", () => {
    const first = generateOpaqueToken();
    const second = generateOpaqueToken();

    expect(first).toHaveLength(43);
    expect(first).not.toBe(second);
  });

  it("uses purpose-specific token hashes", () => {
    const token = generateOpaqueToken();

    expect(hashOpaqueToken(token, "refresh")).not.toBe(
      hashOpaqueToken(token, "password-reset")
    );
  });

  it("creates and verifies access tokens", async () => {
    const token = await createAccessToken(
      "00000000-0000-4000-8000-000000000001",
      "test_user"
    );

    const payload = await verifyAccessToken(token);

    expect(payload.sub).toBe(
      "00000000-0000-4000-8000-000000000001"
    );
    expect(payload.username).toBe("test_user");
  });

  it("rejects tampered access tokens", async () => {
    const token = await createAccessToken(
      "00000000-0000-4000-8000-000000000001",
      "test_user"
    );

    const tampered = token.slice(0, -5) + "abcde";

    await expect(verifyAccessToken(tampered)).rejects.toThrow();
  });

  it("rejects expired access tokens", async () => {
    const { SignJWT } = await import("jose");

    const secret = new TextEncoder().encode(
      process.env.COMMUNITY_JWT_SECRET!
    );

    const expiredToken = await new SignJWT({
      username: "test_user"
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("00000000-0000-4000-8000-000000000001")
      .setIssuer("sharx-community")
      .setAudience("sharx-community-api")
      .setIssuedAt(Math.floor(Date.now() / 1000) - 120)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(secret);

    await expect(verifyAccessToken(expiredToken)).rejects.toThrow();
  });

  it("rejects malformed refresh tokens", () => {
    expect(parseRefreshToken("invalid-token")).toBeNull();
    expect(parseRefreshToken("")).toBeNull();
  });

  it("creates parseable refresh tokens", () => {
    const refresh = createRefreshToken();
    const parsed = parseRefreshToken(refresh.token);

    expect(parsed).not.toBeNull();
    expect(parsed?.sessionId).toBe(refresh.sessionId);
    expect(refresh.tokenHash).toHaveLength(64);
  });
});
