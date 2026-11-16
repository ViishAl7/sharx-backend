function requiredSecret(name: string): string {
  const value = process.env[name];

  if (!value || Buffer.byteLength(value, "utf8") < 32) {
    throw new Error(
      `${name} must be configured with at least 32 bytes`
    );
  }

  return value;
}

const isProduction = process.env.NODE_ENV === "production";

export const authConfig = Object.freeze({
  accessTokenSecret: requiredSecret("COMMUNITY_JWT_SECRET"),
  refreshTokenSecret: requiredSecret("COMMUNITY_REFRESH_TOKEN_SECRET"),

  issuer: "sharx-community",
  audience: "sharx-community-api",

  accessTokenTtlSeconds: 10 * 60,
  refreshTokenTtlSeconds: 30 * 24 * 60 * 60,

  verificationTokenTtlMs: 24 * 60 * 60 * 1000,
  passwordResetTokenTtlMs: 30 * 60 * 1000,

  refreshCookieName: "sharx_community_refresh",

  cookie: Object.freeze({
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax" as const,
    path: "/api/v1/auth"
  })
});
