import { randomBytes, randomUUID } from "node:crypto";

import { hashOpaqueToken } from "./auth.crypto.js";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export interface RefreshTokenParts {
  sessionId: string;
  secret: string;
}

export function createRefreshToken(
  sessionId: string = randomUUID()
): {
  sessionId: string;
  token: string;
  tokenHash: string;
} {
  const secret = randomBytes(32).toString("base64url");
  const token = `${sessionId}.${secret}`;

  return {
    sessionId,
    token,
    tokenHash: hashOpaqueToken(secret, "refresh")
  };
}

export function parseRefreshToken(
  token: string
): RefreshTokenParts | null {
  if (typeof token !== "string" || token.length > 128) {
    return null;
  }

  const separator = token.indexOf(".");

  if (separator === -1 || separator !== token.lastIndexOf(".")) {
    return null;
  }

  const sessionId = token.slice(0, separator);
  const secret = token.slice(separator + 1);

  if (
    !UUID_PATTERN.test(sessionId) ||
    !SECRET_PATTERN.test(secret)
  ) {
    return null;
  }

  return { sessionId, secret };
}

export function hashRefreshSecret(secret: string): string {
  return hashOpaqueToken(secret, "refresh");
}
