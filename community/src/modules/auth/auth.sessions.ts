import { timingSafeEqual } from "node:crypto";

import { getPrisma } from "../../lib/database.js";
import { authConfig } from "../../config/auth.js";

import {
  createRefreshToken,
  hashRefreshSecret,
  parseRefreshToken
} from "./auth.refresh-token.js";

function hashesMatch(expected: string, actual: string): boolean {
  const expectedBuffer = Buffer.from(expected, "hex");
  const actualBuffer = Buffer.from(actual, "hex");

  if (
    expectedBuffer.length !== 32 ||
    actualBuffer.length !== 32
  ) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, actualBuffer);
}

function getExpiry(): Date {
  return new Date(
    Date.now() + authConfig.refreshTokenTtlSeconds * 1000
  );
}

/**
 * Create a new Community session.
 * Only a hashed refresh token is stored in the database.
 */
export async function createSession(
  userId: string,
  userAgent?: string
) {
  const prisma = getPrisma();
  const refresh = createRefreshToken();

  const session = await prisma.communitySession.create({
    data: {
      id: refresh.sessionId,
      userId,
      tokenHash: refresh.tokenHash,
      expiresAt: getExpiry(),
      userAgent: userAgent?.slice(0, 500) ?? null
    }
  });

  return {
    sessionId: session.id,
    refreshToken: refresh.token,
    expiresAt: session.expiresAt
  };
}

/**
 * Rotate a refresh token.
 *
 * Security:
 * - Validates token format.
 * - Checks session expiration and revocation.
 * - Checks account status and email verification.
 * - Detects refresh-token reuse.
 * - Uses atomic conditional updates to prevent concurrent rotation.
 */
export async function rotateRefreshSession(token: string) {
  const parts = parseRefreshToken(token);

  if (!parts) return null;

  const prisma = getPrisma();

  const session = await prisma.communitySession.findUnique({
    where: {
      id: parts.sessionId
    },
    include: {
      user: {
        select: {
          username: true,
          status: true,
          emailVerifiedAt: true
        }
      }
    }
  });

  if (!session) return null;

  const now = new Date();

  // Reject revoked or expired sessions.
  if (session.revokedAt || session.expiresAt <= now) {
    return null;
  }

  // Revoke sessions belonging to unavailable accounts.
  if (
    session.user.status !== "ACTIVE" ||
    !session.user.emailVerifiedAt
  ) {
    await prisma.communitySession.updateMany({
      where: {
        id: session.id,
        revokedAt: null
      },
      data: {
        revokedAt: now
      }
    });

    return null;
  }

  const presentedHash = hashRefreshSecret(parts.secret);

  // A token mismatch indicates possible refresh-token reuse.
  if (!hashesMatch(session.tokenHash, presentedHash)) {
    await prisma.communitySession.updateMany({
      where: {
        id: session.id,
        revokedAt: null
      },
      data: {
        revokedAt: now
      }
    });

    return null;
  }

  // Generate a new refresh token for the same session.
  const nextRefresh = createRefreshToken(session.id);
  const nextExpiry = getExpiry();

  // Atomic compare-and-swap rotation.
  const rotation = await prisma.communitySession.updateMany({
    where: {
      id: session.id,
      tokenHash: session.tokenHash,
      revokedAt: null,
      expiresAt: {
        gt: now
      }
    },
    data: {
      tokenHash: nextRefresh.tokenHash,
      expiresAt: nextExpiry
    }
  });

  // Another request may have rotated or revoked this session.
  if (rotation.count !== 1) {
    await prisma.communitySession.updateMany({
      where: {
        id: session.id,
        revokedAt: null
      },
      data: {
        revokedAt: new Date()
      }
    });

    return null;
  }

  return {
    userId: session.userId,
    username: session.user.username,
    sessionId: session.id,
    refreshToken: nextRefresh.token,
    expiresAt: nextExpiry
  };
}

/**
 * Revoke a refresh session during logout.
 */
export async function revokeRefreshSession(
  token: string
): Promise<boolean> {
  const parts = parseRefreshToken(token);

  if (!parts) return false;

  const prisma = getPrisma();

  const session = await prisma.communitySession.findUnique({
    where: {
      id: parts.sessionId
    }
  });

  if (!session || session.revokedAt) {
    return false;
  }

  const presentedHash = hashRefreshSecret(parts.secret);

  if (!hashesMatch(session.tokenHash, presentedHash)) {
    return false;
  }

  const result = await prisma.communitySession.updateMany({
    where: {
      id: session.id,
      tokenHash: session.tokenHash,
      revokedAt: null
    },
    data: {
      revokedAt: new Date()
    }
  });

  return result.count === 1;
}