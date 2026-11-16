import { getPrisma } from "../../lib/database.js";
import { authConfig } from "../../config/auth.js";

import {
  generateOpaqueToken,
  hashOpaqueToken,
  hashPassword
} from "./auth.crypto.js";

export async function createPasswordResetToken(email: string) {
  const prisma = getPrisma();

  const normalizedEmail = email.trim().toLowerCase();

  const user = await prisma.communityUser.findUnique({
    where: { email: normalizedEmail },
    select: {
      id: true,
      email: true,
      status: true
    }
  });

  // Do not reveal whether an account exists.
  if (!user || user.status !== "ACTIVE") {
    return null;
  }

  const token = generateOpaqueToken();
  const tokenHash = hashOpaqueToken(token, "password-reset");

  const expiresAt = new Date(
    Date.now() + authConfig.passwordResetTokenTtlMs
  );

  await prisma.$transaction(async (tx) => {
    await tx.passwordResetToken.updateMany({
      where: {
        userId: user.id,
        consumedAt: null
      },
      data: {
        consumedAt: new Date()
      }
    });

    await tx.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt
      }
    });
  });

  // Internal result for the email delivery service only.
  // Never return this token from a public API response.
  return {
    email: user.email,
    token,
    expiresAt
  };
}

export async function completePasswordReset(
  token: string,
  newPassword: string
): Promise<boolean> {
  if (
    typeof token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(token)
  ) {
    return false;
  }

  const prisma = getPrisma();
  const tokenHash = hashOpaqueToken(token, "password-reset");
  const newPasswordHash = await hashPassword(newPassword);
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const reset = await tx.passwordResetToken.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true
      }
    });

    if (!reset) return false;

    const user = await tx.communityUser.findUnique({
      where: { id: reset.userId },
      select: {
        id: true,
        status: true
      }
    });

    if (!user || user.status !== "ACTIVE") {
      return false;
    }

    const consumed = await tx.passwordResetToken.updateMany({
      where: {
        id: reset.id,
        tokenHash,
        consumedAt: null,
        expiresAt: { gt: now }
      },
      data: {
        consumedAt: now
      }
    });

    if (consumed.count !== 1) return false;

    await tx.communityUser.update({
      where: { id: user.id },
      data: {
        passwordHash: newPasswordHash
      }
    });

    await tx.communitySession.updateMany({
      where: {
        userId: user.id,
        revokedAt: null
      },
      data: {
        revokedAt: now
      }
    });

    return true;
  });
}
