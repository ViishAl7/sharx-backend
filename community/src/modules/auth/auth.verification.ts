import { getPrisma } from "../../lib/database.js";
import { authConfig } from "../../config/auth.js";

import {
  generateOpaqueToken,
  hashOpaqueToken
} from "./auth.crypto.js";

export async function createEmailVerificationToken(userId: string) {
  const prisma = getPrisma();

  const user = await prisma.communityUser.findUnique({
    where: { id: userId },
    select: {
      id: true,
      status: true,
      emailVerifiedAt: true
    }
  });

  if (
    !user ||
    user.status !== "PENDING_VERIFICATION" ||
    user.emailVerifiedAt
  ) {
    return null;
  }

  const token = generateOpaqueToken();
  const tokenHash = hashOpaqueToken(token, "email-verification");
  const expiresAt = new Date(
    Date.now() + authConfig.verificationTokenTtlMs
  );

  await prisma.$transaction(async (tx) => {
    await tx.emailVerificationToken.updateMany({
      where: {
        userId,
        consumedAt: null
      },
      data: {
        consumedAt: new Date()
      }
    });

    await tx.emailVerificationToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt
      }
    });
  });

  return { token, expiresAt };
}

export async function createEmailVerificationTokenForEmail(email: string) {
  const prisma = getPrisma();

  const user = await prisma.communityUser.findUnique({
    where: { email: email.trim().toLowerCase() },
    select: {
      id: true,
      status: true,
      emailVerifiedAt: true
    }
  });

  if (
    !user ||
    user.status !== "PENDING_VERIFICATION" ||
    user.emailVerifiedAt
  ) {
    return null;
  }

  return createEmailVerificationToken(user.id);
}

export async function verifyEmailToken(token: string): Promise<boolean> {
  if (
    typeof token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(token)
  ) {
    return false;
  }

  const prisma = getPrisma();
  const tokenHash = hashOpaqueToken(token, "email-verification");
  const now = new Date();

  return prisma.$transaction(async (tx) => {
    const verification = await tx.emailVerificationToken.findUnique({
      where: { tokenHash },
      select: { id: true, userId: true }
    });

    if (!verification) return false;

    const consumed = await tx.emailVerificationToken.updateMany({
      where: {
        id: verification.id,
        tokenHash,
        consumedAt: null,
        expiresAt: { gt: now }
      },
      data: {
        consumedAt: now
      }
    });

    if (consumed.count !== 1) return false;

    const activated = await tx.communityUser.updateMany({
      where: {
        id: verification.userId,
        status: "PENDING_VERIFICATION",
        emailVerifiedAt: null
      },
      data: {
        status: "ACTIVE",
        emailVerifiedAt: now
      }
    });

    return activated.count === 1;
  });
}
