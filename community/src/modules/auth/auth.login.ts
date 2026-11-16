import { getPrisma } from "../../lib/database.js";
import { verifyPassword } from "./auth.crypto.js";
import { createSession } from "./auth.sessions.js";
import { createAccessToken } from "./auth.jwt.js";
import type { LoginInput } from "./auth.schemas.js";

export class InvalidCredentialsError extends Error {
  constructor() {
    super("Invalid email or password");
    this.name = "InvalidCredentialsError";
  }
}

export class AccountUnavailableError extends Error {
  constructor() {
    super("This account is currently unavailable");
    this.name = "AccountUnavailableError";
  }
}

export async function loginCommunityUser(
  input: LoginInput,
  userAgent?: string
) {
  const prisma = getPrisma();

  const email = input.email.trim().toLowerCase();

  const user = await prisma.communityUser.findUnique({
    where: { email },
    select: {
      id: true,
      username: true,
      passwordHash: true,
      status: true,
      emailVerifiedAt: true
    }
  });

  if (!user) {
    throw new InvalidCredentialsError();
  }

  const passwordValid = await verifyPassword(
    user.passwordHash,
    input.password
  );

  if (!passwordValid) {
    throw new InvalidCredentialsError();
  }

  if (user.status === "SUSPENDED" || user.status === "DELETED") {
    throw new AccountUnavailableError();
  }

  if (
    user.status !== "ACTIVE" ||
    !user.emailVerifiedAt
  ) {
    throw new AccountUnavailableError();
  }

  const session = await createSession(user.id, userAgent);

  try {
    const accessToken = await createAccessToken(
      user.id,
      user.username
    );

    await prisma.communityUser.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    return {
      user: {
        id: user.id,
        username: user.username
      },
      accessToken,
      refreshToken: session.refreshToken,
      refreshTokenExpiresAt: session.expiresAt
    };
  } catch (error) {
    await prisma.communitySession.updateMany({
      where: {
        id: session.sessionId,
        revokedAt: null
      },
      data: { revokedAt: new Date() }
    });

    throw error;
  }
}
