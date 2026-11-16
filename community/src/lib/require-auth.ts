import type { FastifyReply, FastifyRequest } from "fastify";

import { getPrisma } from "./database.js";
import { verifyAccessToken } from "../modules/auth/auth.jwt.js";

export interface AuthenticatedUser {
  id: string;
  username: string;
}

export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<AuthenticatedUser | null> {
  const authorization = request.headers.authorization;

  if (!authorization?.startsWith("Bearer ")) {
    await reply.code(401).send({ error: "Authentication required" });
    return null;
  }

  const token = authorization.slice(7).trim();

  if (!token || token.length > 4096) {
    await reply.code(401).send({ error: "Invalid access token" });
    return null;
  }

  try {
    const payload = await verifyAccessToken(token);
    const prisma = getPrisma();

    const user = await prisma.communityUser.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        username: true,
        status: true,
        emailVerifiedAt: true
      }
    });

    if (!user || user.status !== "ACTIVE" || !user.emailVerifiedAt) {
      await reply.code(401).send({ error: "Account unavailable" });
      return null;
    }

    return {
      id: user.id,
      username: user.username
    };
  } catch {
    await reply.code(401).send({
      error: "Invalid or expired access token"
    });
    return null;
  }
}
