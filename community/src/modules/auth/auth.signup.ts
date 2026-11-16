import { Prisma } from "../../../generated/prisma/client.js";

import { getPrisma } from "../../lib/database.js";
import type { SignupInput } from "./auth.schemas.js";
import { hashPassword } from "./auth.crypto.js";

export interface SignupResult {
  id: string;
  username: string;
  status: string;
}

export class SignupConflictError extends Error {
  constructor() {
    super("Email or username is already registered");
    this.name = "SignupConflictError";
  }
}

export async function registerCommunityUser(
  input: SignupInput
): Promise<SignupResult> {
  const prisma = getPrisma();

  const email = input.email.trim().toLowerCase();
  const username = input.username.trim().toLowerCase();

  const passwordHash = await hashPassword(input.password);

  try {
    const user = await prisma.communityUser.create({
      data: {
        email,
        username,
        passwordHash,
        profile: {
          create: {}
        }
      },
      select: {
        id: true,
        username: true,
        status: true
      }
    });

    return user;
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === "P2002"
    ) {
      throw new SignupConflictError();
    }

    throw error;
  }
}
