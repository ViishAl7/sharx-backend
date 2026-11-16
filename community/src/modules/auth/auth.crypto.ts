import argon2 from "argon2";
import { createHmac, randomBytes } from "node:crypto";

import { authConfig } from "../../config/auth.js";

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1
} as const;

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(
  passwordHash: string,
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(passwordHash, password);
  } catch {
    return false;
  }
}

export function generateOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashOpaqueToken(
  token: string,
  purpose: "refresh" | "email-verification" | "password-reset"
): string {
  return createHmac("sha256", authConfig.refreshTokenSecret)
    .update(`sharx-community:${purpose}:`)
    .update(token)
    .digest("hex");
}
