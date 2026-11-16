import {
  SignJWT,
  jwtVerify,
  type JWTPayload
} from "jose";

import { authConfig } from "../../config/auth.js";

const secret = new TextEncoder().encode(
  authConfig.accessTokenSecret
);

export interface AccessTokenPayload extends JWTPayload {
  sub: string;
  username: string;
}

export async function createAccessToken(
  userId: string,
  username: string
): Promise<string> {
  return new SignJWT({ username })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(userId)
    .setIssuer(authConfig.issuer)
    .setAudience(authConfig.audience)
    .setIssuedAt()
    .setExpirationTime(`${authConfig.accessTokenTtlSeconds}s`)
    .sign(secret);
}

export async function verifyAccessToken(
  token: string
): Promise<AccessTokenPayload> {
  const { payload } = await jwtVerify(token, secret, {
    algorithms: ["HS256"],
    issuer: authConfig.issuer,
    audience: authConfig.audience
  });

  if (
    typeof payload.sub !== "string" ||
    typeof payload.username !== "string"
  ) {
    throw new Error("Invalid access token payload");
  }

  return payload as AccessTokenPayload;
}
