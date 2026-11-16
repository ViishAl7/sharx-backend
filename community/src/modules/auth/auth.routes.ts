
import type { FastifyPluginAsync, FastifyReply } from "fastify";

import { authConfig } from "../../config/auth.js";
import { getPrisma } from "../../lib/database.js";

import {
  loginSchema,
  signupSchema
} from "./auth.schemas.js";

import {
  registerCommunityUser,
  SignupConflictError
} from "./auth.signup.js";

import {
  loginCommunityUser,
  InvalidCredentialsError,
  AccountUnavailableError
} from "./auth.login.js";

import {
  createEmailVerificationToken,
  createEmailVerificationTokenForEmail,
  verifyEmailToken
} from "./auth.verification.js";
import { sendCommunityEmail } from "./auth.email.js";
import {
  verifyEmailSchema,
  resendVerificationSchema
} from "./auth.schemas.js";


import {
  rotateRefreshSession,
  revokeRefreshSession
} from "./auth.sessions.js";

import {
  createAccessToken,
  verifyAccessToken
} from "./auth.jwt.js";

function isAllowedOrigin(origin: string | undefined): boolean {
  return Boolean(
    origin &&
    origin === (process.env.FRONTEND_ORIGIN ?? "http://localhost:3000")
  );
}

function setRefreshCookie(
  reply: FastifyReply,
  token: string,
  expiresAt: Date
): void {
  reply.setCookie(authConfig.refreshCookieName, token, {
    ...authConfig.cookie,
    expires: expiresAt,
    maxAge: Math.max(
      0,
      Math.floor((expiresAt.getTime() - Date.now()) / 1000)
    )
  });
}

function clearRefreshCookie(reply: FastifyReply): void {
  reply.clearCookie(
    authConfig.refreshCookieName,
    authConfig.cookie
  );
}

const authRoutes: FastifyPluginAsync = async (app) => {

  // SIGNUP
  app.post("/signup", {
    config: {
      rateLimit: { max: 3, timeWindow: 60_000 }
    }
  }, async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const parsed = signupSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid request data"
      });
    }

    try {
      const user = await registerCommunityUser(parsed.data);

      const verification = await createEmailVerificationToken(user.id);

      if (!verification) {
        request.log.error("Unable to create email verification token");
        return reply.code(500).send({
          error: "Unable to start email verification"
        });
      }

      const frontendOrigin =
        process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";

      const verificationUrl = new URL("/verify-email", frontendOrigin);
      verificationUrl.searchParams.set("token", verification.token);

      try {
        await sendCommunityEmail({
          to: parsed.data.email,
          subject: "Verify your SHARX Community account",
          text: `Welcome to SHARX Community. Verify your email using this link: ${verificationUrl.toString()}`,
          html: `<p>Welcome to SHARX Community!</p><p>Please verify your email address:</p><p><a href="${verificationUrl.toString()}">Verify email</a></p><p>This link expires in 24 hours.</p>`
        });
      } catch (emailError) {
        request.log.error(emailError, "Community verification email failed");
        return reply.code(503).send({
          error: "Account created, but verification email could not be sent. Please request another email."
        });
      }

      return reply.code(201).send({
        message: "Account created. Please check your email to verify your account.",
        user
      });
    } catch (error) {
      if (error instanceof SignupConflictError) {
        return reply.code(409).send({
          error: "Email or username is already registered"
        });
      }

      request.log.error(error);

      return reply.code(500).send({
        error: "Unable to create account"
      });
    }
  });

  // VERIFY EMAIL
  app.post("/verify-email", {
    config: {
      rateLimit: { max: 10, timeWindow: 60_000 }
    }
  }, async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const parsed = verifyEmailSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid verification request"
      });
    }

    try {
      const verified = await verifyEmailToken(parsed.data.token);

      if (!verified) {
        return reply.code(400).send({
          error: "Verification link is invalid, expired, or already used"
        });
      }

      return reply.send({
        message: "Email verified successfully. You can now log in."
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({
        error: "Unable to verify email"
      });
    }
  });

  // RESEND EMAIL VERIFICATION
  app.post("/resend-verification", {
    config: {
      rateLimit: { max: 3, timeWindow: 60_000 }
    }
  }, async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const parsed = resendVerificationSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid request data"
      });
    }

    const genericMessage =
      "If your account requires verification, a verification email will be sent.";

    try {
      const verification = await createEmailVerificationTokenForEmail(
        parsed.data.email
      );

      if (verification) {
        const frontendOrigin =
          process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";

        const verificationUrl = new URL("/verify-email", frontendOrigin);
        verificationUrl.searchParams.set("token", verification.token);

        await sendCommunityEmail({
          to: parsed.data.email,
          subject: "Verify your SHARX Community account",
          text: `Verify your SHARX Community email using this link: ${verificationUrl.toString()}`,
          html: `<p>Please verify your SHARX Community email:</p><p><a href="${verificationUrl.toString()}">Verify email</a></p><p>This link expires in 24 hours.</p>`
        });
      }
    } catch (error) {
      request.log.error(error, "Community verification resend failed");
    }

    return reply.send({ message: genericMessage });
  });

  // LOGIN
  app.post("/login", {
    config: {
      rateLimit: { max: 5, timeWindow: 60_000 }
    }
  }, async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const parsed = loginSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid request data"
      });
    }

    try {
      const result = await loginCommunityUser(
        parsed.data,
        request.headers["user-agent"]
      );

      setRefreshCookie(
        reply,
        result.refreshToken,
        result.refreshTokenExpiresAt
      );

      return reply.send({
        user: result.user,
        accessToken: result.accessToken,
        tokenType: "Bearer",
        expiresIn: authConfig.accessTokenTtlSeconds
      });
    } catch (error) {
      if (
        error instanceof InvalidCredentialsError ||
        error instanceof AccountUnavailableError
      ) {
        return reply.code(401).send({
          error: "Invalid email or password, or account unavailable"
        });
      }

      request.log.error(error);

      return reply.code(500).send({
        error: "Unable to complete login"
      });
    }
  });

  // REFRESH TOKEN
  app.post("/refresh", {
    config: {
      rateLimit: { max: 10, timeWindow: 60_000 }
    }
  }, async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const token = request.cookies[authConfig.refreshCookieName];

    if (!token) {
      clearRefreshCookie(reply);

      return reply.code(401).send({
        error: "Authentication required"
      });
    }

    try {
      const rotated = await rotateRefreshSession(token);

      if (!rotated) {
        clearRefreshCookie(reply);

        return reply.code(401).send({
          error: "Session expired or invalid"
        });
      }

      const accessToken = await createAccessToken(
        rotated.userId,
        rotated.username
      );

      setRefreshCookie(
        reply,
        rotated.refreshToken,
        rotated.expiresAt
      );

      return reply.send({
        accessToken,
        tokenType: "Bearer",
        expiresIn: authConfig.accessTokenTtlSeconds
      });
    } catch (error) {
      request.log.error(error);
      clearRefreshCookie(reply);

      return reply.code(500).send({
        error: "Unable to refresh session"
      });
    }
  });

  // LOGOUT
  app.post("/logout", async (request, reply) => {
    if (!isAllowedOrigin(request.headers.origin)) {
      return reply.code(403).send({
        error: "Invalid request origin"
      });
    }

    const token = request.cookies[authConfig.refreshCookieName];

    if (token) {
      try {
        await revokeRefreshSession(token);
      } catch (error) {
        request.log.error(error);

        return reply.code(500).send({
          error: "Unable to complete logout"
        });
      }
    }

    clearRefreshCookie(reply);

    return reply.code(204).send();
  });

  // CURRENT USER
  app.get("/me", async (request, reply) => {
    const authorization = request.headers.authorization;

    if (!authorization?.startsWith("Bearer ")) {
      return reply.code(401).send({
        error: "Authentication required"
      });
    }

    const token = authorization.slice(7).trim();

    if (!token || token.length > 4096) {
      return reply.code(401).send({
        error: "Invalid access token"
      });
    }

    try {
      const payload = await verifyAccessToken(token);
      const prisma = getPrisma();

      const user = await prisma.communityUser.findUnique({
        where: {
          id: payload.sub
        },
        select: {
          id: true,
          username: true,
          status: true,
          emailVerifiedAt: true,
          profile: {
            select: {
              displayName: true,
              bio: true,
              avatarKey: true,
              website: true,
              isPrivate: true
            }
          }
        }
      });

      if (
        !user ||
        user.status !== "ACTIVE" ||
        !user.emailVerifiedAt
      ) {
        return reply.code(401).send({
          error: "Account unavailable"
        });
      }

      return reply.send({ user });
    } catch {
      return reply.code(401).send({
        error: "Invalid or expired access token"
      });
    }
  });
};

export default authRoutes;
