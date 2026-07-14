// authController.js — FIXED (v3: shared Prisma client, env validation)

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MicrosoftStrategy = require("passport-microsoft").Strategy;
const jwt = require("jsonwebtoken");
const prisma = require("../lib/prisma");

// FIX: previously this file created its OWN `new PrismaClient()` — a
// second connection pool on top of index.js's. Now it reuses the single
// shared client from lib/prisma.js.

// FIX: connectWithRetry used to call `prisma.$connect()` on every single
// attempt, including the first, and `$disconnect()` on every failure.
// PrismaClient already lazily connects on the first query, and this file
// shares its client with the rest of the app now — disconnecting it here
// would break every other in-flight request using the same client. This
// version only retries on genuine connection-shaped errors, and never
// disconnects the shared client itself.
async function connectWithRetry(fn, retries = 3) {
  let lastError;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      // Prisma connection-related error codes / known transient signals.
      const isConnectionIssue =
        error?.code === "P1001" || // Can't reach database server
        error?.code === "P1002" || // Database server timed out
        error?.code === "P1017" || // Server closed the connection
        /connect/i.test(error?.message || "");

      if (!isConnectionIssue || i === retries - 1) throw error;

      console.error(`DB attempt ${i + 1} failed (retrying):`, error.message);
      await new Promise((res) => setTimeout(res, 1000 * (i + 1)));
    }
  }
  throw lastError;
}

// FIX: if these env vars are missing, passport-google-oauth20 /
// passport-microsoft throw a cryptic error deep inside their own code the
// FIRST time someone hits /auth/google or /auth/microsoft, rather than a
// clear one at startup. Warn loudly at load time instead so a missing
// credential is obvious in the logs immediately, not after a user report.
function warnIfMissing(name) {
  if (!process.env[name]) {
    console.warn(`⚠️  [authController] ${name} is not set — the related OAuth route will fail at request time.`);
  }
}
["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_CALLBACK_URL",
 "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_CALLBACK_URL",
 "JWT_SECRET"].forEach(warnIfMissing);

// ✅ Google Strategy — callbackURL from env
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Google can theoretically omit email if the scope/consent didn't
        // include it — guard here too, not just for Microsoft.
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error("Google account has no accessible email address. Cannot create account."), null);
        }

        const user = await connectWithRetry(async () => {
          let existingUser = await prisma.user.findUnique({
            where: { googleId: profile.id },
          });

          if (!existingUser) {
            // A user may already exist with this email from a different
            // sign-in method (e.g. Microsoft, or a password account).
            // Without this check, Prisma throws a unique-constraint error
            // on `email` instead of linking the accounts.
            existingUser = await prisma.user.findUnique({ where: { email } });

            if (existingUser) {
              existingUser = await prisma.user.update({
                where: { email },
                data: { googleId: profile.id },
              });
            } else {
              existingUser = await prisma.user.create({
                data: {
                  name: profile.displayName,
                  email,
                  googleId: profile.id,
                  avatar: profile.photos?.[0]?.value || null,
                },
              });
            }
          }

          return existingUser;
        });

        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        return done(null, { ...user, token });
      } catch (error) {
        console.error("Google Auth Error:", error.message);
        return done(error, null);
      }
    }
  )
);

// ✅ Microsoft Strategy — callbackURL from env
passport.use(
  new MicrosoftStrategy(
    {
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: process.env.MICROSOFT_CALLBACK_URL,
      tenant: process.env.MICROSOFT_TENANT_ID || "consumers",
      scope: ["user.read"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Some Microsoft/Outlook accounts don't expose an email in the
        // profile at all (privacy settings, work/school accounts, etc).
        // Since `email` is a required, unique field in the schema,
        // calling prisma.user.create() with email: undefined would throw
        // and crash this auth attempt. Fail cleanly instead.
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(
            new Error("Microsoft account has no accessible email address. Cannot create account — please try Google sign-in instead, or make your Microsoft email visible."),
            null
          );
        }

        const user = await connectWithRetry(async () => {
          let existingUser = await prisma.user.findUnique({
            where: { microsoftId: profile.id },
          });

          if (!existingUser) {
            existingUser = await prisma.user.findUnique({
              where: { email },
            });

            if (existingUser) {
              existingUser = await prisma.user.update({
                where: { email },
                data: { microsoftId: profile.id },
              });
            }
          }

          if (!existingUser) {
            existingUser = await prisma.user.create({
              data: {
                name: profile.displayName,
                email,
                microsoftId: profile.id,
                avatar: profile.photos?.[0]?.value || null,
              },
            });
          }

          return existingUser;
        });

        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        return done(null, { ...user, token });
      } catch (error) {
        console.error("Microsoft Auth Error:", error.message);
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (error) {
    console.error("DeserializeUser Error:", error.message);
    done(error, null);
  }
});

module.exports = passport;
