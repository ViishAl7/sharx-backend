const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MicrosoftStrategy = require("passport-microsoft").Strategy;
const { PrismaClient } = require("@prisma/client");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
  log: ["error", "warn"],
});

async function connectWithRetry(fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      await prisma.$connect();
      return await fn();
    } catch (error) {
      console.error(`Attempt ${i + 1} failed:`, error.message);
      await prisma.$disconnect();
      if (i === retries - 1) throw error;
      await new Promise((res) => setTimeout(res, 2000));
    }
  }
}

// Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5001/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await connectWithRetry(async () => {
          let existingUser = await prisma.user.findUnique({
            where: { googleId: profile.id },
          });

          if (!existingUser) {
            existingUser = await prisma.user.create({
              data: {
                name: profile.displayName,
                email: profile.emails[0].value,
                googleId: profile.id,
                avatar: profile.photos[0].value,
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
        console.error("Google Auth Error:", error.message);
        return done(error, null);
      }
    }
  )
);

// Microsoft Strategy
passport.use(
  new MicrosoftStrategy(
    {
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: "http://localhost:5001/auth/microsoft/callback",
      tenant: "consumers",
      scope: ["user.read"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await connectWithRetry(async () => {
          const email = profile.emails?.[0]?.value;

          let existingUser = await prisma.user.findUnique({
            where: { microsoftId: profile.id },
          });

          if (!existingUser && email) {
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
                email: email,
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