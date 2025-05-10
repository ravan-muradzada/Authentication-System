import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import prisma from "../../config/db.js";


passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (AccessToken, refreshToken, profile, done) => {
      try {
        const googleId = profile.id;
        const email = profile.emails[0].value;
        const name = profile.displayName;
        const provider = "google";

        let user;
        try {
          user = await prisma.user.findUnique({
            where: {
              email,
            },
          });
        } catch (error) {
          return done(new Error("Error fetching user from the database"), null);
        }

        if (user && user.provider !== "google") {
          throw new Error(
            "This email is already registered using a different login method!"
          );
        } else if (!user) {
          user = await prisma.user.create({
            data: {
              email,
              googleId,
              name,
              provider,
            },
          });
        }

        const userId = user.id;

        done(null, { userId });
      } catch (e) {
        done(e.message, null);
      }
    }
  )
);
