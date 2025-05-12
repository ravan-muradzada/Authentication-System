import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';

const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.ACCESS_TOKEN_SECRET
}

passport.use(new JwtStrategy(opts, async (payload, done) => {
    try {
        const userId = payload.userId;
        const sessionId = payload.sessionId;

        done(null, { userId, sessionId });
    } catch(err) {
        done(`Error while authentication of token in passport! ${err.message}`, false);
    }
}));