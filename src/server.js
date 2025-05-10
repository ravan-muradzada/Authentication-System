import express from 'express';
import authRouter from './routers/auth-router.js';
import passport from './auth/index.js';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(passport.initialize());

app.use(authRouter);


const port = 3000;
if (process.env.NODE_ENV !== 'test'){
    app.listen(port, () => console.log(`Server started at http://localhost:${port}`));
}

export default app;