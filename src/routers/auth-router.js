import express from 'express';
import * as authController from '../controllers/auth-controller.js';
import validateRequestMiddleware from '../middlewares/validator.js';
import passport from 'passport';
import authLimit from '../middlewares/rateLimit.js';

const router = new express.Router();

const jwtMiddleware = passport.authenticate('jwt', { session: false });

// OTP sign up
router.post('/sign-up', authLimit, validateRequestMiddleware, authController.signUp);
router.post('/verify-otp', authLimit, validateRequestMiddleware, authController.verifyOtp);
router.post('/add-other-credentials', jwtMiddleware, authController.otherCredentials);

// Sign up with Google
router.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback', 
    passport.authenticate('google', { session: false, failureMessage: true, failureRedirect: '/login-failed' }), authController.callbackOfGoogle
);

router.get('/login-failed', authController.loginFailed);

// Log in manual
router.post('/login', authLimit, authController.loginManual);

// Refresh the tokens
router.post('/refresh', authController.refresh);

router.get('/hello-world', jwtMiddleware, (req, res) => res.send('Hello World from protected route!'));

router.post('/logout', jwtMiddleware, authController.logout);

router.patch('/change-password', jwtMiddleware, authController.changePassword);

router.post('/forget-password', authLimit, authController.forgetPassword);

router.patch('/reset-password/:token', authLimit, authController.resetPassword);

export default router;
