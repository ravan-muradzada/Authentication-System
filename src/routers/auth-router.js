import express from 'express';
import * as authController from '../controllers/auth-controller.js';
import validateRequestMiddleware from '../middlewares/validator.js';
import loginFreezeMiddleware from '../middlewares/login-freeze.js';
import passport from 'passport';

const router = new express.Router();

const jwtMiddleware = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.user = user;
    next();
  })(req, res, next);
};


// OTP sign up
router.post('/auth/sign-up', validateRequestMiddleware, authController.signUp);
router.post('/auth/verify-otp', validateRequestMiddleware, authController.verifyOtp);
router.post('/protected/add-other-credentials', jwtMiddleware, authController.otherCredentials);

// Sign up with Google
router.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback', 
    passport.authenticate('google', { session: false, failureMessage: true, failureRedirect: '/login-failed' }), authController.callbackOfGoogle
);

router.get('/auth/login-failed', authController.loginFailed);

// Log in manual
router.post('/auth/login', validateRequestMiddleware, loginFreezeMiddleware, authController.loginManual);
router.post('/auth/verify-login', validateRequestMiddleware, authController.verifyLogIn);

// Refresh the tokens
router.post('/protected/refresh', authController.refresh);

router.get('/protected/protected-route-example', jwtMiddleware, (req, res) => res.send('Hello World from protected route!'));

router.post('/protected/logout', jwtMiddleware, authController.logout);

router.patch('/auth/change-password', jwtMiddleware, authController.changePassword);

router.post('/auth/forget-password', authController.forgetPassword);

router.patch('/auth/reset-password/:token', authController.resetPassword);

export default router;
