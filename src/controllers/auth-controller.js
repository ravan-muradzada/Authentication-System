import * as msgSender from '../utils/msg-sender.js';
import otpGenerator from 'otp-generator';
import jwt from 'jsonwebtoken';
import * as handleTokens from '../utils/handle-tokens.js'
import redis from '../config/redis-client.js';
import bcrypt from 'bcrypt';
import prisma from '../config/db.js';
import crypto from 'crypto';

// Manual sign up

export const signUp = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Generating and saving OTP
        const otpCode = otpGenerator.generate();
        const otpKey = `otp_signup:${email}`;
        await redis.lPush(otpKey, otpCode);
        await redis.expire(otpKey, 300); // Set expiration time to 5 minutes

        // Sending OTP
        const subject = `OTP Verification to sign up`;
        const text = `Don't share!`;
        const html = `<h1>Please confirm your OTP</h1> <p>Here is your OTP code: ${otpCode}</p>`;

        await msgSender.sendMail(email, subject, text, html);
        
        // Saving password
        const hashedPassword = await bcrypt.hash(password, 8);
        const passwordKey = `password:${email}`;
        await redis.set(passwordKey, hashedPassword, {EX: 300 });

        // Sending response
        res.status(200).json({
            success: true,
            email,
            message: 'OTP sent successfully!',
            redirect: '/verify-otp'
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: e.message || 'Error happened while signing up!'
        });
    }
}

export const verifyOtp = async (req, res) => {
    try {
        // Verifying the input otp 
        const { email, inputOtp } = req.body;

        const otpKey = `otp_signup:${email}`;
        const allOtps = await redis.lRange(otpKey, 0, -1);
        
        if (!allOtps.includes(inputOtp)) {
            return res.status(404).json({
                success: false,
                message: 'OTP not found!'
            });
        }
        
        // Taking password from redis and create a user        
        const hashedPassword = await redis.get(`password:${email}`);
        await redis.del(`password:${email}`);

        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                provider: "manual"
            }
        });
        
        await redis.del(otpKey);   

        // Generating and getting tokens
        const { accessToken, refreshToken } = await handleTokens.generateToken(user.id);

        // Attach a refresh token to a cookie
        res.cookie('refreshToken', refreshToken, {
            httOnly: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60
        });

        // Sending response
        res.status(201).json({
            success: true,
            message: 'User has been created!',
            accessToken,
            redirect: '/add-other-credentials'
        });
    } catch(e) {
        console.log(e.message);
        res.status(400).json({
            success: false,
            message: `Error happened while verifying OTP: ${e.message}`
        });
    }
}

export const otherCredentials = async (req, res) => {
    try {
        const { name } = req.body;

        const updatedUser = await prisma.user.update({
            where: {
                id: parseInt(req.user.userId)
            },
            data: {
                name
            }
        });
        
        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found!'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Name added successfully!',
            updatedUser
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: e.message || 'Error while adding other credentials!'
        });
    }
}


// Sign up with Google
export const callbackOfGoogle = async (req, res) => {
    try {
        const userId = req.user.userId;

        // Generating and getting tokens
        const { accessToken, refreshToken } = await handleTokens.generateToken(userId);

        // Attaching a refresh token to a cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60
        });

        res.status(200).json({
            success: true,
            message: 'Logged in via Google',
            accessToken
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error while signing up/logging in via Google! ${e.message}`
        });
    }
}

export const loginFailed = (req, res) => {
    res.status(401).json({
        success: false,
        message: 'Google login failed!',
    });
}


// Manual log in

export const loginManual = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({
            where: {
                email
            }
        });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found!'
            });
        }

        if (user.provider === 'google') {
            return res.status(400).json({
                success: false,
                message: 'You need to log in with Google!'
            });
        }

        const isCorrectPassword = await bcrypt.compare(password, user.password);
        if (!isCorrectPassword) {
            const key = `fail-in-login:${email}:${req.ip}`;
            const attempts = await redis.incr(key);
            if (attempts === 1) {
                await redis.expire(key, 10*60);
            }

            return res.status(400).json({
                success: false,
                message: 'Wrong in credentials!'
            });
        }

        
        // Generating and saving OTP
        const otpCode = otpGenerator.generate();
        console.log('OTP Code: ', otpCode);
        const otpKey = `otp_login:${email}`;
        await redis.set(`userId:${email}`, user.id, { EX: 300 });
        await redis.lPush(otpKey, otpCode);
        await redis.expire(otpKey, 300); // Set expiration time to 5 minutes

        // Sending OTP to verify the user
        const subject = `OTP Verification to log in`;
        const text = `Don't share!`;
        const html = `<h1>Please confirm your OTP</h1> <p>Here is your OTP code: ${otpCode}</p>`;

        await msgSender.sendMail(email, subject, text, html);

        res.status(200).json({
            success: true,
            message: 'OTP sent to verify the user!'
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error happened! ${e.message}`,
        });
    }
}

export const verifyLogIn = async (req, res) => {
    try {
        const { email, inputOtp } = req.body;
        const otpKey = `otp_login:${email}`;
        const allOtps = await redis.lRange(otpKey, 0, -1);

        const checkExistenceOfOtp = allOtps.includes(inputOtp);

        if (!checkExistenceOfOtp) {
            return res.status(404).json({
                success: false,
                message: 'OTP not found!'
            });
        }
        await redis.del(otpKey);
        
        const userId = await redis.get(`userId:${email}`);
        await redis.del(`userId:${email}`);

        const { accessToken, refreshToken } = await handleTokens.generateToken(userId);

        res.cookie('refreshToken', refreshToken, {
            maxAge: 7 * 24 * 60 * 60,
            sameSite: 'strict',
            httpOnly: true
        });

        res.status(200).json({
            success: true,
            message: 'Successfully logged in!',
            accessToken
        });
    } catch(e) {
        console.log(e.message);
        res.status(400).json({
            success: false,
            message: `Error happened while verifying log in! ${e.message}`
        });
    }
}

// Refresh Token
export const refresh = async (req, res) => {
    try {
        const oldRefreshToken = req.cookies.refreshToken;
        if (!oldRefreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Refresh Token not found!'
            });
        }

        const payload = jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = payload.userId, sessionId = payload.sessionId;

        const refreshTokenInRedis = await redis.get(`REFRESH_TOKEN:${userId}:${sessionId}`);
        if (!refreshTokenInRedis) {
            return res.status(401).json({
                success: false,
                message: 'Refresh Token not found!'
            });
        }
        await handleTokens.removeOneRefreshToken(userId, sessionId); // Removing refresh token from redis

        const checkMatching = await bcrypt.compare(oldRefreshToken, refreshTokenInRedis);

        if (!checkMatching) {
            return res.status(400).json({
                success: false,
                message: 'Refresh Token does not match!'
            });
        }

        // Generating and getting tokens
        const { accessToken, refreshToken } = await handleTokens.generateToken(userId);

        // Attaching a refresh token to a cookie
        res.cookie('refreshToken', refreshToken, {
            httOnly: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60
        });

        res.status(200).json({
            success: true,
            message: 'Tokens have been refreshed!',
            accessToken
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error occurred while refreshing the tokens! ${e.message}`
        });
    }
}

// Log out
export const logout = async (req, res) => {
    try {
        const { userId, sessionId } = req.user;

        // Removing refresh token from redis
        await handleTokens.removeOneRefreshToken(userId, sessionId);

        // Clear the cookie where the refresh token is stored
        res.clearCookie('refreshToken', {
            httOnly: true,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60
        });

        res.status(200).json({
            success: true,
            message: 'Successfully logged out!'
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error happened while logging out! ${e.message}`
        });
    }
}


// Change Password
export const changePassword = async (req, res) => {
    try {
        const { userId } = req.user;
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({
                success: false,
                message: 'You need to send a new password'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 8);

        const user = await prisma.user.findUnique({
            where: {
                id: parseInt(userId)
            }
        });

        if (user.provider === 'google') {
            return res.status(400).json({
                success: false,
                message: 'You cannot change the password, because you registered via Google!'
            });
        }

        const updatedUser = await prisma.user.update({
            where: {
                id: parseInt(userId)
            }, 
            data: {
                password: hashedPassword
            }
        });
        
        await handleTokens.removeRefreshTokensFromRedis(userId);

        res.status(200).json({
            success: true,
            message: 'Password changed successfully!'
        });
    } catch(e) {
        return res.status(400).json({
            success: false,
            message: `Error happened while changing your password! ${e.message}`
        });
    }
}

export const forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({
            where: {
                email
            }
        });

        if (!user) { 
            return res.status(404).json({
                success: true,
                message: 'User with this email not found!'
            });
        }

        if (user.provider === 'google') {
            return res.status(400).json({
                success: false,
                message: 'You cannot change the password, because you registered via Google!'
            });
        }

        const token = crypto.randomBytes(32).toString('hex');
        await redis.set(`reset:${token}`, user.id, 'EX', 60 * 15);
        console.log(`Token: ${token}`);

        const resetLink = `http://localhost:3000/reset-password/:${token}`;

        // Sending email
        const subject = 'Password Reset';
        const html = `<a href="${resetLink}">Reset Your Password</a>`;
        await msgSender.sendMail(email, subject, 'undefined', html);
        
        res.status(200).json({
            success: true,
            message: 'Email sent successfully!'
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error happened while sending reset link to your email! ${e.message}`
        });
    }
}

export const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { newPassword } = req.body;

        const hashedPassword = await bcrypt.hash(newPassword, 8);

        const id = await redis.get(`reset:${token}`);

        if (!id) {
            return res.status(404).json({
                success: false,
                message: 'Invalid or expired token!'
            });
        }

        const updatedUser = await prisma.user.update({
            where: {
                id: parseInt(id)
            },
            data: {
                password: hashedPassword
            }
        });

        await redis.del(`reset:${token}`);
        await handleTokens.removeRefreshTokensFromRedis(userId);

        res.status(200).json({
            success: true,
            message: 'Password reset successfully!'
        });
    } catch(e) {
        res.status(400).json({
            success: false,
            message: 'Error happened while resetting the password'
        });
    }
}
