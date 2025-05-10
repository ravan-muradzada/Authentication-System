import rateLimit from "express-rate-limit";

const authLimit = rateLimit({
    windowMs: 15*60*1000,
    max: process.env.MAX_RATE_LIMIT,
    message: {
        success: false,
        message: 'Too many attempts, try again later'
    }
});

export default authLimit;