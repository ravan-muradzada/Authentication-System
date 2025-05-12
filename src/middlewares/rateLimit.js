import rateLimit from "express-rate-limit";

export const sensitiveRouteLimiter = rateLimit({
    windowMs: 15*60*1000,
    max: process.env.SENSITIVE_ROUTE_LIMITER,
    message: {
        success: false,
        message: 'Too many attempts for sensitive router, try again later!'
    }
});

export const protectedRouteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.PROTECTED_ROUTE_LIMITER,
    message: {
        success: false,
        message: 'Too many attempts for protected route, try again later!'
    }
});

