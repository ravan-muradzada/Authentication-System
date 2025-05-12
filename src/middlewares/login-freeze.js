import redis from '../config/redis-client.js';

const loginFreezeMiddleware = async (req, res, next) => {
    try {
        const { email } = req.body;
        const key = `fail-in-login:${email}:${req.ip}`;
        const unsuccessfulLoginAttempts = await redis.get(key) || 0;

        if (unsuccessfulLoginAttempts > 10) {
            return res.status(429).json({
                success: false,
                message: 'Too many requests!'
            });
        }

        next();
    } catch(e) {
        console.log(`Error happened in login freezing middleware: ${e.message}`);
    }
}

export default loginFreezeMiddleware;