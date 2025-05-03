import jwt from 'jsonwebtoken';
import chalk from 'chalk';
import redis from './redis-client.js';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

export const generateToken = async (userId) => {
    try {
        const sessionId = uuidv4();

        const accessToken = jwt.sign({ userId, sessionId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId, sessionId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        const hashedRefreshToken = await bcrypt.hash(refreshToken, 8);
        
        const keyForRefreshToken = `REFRESH_TOKEN:${userId}:${sessionId}`;
        await redis.set(keyForRefreshToken, hashedRefreshToken, { EX: 7 * 24 * 60 * 60 });
          
        return { accessToken, refreshToken };
    } catch(e) {
        console.log(chalk.red.bold('Error occurred while generating jwt! '), e.message);
        throw new Error('Failed to generate jwt!');
    }
}

export const removeRefreshTokensFromRedis = async (userId) => {
    try {
        const keys = redis.keys(`REFRESH_TOKEN:${userId}`);

        if (keys.length > 0) {
            await redis.del(...keys);
        }

        console.log(chalk.green.bold('All refresh tokens removed successfully!'));
        return true;
    } catch(e) {
        console.log(chalk.red.bold('Error occurred while removing refresh tokens! ', e.message));
        throw new Error('Failed to remove refresh tokens');
    }
}

export const removeOneRefreshToken = async (userId, sessionId) => {
    try {
        const key = `REFRESH_TOKEN:${userId}:${sessionId}`;
        await redis.del(key);

        console.log(chalk.green.bold('The refresh token removed successfully!'));
        return true;
    } catch(e) {
        console.log(chalk.red.bold('Error occurred while removing the refresh token! ', e.message));
        throw new Error('Failed to remove the refresh token!');
    }
}


