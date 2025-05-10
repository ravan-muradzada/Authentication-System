import vitest from 'vitest';
import request  from 'supertest';
import { beforeEach, beforeAll, afterEach, afterAll, expect, describe, it, vi } from 'vitest';
import app from '../../src/server.js';
import redis from '../../src/config/redis-client.js';
import prisma from '../../src/config/db.js';
import bcrypt from 'bcrypt';
import * as handleToken from '../../src/utils/handle-tokens.js';

vi.mock('@sendgrid/mail', () => ({
  default: {
    setApiKey: vi.fn(),
    send: vi.fn(() => Promise.resolve('mocked send')),
  },
}));

describe('Checking login process', () => {
    beforeAll(async () => {
        await prisma.user.deleteMany();  
        
        let data = [
                { name: 'name_1', email: 'email_1@gmail.com', password: 'password_1', provider: 'manual' },

                { name: 'name_2', email: 'email_2@gmail.com', password: 'password_2', provider: 'manual' },

                { name: 'name_3', email: 'email_3@gmail.com', password: 'password_3', provider: 'manual' },

                { name: 'name_4', email: 'email_4@gmail.com', password: 'password_4', provider: 'google' }
            ];

        for (let i = 0; i < data.length; ++i) {
            data[i].password = await bcrypt.hash(data[i].password, 8);
        }
        await prisma.user.createMany({
            data
        })
    });

    it('Validate Request Middleware Checking', async () => {
        const resultFromValidateRequest1 = await request(app).post('/login').send({ email: 'non-email-string' });

        expect(resultFromValidateRequest1.body.success).toBe(false);
        expect(resultFromValidateRequest1.statusCode).toBe(400);

        const resultFromValidateRequest2 = await request(app).post('/login').send();

        expect(resultFromValidateRequest2.body.success).toBe(false);
        expect(resultFromValidateRequest2.statusCode).toBe(400);
    });

    it('Checking successful login', async () => {
        const responseFromLogin = await request(app).post('/login').send({
            email: 'email_1@gmail.com', password: 'password_1'
        });

        const otpKey = await redis.lIndex(`otp:email_1@gmail.com`, 0);
        console.log(responseFromLogin.body.message)
        expect(responseFromLogin.body.success).toBe(true);
        expect(otpKey).toBeDefined();
        expect(responseFromLogin.statusCode).toBe(200);

        const responseFromVerify = await request(app).post('/verify-login').send({ email: 'email_1@gmail.com', inputOtp: otpKey });

        expect(responseFromVerify.body.success).toBe(true);
        expect(responseFromVerify.statusCode).toBe(200);
        expect(responseFromVerify.body.accessToken).toBeDefined();
    });

    it('Wrong password checking', async () => {
        const responseFromLogin = await request(app).post('/login').send({
            email: 'email_1@gmail.com', password: 'someWrongPassword'
        });

        expect(responseFromLogin.statusCode).toBe(400);
        expect(responseFromLogin.body.success).toBe(false);
    });

    it('Registered with Google error', async () => {
        const responseFromLogin = await request(app).post('/login').send({
            email: 'email_4@gmail.com', password: 'password_4'
        });

        expect(responseFromLogin.body.success).toBe(false);
        expect(responseFromLogin.statusCode).toBe(400);
        expect(responseFromLogin.body.message).toBe('You need to log in with Google!');
    })
    
    it('User not found error', async () => {
        const responseFromLogin = await request(app).post('/login').send({
            email: 'wrong_email@gmail.com', password: 'smth'
        });

        expect(responseFromLogin.body.success).toBe(false);
        expect(responseFromLogin.statusCode).toBe(404);
    })

    it('Failed with invalid OTP', async () => {
        const responseFromLogin = await request(app).post('/verify-login').send({
            email: 'email_1@gmail.com', inputOtp: 'wrong otp code'
        });

        expect(responseFromLogin.statusCode).toBe(404);
        expect(responseFromLogin.body.success).toBe(false);
    })
}); 

describe('Checking logout process', () => {
    beforeAll(async () => {
        await prisma.user.deleteMany();  
        
        let data = [
                { name: 'name_1', email: 'email_1@gmail.com', password: 'password_1', provider: 'manual' },

                { name: 'name_2', email: 'email_2@gmail.com', password: 'password_2', provider: 'manual' }
            ];

        for (let i = 0; i < data.length; ++i) {
            data[i].password = await bcrypt.hash(data[i].password, 8);
        }
        await prisma.user.createMany({
            data
        })
    });

    it('Checking successful log out', async () => {
        const { accessToken } = await handleToken.generateToken(1);
        const resFromLogout = await request(app).post('/logout').set('Authorization', `Bearer ${accessToken}`).send({});

        expect(resFromLogout.body.success).toBe(true);
        expect(resFromLogout.statusCode).toBe(200);
        expect(resFromLogout.body.message).toBe('Successfully logged out!');
    });
});