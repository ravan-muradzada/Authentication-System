import vitest from 'vitest';
import request  from 'supertest';
import { beforeEach, beforeAll, afterEach, afterAll, expect, describe, it, vi } from 'vitest';
import app from '../../src/server.js';
import redis from '../../src/config/redis-client.js';
import prisma from '../../src/config/db.js';

vi.mock('@sendgrid/mail', () => ({
  default: {
    setApiKey: vi.fn(),
    send: vi.fn(() => Promise.resolve('mocked send')),
  },
}));

describe('Checking /sign-up router', () => {
  beforeAll(async () => {
        await prisma.user.deleteMany();  
    })
    it('Sending proper data', async () => {
        const userInfo = {
            email: 'testing@gmail.com',
            password: 'testingPassword'
        };

        const resFromSignUp = await request(app).post('/sign-up').send(userInfo);

       expect(resFromSignUp.body.success).toBe(true);
      
       const otpCode = await redis.lIndex(`otp:${userInfo.email}`, 0);
       expect(otpCode).toBeDefined();

    
       const resFromVerify = await request(app).post('/verify-otp').send({ 
        email: userInfo.email, inputOtp: otpCode
       });
       
       expect(resFromVerify.body.success).toBe(true);

      const accessToken = resFromVerify.body.accessToken;
      expect(accessToken).toBeDefined();

      const resFromOtherCredentials = await request(app).post('/add-other-credentials').set('Authorization', `Bearer ${accessToken}`).send({ name: 'ExampleName' });
       
      expect(resFromOtherCredentials.body.success).toBe(true);
    });

    it('Fails with invalid OTP', async () => {
      const userInfo = { email: 'wrongotp@gmail.com', password: 'pass123' };
      await request(app).post('/sign-up').send(userInfo);

      const res = await request(app).post('/verify-otp').send({
        email: userInfo.email,
        inputOtp: '000000' // definitely invalid
      });

      expect(res.status).toBe(404); // or whatever your app returns
      expect(res.body.success).toBe(false);
    });

    it('Fails if no token is provided for protected route', async () => {
      const res = await request(app).post('/add-other-credentials').send({ name: 'NoTokenGuy' });

      expect(res.status).toBe(401); 
      expect(res.body.success).toBe(false);
    });

    it('Fails with a malformed token', async () => {
      const res = await request(app)
        .post('/add-other-credentials')
        .set('Authorization', 'Bearer bad.token.value')
        .send({ name: 'BadTokenUser' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
});

