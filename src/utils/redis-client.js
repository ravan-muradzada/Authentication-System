import { createClient } from 'redis';

const redis = createClient();

redis.on('connect', () => {
  console.log('✅ Connected to Redis');
});

redis.on('error', (err) => {
  console.error('❌ Redis connection error:', err);
});

await redis.connect();

export default redis;
