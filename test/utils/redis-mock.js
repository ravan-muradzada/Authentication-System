import redis from 'redis';
import redisMock from 'redis-mock';

const isTest = process.env.NODE_ENV === 'test';
const client = isTest
  ? redisMock.createClient()
  : redis.createClient();

export default client;

