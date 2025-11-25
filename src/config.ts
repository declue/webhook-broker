import dotenv from 'dotenv';

dotenv.config();

export const config = {
  server: {
    port: parseInt(process.env.PORT || '3000', 10),
    host: process.env.HOST || '0.0.0.0',
    env: process.env.NODE_ENV || 'development',
  },
  nats: {
    url: process.env.NATS_URL || 'nats://localhost:4222',
    streamName: process.env.NATS_STREAM_NAME || 'WEBHOOKS',
    streamSubjects: process.env.NATS_STREAM_SUBJECTS || 'webhooks.>',
  },
  database: {
    url: process.env.DATABASE_URL || 'postgresql://webhook:webhook@localhost:5432/webhook_broker',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    cacheTTL: parseInt(process.env.REDIS_CACHE_TTL || '300', 10),
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    callbackUrl: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/api/v1/auth/github/callback',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
  paths: {
    webhookPrefix: process.env.WEBHOOK_PATH_PREFIX || '/webhook',
    apiPrefix: process.env.API_PATH_PREFIX || '/api/v1',
  },
};

export function validateConfig() {
  const required = [
    { key: 'GITHUB_CLIENT_ID', value: config.github.clientId },
    { key: 'GITHUB_CLIENT_SECRET', value: config.github.clientSecret },
    { key: 'JWT_SECRET', value: config.jwt.secret },
  ];

  const missing = required.filter(({ value }) => !value || value === 'your-super-secret-jwt-key');

  if (missing.length > 0 && config.server.env === 'production') {
    throw new Error(`Missing required environment variables: ${missing.map(m => m.key).join(', ')}`);
  }
}
