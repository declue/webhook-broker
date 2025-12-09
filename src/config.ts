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
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || '',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    // Access token: short-lived (15 minutes)
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    accessExpiresInSeconds: parseInt(process.env.JWT_ACCESS_EXPIRES_IN_SECONDS || '900', 10),
    // Refresh token: longer-lived (7 days)
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    // Legacy support (deprecated)
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  },
  paths: {
    webhookPrefix: process.env.WEBHOOK_PATH_PREFIX || '/webhook',
    apiPrefix: process.env.API_PATH_PREFIX || '/api/v1',
  },
  security: {
    // Rate limiting
    rateLimit: {
      max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
      timeWindow: process.env.RATE_LIMIT_WINDOW || '1 minute',
    },
  },
};

export function validateConfig() {
  const errors: string[] = [];

  // Required in production
  const requiredInProduction = [
    { key: 'GITHUB_CLIENT_ID', value: config.github.clientId },
    { key: 'GITHUB_CLIENT_SECRET', value: config.github.clientSecret },
    { key: 'JWT_SECRET', value: config.jwt.secret, invalidValues: ['your-super-secret-jwt-key'] },
    { key: 'GITHUB_WEBHOOK_SECRET', value: config.github.webhookSecret },
  ];

  if (config.server.env === 'production') {
    for (const { key, value, invalidValues } of requiredInProduction) {
      if (!value) {
        errors.push(`Missing required environment variable: ${key}`);
      } else if (invalidValues && invalidValues.includes(value)) {
        errors.push(`Invalid default value for ${key}. Please set a secure value.`);
      }
    }

    // JWT secret should be at least 32 characters
    if (config.jwt.secret && config.jwt.secret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters long');
    }

    // GITHUB_WEBHOOK_SECRET should be at least 20 characters
    if (config.github.webhookSecret && config.github.webhookSecret.length < 20) {
      errors.push('GITHUB_WEBHOOK_SECRET should be at least 20 characters long');
    }
  }

  // Warnings for development
  if (config.server.env !== 'production') {
    if (!config.github.webhookSecret) {
      console.warn('⚠️  WARNING: GITHUB_WEBHOOK_SECRET is not set. Webhook signature verification will be skipped in development.');
    }
    if (config.jwt.secret === 'your-super-secret-jwt-key') {
      console.warn('⚠️  WARNING: Using default JWT_SECRET. This is insecure for production.');
    }
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.map(e => `  - ${e}`).join('\n')}`);
  }
}
