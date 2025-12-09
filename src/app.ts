import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import helmet from '@fastify/helmet';
import { config, validateConfig } from './config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { natsService } from './services/nats';
import { redisService } from './services/redis';
import webhookRoutes from './routes/webhook';
import authRoutes from './routes/auth';
import messagesRoutes from './routes/messages';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
export const prisma = new PrismaClient({ adapter });

export async function buildApp(): Promise<FastifyInstance> {
  // Validate configuration before starting
  validateConfig();

  const app = Fastify({
    logger: {
      level: config.server.env === 'production' ? 'info' : 'debug',
      transport: config.server.env === 'development' ? {
        target: 'pino-pretty',
        options: {
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      } : undefined,
    },
    // Trust proxy for correct IP detection behind load balancer
    trustProxy: true,
  });

  // Security headers using Helmet
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  });

  // CORS
  await app.register(cors, {
    origin: config.server.env === 'production'
      ? (process.env.CORS_ORIGIN || false)
      : true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  });

  // Rate limiting
  await app.register(rateLimit, {
    max: config.security.rateLimit.max,
    timeWindow: config.security.rateLimit.timeWindow,
    // Use Redis for distributed rate limiting in production
    // redis: redisService.getClient(),
    keyGenerator: (request) => {
      // Use user ID if authenticated, otherwise use IP
      const user = request.user as { userId?: number } | undefined;
      return user?.userId ? `user:${user.userId}` : request.ip;
    },
    errorResponseBuilder: (request, context) => ({
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Try again in ${Math.ceil(context.ttl / 1000)} seconds.`,
      retryAfter: Math.ceil(context.ttl / 1000),
    }),
    // Skip rate limiting for health checks
    allowList: (request) => {
      return request.url === '/health';
    },
  });

  // JWT
  await app.register(jwt, {
    secret: config.jwt.secret,
  });

  // Initialize services
  await natsService.connect();
  await redisService.connect();

  // Register routes
  await app.register(webhookRoutes, { prefix: config.paths.webhookPrefix });
  await app.register(authRoutes, { prefix: `${config.paths.apiPrefix}/auth` });
  await app.register(messagesRoutes, { prefix: `${config.paths.apiPrefix}/messages` });

  // Health check
  app.get('/health', async () => {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  });

  // Security-focused error handler
  app.setErrorHandler((error, request, reply) => {
    app.log.error(error);

    // Don't expose internal errors in production
    if (config.server.env === 'production') {
      if (error.statusCode && error.statusCode < 500) {
        return reply.status(error.statusCode).send({
          error: error.name || 'Error',
          message: error.message,
        });
      }
      return reply.status(500).send({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred',
      });
    }

    // In development, show full error details
    return reply.status(error.statusCode || 500).send({
      error: error.name || 'Error',
      message: error.message,
      stack: error.stack,
    });
  });

  // Graceful shutdown
  app.addHook('onClose', async () => {
    await prisma.$disconnect();
    await natsService.disconnect();
    await redisService.disconnect();
  });

  return app;
}
