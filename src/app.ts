import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import helmet from '@fastify/helmet';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { config, validateConfig } from './config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { natsService } from './services/nats';
import { redisService } from './services/redis';
import webhookRoutes from './routes/webhook';
import authRoutes from './routes/auth';
import messagesRoutes from './routes/messages';
import {
  register,
  httpRequestsTotal,
  httpRequestDuration,
} from './services/metrics';

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
    errorResponseBuilder: (_request, context) => ({
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Try again in ${Math.ceil(context.ttl / 1000)} seconds.`,
      retryAfter: Math.ceil(context.ttl / 1000),
    }),
    // Skip rate limiting for health checks
    allowList: (_request) => {
      return _request.url === '/health';
    },
  });

  // JWT
  await app.register(jwt, {
    secret: config.jwt.secret,
  });

  // Swagger documentation
  await app.register(swagger, {
    openapi: {
      openapi: '3.0.0',
      info: {
        title: 'Webhook Broker API',
        description: 'GitHub Webhook Broker with NATS JetStream - API Documentation',
        version: '1.0.0',
      },
      servers: [
        {
          url: `http://localhost:${config.server.port}`,
          description: 'Development server',
        },
      ],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
      },
      tags: [
        { name: 'Auth', description: 'Authentication endpoints' },
        { name: 'Messages', description: 'Message pull and acknowledgment' },
        { name: 'Webhook', description: 'Webhook receiver endpoints' },
        { name: 'Health', description: 'Health check endpoints' },
      ],
    },
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
    },
  });

  // Initialize services
  await natsService.connect();
  await redisService.connect();

  // Register routes
  await app.register(webhookRoutes, { prefix: config.paths.webhookPrefix });
  await app.register(authRoutes, { prefix: `${config.paths.apiPrefix}/auth` });
  await app.register(messagesRoutes, { prefix: `${config.paths.apiPrefix}/messages` });

  // Simple health check for load balancers
  app.get('/health', async () => {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  });

  // Detailed health check for monitoring
  app.get('/health/ready', async (_request, reply) => {
    const [natsHealth, redisHealth] = await Promise.all([
      natsService.healthCheck(),
      redisService.healthCheck(),
    ]);

    // Database health check
    let dbHealth: { healthy: boolean; details: Record<string, any> };
    try {
      await prisma.$queryRaw`SELECT 1`;
      dbHealth = {
        healthy: true,
        details: { connected: true },
      };
    } catch (err: any) {
      dbHealth = {
        healthy: false,
        details: { error: err.message, connected: false },
      };
    }

    const allHealthy = natsHealth.healthy && redisHealth.healthy && dbHealth.healthy;
    const statusCode = allHealthy ? 200 : 503;

    return reply.code(statusCode).send({
      status: allHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: {
        nats: natsHealth,
        redis: redisHealth,
        database: dbHealth,
      },
    });
  });

  // Liveness probe - just checks if the server is running
  app.get('/health/live', async () => {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  });

  // Prometheus metrics endpoint
  app.get('/metrics', async (_request, reply) => {
    reply.header('Content-Type', register.contentType);
    return register.metrics();
  });

  // Request metrics hook
  app.addHook('onRequest', async (request) => {
    (request as any).startTime = process.hrtime.bigint();
  });

  app.addHook('onResponse', async (request, reply) => {
    const startTime = (request as any).startTime;
    if (startTime) {
      const duration = Number(process.hrtime.bigint() - startTime) / 1e9;
      const path = request.routeOptions?.url || request.url.split('?')[0];

      // Skip metrics for the metrics endpoint itself
      if (path !== '/metrics') {
        httpRequestsTotal.inc({
          method: request.method,
          path,
          status_code: reply.statusCode.toString(),
        });

        httpRequestDuration.observe(
          { method: request.method, path },
          duration
        );
      }
    }
  });

  // Security-focused error handler
  app.setErrorHandler((error: Error & { statusCode?: number }, _request, reply) => {
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
