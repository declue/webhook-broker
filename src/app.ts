import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { config } from './config';
import { PrismaClient } from '@prisma/client';
import { natsService } from './services/nats';
import { redisService } from './services/redis';
import webhookRoutes from './routes/webhook';
import authRoutes from './routes/auth';
import messagesRoutes from './routes/messages';

export const prisma = new PrismaClient();

export async function buildApp(): Promise<FastifyInstance> {
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
  });

  // CORS
  await app.register(cors, {
    origin: config.server.env === 'production' ? false : true,
    credentials: true,
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

  // Graceful shutdown
  app.addHook('onClose', async () => {
    await prisma.$disconnect();
    await natsService.disconnect();
    await redisService.disconnect();
  });

  return app;
}
