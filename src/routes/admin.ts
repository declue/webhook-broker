import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { authenticateAdmin, getUserFromToken } from '../middleware/auth';
import { prisma } from '../app';
import { natsService } from '../services/nats';
import { redisService } from '../services/redis';

interface UserUpdateBody {
  role?: 'USER' | 'ADMIN';
  isActive?: boolean;
}

interface SettingUpdateBody {
  value: string;
  description?: string;
}

interface PaginationQuery {
  page?: string;
  limit?: string;
  search?: string;
}

// Input validation constants
const MAX_SEARCH_LENGTH = 100;
const MAX_SETTING_VALUE_LENGTH = 10000;
const MAX_SETTING_DESCRIPTION_LENGTH = 500;

// Input sanitization helpers
function sanitizeSearch(search: string | undefined): string | undefined {
  if (!search) return undefined;
  // Truncate to max length and trim whitespace
  return search.substring(0, MAX_SEARCH_LENGTH).trim() || undefined;
}

function validatePositiveInt(value: string | undefined, defaultVal: number, max: number): number {
  if (!value) return defaultVal;
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed < 1) return defaultVal;
  return Math.min(parsed, max);
}

function validateId(id: string): { valid: true; value: number } | { valid: false; error: string } {
  const parsed = parseInt(id, 10);
  if (isNaN(parsed) || parsed < 1) {
    return { valid: false, error: 'Invalid ID format' };
  }
  return { valid: true, value: parsed };
}

function validateBigIntId(id: string): { valid: true; value: bigint } | { valid: false; error: string } {
  try {
    const parsed = BigInt(id);
    if (parsed < 1n) {
      return { valid: false, error: 'Invalid ID format' };
    }
    return { valid: true, value: parsed };
  } catch {
    return { valid: false, error: 'Invalid ID format' };
  }
}

// Admin-specific rate limit configuration
const ADMIN_RATE_LIMIT = {
  max: 30, // 30 requests per minute for admin endpoints
  timeWindow: '1 minute',
};

async function adminRoutes(app: FastifyInstance) {
  // Apply stricter rate limiting for admin routes
  app.addHook('onRequest', async (request, reply) => {
    // Rate limit key based on user ID from JWT
    const user = request.user as { userId?: number } | undefined;
    const key = `admin_rate_limit:${user?.userId || request.ip}`;

    const current = await redisService.get<number>(key);
    const count = (current || 0) + 1;

    if (count > ADMIN_RATE_LIMIT.max) {
      return reply.code(429).send({
        error: 'Too Many Requests',
        message: 'Admin API rate limit exceeded. Please try again later.',
      });
    }

    await redisService.set(key, count, 60); // 60 seconds TTL
  });

  // All admin routes require admin authentication
  app.addHook('onRequest', authenticateAdmin);

  // ==================== Dashboard Stats ====================

  app.get('/stats', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const [
        userCount,
        activeUserCount,
        consumerCount,
        webhookLogCount,
        recentWebhooks,
      ] = await Promise.all([
        prisma.user.count(),
        prisma.user.count({ where: { isActive: true } }),
        prisma.consumer.count(),
        prisma.webhookLog.count(),
        prisma.webhookLog.count({
          where: {
            receivedAt: {
              gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
            },
          },
        }),
      ]);

      // Get NATS stats
      const natsHealth = await natsService.healthCheck();

      // Get Redis stats
      const redisHealth = await redisService.healthCheck();

      return reply.send({
        users: {
          total: userCount,
          active: activeUserCount,
        },
        consumers: consumerCount,
        webhooks: {
          total: webhookLogCount,
          last24h: recentWebhooks,
        },
        services: {
          nats: natsHealth,
          redis: redisHealth,
        },
        serverUptime: process.uptime(),
      });
    } catch (error: any) {
      app.log.error('Admin stats error:', error);
      return reply.code(500).send({ error: 'Failed to get stats' });
    }
  });

  // ==================== User Management ====================

  app.get<{ Querystring: PaginationQuery }>(
    '/users',
    async (request: FastifyRequest<{ Querystring: PaginationQuery }>, reply: FastifyReply) => {
      const page = validatePositiveInt(request.query.page, 1, 10000);
      const limit = validatePositiveInt(request.query.limit, 20, 100);
      const search = sanitizeSearch(request.query.search);

      try {
        const where = search
          ? {
              OR: [
                { username: { contains: search, mode: 'insensitive' as const } },
                { email: { contains: search, mode: 'insensitive' as const } },
              ],
            }
          : {};

        const [users, total] = await Promise.all([
          prisma.user.findMany({
            where,
            select: {
              id: true,
              githubId: true,
              username: true,
              email: true,
              avatarUrl: true,
              role: true,
              isActive: true,
              createdAt: true,
              updatedAt: true,
              _count: {
                select: { consumers: true },
              },
            },
            skip: (page - 1) * limit,
            take: limit,
            orderBy: { createdAt: 'desc' },
          }),
          prisma.user.count({ where }),
        ]);

        return reply.send({
          users,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error: any) {
        app.log.error('Admin get users error:', error);
        return reply.code(500).send({ error: 'Failed to get users' });
      }
    }
  );

  app.get<{ Params: { id: string } }>(
    '/users/:id',
    async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const idResult = validateId(request.params.id);
      if (!idResult.valid) {
        return reply.code(400).send({ error: idResult.error });
      }
      const userId = idResult.value;

      try {
        const user = await prisma.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            githubId: true,
            username: true,
            email: true,
            avatarUrl: true,
            role: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
            consumers: {
              select: {
                id: true,
                consumerName: true,
                filterSubjects: true,
                pendingMessages: true,
                deliveredCount: true,
                ackCount: true,
                createdAt: true,
              },
            },
          },
        });

        if (!user) {
          return reply.code(404).send({ error: 'User not found' });
        }

        return reply.send(user);
      } catch (error: any) {
        app.log.error('Admin get user error:', error);
        return reply.code(500).send({ error: 'Failed to get user' });
      }
    }
  );

  app.patch<{ Params: { id: string }; Body: UserUpdateBody }>(
    '/users/:id',
    async (
      request: FastifyRequest<{ Params: { id: string }; Body: UserUpdateBody }>,
      reply: FastifyReply
    ) => {
      const idResult = validateId(request.params.id);
      if (!idResult.valid) {
        return reply.code(400).send({ error: idResult.error });
      }
      const userId = idResult.value;
      const { role, isActive } = request.body;
      const adminUser = getUserFromToken(request);

      // Validate role if provided
      if (role !== undefined && role !== 'USER' && role !== 'ADMIN') {
        return reply.code(400).send({ error: 'Invalid role. Must be USER or ADMIN' });
      }

      try {
        // Prevent self-demotion
        if (userId === adminUser.userId && role === 'USER') {
          return reply.code(400).send({ error: 'Cannot demote yourself' });
        }

        const oldUser = await prisma.user.findUnique({
          where: { id: userId },
          select: { role: true, isActive: true },
        });

        if (!oldUser) {
          return reply.code(404).send({ error: 'User not found' });
        }

        const updateData: { role?: 'USER' | 'ADMIN'; isActive?: boolean } = {};
        if (role !== undefined) updateData.role = role;
        if (isActive !== undefined) updateData.isActive = isActive;

        const user = await prisma.user.update({
          where: { id: userId },
          data: updateData,
          select: {
            id: true,
            username: true,
            role: true,
            isActive: true,
          },
        });

        // Create audit log
        await prisma.auditLog.create({
          data: {
            userId: adminUser.userId,
            action: 'user.update',
            targetType: 'user',
            targetId: String(userId),
            oldValue: oldUser,
            newValue: updateData,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
          },
        });

        // Invalidate user's cache if deactivated
        if (isActive === false) {
          await redisService.invalidateUserPermissions(userId);
        }

        app.log.info(`Admin ${adminUser.username} updated user ${userId}`);

        return reply.send(user);
      } catch (error: any) {
        app.log.error('Admin update user error:', error);
        return reply.code(500).send({ error: 'Failed to update user' });
      }
    }
  );

  // ==================== Webhook Logs ====================

  app.get<{ Querystring: PaginationQuery & { source?: string; status?: string } }>(
    '/webhooks',
    async (
      request: FastifyRequest<{ Querystring: PaginationQuery & { source?: string; status?: string } }>,
      reply: FastifyReply
    ) => {
      const page = validatePositiveInt(request.query.page, 1, 10000);
      const limit = validatePositiveInt(request.query.limit, 50, 100);
      // Sanitize source input - only allow alphanumeric and underscore
      const source = request.query.source?.replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 50);
      const status = request.query.status;

      try {
        const where: any = {};
        if (source) where.source = source;
        if (status === 'success') where.statusCode = { lt: 400 };
        if (status === 'error') where.statusCode = { gte: 400 };

        const [webhooks, total] = await Promise.all([
          prisma.webhookLog.findMany({
            where,
            select: {
              id: true,
              webhookPath: true,
              source: true,
              method: true,
              payloadSize: true,
              statusCode: true,
              errorMessage: true,
              receivedAt: true,
            },
            skip: (page - 1) * limit,
            take: limit,
            orderBy: { receivedAt: 'desc' },
          }),
          prisma.webhookLog.count({ where }),
        ]);

        return reply.send({
          webhooks,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error: any) {
        app.log.error('Admin get webhooks error:', error);
        return reply.code(500).send({ error: 'Failed to get webhooks' });
      }
    }
  );

  app.get<{ Params: { id: string } }>(
    '/webhooks/:id',
    async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const idResult = validateBigIntId(request.params.id);
      if (!idResult.valid) {
        return reply.code(400).send({ error: idResult.error });
      }
      const webhookId = idResult.value;

      try {
        const webhook = await prisma.webhookLog.findUnique({
          where: { id: webhookId },
        });

        if (!webhook) {
          return reply.code(404).send({ error: 'Webhook log not found' });
        }

        return reply.send({
          ...webhook,
          id: webhook.id.toString(),
        });
      } catch (error: any) {
        app.log.error('Admin get webhook error:', error);
        return reply.code(500).send({ error: 'Failed to get webhook' });
      }
    }
  );

  // ==================== Consumer Management ====================

  app.get<{ Querystring: PaginationQuery }>(
    '/consumers',
    async (request: FastifyRequest<{ Querystring: PaginationQuery }>, reply: FastifyReply) => {
      const page = validatePositiveInt(request.query.page, 1, 10000);
      const limit = validatePositiveInt(request.query.limit, 20, 100);

      try {
        const [consumers, total] = await Promise.all([
          prisma.consumer.findMany({
            include: {
              user: {
                select: {
                  id: true,
                  username: true,
                  avatarUrl: true,
                },
              },
            },
            skip: (page - 1) * limit,
            take: limit,
            orderBy: { createdAt: 'desc' },
          }),
          prisma.consumer.count(),
        ]);

        return reply.send({
          consumers: consumers.map((c) => ({
            ...c,
            lastSequence: c.lastSequence?.toString(),
            lastAck: c.lastAck?.toString(),
            deliveredCount: c.deliveredCount.toString(),
            ackCount: c.ackCount.toString(),
          })),
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error: any) {
        app.log.error('Admin get consumers error:', error);
        return reply.code(500).send({ error: 'Failed to get consumers' });
      }
    }
  );

  app.delete<{ Params: { id: string } }>(
    '/consumers/:id',
    async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const idResult = validateId(request.params.id);
      if (!idResult.valid) {
        return reply.code(400).send({ error: idResult.error });
      }
      const consumerId = idResult.value;
      const adminUser = getUserFromToken(request);

      try {
        const consumer = await prisma.consumer.findUnique({
          where: { id: consumerId },
        });

        if (!consumer) {
          return reply.code(404).send({ error: 'Consumer not found' });
        }

        // Delete from NATS
        try {
          await natsService.deleteConsumer(consumer.consumerName);
        } catch (err) {
          app.log.warn(`Failed to delete NATS consumer: ${consumer.consumerName}`);
        }

        // Delete from database
        await prisma.consumer.delete({
          where: { id: consumerId },
        });

        // Create audit log - convert BigInt values to strings for JSON serialization
        await prisma.auditLog.create({
          data: {
            userId: adminUser.userId,
            action: 'consumer.delete',
            targetType: 'consumer',
            targetId: String(consumerId),
            oldValue: {
              ...consumer,
              lastSequence: consumer.lastSequence?.toString() ?? null,
              lastAck: consumer.lastAck?.toString() ?? null,
              deliveredCount: consumer.deliveredCount.toString(),
              ackCount: consumer.ackCount.toString(),
            },
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
          },
        });

        app.log.info(`Admin ${adminUser.username} deleted consumer ${consumerId}`);

        return reply.send({ message: 'Consumer deleted successfully' });
      } catch (error: any) {
        app.log.error('Admin delete consumer error:', error);
        return reply.code(500).send({ error: 'Failed to delete consumer' });
      }
    }
  );

  // ==================== System Settings ====================

  app.get('/settings', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const settings = await prisma.systemSetting.findMany({
        orderBy: { key: 'asc' },
      });

      return reply.send({ settings });
    } catch (error: any) {
      app.log.error('Admin get settings error:', error);
      return reply.code(500).send({ error: 'Failed to get settings' });
    }
  });

  app.put<{ Params: { key: string }; Body: SettingUpdateBody }>(
    '/settings/:key',
    async (
      request: FastifyRequest<{ Params: { key: string }; Body: SettingUpdateBody }>,
      reply: FastifyReply
    ) => {
      const { key } = request.params;
      const { value, description } = request.body;
      const adminUser = getUserFromToken(request);

      // Validate key format - alphanumeric, underscore, dot only
      if (!/^[a-zA-Z0-9_.-]+$/.test(key) || key.length > 100) {
        return reply.code(400).send({ error: 'Invalid setting key format' });
      }

      // Validate value
      if (!value || typeof value !== 'string') {
        return reply.code(400).send({ error: 'Setting value is required' });
      }
      if (value.length > MAX_SETTING_VALUE_LENGTH) {
        return reply.code(400).send({ error: `Setting value exceeds maximum length of ${MAX_SETTING_VALUE_LENGTH}` });
      }

      // Validate description if provided
      if (description && description.length > MAX_SETTING_DESCRIPTION_LENGTH) {
        return reply.code(400).send({ error: `Description exceeds maximum length of ${MAX_SETTING_DESCRIPTION_LENGTH}` });
      }

      try {
        const oldSetting = await prisma.systemSetting.findUnique({
          where: { key },
        });

        const setting = await prisma.systemSetting.upsert({
          where: { key },
          create: {
            key,
            value,
            description,
            updatedBy: adminUser.userId,
          },
          update: {
            value,
            description,
            updatedBy: adminUser.userId,
          },
        });

        // Create audit log - handle null oldSetting
        await prisma.auditLog.create({
          data: {
            userId: adminUser.userId,
            action: 'settings.update',
            targetType: 'setting',
            targetId: key,
            oldValue: oldSetting ?? undefined,
            newValue: { value, description },
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
          },
        });

        app.log.info(`Admin ${adminUser.username} updated setting ${key}`);

        return reply.send(setting);
      } catch (error: any) {
        app.log.error('Admin update setting error:', error);
        return reply.code(500).send({ error: 'Failed to update setting' });
      }
    }
  );

  // ==================== Audit Logs ====================

  app.get<{ Querystring: PaginationQuery & { action?: string; userId?: string } }>(
    '/audit-logs',
    async (
      request: FastifyRequest<{ Querystring: PaginationQuery & { action?: string; userId?: string } }>,
      reply: FastifyReply
    ) => {
      const page = validatePositiveInt(request.query.page, 1, 10000);
      const limit = validatePositiveInt(request.query.limit, 50, 100);
      // Sanitize action input
      const action = request.query.action?.replace(/[^a-zA-Z0-9_.-]/g, '').substring(0, 50) || undefined;
      // Validate userId if provided
      let userId: number | undefined;
      if (request.query.userId) {
        const userIdResult = validateId(request.query.userId);
        if (!userIdResult.valid) {
          return reply.code(400).send({ error: 'Invalid userId format' });
        }
        userId = userIdResult.value;
      }

      try {
        const where: any = {};
        if (action) where.action = action;
        if (userId) where.userId = userId;

        const [logs, total] = await Promise.all([
          prisma.auditLog.findMany({
            where,
            skip: (page - 1) * limit,
            take: limit,
            orderBy: { createdAt: 'desc' },
          }),
          prisma.auditLog.count({ where }),
        ]);

        return reply.send({
          logs: logs.map((log) => ({
            ...log,
            id: log.id.toString(),
          })),
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error: any) {
        app.log.error('Admin get audit logs error:', error);
        return reply.code(500).send({ error: 'Failed to get audit logs' });
      }
    }
  );

  // ==================== Dead Letter Queue ====================

  app.get<{ Querystring: { limit?: string } }>(
    '/dlq',
    async (request: FastifyRequest<{ Querystring: { limit?: string } }>, reply: FastifyReply) => {
      const limit = validatePositiveInt(request.query.limit, 20, 100);

      try {
        const messages = await natsService.getDLQMessages(limit);

        return reply.send({
          messages: messages.map((m) => ({
            originalSubject: m.originalSubject,
            originalSeq: m.originalSeq?.toString(),
            reason: m.reason,
            movedAt: m.movedAt,
          })),
          count: messages.length,
        });
      } catch (error: any) {
        app.log.error('Admin get DLQ error:', error);
        return reply.code(500).send({ error: 'Failed to get DLQ messages' });
      }
    }
  );

  // ==================== Cache Management ====================

  app.post<{ Params: { userId: string } }>(
    '/cache/invalidate/user/:userId',
    async (request: FastifyRequest<{ Params: { userId: string } }>, reply: FastifyReply) => {
      const idResult = validateId(request.params.userId);
      if (!idResult.valid) {
        return reply.code(400).send({ error: idResult.error });
      }
      const userId = idResult.value;
      const adminUser = getUserFromToken(request);

      try {
        await redisService.invalidateUserPermissions(userId);

        await prisma.auditLog.create({
          data: {
            userId: adminUser.userId,
            action: 'cache.invalidate',
            targetType: 'user',
            targetId: String(userId),
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
          },
        });

        return reply.send({ message: `Cache invalidated for user ${userId}` });
      } catch (error: any) {
        app.log.error('Admin invalidate cache error:', error);
        return reply.code(500).send({ error: 'Failed to invalidate cache' });
      }
    }
  );
}

export default adminRoutes;
