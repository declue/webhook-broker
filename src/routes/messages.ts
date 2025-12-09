import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { authenticate, getUserFromToken } from '../middleware/auth';
import { natsService } from '../services/nats';
import { githubService, GitHubRateLimitError, GitHubAPIError } from '../services/github';
import { redisService } from '../services/redis';
import { prisma } from '../app';
import { config } from '../config';
import { PullMessagesResponse } from '../types';
import { decrypt } from '../services/crypto';

interface PullQuery {
  limit?: string;
  batch?: string;
  source?: string;
  repository?: string;
}

interface AckBody {
  messageIds: string[];
}

async function messagesRoutes(app: FastifyInstance) {
  app.get<{ Querystring: PullQuery }>(
    '/',
    { onRequest: [authenticate] },
    async (request: FastifyRequest<{ Querystring: PullQuery }>, reply: FastifyReply) => {
      const user = getUserFromToken(request);
      const limit = parseInt(request.query.limit || '10', 10);
      const batch = Math.min(limit, 100);

      try {
        const dbUser = await prisma.user.findUnique({
          where: { id: user.userId },
        });

        if (!dbUser) {
          return reply.code(404).send({ error: 'User not found' });
        }

        // Decrypt the access token for GitHub API calls
        const decryptedAccessToken = decrypt(dbUser.accessToken);

        let filterSubjects = await redisService.getCachedUserPermissions(user.userId);

        if (!filterSubjects) {
          filterSubjects = await githubService.getAccessibleSubjects(decryptedAccessToken);
          await redisService.cacheUserPermissions(user.userId, filterSubjects);
          app.log.info(`Cached ${filterSubjects.length} permissions for user ${user.userId}`);
        }

        if (filterSubjects.length === 0) {
          return reply.send({
            messages: [],
            nextCursor: undefined,
            hasMore: false,
          });
        }

        const consumerName = `user_${user.userId}`;

        let consumer = await prisma.consumer.findUnique({
          where: { consumerName },
        });

        if (!consumer) {
          await natsService.createConsumer(
            user.userId,
            consumerName,
            filterSubjects,
            true
          );

          consumer = await prisma.consumer.create({
            data: {
              userId: user.userId,
              consumerName,
              natsSubject: filterSubjects[0] || 'webhooks.>',
              filterSubjects,
            },
          });

          app.log.info(`Created consumer for user ${user.userId}`);
        } else {
          const subjectsChanged =
            JSON.stringify(consumer.filterSubjects.sort()) !==
            JSON.stringify(filterSubjects.sort());

          if (subjectsChanged) {
            await natsService.deleteConsumer(consumerName);
            await natsService.createConsumer(
              user.userId,
              consumerName,
              filterSubjects,
              false
            );

            await prisma.consumer.update({
              where: { id: consumer.id },
              data: { filterSubjects },
            });

            app.log.info(`Updated consumer permissions for user ${user.userId}`);
          }
        }

        const rawMessages = await natsService.pullMessages(consumerName, batch);

        // Filter messages by checking webhook access with GitHub API
        const accessibleMessages = [];
        for (const message of rawMessages) {
          // Check cache first
          let hasAccess = await redisService.getCachedWebhookAccess(
            user.userId,
            message.webhookPath
          );

          if (hasAccess === null) {
            // Cache miss - check with GitHub API
            hasAccess = await githubService.checkWebhookAccess(
              decryptedAccessToken,
              message.webhookPath
            );

            // Cache the result
            await redisService.cacheWebhookAccess(
              user.userId,
              message.webhookPath,
              hasAccess
            );

            app.log.debug(
              `Checked webhook access for ${message.webhookPath}: ${hasAccess ? 'granted' : 'denied'}`
            );
          }

          if (hasAccess) {
            accessibleMessages.push(message);
          } else {
            // Acknowledge and skip unauthorized messages
            await natsService.ackMessage(message);
            app.log.warn(
              `User ${user.userId} attempted to access unauthorized webhook: ${message.webhookPath}`
            );
          }
        }

        const consumerInfo = await natsService.getConsumerInfo(consumerName);

        await prisma.consumer.update({
          where: { id: consumer.id },
          data: {
            lastSequence: BigInt(consumerInfo.delivered.stream_seq),
            pendingMessages: consumerInfo.num_pending,
            deliveredCount: BigInt(consumerInfo.delivered.consumer_seq),
          },
        });

        const response: PullMessagesResponse = {
          messages: accessibleMessages,
          nextCursor: accessibleMessages.length > 0 ? accessibleMessages[accessibleMessages.length - 1].id : undefined,
          hasMore: consumerInfo.num_pending > 0,
        };

        app.log.info(
          `User ${user.userId} pulled ${accessibleMessages.length}/${rawMessages.length} messages`
        );

        return reply.send(response);
      } catch (error) {
        // Handle GitHub API rate limit errors specifically
        if (error instanceof GitHubRateLimitError) {
          app.log.warn(`GitHub rate limit hit for user ${user.userId}: ${error.message}`);
          return reply.code(429).send({
            error: 'GitHub API rate limit exceeded',
            message: 'Please try again later',
            retryAfter: Math.ceil((error.resetAt.getTime() - Date.now()) / 1000),
          });
        }

        // Handle other GitHub API errors
        if (error instanceof GitHubAPIError) {
          app.log.error(`GitHub API error for user ${user.userId}: ${error.message}`);
          return reply.code(502).send({
            error: 'GitHub API error',
            message: config.server.env === 'production'
              ? 'Failed to verify repository access'
              : error.message,
          });
        }

        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        app.log.error(`Pull messages error: ${errorMessage}`);
        return reply.code(500).send({
          error: 'Failed to pull messages',
          // Don't expose internal error details in production
          ...(config.server.env !== 'production' && { message: errorMessage }),
        });
      }
    }
  );

  app.post<{ Body: AckBody }>(
    '/ack',
    { onRequest: [authenticate] },
    async (request: FastifyRequest<{ Body: AckBody }>, reply: FastifyReply) => {
      const user = getUserFromToken(request);
      const { messageIds } = request.body;

      if (!Array.isArray(messageIds) || messageIds.length === 0) {
        return reply.code(400).send({ error: 'messageIds must be a non-empty array' });
      }

      try {
        const consumerName = `user_${user.userId}`;

        const consumer = await prisma.consumer.findUnique({
          where: { consumerName },
        });

        if (!consumer) {
          return reply.code(404).send({ error: 'Consumer not found' });
        }

        let ackCount = 0;
        for (const msgId of messageIds) {
          const msg = { _natsMsg: { ack: () => {}, seq: BigInt(msgId) } };
          await natsService.ackMessage(msg);
          ackCount++;
        }

        const consumerInfo = await natsService.getConsumerInfo(consumerName);

        await prisma.consumer.update({
          where: { id: consumer.id },
          data: {
            lastAck: BigInt(consumerInfo.ack_floor.stream_seq),
            ackCount: BigInt(Number(consumer.ackCount) + ackCount),
          },
        });

        app.log.info(`Acknowledged ${ackCount} messages for user ${user.userId}`);

        return reply.send({
          acknowledged: ackCount,
          messageIds,
        });
      } catch (error: any) {
        app.log.error('Ack messages error:', error);
        return reply.code(500).send({
          error: 'Failed to acknowledge messages',
          // Don't expose internal error details in production
          ...(config.server.env !== 'production' && { message: error.message }),
        });
      }
    }
  );

  app.get(
    '/stats',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = getUserFromToken(request);

      try {
        const consumerName = `user_${user.userId}`;

        const consumer = await prisma.consumer.findUnique({
          where: { consumerName },
        });

        if (!consumer) {
          return reply.code(404).send({ error: 'Consumer not found' });
        }

        const consumerInfo = await natsService.getConsumerInfo(consumerName);

        return reply.send({
          consumerName,
          filterSubjects: consumer.filterSubjects,
          pending: consumerInfo.num_pending,
          delivered: consumerInfo.delivered.consumer_seq,
          ackFloor: consumerInfo.ack_floor.stream_seq,
          redelivered: consumerInfo.num_redelivered,
        });
      } catch (error: any) {
        app.log.error('Get stats error:', error);
        return reply.code(500).send({
          error: 'Failed to get stats',
          // Don't expose internal error details in production
          ...(config.server.env !== 'production' && { message: error.message }),
        });
      }
    }
  );
}

export default messagesRoutes;
