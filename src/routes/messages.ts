import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { authenticate, getUserFromToken } from '../middleware/auth';
import { natsService } from '../services/nats';
import { githubService } from '../services/github';
import { redisService } from '../services/redis';
import { prisma } from '../app';
import { PullMessagesRequest, PullMessagesResponse } from '../types';

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

        let filterSubjects = await redisService.getCachedUserPermissions(user.userId);

        if (!filterSubjects) {
          filterSubjects = await githubService.getAccessibleSubjects(dbUser.accessToken);
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

        const messages = await natsService.pullMessages(consumerName, batch);

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
          messages,
          nextCursor: messages.length > 0 ? messages[messages.length - 1].id : undefined,
          hasMore: consumerInfo.num_pending > 0,
        };

        return reply.send(response);
      } catch (error: any) {
        app.log.error('Pull messages error:', error);
        return reply.code(500).send({
          error: 'Failed to pull messages',
          message: error.message,
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
          message: error.message,
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
          message: error.message,
        });
      }
    }
  );
}

export default messagesRoutes;
