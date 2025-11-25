import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { natsService } from '../services/nats';
import { prisma } from '../app';
import { WebhookMessage } from '../types';
import crypto from 'crypto';

interface WebhookParams {
  '*': string;
}

async function webhookRoutes(app: FastifyInstance) {
  app.addContentTypeParser('*', { parseAs: 'buffer' }, async (req, payload: Buffer) => {
    return payload;
  });

  app.post<{ Params: WebhookParams }>(
    '/*',
    async (request: FastifyRequest<{ Params: WebhookParams }>, reply: FastifyReply) => {
      const fullPath = `/webhook/${request.params['*'] || ''}`;
      const startTime = Date.now();

      try {
        const rawBody = request.body as Buffer;
        let payload: unknown;

        try {
          payload = JSON.parse(rawBody.toString('utf-8'));
        } catch {
          payload = rawBody.toString('utf-8');
        }

        const headers: Record<string, string> = {};
        Object.keys(request.headers).forEach((key) => {
          const value = request.headers[key];
          if (typeof value === 'string') {
            headers[key] = value;
          } else if (Array.isArray(value)) {
            headers[key] = value.join(', ');
          }
        });

        const source = detectWebhookSource(fullPath, headers);

        if (source === 'github') {
          const isValid = verifyGitHubSignature(
            rawBody,
            headers['x-hub-signature-256'] || headers['x-hub-signature']
          );
          if (!isValid && process.env.NODE_ENV === 'production') {
            return reply.code(401).send({ error: 'Invalid signature' });
          }
        }

        const webhookMessage: WebhookMessage = {
          webhookPath: fullPath,
          source,
          method: request.method,
          headers,
          payload,
          receivedAt: new Date(),
        };

        await natsService.publishWebhook(webhookMessage);

        await prisma.webhookLog.create({
          data: {
            webhookPath: fullPath,
            natsSubject: natsService.webhookPathToSubject(fullPath),
            source,
            method: request.method,
            headers,
            payloadSize: rawBody.length,
            statusCode: 202,
            receivedAt: webhookMessage.receivedAt,
          },
        });

        const duration = Date.now() - startTime;
        app.log.info(`Webhook received: ${fullPath} [${source}] (${duration}ms)`);

        return reply.code(202).send({
          status: 'accepted',
          webhookPath: fullPath,
          source,
          receivedAt: webhookMessage.receivedAt,
        });
      } catch (error: any) {
        app.log.error(`Webhook error: ${fullPath}`, error);

        await prisma.webhookLog.create({
          data: {
            webhookPath: fullPath,
            natsSubject: natsService.webhookPathToSubject(fullPath),
            source: detectWebhookSource(fullPath, {}),
            method: request.method,
            headers: {},
            payloadSize: 0,
            statusCode: 500,
            errorMessage: error.message,
            receivedAt: new Date(),
          },
        });

        return reply.code(500).send({
          error: 'Internal server error',
          message: error.message,
        });
      }
    }
  );
}

function detectWebhookSource(path: string, headers: Record<string, string>): string {
  if (path.includes('/github/') || headers['x-github-event']) {
    return 'github';
  }
  if (path.includes('/jira/') || headers['x-atlassian-webhook-identifier']) {
    return 'jira';
  }
  if (path.includes('/gitlab/') || headers['x-gitlab-event']) {
    return 'gitlab';
  }

  const parts = path.split('/').filter(Boolean);
  if (parts.length >= 2) {
    return parts[1];
  }

  return 'unknown';
}

function verifyGitHubSignature(payload: Buffer, signature?: string): boolean {
  if (!signature) return false;

  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    return true;
  }

  const algorithm = signature.startsWith('sha256=') ? 'sha256' : 'sha1';
  const expectedSignature = signature.replace(/^sha(1|256)=/, '');

  const hmac = crypto.createHmac(algorithm, secret);
  hmac.update(payload);
  const calculatedSignature = hmac.digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(calculatedSignature)
  );
}

export default webhookRoutes;
