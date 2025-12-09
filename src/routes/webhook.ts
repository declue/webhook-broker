import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { natsService } from '../services/nats';
import { prisma } from '../app';
import { config } from '../config';
import { WebhookMessage } from '../types';
import crypto from 'crypto';
import {
  webhookReceivedTotal,
  webhookProcessingDuration,
} from '../services/metrics';

interface WebhookParams {
  '*': string;
}

async function webhookRoutes(app: FastifyInstance) {
  app.addContentTypeParser('*', { parseAs: 'buffer' }, async (_req: FastifyRequest, payload: Buffer) => {
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

        // Validate webhook signature based on source
        const signatureValidation = validateWebhookSignature(source, rawBody, headers);
        if (!signatureValidation.valid) {
          app.log.warn(`Webhook signature validation failed for ${source}: ${signatureValidation.reason}`);
          return reply.code(401).send({
            error: 'Signature verification failed',
            message: signatureValidation.reason,
          });
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

        // Record metrics
        webhookReceivedTotal.inc({ source, status: 'success' });
        webhookProcessingDuration.observe({ source }, duration / 1000);

        return reply.code(202).send({
          status: 'accepted',
          webhookPath: fullPath,
          source,
          receivedAt: webhookMessage.receivedAt,
        });
      } catch (error: any) {
        app.log.error(`Webhook error: ${fullPath}`, error);
        webhookReceivedTotal.inc({ source: detectWebhookSource(fullPath, {}), status: 'error' });

        await prisma.webhookLog.create({
          data: {
            webhookPath: fullPath,
            natsSubject: natsService.webhookPathToSubject(fullPath),
            source: detectWebhookSource(fullPath, {}),
            method: request.method,
            headers: {},
            payloadSize: 0,
            statusCode: 500,
            errorMessage: config.server.env === 'production' ? 'Internal error' : error.message,
            receivedAt: new Date(),
          },
        });

        return reply.code(500).send({
          error: 'Internal server error',
          // Don't expose internal error details in production
          ...(config.server.env !== 'production' && { message: error.message }),
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

interface SignatureValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validates webhook signature based on source
 * Returns validation result with reason if failed
 */
function validateWebhookSignature(
  source: string,
  payload: Buffer,
  headers: Record<string, string>
): SignatureValidationResult {
  switch (source) {
    case 'github':
      return validateGitHubSignature(payload, headers);
    case 'gitlab':
      return validateGitLabSignature(headers);
    case 'jira':
      // Jira uses different authentication methods
      return { valid: true };
    default:
      // Unknown sources - allow in development, reject in production
      if (config.server.env === 'production') {
        return { valid: false, reason: 'Unknown webhook source' };
      }
      return { valid: true };
  }
}

/**
 * Validates GitHub webhook signature using HMAC-SHA256
 * @see https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 */
function validateGitHubSignature(
  payload: Buffer,
  headers: Record<string, string>
): SignatureValidationResult {
  const signature = headers['x-hub-signature-256'] || headers['x-hub-signature'];
  const secret = config.github.webhookSecret;

  // In production, signature and secret are required
  if (config.server.env === 'production') {
    if (!secret) {
      return { valid: false, reason: 'Webhook secret not configured' };
    }
    if (!signature) {
      return { valid: false, reason: 'Missing signature header' };
    }
  } else {
    // In development, warn but allow if not configured
    if (!secret) {
      console.warn('⚠️  Skipping GitHub signature verification: GITHUB_WEBHOOK_SECRET not set');
      return { valid: true };
    }
    if (!signature) {
      return { valid: false, reason: 'Missing signature header' };
    }
  }

  // Determine algorithm from signature prefix
  const isSha256 = signature.startsWith('sha256=');
  const algorithm = isSha256 ? 'sha256' : 'sha1';

  // Prefer SHA-256, warn if using SHA-1
  if (!isSha256) {
    console.warn('⚠️  Received SHA-1 signature. Consider configuring GitHub webhook to use SHA-256.');
  }

  // Extract the hex signature
  const expectedSignature = signature.replace(/^sha(1|256)=/, '');

  // Calculate HMAC
  const hmac = crypto.createHmac(algorithm, secret);
  hmac.update(payload);
  const calculatedSignature = hmac.digest('hex');

  // Use constant-time comparison to prevent timing attacks
  try {
    const isValid = crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(calculatedSignature, 'hex')
    );

    if (!isValid) {
      return { valid: false, reason: 'Signature mismatch' };
    }
    return { valid: true };
  } catch (error) {
    // timingSafeEqual throws if buffers have different lengths
    return { valid: false, reason: 'Invalid signature format' };
  }
}

/**
 * Validates GitLab webhook token
 * @see https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#validate-payloads-by-using-a-secret-token
 */
function validateGitLabSignature(headers: Record<string, string>): SignatureValidationResult {
  const token = headers['x-gitlab-token'];
  const secret = process.env.GITLAB_WEBHOOK_SECRET;

  // If no secret configured, allow (but warn in production)
  if (!secret) {
    if (config.server.env === 'production') {
      console.warn('⚠️  GITLAB_WEBHOOK_SECRET not set. Consider configuring it for security.');
    }
    return { valid: true };
  }

  if (!token) {
    return { valid: false, reason: 'Missing X-Gitlab-Token header' };
  }

  // Use constant-time comparison
  try {
    const isValid = crypto.timingSafeEqual(
      Buffer.from(token),
      Buffer.from(secret)
    );

    if (!isValid) {
      return { valid: false, reason: 'Token mismatch' };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: 'Invalid token format' };
  }
}

export default webhookRoutes;
