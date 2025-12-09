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

// Maximum payload size: 1MB
const MAX_PAYLOAD_SIZE = 1 * 1024 * 1024;

// Headers to exclude from storage (may contain sensitive data)
const SENSITIVE_HEADERS = [
  'authorization',
  'cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-secret',
  'proxy-authorization',
];

/**
 * Filters out sensitive headers before storing in database
 * Preserves webhook-specific headers needed for debugging
 */
function filterSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (!SENSITIVE_HEADERS.includes(lowerKey)) {
      filtered[key] = value;
    } else {
      filtered[key] = '[REDACTED]';
    }
  }
  return filtered;
}

async function webhookRoutes(app: FastifyInstance) {
  app.addContentTypeParser('*', { parseAs: 'buffer' }, async (_req: FastifyRequest, payload: Buffer) => {
    // Enforce payload size limit to prevent DoS
    if (payload.length > MAX_PAYLOAD_SIZE) {
      const error = new Error(`Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`);
      (error as any).statusCode = 413;
      throw error;
    }
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
          // Log detailed reason internally, but don't expose to client
          app.log.warn(`Webhook signature validation failed for ${source}: ${signatureValidation.reason}`);
          return reply.code(401).send({
            error: 'Signature verification failed',
            // Don't expose detailed reason to prevent information leakage
          });
        }

        // Filter sensitive headers before storing/publishing
        const safeHeaders = filterSensitiveHeaders(headers);

        const webhookMessage: WebhookMessage = {
          webhookPath: fullPath,
          source,
          method: request.method,
          headers: safeHeaders,
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
            headers: safeHeaders,
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
      return validateJiraSignature(payload, headers);
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
 * Validates Jira webhook signature using HMAC-SHA256
 * @see https://developer.atlassian.com/cloud/jira/platform/webhooks/#verify-a-webhook
 */
function validateJiraSignature(
  payload: Buffer,
  headers: Record<string, string>
): SignatureValidationResult {
  const signature = headers['x-hub-signature'] || headers['x-atlassian-signature'];
  const secret = config.jira?.webhookSecret || process.env.JIRA_WEBHOOK_SECRET || '';

  // In production, secret is required
  if (config.server.env === 'production') {
    if (!secret) {
      return { valid: false, reason: 'Jira webhook secret not configured' };
    }
    if (!signature) {
      return { valid: false, reason: 'Missing Jira signature header' };
    }
  } else {
    // In development, warn but allow if not configured
    if (!secret) {
      console.warn('⚠️  Skipping Jira signature verification: JIRA_WEBHOOK_SECRET not set');
      return { valid: true };
    }
    if (!signature) {
      return { valid: false, reason: 'Missing Jira signature header' };
    }
  }

  // Extract the hex signature (format: sha256=<signature>)
  const expectedSignature = signature.replace(/^sha256=/, '');

  // Calculate HMAC-SHA256
  const hmac = crypto.createHmac('sha256', secret);
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
  } catch {
    return { valid: false, reason: 'Invalid signature format' };
  }
}

/**
 * Validates GitLab webhook token
 * @see https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#validate-payloads-by-using-a-secret-token
 */
function validateGitLabSignature(headers: Record<string, string>): SignatureValidationResult {
  const token = headers['x-gitlab-token'];
  const secret = config.gitlab.webhookSecret;

  // In production, secret is required
  if (config.server.env === 'production') {
    if (!secret) {
      return { valid: false, reason: 'GitLab webhook secret not configured' };
    }
    if (!token) {
      return { valid: false, reason: 'Missing X-Gitlab-Token header' };
    }
  } else {
    // In development, warn but allow if not configured
    if (!secret) {
      console.warn('⚠️  Skipping GitLab signature verification: GITLAB_WEBHOOK_SECRET not set');
      return { valid: true };
    }
    if (!token) {
      return { valid: false, reason: 'Missing X-Gitlab-Token header' };
    }
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
