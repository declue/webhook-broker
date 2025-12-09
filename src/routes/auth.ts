import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'crypto';
import { config } from '../config';
import { githubService } from '../services/github';
import { redisService } from '../services/redis';
import { prisma } from '../app';
import { encrypt, generateSecureState } from '../services/crypto';
import { RefreshTokenPayloadSchema } from '../types';

// Generate a unique JWT ID
function generateJti(): string {
  return crypto.randomBytes(16).toString('hex');
}

interface CallbackQuery {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

// OAuth state TTL in seconds (10 minutes)
const STATE_TTL = 600;

async function authRoutes(app: FastifyInstance) {
  /**
   * Initiates GitHub OAuth flow
   * GET /auth/github
   */
  app.get('/github', async (request: FastifyRequest, reply: FastifyReply) => {
    // Generate cryptographically secure state
    const state = generateSecureState();

    // Store state in Redis with TTL for validation
    await redisService.set(`oauth:state:${state}`, {
      createdAt: Date.now(),
      ip: request.ip,
      userAgent: request.headers['user-agent'] || 'unknown',
    }, STATE_TTL);

    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', config.github.clientId);
    authUrl.searchParams.set('redirect_uri', config.github.callbackUrl);
    // Minimized scope - only request what's needed
    authUrl.searchParams.set('scope', 'read:user user:email');
    authUrl.searchParams.set('state', state);

    return reply.redirect(authUrl.toString());
  });

  /**
   * GitHub OAuth callback handler
   * GET /auth/github/callback
   */
  app.get<{ Querystring: CallbackQuery }>(
    '/github/callback',
    async (request: FastifyRequest<{ Querystring: CallbackQuery }>, reply: FastifyReply) => {
      const { code, state, error, error_description } = request.query;

      // Handle OAuth errors from GitHub
      if (error) {
        app.log.warn(`GitHub OAuth error: ${error} - ${error_description}`);
        return reply.code(400).send({
          error: 'Authorization failed',
          code: error,
        });
      }

      // Validate required parameters
      if (!code) {
        return reply.code(400).send({ error: 'Missing authorization code' });
      }

      if (!state) {
        return reply.code(400).send({ error: 'Missing state parameter' });
      }

      // Validate state to prevent CSRF attacks
      const stateKey = `oauth:state:${state}`;
      const storedState = await redisService.get<{
        createdAt: number;
        ip: string;
        userAgent: string;
      }>(stateKey);

      if (!storedState) {
        app.log.warn(`Invalid or expired OAuth state: ${state.substring(0, 8)}...`);
        return reply.code(400).send({
          error: 'Invalid or expired state',
          message: 'Please try logging in again',
        });
      }

      // Delete state immediately to prevent replay attacks
      await redisService.del(stateKey);

      // Optional: Verify IP hasn't changed (may cause issues with mobile networks)
      // if (storedState.ip !== request.ip) {
      //   app.log.warn(`OAuth state IP mismatch: expected ${storedState.ip}, got ${request.ip}`);
      // }

      try {
        const tokenResponse = await githubService.exchangeCodeForToken(
          code,
          config.github.clientId,
          config.github.clientSecret
        );

        const { access_token, refresh_token, expires_in } = tokenResponse;

        if (!access_token) {
          app.log.error('GitHub token exchange failed: no access_token received');
          return reply.code(500).send({ error: 'Failed to obtain access token' });
        }

        const githubUser = await githubService.getUserInfo(access_token);

        const expiresAt = expires_in
          ? new Date(Date.now() + expires_in * 1000)
          : null;

        // Encrypt tokens before storing
        const encryptedAccessToken = encrypt(access_token);
        const encryptedRefreshToken = refresh_token ? encrypt(refresh_token) : null;

        let user = await prisma.user.findUnique({
          where: { githubId: String(githubUser.id) },
        });

        if (user) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: {
              username: githubUser.login,
              email: githubUser.email,
              avatarUrl: githubUser.avatar_url,
              accessToken: encryptedAccessToken,
              refreshToken: encryptedRefreshToken,
              tokenExpiresAt: expiresAt,
            },
          });
        } else {
          // Check if this is the first user - auto-promote to ADMIN
          const userCount = await prisma.user.count();
          const isFirstUser = userCount === 0;

          user = await prisma.user.create({
            data: {
              githubId: String(githubUser.id),
              username: githubUser.login,
              email: githubUser.email,
              avatarUrl: githubUser.avatar_url,
              accessToken: encryptedAccessToken,
              refreshToken: encryptedRefreshToken,
              tokenExpiresAt: expiresAt,
              // First user becomes admin automatically
              role: isFirstUser ? 'ADMIN' : 'USER',
            },
          });

          if (isFirstUser) {
            app.log.info(`First user ${githubUser.login} automatically promoted to ADMIN`);
          }
        }

        // Sign JWT with shorter expiration for access token
        const accessJti = generateJti();
        const jwtToken = app.jwt.sign(
          {
            userId: user.id,
            githubId: user.githubId,
            username: user.username,
            type: 'access',
            jti: accessJti,
            iat: Math.floor(Date.now() / 1000),
          },
          {
            expiresIn: config.jwt.accessExpiresIn,
          }
        );

        // Generate refresh token with longer expiration
        const refreshJti = generateJti();
        const refreshJwtToken = app.jwt.sign(
          {
            userId: user.id,
            githubId: user.githubId,
            type: 'refresh',
            jti: refreshJti,
            iat: Math.floor(Date.now() / 1000),
          },
          {
            expiresIn: config.jwt.refreshExpiresIn,
          }
        );

        app.log.info(`User authenticated: ${user.username} (ID: ${user.id})`);

        return reply.send({
          accessToken: jwtToken,
          refreshToken: refreshJwtToken,
          expiresIn: config.jwt.accessExpiresInSeconds,
          tokenType: 'Bearer',
          user: {
            id: user.id,
            githubId: user.githubId,
            username: user.username,
            email: user.email,
            avatarUrl: user.avatarUrl,
          },
        });
      } catch (error: any) {
        app.log.error('GitHub OAuth error:', error);
        // Don't expose internal error details in production
        return reply.code(500).send({
          error: 'Authentication failed',
          message: config.server.env === 'production'
            ? 'An unexpected error occurred. Please try again.'
            : error.message,
        });
      }
    }
  );

  /**
   * Refresh access token using refresh token
   * POST /auth/refresh
   */
  app.post('/refresh', async (request: FastifyRequest, reply: FastifyReply) => {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'Missing refresh token' });
    }

    const refreshToken = authHeader.substring(7);

    try {
      const rawDecoded = app.jwt.verify(refreshToken);

      // Runtime validation of JWT payload
      const parseResult = RefreshTokenPayloadSchema.safeParse(rawDecoded);
      if (!parseResult.success) {
        app.log.warn('Invalid refresh token payload structure');
        return reply.code(401).send({ error: 'Invalid token format' });
      }

      const decoded = parseResult.data;

      // Verify user still exists and is active
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, githubId: true, username: true, isActive: true },
      });

      if (!user) {
        return reply.code(401).send({ error: 'User not found' });
      }

      if (!user.isActive) {
        return reply.code(403).send({ error: 'Account is deactivated' });
      }

      // Issue new access token
      const newJti = generateJti();
      const newAccessToken = app.jwt.sign(
        {
          userId: user.id,
          githubId: user.githubId,
          username: user.username,
          type: 'access',
          jti: newJti,
          iat: Math.floor(Date.now() / 1000),
        },
        {
          expiresIn: config.jwt.accessExpiresIn,
        }
      );

      return reply.send({
        accessToken: newAccessToken,
        expiresIn: config.jwt.accessExpiresInSeconds,
        tokenType: 'Bearer',
      });
    } catch (error: any) {
      return reply.code(401).send({ error: 'Invalid or expired refresh token' });
    }
  });

  /**
   * Get current user info
   * GET /auth/me
   */
  app.get('/me', { onRequest: [authenticate] }, async (request: FastifyRequest) => {
    const { userId } = request.user as { userId: number };

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        githubId: true,
        username: true,
        email: true,
        avatarUrl: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new Error('User not found');
    }

    return user;
  });

  /**
   * Logout - invalidate tokens
   * POST /auth/logout
   */
  app.post('/logout', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.user as { userId: number; jti?: string; iat?: number };

    // Blacklist all user tokens issued before now
    await redisService.blacklistUserTokens(user.userId);

    // Invalidate user's cached permissions
    await redisService.invalidateUserPermissions(user.userId);

    app.log.info(`User logged out: ID ${user.userId}`);

    return reply.send({ message: 'Logged out successfully' });
  });

  /**
   * Logout from all devices - invalidate all tokens
   * POST /auth/logout-all
   */
  app.post('/logout-all', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.user as { userId: number };

    // Blacklist all user tokens
    await redisService.blacklistUserTokens(user.userId);

    // Invalidate user's cached permissions
    await redisService.invalidateUserPermissions(user.userId);

    app.log.info(`User logged out from all devices: ID ${user.userId}`);

    return reply.send({ message: 'Logged out from all devices successfully' });
  });
}

async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    const decoded = await request.jwtVerify() as { type?: string };

    // Ensure it's an access token, not a refresh token
    if (decoded.type && decoded.type !== 'access') {
      return reply.code(401).send({ error: 'Invalid token type' });
    }
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
  }
}

export default authRoutes;
