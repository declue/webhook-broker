import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config';
import { githubService } from '../services/github';
import { prisma } from '../app';

interface CallbackQuery {
  code?: string;
  state?: string;
  error?: string;
}

async function authRoutes(app: FastifyInstance) {
  app.get('/github', async (request: FastifyRequest, reply: FastifyReply) => {
    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', config.github.clientId);
    authUrl.searchParams.set('redirect_uri', config.github.callbackUrl);
    authUrl.searchParams.set('scope', 'read:user user:email repo');
    authUrl.searchParams.set('state', generateRandomState());

    return reply.redirect(authUrl.toString());
  });

  app.get<{ Querystring: CallbackQuery }>(
    '/github/callback',
    async (request: FastifyRequest<{ Querystring: CallbackQuery }>, reply: FastifyReply) => {
      const { code, error } = request.query;

      if (error) {
        return reply.code(400).send({ error: 'Authorization failed', message: error });
      }

      if (!code) {
        return reply.code(400).send({ error: 'Missing authorization code' });
      }

      try {
        const tokenResponse = await githubService.exchangeCodeForToken(
          code,
          config.github.clientId,
          config.github.clientSecret
        );

        const { access_token, refresh_token, expires_in } = tokenResponse;

        if (!access_token) {
          return reply.code(500).send({ error: 'Failed to obtain access token' });
        }

        const githubUser = await githubService.getUserInfo(access_token);

        const expiresAt = expires_in
          ? new Date(Date.now() + expires_in * 1000)
          : null;

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
              accessToken: access_token,
              refreshToken: refresh_token,
              tokenExpiresAt: expiresAt,
            },
          });
        } else {
          user = await prisma.user.create({
            data: {
              githubId: String(githubUser.id),
              username: githubUser.login,
              email: githubUser.email,
              avatarUrl: githubUser.avatar_url,
              accessToken: access_token,
              refreshToken: refresh_token,
              tokenExpiresAt: expiresAt,
            },
          });
        }

        const jwtToken = app.jwt.sign(
          {
            userId: user.id,
            githubId: user.githubId,
            username: user.username,
          },
          {
            expiresIn: config.jwt.expiresIn,
          }
        );

        app.log.info(`User authenticated: ${user.username} (ID: ${user.id})`);

        return reply.send({
          token: jwtToken,
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
        return reply.code(500).send({
          error: 'Authentication failed',
          message: error.message,
        });
      }
    }
  );

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
}

async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized' });
  }
}

function generateRandomState(): string {
  return Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15);
}

export default authRoutes;
