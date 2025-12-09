import { FastifyRequest, FastifyReply } from 'fastify';
import { JWTPayload } from '../types';
import { prisma } from '../app';
import { redisService } from '../services/redis';

interface ExtendedJWTPayload extends JWTPayload {
  jti?: string;
  iat?: number;
  type?: string;
}

export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
    const user = request.user as ExtendedJWTPayload;

    // Check if token was issued before user's blacklist time
    const blacklistTime = await redisService.getUserTokenBlacklistTime(user.userId);
    if (blacklistTime && user.iat && user.iat * 1000 < blacklistTime) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Token has been revoked' });
    }

    // Ensure it's an access token, not a refresh token
    if (user.type && user.type !== 'access') {
      return reply.code(401).send({ error: 'Invalid token type' });
    }
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
  }
}

export async function authenticateAdmin(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
    const user = request.user as ExtendedJWTPayload;

    // Check if token was issued before user's blacklist time
    const blacklistTime = await redisService.getUserTokenBlacklistTime(user.userId);
    if (blacklistTime && user.iat && user.iat * 1000 < blacklistTime) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Token has been revoked' });
    }

    // Check if user is admin
    const dbUser = await prisma.user.findUnique({
      where: { id: user.userId },
      select: { role: true, isActive: true },
    });

    if (!dbUser) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'User not found' });
    }

    if (!dbUser.isActive) {
      return reply.code(403).send({ error: 'Forbidden', message: 'Account is deactivated' });
    }

    if (dbUser.role !== 'ADMIN') {
      return reply.code(403).send({ error: 'Forbidden', message: 'Admin access required' });
    }
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
  }
}

export function getUserFromToken(request: FastifyRequest): JWTPayload {
  return request.user as JWTPayload;
}
