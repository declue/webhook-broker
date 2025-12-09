import { FastifyRequest, FastifyReply } from 'fastify';
import { JWTPayload } from '../types';
import { prisma } from '../app';

export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
  }
}

export async function authenticateAdmin(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
    const user = request.user as JWTPayload;

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
