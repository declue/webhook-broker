import { FastifyRequest, FastifyReply } from 'fastify';
import { JWTPayload } from '../types';

export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
  }
}

export function getUserFromToken(request: FastifyRequest): JWTPayload {
  return request.user as JWTPayload;
}
