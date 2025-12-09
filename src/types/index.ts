import { z } from 'zod';

// JWT Payload schema for runtime validation
export const JWTPayloadSchema = z.object({
  userId: z.number().int().positive(),
  githubId: z.string().min(1),
  username: z.string().min(1),
});

export type JWTPayload = z.infer<typeof JWTPayloadSchema>;

// Refresh token payload schema
export const RefreshTokenPayloadSchema = z.object({
  userId: z.number().int().positive(),
  githubId: z.string().min(1),
  type: z.literal('refresh'),
});

export type RefreshTokenPayload = z.infer<typeof RefreshTokenPayloadSchema>;

export interface WebhookMessage {
  id?: string;
  webhookPath: string;
  source: string;
  method: string;
  headers: Record<string, string>;
  payload: unknown;
  receivedAt: Date;
}

export interface PullMessagesRequest {
  limit?: number;
  afterId?: string;
  source?: string;
  repository?: string;
}

export interface PullMessagesResponse {
  messages: WebhookMessage[];
  nextCursor?: string;
  hasMore: boolean;
}

export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  permissions?: {
    admin: boolean;
    push: boolean;
    pull: boolean;
  };
}
