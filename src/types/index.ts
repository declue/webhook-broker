export interface JWTPayload {
  userId: number;
  githubId: string;
  username: string;
}

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
