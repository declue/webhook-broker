import Redis from 'ioredis';
import { config } from '../config';

class RedisService {
  private client: Redis | null = null;

  async connect(): Promise<void> {
    this.client = new Redis(config.redis.url, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
    });

    await this.client.connect();

    this.client.on('error', (err) => {
      console.error('Redis error:', err);
    });

    this.client.on('connect', () => {
      console.log('✅ Connected to Redis');
    });

    this.client.on('ready', () => {
      console.log('✅ Redis is ready');
    });
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.client) throw new Error('Redis not connected');

    const value = await this.client.get(key);
    return value ? JSON.parse(value) : null;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    if (!this.client) throw new Error('Redis not connected');

    const stringValue = JSON.stringify(value);

    if (ttl) {
      await this.client.setex(key, ttl, stringValue);
    } else {
      await this.client.set(key, stringValue);
    }
  }

  async del(key: string): Promise<void> {
    if (!this.client) throw new Error('Redis not connected');
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    if (!this.client) throw new Error('Redis not connected');
    const result = await this.client.exists(key);
    return result === 1;
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      console.log('❌ Disconnected from Redis');
    }
  }

  // Cache helpers
  async cacheUserPermissions(userId: number, subjects: string[]): Promise<void> {
    await this.set(`permissions:user:${userId}`, subjects, config.redis.cacheTTL);
  }

  async getCachedUserPermissions(userId: number): Promise<string[] | null> {
    return await this.get<string[]>(`permissions:user:${userId}`);
  }

  async invalidateUserPermissions(userId: number): Promise<void> {
    await this.del(`permissions:user:${userId}`);
  }

  // Webhook-specific access caching
  async cacheWebhookAccess(userId: number, webhookPath: string, hasAccess: boolean): Promise<void> {
    const key = this.getWebhookAccessKey(userId, webhookPath);
    await this.set(key, hasAccess, config.redis.cacheTTL);
  }

  async getCachedWebhookAccess(userId: number, webhookPath: string): Promise<boolean | null> {
    const key = this.getWebhookAccessKey(userId, webhookPath);
    return await this.get<boolean>(key);
  }

  async invalidateWebhookAccess(userId: number, webhookPath: string): Promise<void> {
    const key = this.getWebhookAccessKey(userId, webhookPath);
    await this.del(key);
  }

  private getWebhookAccessKey(userId: number, webhookPath: string): string {
    // Normalize webhook path to remove leading/trailing slashes
    const normalized = webhookPath.replace(/^\/+|\/+$/g, '');
    return `webhook_access:${userId}:${normalized}`;
  }

  async healthCheck(): Promise<{ healthy: boolean; details: Record<string, any> }> {
    try {
      if (!this.client) {
        return {
          healthy: false,
          details: { error: 'Not connected', connected: false },
        };
      }

      // Ping Redis to check connection
      const pingResult = await this.client.ping();
      if (pingResult !== 'PONG') {
        return {
          healthy: false,
          details: { error: 'Ping failed', connected: false },
        };
      }

      // Get Redis info
      const info = await this.client.info('memory');
      const usedMemoryMatch = info.match(/used_memory_human:(\S+)/);
      const usedMemory = usedMemoryMatch ? usedMemoryMatch[1] : 'unknown';

      return {
        healthy: true,
        details: {
          connected: true,
          usedMemory,
        },
      };
    } catch (err: any) {
      return {
        healthy: false,
        details: { error: err.message, connected: false },
      };
    }
  }

  // JWT Blacklist management
  async blacklistToken(jti: string, expiresIn: number): Promise<void> {
    // Store token ID in blacklist until it expires
    await this.set(`blacklist:jwt:${jti}`, true, expiresIn);
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const result = await this.get<boolean>(`blacklist:jwt:${jti}`);
    return result === true;
  }

  async blacklistUserTokens(userId: number): Promise<void> {
    // Mark all tokens for this user as invalid
    // This will be checked on token validation
    await this.set(`blacklist:user:${userId}`, Date.now(), 7 * 24 * 60 * 60); // 7 days (max refresh token lifetime)
  }

  async getUserTokenBlacklistTime(userId: number): Promise<number | null> {
    return await this.get<number>(`blacklist:user:${userId}`);
  }

  isConnected(): boolean {
    return this.client !== null && this.client.status === 'ready';
  }

  getClient(): Redis | null {
    return this.client;
  }
}

export const redisService = new RedisService();
