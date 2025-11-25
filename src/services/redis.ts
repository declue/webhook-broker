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
}

export const redisService = new RedisService();
