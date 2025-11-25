import {
  connect,
  NatsConnection,
  JetStreamClient,
  JetStreamManager,
  StreamConfig,
  ConsumerConfig,
  JsMsg,
  AckPolicy,
  DeliverPolicy,
  StorageType,
} from 'nats';
import { config } from '../config';
import { WebhookMessage } from '../types';

class NATSService {
  private nc: NatsConnection | null = null;
  private js: JetStreamClient | null = null;
  private jsm: JetStreamManager | null = null;

  async connect(): Promise<void> {
    try {
      this.nc = await connect({
        servers: config.nats.url,
        name: 'webhook-broker',
        maxReconnectAttempts: -1,
        reconnectTimeWait: 1000,
      });

      console.log(`✅ Connected to NATS at ${config.nats.url}`);

      this.js = this.nc.jetstream();
      this.jsm = await this.nc.jetstreamManager();

      await this.ensureStream();

      // Handle connection events
      (async () => {
        for await (const status of this.nc!.status()) {
          console.log(`NATS Status: ${status.type}`);
        }
      })();
    } catch (err) {
      console.error('Failed to connect to NATS:', err);
      throw err;
    }
  }

  async ensureStream(): Promise<void> {
    if (!this.jsm) throw new Error('NATS not connected');

    const streamConfig: Partial<StreamConfig> = {
      name: config.nats.streamName,
      subjects: [config.nats.streamSubjects],
      storage: StorageType.File,
      retention: 'limits' as any,
      max_age: 30 * 24 * 60 * 60 * 1_000_000_000, // 30 days in nanoseconds
      max_bytes: 10 * 1024 * 1024 * 1024, // 10GB
      max_consumers: -1,
      discard: 'old' as any,
      duplicate_window: 2 * 60 * 1_000_000_000, // 2 minutes
    };

    try {
      const stream = await this.jsm.streams.info(config.nats.streamName);
      console.log(`✅ Stream '${config.nats.streamName}' already exists`);
      console.log(`   Messages: ${stream.state.messages}, Bytes: ${stream.state.bytes}`);
    } catch (err: any) {
      if (err.message.includes('stream not found')) {
        await this.jsm.streams.add(streamConfig);
        console.log(`✅ Created stream '${config.nats.streamName}'`);
      } else {
        throw err;
      }
    }
  }

  async publishWebhook(message: WebhookMessage): Promise<void> {
    if (!this.js) throw new Error('NATS not connected');

    const subject = this.webhookPathToSubject(message.webhookPath);
    const data = JSON.stringify(message);

    const pubAck = await this.js.publish(subject, new TextEncoder().encode(data));

    console.log(`📤 Published to ${subject}, seq: ${pubAck.seq}`);
  }

  async createConsumer(
    userId: number,
    consumerName: string,
    filterSubjects: string[],
    deliverAll: boolean = true
  ): Promise<void> {
    if (!this.jsm) throw new Error('NATS not connected');

    const consumerConfig: Partial<ConsumerConfig> = {
      name: consumerName,
      durable_name: consumerName,
      ack_policy: AckPolicy.Explicit,
      deliver_policy: deliverAll ? DeliverPolicy.All : DeliverPolicy.New,
      filter_subjects: filterSubjects,
      max_deliver: 3,
      ack_wait: 30_000_000_000, // 30 seconds
    };

    try {
      await this.jsm.consumers.add(config.nats.streamName, consumerConfig);
      console.log(`✅ Created consumer '${consumerName}' for user ${userId}`);
    } catch (err: any) {
      if (err.message.includes('consumer already exists')) {
        console.log(`ℹ️  Consumer '${consumerName}' already exists`);
      } else {
        throw err;
      }
    }
  }

  async pullMessages(
    consumerName: string,
    batch: number = 10
  ): Promise<WebhookMessage[]> {
    if (!this.js) throw new Error('NATS not connected');

    const consumer = await this.js.consumers.get(config.nats.streamName, consumerName);
    const messages: WebhookMessage[] = [];

    try {
      const iter = await consumer.fetch({ max_messages: batch, expires: 5000 });

      for await (const msg of iter) {
        try {
          const data = new TextDecoder().decode(msg.data);
          const webhookMsg: WebhookMessage = JSON.parse(data);
          webhookMsg.id = `${msg.seq}`;
          messages.push(webhookMsg);

          // Store msg for manual ack later
          (webhookMsg as any)._natsMsg = msg;
        } catch (err) {
          console.error('Failed to parse message:', err);
          msg.nak();
        }
      }
    } catch (err: any) {
      if (err.message?.includes('no messages')) {
        // No messages available, not an error
        return [];
      }
      throw err;
    }

    return messages;
  }

  async ackMessage(msg: any): Promise<void> {
    if (msg._natsMsg) {
      (msg._natsMsg as JsMsg).ack();
    }
  }

  async ackMessages(messages: any[]): Promise<void> {
    for (const msg of messages) {
      await this.ackMessage(msg);
    }
  }

  async getConsumerInfo(consumerName: string) {
    if (!this.jsm) throw new Error('NATS not connected');
    return await this.jsm.consumers.info(config.nats.streamName, consumerName);
  }

  async deleteConsumer(consumerName: string): Promise<void> {
    if (!this.jsm) throw new Error('NATS not connected');
    await this.jsm.consumers.delete(config.nats.streamName, consumerName);
    console.log(`🗑️  Deleted consumer '${consumerName}'`);
  }

  webhookPathToSubject(webhookPath: string): string {
    // /webhook/github/owner/repo -> webhooks.github.owner.repo
    const path = webhookPath.replace(/^\/webhook\//, '').replace(/\//g, '.');
    return `webhooks.${path}`;
  }

  subjectToWebhookPath(subject: string): string {
    // webhooks.github.owner.repo -> /webhook/github/owner/repo
    const path = subject.replace(/^webhooks\./, '').replace(/\./g, '/');
    return `/webhook/${path}`;
  }

  async disconnect(): Promise<void> {
    if (this.nc) {
      await this.nc.drain();
      await this.nc.close();
      console.log('❌ Disconnected from NATS');
    }
  }
}

export const natsService = new NATSService();
