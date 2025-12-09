import {
  Registry,
  Counter,
  Histogram,
  Gauge,
  collectDefaultMetrics,
} from 'prom-client';

// Create a new registry
export const register = new Registry();

// Collect default metrics (CPU, memory, event loop, etc.)
collectDefaultMetrics({ register });

// Custom metrics

// Webhook metrics
export const webhookReceivedTotal = new Counter({
  name: 'webhook_received_total',
  help: 'Total number of webhooks received',
  labelNames: ['source', 'status'],
  registers: [register],
});

export const webhookProcessingDuration = new Histogram({
  name: 'webhook_processing_duration_seconds',
  help: 'Duration of webhook processing in seconds',
  labelNames: ['source'],
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

// Message metrics
export const messagesDeliveredTotal = new Counter({
  name: 'messages_delivered_total',
  help: 'Total number of messages delivered to consumers',
  labelNames: ['consumer'],
  registers: [register],
});

export const messagesAcknowledgedTotal = new Counter({
  name: 'messages_acknowledged_total',
  help: 'Total number of messages acknowledged',
  labelNames: ['consumer'],
  registers: [register],
});

export const messagePullDuration = new Histogram({
  name: 'message_pull_duration_seconds',
  help: 'Duration of message pull operations in seconds',
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [register],
});

// Authentication metrics
export const authRequestsTotal = new Counter({
  name: 'auth_requests_total',
  help: 'Total number of authentication requests',
  labelNames: ['type', 'status'],
  registers: [register],
});

// HTTP request metrics
export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'path', 'status_code'],
  registers: [register],
});

export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'path'],
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

// Active connections gauge
export const activeConnections = new Gauge({
  name: 'active_connections',
  help: 'Number of active connections',
  registers: [register],
});

// Consumer metrics
export const activeConsumers = new Gauge({
  name: 'active_consumers',
  help: 'Number of active consumers',
  registers: [register],
});

export const consumerPendingMessages = new Gauge({
  name: 'consumer_pending_messages',
  help: 'Number of pending messages per consumer',
  labelNames: ['consumer'],
  registers: [register],
});

// NATS metrics
export const natsStreamMessages = new Gauge({
  name: 'nats_stream_messages',
  help: 'Number of messages in NATS stream',
  labelNames: ['stream'],
  registers: [register],
});

export const natsStreamBytes = new Gauge({
  name: 'nats_stream_bytes',
  help: 'Size of NATS stream in bytes',
  labelNames: ['stream'],
  registers: [register],
});

// Rate limiting metrics
export const rateLimitedRequestsTotal = new Counter({
  name: 'rate_limited_requests_total',
  help: 'Total number of rate limited requests',
  labelNames: ['key_type'],
  registers: [register],
});
