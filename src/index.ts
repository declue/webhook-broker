import { buildApp } from './app';
import { config, validateConfig } from './config';
import { FastifyInstance } from 'fastify';

let app: FastifyInstance | null = null;
let isShuttingDown = false;

async function gracefulShutdown(signal: string) {
  if (isShuttingDown) {
    console.log(`Already shutting down, ignoring ${signal}`);
    return;
  }

  isShuttingDown = true;
  console.log(`\n${signal} received. Starting graceful shutdown...`);

  const shutdownTimeout = setTimeout(() => {
    console.error('Shutdown timed out, forcing exit');
    process.exit(1);
  }, 30000); // 30 seconds timeout

  try {
    if (app) {
      // Stop accepting new connections
      console.log('Closing server...');
      await app.close();
      console.log('Server closed successfully');
    }

    clearTimeout(shutdownTimeout);
    console.log('Graceful shutdown completed');
    process.exit(0);
  } catch (err) {
    clearTimeout(shutdownTimeout);
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
}

async function start() {
  try {
    // Validate configuration
    validateConfig();

    // Build and start server
    app = await buildApp();

    await app.listen({
      port: config.server.port,
      host: config.server.host,
    });

    app.log.info(`Webhook Broker is running on http://${config.server.host}:${config.server.port}`);
    app.log.info(`Environment: ${config.server.env}`);
    app.log.info(`NATS URL: ${config.nats.url}`);

    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
      console.error('Uncaught exception:', err);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled rejection at:', promise, 'reason:', reason);
    });

  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
