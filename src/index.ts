import { buildApp } from './app';
import { config, validateConfig } from './config';

async function start() {
  try {
    // Validate configuration
    validateConfig();

    // Build and start server
    const app = await buildApp();

    await app.listen({
      port: config.server.port,
      host: config.server.host,
    });

    app.log.info(`🚀 Webhook Broker is running on http://${config.server.host}:${config.server.port}`);
    app.log.info(`📝 Environment: ${config.server.env}`);
    app.log.info(`🔌 NATS URL: ${config.nats.url}`);
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
