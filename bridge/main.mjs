#!/usr/bin/env node
import { createBridgeFromEnv, createBridgeServer } from './server.mjs';

const fail = (message) => {
  console.error(`[bridge] ${message}`);
  process.exitCode = 1;
};

async function main() {
  let bridge;
  try {
    bridge = await createBridgeFromEnv(process.env);
  } catch (error) {
    fail(`startup failed: ${error.message}`);
    return;
  }
  const server = createBridgeServer({
    store: bridge.store,
    handler: bridge.handler,
    logger: (line) => console.error(`[bridge] ${line}`),
  });
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? '0.0.0.0';
  server.listen(port, host, () => {
    console.log(`[bridge] listening on http://${host}:${port}`);
  });
  server.on('error', (error) => fail(`server error: ${error.message}`));

  const shutdown = (signal) => {
    console.log(`[bridge] ${signal}; draining`);
    bridge.worker.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
