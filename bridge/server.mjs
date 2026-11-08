import { createServer } from 'node:http';
import path from 'node:path';
import { FileOutbox } from './lib/outbox.mjs';
import { createWebhookHandler } from './lib/webhook.mjs';
import { createDispatcher } from './lib/dispatcher.mjs';
import { startWorker } from './lib/worker.mjs';
import { GitHubClient } from '../lib/github.mjs';
import { HttpsDownloader } from '../lib/download.mjs';
import { createAppJwt } from './lib/app-jwt.mjs';

export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

function json(res, status, value) {
  const body = value === null ? '' : `${JSON.stringify(value)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function readRaw(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error('payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function createBridgeServer({ store, handler, logger = () => {} }) {
  return createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/healthz') {
        return json(res, 200, { ok: true, pending: await store.pendingCount() });
      }
      if (req.method === 'POST' && req.url === '/webhooks/github') {
        const body = await readRaw(req, DEFAULT_MAX_BODY_BYTES);
        const response = await handler({ headers: req.headers, body });
        return json(res, response.status, response.body);
      }
      return json(res, 404, { error: 'not found' });
    } catch (error) {
      const status = error?.status ?? 500;
      if (status >= 500) logger(`request failed: ${error?.message ?? error}`);
      return json(res, status, { error: status === 413 ? 'payload too large' : 'internal error' });
    }
  });
}

function required(env, name) {
  const value = env[name];
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

export async function createBridgeFromEnv(env = process.env, { logger = console } = {}) {
  const webhookSecret = required(env, 'GITHUB_WEBHOOK_SECRET');
  if (webhookSecret.length < 16) throw new Error('GITHUB_WEBHOOK_SECRET must be at least 16 characters');
  const appId = required(env, 'REGISTRY_APP_ID');
  const privateKey = required(env, 'REGISTRY_PRIVATE_KEY').replace(/\\n/gu, '\n');
  const repository = required(env, 'REGISTRY_REPOSITORY');
  const notifierAppId = required(env, 'NOTIFIER_APP_ID');
  const notifierPrivateKey = required(env, 'NOTIFIER_PRIVATE_KEY').replace(/\\n/gu, '\n');
  if (String(notifierAppId) === String(appId)) throw new Error('Notifier and Registry writer must be separate GitHub Apps');
  const dataDir = path.resolve(env.BRIDGE_DATA_DIR ?? 'bridge-data');
  const config = {
    webhookSecret,
    maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
    repository,
    dataDir,
  };
  const store = new FileOutbox({ dir: dataDir });
  await store.init();
  const dispatcher = createDispatcher({ appId, privateKey, repository });
  const handler = createWebhookHandler({
    config,
    store,
    verifyInstallation: async (fullName, installationId) => {
      const notifier = new GitHubClient({ appJwt: createAppJwt({ appId: notifierAppId, privateKey: notifierPrivateKey }), downloader: new HttpsDownloader() });
      const installation = await notifier.getInstallation(fullName);
      return String(installation.id) === String(installationId);
    },
  });
  const worker = startWorker({ store, dispatch: dispatcher.dispatch, intervalMs: Number(env.BRIDGE_INTERVAL_MS ?? 5000), logger: (line) => logger.info?.(line) ?? logger.log?.(line) });
  return { config, store, dispatcher, handler, worker };
}
