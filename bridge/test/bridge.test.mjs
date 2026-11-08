import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FileOutbox } from '../lib/outbox.mjs';
import { verifyWebhookSignature } from '../lib/signature.mjs';
import { createWebhookHandler } from '../lib/webhook.mjs';
import { runOnce, backoffFor } from '../lib/worker.mjs';

const SECRET = 'test-secret-that-is-long-enough';

function sign(body) {
  return `sha256=${createHmac('sha256', SECRET).update(body).digest('hex')}`;
}

function payload(overrides = {}) {
  return {
    action: 'published',
    repository: { id: 123456, full_name: 'author/example', private: false, ...overrides.repository },
    release: { id: 987654, tag_name: 'v1.0.0', draft: false, prerelease: false, ...overrides.release },
    installation: { id: 42 },
    ...overrides,
  };
}

async function setup() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'bepack-bridge-'));
  const store = new FileOutbox({ dir });
  await store.init();
  const handler = createWebhookHandler({
    config: { webhookSecret: SECRET, maxBodyBytes: 1024 * 1024 },
    store,
    verifyInstallation: async (fullName) => fullName === 'author/example',
  });
  return { dir, store, handler };
}

function headers(body, deliveryId = randomUUID(), event = 'release') {
  return {
    'x-github-event': event,
    'x-github-delivery': deliveryId,
    'x-hub-signature-256': sign(body),
    'content-type': 'application/json',
  };
}

test('rejects a body whose signature does not match', async () => {
  const { dir, handler } = await setup();
  try {
    const body = Buffer.from(JSON.stringify(payload()));
    const response = await handler({ headers: { ...headers(body), 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` }, body });
    assert.equal(response.status, 401);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('queues a verified release hint and deduplicates its delivery id', async () => {
  const { dir, store, handler } = await setup();
  try {
    const body = Buffer.from(JSON.stringify(payload()));
    const deliveryId = randomUUID();
    const first = await handler({ headers: headers(body, deliveryId), body });
    assert.equal(first.status, 202);
    assert.equal(first.body.status, 'queued');
    const second = await handler({ headers: headers(body, deliveryId), body });
    assert.equal(second.status, 202);
    assert.equal(second.body.status, 'duplicate');
    const due = await store.due();
    assert.equal(due.length, 1);
    assert.equal(due[0].payload.repository_id, '123456');
    assert.equal(due[0].payload.tag, 'v1.0.0');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('merges a new delivery for the same repository and release', async () => {
  const { dir, store, handler } = await setup();
  try {
    const body = Buffer.from(JSON.stringify(payload()));
    await handler({ headers: headers(body), body });
    const merged = await handler({ headers: headers(body), body });
    assert.equal(merged.body.status, 'merged');
    assert.equal((await store.due()).length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('keeps a failed dispatch pending with backoff and records success once', async () => {
  const { dir, store, handler } = await setup();
  try {
    const body = Buffer.from(JSON.stringify(payload()));
    await handler({ headers: headers(body), body });
    const [entry] = await store.due();
    const failed = await runOnce({
      store,
      dispatch: async () => { throw new Error('network down'); },
      now: () => new Date('2026-11-08T00:00:00Z'),
    });
    assert.equal(failed.delivered, 0);
    assert.ok(backoffFor(0) >= 60_000);
    assert.equal((await store.due(new Date('2026-11-08T00:00:01Z'))).length, 0);
    const later = new Date(Date.parse(entry.next_attempt_at) + backoffFor(0) + 1);
    assert.ok((await store.due(later)).length === 1);
    const delivered = await runOnce({ store, dispatch: async () => {}, now: () => later });
    assert.equal(delivered.delivered, 1);
    assert.equal(await store.pendingCount(), 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('fails closed for missing signatures and reports installation mismatches', async () => {
  assert.equal(verifyWebhookSignature({ secret: SECRET, body: Buffer.from('{}'), signature: null }), false);
  const { dir, handler } = await setup();
  try {
    const body = Buffer.from(JSON.stringify(payload({ repository: { id: 123456, full_name: 'attacker/repo', private: false } })));
    const response = await handler({ headers: headers(body), body });
    assert.equal(response.status, 403);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
