import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const STATE_VERSION = 1;
const DELIVERY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DONE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function emptyState() {
  return { version: STATE_VERSION, deliveries: {}, outbox: {} };
}

function validState(value) {
  return value && value.version === STATE_VERSION && value.deliveries && value.outbox
    && typeof value.deliveries === 'object' && typeof value.outbox === 'object';
}

function prune(state, now) {
  const nowMs = now.getTime();
  for (const [id, entry] of Object.entries(state.deliveries)) {
    if (!entry || typeof entry.at !== 'string' || nowMs - Date.parse(entry.at) > DELIVERY_TTL_MS) delete state.deliveries[id];
  }
  for (const [key, entry] of Object.entries(state.outbox)) {
    if (entry?.status === 'done' && entry.updated_at && nowMs - Date.parse(entry.updated_at) > DONE_TTL_MS) delete state.outbox[key];
  }
}

/**
 * Small single-process durable outbox. A single JSON file is rewritten with an
 * atomic rename and all mutations are serialized; deploy exactly one replica or
 * replace this class with a transactional store. Delivery IDs survive seven
 * days; dispatch is at-least-once, so the registry workflow must be idempotent.
 */
export class FileOutbox {
  constructor({ dir }) {
    if (!dir) throw new TypeError('dir is required');
    this.dir = dir;
    this.file = path.join(dir, 'state.json');
    this.state = emptyState();
    this.chain = Promise.resolve();
  }

  async init() {
    await mkdir(this.dir, { recursive: true });
    try {
      const bytes = await readFile(this.file);
      const parsed = JSON.parse(bytes.toString('utf8'));
      if (!validState(parsed)) throw new Error('outbox state has an unsupported shape');
      this.state = parsed;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    prune(this.state, new Date());
    await this.persist();
  }

  async persist() {
    const temporary = `${this.file}.tmp-${randomUUID()}`;
    await writeFile(temporary, JSON.stringify(this.state), { mode: 0o600 });
    await rename(temporary, this.file);
  }

  serialize(fn) {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }

  async accept({ deliveryId, repositoryId, releaseId, tag, installationId, now = new Date() }) {
    return this.serialize(async () => {
      if (this.state.deliveries[deliveryId]) return { status: 'duplicate' };
      this.state.deliveries[deliveryId] = { at: now.toISOString(), repository_id: repositoryId, release_id: releaseId };
      const key = `${repositoryId}:${releaseId}`;
      let entry = this.state.outbox[key];
      const isNew = !entry;
      if (!entry) {
        entry = {
          key,
          delivery_id: deliveryId,
          installation_id: String(installationId),
          payload: {
            schema_version: 1,
            repository_id: String(repositoryId),
            release_id: String(releaseId),
            tag,
            delivery_id: deliveryId,
          },
          status: 'pending',
          attempts: 0,
          created_at: now.toISOString(),
          updated_at: now.toISOString(),
          next_attempt_at: now.toISOString(),
          last_error: null,
        };
        this.state.outbox[key] = entry;
      } else {
        entry.delivery_id = deliveryId;
        entry.installation_id = String(installationId);
        entry.payload = {
          schema_version: 1,
          repository_id: String(repositoryId),
          release_id: String(releaseId),
          tag,
          delivery_id: deliveryId,
        };
        if (entry.status === 'done') {
          entry.status = 'pending';
          entry.next_attempt_at = now.toISOString();
        }
        entry.updated_at = now.toISOString();
      }
      await this.persist();
      return { status: isNew ? 'queued' : 'merged', key };
    });
  }

  async due(now = new Date()) {
    return this.serialize(async () => Object.values(this.state.outbox)
      .filter((entry) => entry.status === 'pending' && Date.parse(entry.next_attempt_at) <= now.getTime())
      .map((entry) => ({ ...entry })));
  }

  async recordSuccess(key, now = new Date()) {
    return this.serialize(async () => {
      const entry = this.state.outbox[key];
      if (!entry) return;
      entry.status = 'done';
      entry.attempts += 1;
      entry.updated_at = now.toISOString();
      entry.next_attempt_at = now.toISOString();
      entry.last_error = null;
      await this.persist();
    });
  }

  async recordFailure(key, { error, nextAttemptAt, now = new Date() }) {
    return this.serialize(async () => {
      const entry = this.state.outbox[key];
      if (!entry) return;
      entry.status = 'pending';
      entry.attempts += 1;
      entry.updated_at = now.toISOString();
      entry.next_attempt_at = nextAttemptAt.toISOString();
      entry.last_error = String(error).slice(0, 500);
      await this.persist();
    });
  }

  async pendingCount() {
    return this.serialize(async () => Object.values(this.state.outbox).filter((entry) => entry.status === 'pending').length);
  }
}
