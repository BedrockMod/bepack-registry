import { verifyWebhookSignature } from './signature.mjs';
import { parseSemver } from '../../lib/semver.mjs';

const ACTIONS = new Set(['published', 'released', 'prereleased']);
const FULL_NAME_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const DELIVERY_RE = /^[0-9a-f-]{8,64}$/iu;

function result(status, body) {
  return { status, body };
}

function header(headers, name) {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function positiveId(value) {
  const text = typeof value === 'number' ? String(value) : value;
  return typeof text === 'string' && /^[1-9][0-9]{0,30}$/u.test(text) ? text : null;
}

/**
 * Validate and durably enqueue a GitHub release webhook. The payload is treated
 * as a hint only: the sync workflow re-fetches the repository, tag, Release and
 * assets and never trusts asset URLs or hashes from this request.
 */
export function createWebhookHandler({ config, store, verifyInstallation, now = () => new Date() }) {
  if (!config?.webhookSecret) throw new TypeError('webhookSecret is required');
  if (!store) throw new TypeError('store is required');
  if (typeof verifyInstallation !== 'function') throw new TypeError('verifyInstallation is required');

  return async function handleWebhook({ headers = {}, body }) {
    if (!Buffer.isBuffer(body)) return result(400, { error: 'body must be raw bytes' });
    if (body.length > config.maxBodyBytes) return result(413, { error: 'payload too large' });
    if (!verifyWebhookSignature({
      secret: config.webhookSecret,
      body,
      signature: header(headers, 'x-hub-signature-256'),
    })) return result(401, { error: 'invalid signature' });

    const event = header(headers, 'x-github-event');
    const deliveryId = header(headers, 'x-github-delivery');
    if (!DELIVERY_RE.test(deliveryId ?? '')) return result(400, { error: 'missing or invalid delivery id' });
    if (event === 'ping') return result(204, null);
    if (event !== 'release') return result(204, null);

    let payload;
    try {
      payload = JSON.parse(body.toString('utf8'));
    } catch {
      return result(400, { error: 'invalid JSON' });
    }
    if (!ACTIONS.has(payload?.action)) return result(204, null);
    const repository = payload.repository;
    const release = payload.release;
    const installationId = positiveId(payload.installation?.id);
    if (!repository || !release || !installationId) return result(400, { error: 'missing repository, release, or installation' });
    const repositoryId = positiveId(repository.id);
    const releaseId = positiveId(release.id);
    if (!repositoryId || !releaseId) return result(400, { error: 'invalid numeric repository or release id' });
    if (!FULL_NAME_RE.test(repository.full_name ?? '')) return result(400, { error: 'invalid repository full_name' });
    if (repository.private === true) return result(403, { error: 'private repositories are not eligible' });
    if (typeof release.tag_name !== 'string' || !release.tag_name.startsWith('v') || !parseSemver(release.tag_name.slice(1))) {
      return result(400, { error: 'release tag is not v<SemVer>' });
    }
    if (release.draft === true) return result(204, null);
    if (typeof release.prerelease !== 'boolean') return result(400, { error: 'release prerelease flag is missing' });

    let installationMatches;
    try {
      installationMatches = await verifyInstallation(repository.full_name, installationId);
    } catch (error) {
      const status = error?.status === 404 ? 403 : 503;
      return result(status, { error: status === 403 ? 'app is not installed on repository' : 'installation lookup failed' });
    }
    if (!installationMatches) return result(403, { error: 'installation does not belong to repository' });

    const accepted = await store.accept({
      deliveryId,
      repositoryId,
      releaseId,
      tag: release.tag_name,
      installationId,
      now: now(),
    });
    if (accepted.status === 'duplicate') return result(202, { status: 'duplicate' });
    return result(202, { status: accepted.status, key: accepted.key });
  };
}
