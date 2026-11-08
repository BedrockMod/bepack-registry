import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Verify GitHub's X-Hub-Signature-256 over the exact raw request body.
 * Fails closed for missing/malformed signatures; comparison is constant time.
 */
export function verifyWebhookSignature({ secret, body, signature }) {
  if (typeof secret !== 'string' || secret.length < 16) throw new TypeError('webhook secret is too short');
  if (!Buffer.isBuffer(body)) throw new TypeError('raw body must be a Buffer');
  if (typeof signature !== 'string' || !/^sha256=[0-9a-f]{64}$/u.test(signature)) return false;
  const expected = createHmac('sha256', secret).update(body).digest();
  const provided = Buffer.from(signature.slice('sha256='.length), 'hex');
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}
