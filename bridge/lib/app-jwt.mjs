import { createSign } from 'node:crypto';

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

/**
 * GitHub App JWT (RS256). GitHub requires iat slightly in the past and exp
 * within ten minutes. The private key is a PEM supplied only through env.
 */
export function createAppJwt({ appId, privateKey, now = Date.now() }) {
  if (!appId) throw new TypeError('appId is required');
  if (typeof privateKey !== 'string' || !privateKey.includes('BEGIN')) throw new TypeError('privateKey must be a PEM');
  const issuedAt = Math.floor(now / 1000) - 60;
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({ iat: issuedAt, exp: issuedAt + 540, iss: String(appId) }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign(privateKey).toString('base64url');
  return `${header}.${payload}.${signature}`;
}
