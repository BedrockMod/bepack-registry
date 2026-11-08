import https from 'node:https';
import dns from 'node:dns';
import { createHash, randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { RegistryError, codes } from './errors.mjs';
import { assertPublicHttpsUrl, isSameOrigin, resolvePublicHost, isBlockedAddress } from './url-safety.mjs';

const USER_AGENT = 'bepack-registry/0.1 (+https://github.com/BedrockMod/bepack-registry)';

function externalError(message, cause, statusCode) {
  return new RegistryError(codes.DOWNLOAD, message, {
    exitCode: 3,
    details: statusCode ? { status: statusCode } : null,
    cause,
  });
}

// HTTPS-only downloader with per-hop SSRF checks, pinned DNS answers, redirect
// limits, byte limits and streaming SHA-256. Tests inject a compatible
// downloader instead of weakening these checks for loopback fixtures.
export class HttpsDownloader {
  constructor({ lookup = dns.promises.lookup, timeoutMs = 45000, userAgent = USER_AGENT } = {}) {
    this.lookup = lookup;
    this.timeoutMs = timeoutMs;
    this.userAgent = userAgent;
  }

  async _connect(url, { headers = {}, signal, maxRedirects = 0, method = 'GET', body = null }) {
    let current = url;
    let remaining = maxRedirects;
    let carry = { ...headers };
    for (;;) {
      const parsed = assertPublicHttpsUrl(current, { allowFragment: false, label: 'download URL' });
      const addresses = await resolvePublicHost(parsed.hostname, { lookup: this.lookup });
      const chosen = addresses[0];
      const response = await this._request(parsed, chosen, carry, signal, { method, body });
      if (response.statusCode >= 300 && response.statusCode < 400) {
        const location = response.headers.location;
        response.resume();
        if (!location) throw externalError(`Redirect without Location from ${parsed.origin}`, null, response.statusCode);
        if (remaining <= 0) throw externalError(`Too many redirects from ${parsed.origin}`, null, response.statusCode);
        const next = new URL(location, parsed).toString();
        if (!isSameOrigin(parsed, next)) {
          carry = { ...carry };
          delete carry.authorization;
          delete carry.Authorization;
          delete carry.cookie;
        }
        remaining--;
        current = next;
        continue;
      }
      return { response, url: parsed };
    }
  }

  _request(url, address, headers, signal, { method = 'GET', body = null }) {
    return new Promise((resolve, reject) => {
      const request = https.request({
        protocol: 'https:',
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method,
        headers: {
          'user-agent': this.userAgent,
          accept: '*/*',
          'accept-encoding': 'identity',
          ...headers,
        },
        servername: url.hostname,
        signal,
        // Pin the single address that passed the public-address check. A second
        // DNS lookup is never allowed to swap in a private answer.
        lookup: (hostname, options, callback) => {
          const family = typeof options === 'object' && options?.family ? options.family : chosenFamily(address);
          if (family && chosenFamily(address) && family !== chosenFamily(address)) {
            callback(new Error('Address family mismatch'), '');
            return;
          }
          callback(null, address.address, address.family);
        },
      }, (response) => {
        const remote = response.socket?.remoteAddress;
        if (remote && isBlockedAddress(remote)) {
          response.destroy();
          reject(new RegistryError(codes.SSRF, 'Connected peer is a non-public address'));
          return;
        }
        const encoding = String(response.headers['content-encoding'] ?? 'identity').toLowerCase();
        if (encoding !== 'identity') {
          response.destroy();
          reject(externalError('Compressed transfer encoding is not accepted'));
          return;
        }
        resolve(response);
      });
      request.setTimeout(this.timeoutMs, () => {
        request.destroy(new Error('Download timed out'));
      });
      request.on('error', (error) => {
        if (error instanceof RegistryError) reject(error);
        else reject(externalError('HTTPS request failed: ' + error.message, error));
      });
      if (body !== null && body !== undefined) request.write(body);
      request.end();
    });
  }

  async fetchBytes(url, { maxBytes, headers = {}, signal, maxRedirects = 0, method = 'GET', body = null } = {}) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('maxBytes is required');
    const { response, url: finalUrl } = await this._connect(url, { headers, signal, maxRedirects, method, body });
    if (response.statusCode !== 200) {
      response.resume();
      throw externalError(`Download returned HTTP ${response.statusCode}`, null, response.statusCode);
    }
    const declared = Number(response.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      response.destroy();
      throw new RegistryError(codes.LIMIT, `Download exceeds ${maxBytes} bytes`, { exitCode: 2 });
    }
    const chunks = [];
    let size = 0;
    try {
      for await (const chunk of response) {
        size += chunk.length;
        if (size > maxBytes) {
          response.destroy();
          throw new RegistryError(codes.LIMIT, `Download exceeds ${maxBytes} bytes`, { exitCode: 2 });
        }
        chunks.push(chunk);
      }
    } catch (error) {
      if (error instanceof RegistryError) throw error;
      throw externalError('Download stream failed: ' + error.message, error);
    }
    const responseBody = Buffer.concat(chunks, size);
    return {
      bytes: responseBody,
      size,
      sha256: createHash('sha256').update(responseBody).digest('hex'),
      url: finalUrl.toString(),
      status: response.statusCode,
      headers: response.headers,
    };
  }

  async downloadToFile(url, destination, { maxBytes, headers = {}, signal, maxRedirects = 3 } = {}) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('maxBytes is required');
    const { response, url: finalUrl } = await this._connect(url, { headers, signal, maxRedirects });
    if (response.statusCode !== 200) {
      response.resume();
      throw externalError(`Download returned HTTP ${response.statusCode}`, null, response.statusCode);
    }
    const declared = Number(response.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      response.destroy();
      throw new RegistryError(codes.LIMIT, `Download exceeds ${maxBytes} bytes`, { exitCode: 2 });
    }
    await mkdir(path.dirname(destination), { recursive: true });
    const temporary = `${destination}.part-${randomUUID()}`;
    const hash = createHash('sha256');
    let size = 0;
    const output = createWriteStream(temporary, { flags: 'wx', mode: 0o600 });
    try {
      await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error) => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve();
        };
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxBytes) {
            response.destroy(new RegistryError(codes.LIMIT, `Download exceeds ${maxBytes} bytes`));
            return;
          }
          hash.update(chunk);
          if (!output.write(chunk)) response.pause();
        });
        output.on('drain', () => response.resume());
        response.on('end', () => {
          output.end(() => finish());
        });
        response.on('error', (error) => finish(error));
        output.on('error', (error) => finish(error));
        response.on('aborted', () => finish(new Error('Download aborted')));
      });
      await rename(temporary, destination);
    } catch (error) {
      await unlink(temporary).catch(() => {});
      if (error instanceof RegistryError) throw error;
      throw externalError('Download failed: ' + error.message, error);
    }
    return {
      size,
      sha256: hash.digest('hex'),
      url: finalUrl.toString(),
      status: response.statusCode,
      destination,
    };
  }
}

function chosenFamily(address) {
  return address.family === 6 ? 6 : 4;
}
