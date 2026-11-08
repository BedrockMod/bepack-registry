import { RegistryError, codes } from './errors.mjs';
import { HttpsDownloader } from './download.mjs';
import { setTimeout as sleep } from 'node:timers/promises';

const API_VERSION = '2022-11-28';

export class GitHubError extends RegistryError {
  constructor(message, { status = 0, body = '', headers = {}, path = '' } = {}) {
    super(
      status === 404 ? codes.NETWORK : codes.NETWORK,
      message,
      { exitCode: 3, details: { status, path, ...(body ? { body: body.slice(0, 500) } : {}) } },
    );
    this.name = 'GitHubError';
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

// Official REST API client. It sends the token only to the configured API
// origin and never follows redirects; asset bytes are fetched separately from
// browser_download_url without credentials.
export class GitHubClient {
  constructor({ token = null, appJwt = null, downloader = new HttpsDownloader(), apiBase = 'https://api.github.com', userAgent = 'bepack-registry/0.1' } = {}) {
    this.token = token;
    this.appJwt = appJwt;
    this.downloader = downloader;
    this.apiBase = apiBase.replace(/\/+$/u, '');
    this.userAgent = userAgent;
  }

  async request(path, { method = 'GET', body, accept = 'application/vnd.github+json', auth = 'token', maxBytes = 32 * 1024 * 1024 } = {}) {
    if (!path.startsWith('/') || path.startsWith('//')) throw new GitHubError('API path must be origin relative');
    const headers = {
      accept,
      'x-github-api-version': API_VERSION,
      'user-agent': this.userAgent,
    };
    if (auth === 'token' && this.token) headers.authorization = `Bearer ${this.token}`;
    if (auth === 'app' && this.appJwt) headers.authorization = `Bearer ${this.appJwt}`;
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(Buffer.byteLength(body));
    }
    let result;
    for (let attempt = 0; attempt < 4; attempt++) {
    try {
      result = await this.downloader.fetchBytes(`${this.apiBase}${path}`, {
        maxBytes,
        headers,
        maxRedirects: 0,
        method,
        body: body ?? null,
      });
      if ((result.status === 429 || result.status >= 500) && method === 'GET' && attempt < 3) {
        await sleep(1000 * 2 ** attempt);
        continue;
      }
      break;
    } catch (error) {
      const status = error?.details?.status;
      if (method === 'GET' && attempt < 3 && (!status || status === 429 || status >= 500) && [codes.NETWORK, codes.DOWNLOAD].includes(error?.code)) { await sleep(1000 * 2 ** attempt); continue; }
      if (error instanceof RegistryError) throw error;
      throw new GitHubError(`GitHub API request failed: ${error.message}`, { path });
    }
    }
    if (result.status < 200 || result.status >= 300) {
      throw new GitHubError(`GitHub API ${method} ${path} returned ${result.status}`, {
        status: result.status,
        body: result.bytes.toString('utf8'),
        headers: result.headers,
        path,
      });
    }
    return result;
  }

  async json(path, options = {}) {
    const result = await this.request(path, options);
    let value;
    try {
      value = JSON.parse(result.bytes.toString('utf8'));
    } catch (error) {
      throw new GitHubError('GitHub API returned invalid JSON', { path, body: result.bytes.toString('utf8') });
    }
    return value;
  }

  async paginate(path, { maxPages = 30, maxItems = 5000, ...options } = {}) {
    const separator = path.includes('?') ? '&' : '?';
    let next = `${path}${separator}per_page=100`;
    const items = [];
    for (let page = 0; page < maxPages && next; page++) {
      const result = await this.request(next, options);
      let batch;
      try {
        batch = JSON.parse(result.bytes.toString('utf8'));
      } catch {
        throw new GitHubError('GitHub API returned invalid JSON', { path: next });
      }
      if (!Array.isArray(batch)) throw new GitHubError('GitHub API pagination expected an array', { path: next });
      items.push(...batch);
      if (items.length > maxItems) throw new GitHubError('GitHub API pagination exceeded item limit', { path });
      const link = nextLink(result.headers.link);
      if (link) {
        const url = new URL(link, this.apiBase);
        if (url.origin !== new URL(this.apiBase).origin) throw new GitHubError('Pagination link changed API origin');
        next = url.pathname + url.search;
      } else next = null;
    }
    if (next) throw new GitHubError('GitHub pagination exceeded page budget');
    return items;
  }

  getRepository(id) {
    return this.json(`/repositories/${id}`);
  }

  getRepositoryByName(fullName) {
    return this.json(`/repos/${fullName}`);
  }

  getRelease(fullName, releaseId) {
    return this.json(`/repos/${fullName}/releases/${releaseId}`);
  }

  listReleases(fullName) {
    return this.paginate(`/repos/${fullName}/releases`);
  }

  listReleaseAssets(fullName, releaseId) {
    return this.paginate(`/repos/${fullName}/releases/${releaseId}/assets`, { maxItems: 500 });
  }

  async getTagCommit(fullName, tag) {
    const encoded = encodeURIComponent(tag);
    let reference;
    try {
      reference = await this.json(`/repos/${fullName}/git/ref/tags/${encoded}`);
    } catch (error) {
      if (error.status === 404) throw new GitHubError(`Tag ${tag} not found`, { status: 404 });
      throw error;
    }
    if (reference.ref !== `refs/tags/${tag}`) throw new GitHubError(`GitHub resolved an unexpected tag ref for ${tag}`);
    let object = reference.object;
    for (let depth = 0; depth < 8; depth++) {
      if (!object || typeof object.sha !== 'string') throw new GitHubError('Malformed tag object');
      if (object.type === 'commit') return object.sha;
      if (object.type !== 'tag') throw new GitHubError(`Tag ${tag} points to unsupported object ${object.type}`);
      object = await this.json(`/repos/${fullName}/git/tags/${object.sha}`);
      if (object.tag !== tag) throw new GitHubError(`Annotated tag name mismatch for ${tag}`);
    }
    throw new GitHubError(`Tag ${tag} nesting exceeds 8 levels`);
  }

  async getFile(fullName, filePath, ref) {
    const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
    const result = await this.request(`/repos/${fullName}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`, {
      accept: 'application/vnd.github.raw+json',
      maxBytes: 64 * 1024,
    });
    return result.bytes;
  }

  async compare(fullName, base, head) {
    return this.json(`/repos/${fullName}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`);
  }

  async getInstallation(fullName) {
    return this.json(`/repos/${fullName}/installation`, { auth: 'app' });
  }

  async createInstallationToken(installationId, permissions) {
    const body = JSON.stringify(permissions ? { permissions } : {});
    return this.json(`/app/installations/${installationId}/access_tokens`, {
      method: 'POST',
      body,
      auth: 'app',
    });
  }

  async createDispatch(fullName, eventType, clientPayload) {
    const result = await this.request(`/repos/${fullName}/dispatches`, {
      method: 'POST',
      body: JSON.stringify({ event_type: eventType, client_payload: clientPayload }),
    });
    if (result.status !== 204) throw new GitHubError(`Dispatch returned ${result.status}`, { status: result.status });
    return true;
  }

  async createPullRequest(fullName, { title, head, base, body, draft = false }) {
    return this.json(`/repos/${fullName}/pulls`, {
      method: 'POST',
      body: JSON.stringify({ title, head, base, body, draft }),
    });
  }

  async addLabels(fullName, number, labels) {
    return this.json(`/repos/${fullName}/issues/${number}/labels`, {
      method: 'POST',
      body: JSON.stringify({ labels }),
    });
  }
}

function nextLink(header) {
  if (!header) return null;
  for (const part of String(header).split(',')) {
    const match = /<([^>]+)>;\s*rel="next"/u.exec(part.trim());
    if (match) return match[1];
  }
  return null;
}
