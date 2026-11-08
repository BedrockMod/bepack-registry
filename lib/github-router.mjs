import { GitHubClient } from './github.mjs';
import { createAppJwt } from '../bridge/lib/app-jwt.mjs';

/**
 * Read-only GitHub App router. The Notifier App is installed on author
 * repositories; each installation can read only the repositories it covers.
 * Tokens are minted per installation and cached for fifty minutes.
 */
export class GitHubAppRouter {
  constructor({ appId, privateKey, downloader, repositoryNames = new Map() }) {
    if (!appId || !privateKey) throw new TypeError('appId and privateKey are required');
    this.appId = appId;
    this.privateKey = privateKey;
    this.downloader = downloader;
    this.names = new Map([...repositoryNames].map(([id, name]) => [String(id), name]));
    this.tokens = new Map();
  }

  appClient() {
    return new GitHubClient({
      appJwt: createAppJwt({ appId: this.appId, privateKey: this.privateKey }),
      downloader: this.downloader,
    });
  }

  async clientFor(fullName) {
    const cached = this.tokens.get(fullName);
    if (cached && cached.expiresAt > Date.now() + 60_000) return cached.client;
    const app = this.appClient();
    const installation = await app.getInstallation(fullName);
    const token = await app.createInstallationToken(installation.id, {
      contents: 'read',
      metadata: 'read',
    });
    const client = new GitHubClient({ token: token.token, downloader: this.downloader });
    this.tokens.set(fullName, { client, expiresAt: Date.now() + 50 * 60 * 1000 });
    return client;
  }

  async listReleases(fullName) {
    return (await this.clientFor(fullName)).listReleases(fullName);
  }

  async getRelease(fullName, releaseId) {
    return (await this.clientFor(fullName)).getRelease(fullName, releaseId);
  }

  async listReleaseAssets(fullName, releaseId) {
    return (await this.clientFor(fullName)).listReleaseAssets(fullName, releaseId);
  }

  async getTagCommit(fullName, tag) {
    return (await this.clientFor(fullName)).getTagCommit(fullName, tag);
  }

  async getRepository(id) {
    const fullName = this.names.get(String(id));
    if (!fullName) throw new Error(`No repository full_name registered for id ${id}`);
    return (await this.clientFor(fullName)).getRepository(id);
  }

  async getRepositoryByName(fullName) {
    return (await this.clientFor(fullName)).getRepositoryByName(fullName);
  }

  async getFile(fullName, filePath, ref) {
    return (await this.clientFor(fullName)).getFile(fullName, filePath, ref);
  }

  async compare(fullName, base, head) {
    return (await this.clientFor(fullName)).compare(fullName, base, head);
  }
}
