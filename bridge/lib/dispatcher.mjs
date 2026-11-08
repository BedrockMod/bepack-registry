import { GitHubClient } from '../../lib/github.mjs';
import { HttpsDownloader } from '../../lib/download.mjs';
import { createAppJwt } from './app-jwt.mjs';

/**
 * Dispatch-only GitHub App client. The App must be installed on the registry
 * repository with Contents: write; it has no access to author repositories.
 * Tokens are cached briefly and minted on demand.
 */
export function createDispatcher({ appId, privateKey, repository, downloader = new HttpsDownloader(), now = () => Date.now() }) {
  if (!repository || !repository.includes('/')) throw new TypeError('repository must be owner/name');
  let cached = null;

  async function appClient() {
    return new GitHubClient({ appJwt: createAppJwt({ appId, privateKey, now: now() }), downloader });
  }

  async function installationToken() {
    if (cached && cached.expiresAt > now() + 60_000) return cached.token;
    const app = await appClient();
    const installation = await app.getInstallation(repository);
    const token = await app.createInstallationToken(installation.id, { contents: 'write' });
    cached = { token: token.token, expiresAt: now() + 50 * 60 * 1000 };
    return cached.token;
  }

  return {
    repository,
    async dispatch(payload) {
      const token = await installationToken();
      const client = new GitHubClient({ token, downloader });
      await client.createDispatch(repository, 'pack-released', payload);
    },
  };
}
