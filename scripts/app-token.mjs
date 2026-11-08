#!/usr/bin/env node
import { appendFileSync } from 'node:fs';
import { GitHubClient } from '../lib/github.mjs';
import { HttpsDownloader } from '../lib/download.mjs';
import { createAppJwt } from '../bridge/lib/app-jwt.mjs';
import { RegistryError, codes } from '../lib/errors.mjs';

function required(name) {
  const value = process.env[name];
  if (!value) throw new RegistryError(codes.CONFIG, `${name} is not configured`);
  return value;
}

async function main() {
  const appId = required('REGISTRY_APP_ID');
  const privateKey = required('REGISTRY_APP_PRIVATE_KEY').replace(/\\n/gu, '\n');
  const repository = required('REGISTRY_REPOSITORY');
  const downloader = new HttpsDownloader();
  const app = new GitHubClient({
    appJwt: createAppJwt({ appId, privateKey }),
    downloader,
  });
  const installation = await app.getInstallation(repository);
  const token = await app.createInstallationToken(installation.id, {
    contents: 'write',
    pull_requests: 'write',
    metadata: 'read',
  });
  const output = process.env.GITHUB_OUTPUT;
  if (!output) throw new RegistryError(codes.CONFIG, 'GITHUB_OUTPUT is not set');
  appendFileSync(output, `token=${token.token}\n`, { encoding: 'utf8', mode: 0o600 });
  process.stdout.write('::add-mask::' + token.token + '\n');
  process.stdout.write(`Minted installation token for ${repository}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? codes.INTERNAL, message: error.message } }, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
});
