#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { GitHubClient } from '../lib/github.mjs';
import { GitHubAppRouter } from '../lib/github-router.mjs';
import { HttpsDownloader } from '../lib/download.mjs';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import { RegistryError, codes } from '../lib/errors.mjs';
import { loadSources } from '../lib/source.mjs';
import { syncReleaseSet } from '../lib/sync.mjs';

const options = {
  'repository-id': { type: 'string' },
  tag: { type: 'string' },
  all: { type: 'boolean', default: false },
  'dry-run': { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
};

function usage() {
  return 'Usage: node scripts/sync-release.mjs --repository-id <id> [--tag v1.2.3] [--dry-run]\n'
    + '   or: node scripts/sync-release.mjs --all [--dry-run]\n'
    + 'Requires GITHUB_TOKEN and VT_API_KEY. Exit 0 completed (pending/quarantine is reported), 2 failure, 1 internal.';
}

async function main() {
  const values = parseArgs({ options }).values;
  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!values.all && !values['repository-id']) throw new RegistryError(codes.ARGUMENT, '--repository-id or --all is required');
  if (values.tag && !values['repository-id']) throw new RegistryError(codes.ARGUMENT, '--tag requires --repository-id');
  const token = process.env.GITHUB_TOKEN;
  const vtKey = process.env.VT_API_KEY;
  const syncAppId = process.env.SYNC_APP_ID;
  const syncAppKey = process.env.SYNC_APP_PRIVATE_KEY;
  if (!vtKey) throw new RegistryError(codes.CONFIG, 'VT_API_KEY is not configured; scan verification cannot be skipped');

  const downloader = new HttpsDownloader();
  let github;
  if (syncAppId && syncAppKey) {
    const sources = await loadSources(process.cwd());
    github = new GitHubAppRouter({
      appId: syncAppId,
      privateKey: syncAppKey.replace(/\\n/gu, '\n'),
      downloader,
      repositoryNames: sources.map((source) => [source.repository.id, source.repository.full_name]),
    });
  } else if (token) {
    github = new GitHubClient({ token, downloader });
  } else {
    throw new RegistryError(codes.CONFIG, 'SYNC_APP_ID/SYNC_APP_PRIVATE_KEY or GITHUB_TOKEN is required');
  }
  const vt = new VirusTotalClient({ downloader, apiKey: vtKey });
  const summary = await syncReleaseSet({
    github,
    downloader,
    vt,
    root: process.cwd(),
    repositoryId: values['repository-id'] ?? null,
    tag: values.tag ?? null,
    now: new Date(),
    dryRun: values['dry-run'],
    logger: (line) => process.stderr.write(`${line}\n`),
  });
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (summary.failed.length > 0) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? codes.INTERNAL, message: error.message, details: error.details } }, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
});
