#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { GitHubClient } from '../lib/github.mjs';
import { GitHubAppRouter } from '../lib/github-router.mjs';
import { HttpsDownloader } from '../lib/download.mjs';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import { RegistryError, codes } from '../lib/errors.mjs';
import { loadSources } from '../lib/source.mjs';
import { verifyRelease } from '../lib/release-verify.mjs';
import { canonicalJSON } from '../lib/strict-json.mjs';

const options = {
  'repository-id': { type: 'string' },
  'pack-id': { type: 'string' },
  tag: { type: 'string' },
  'release-id': { type: 'string' },
  out: { type: 'string' },
  'keep-work': { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
};

function usage() {
  return 'Usage: node scripts/verify-release.mjs --repository-id <id> --tag v1.2.3 [--out record.json]\n'
    + '   or: node scripts/verify-release.mjs --pack-id <pack-id> --tag v1.2.3\n'
    + 'Requires GITHUB_TOKEN and VT_API_KEY. Exit 0 verified, 2 invalid input/assets, 3 external, 1 internal.';
}

async function main() {
  const values = parseArgs({ options }).values;
  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!values.tag && !values['release-id']) throw new RegistryError(codes.ARGUMENT, '--tag or --release-id is required');
  if (!values['repository-id'] && !values['pack-id']) throw new RegistryError(codes.ARGUMENT, '--repository-id or --pack-id is required');
  const token = process.env.GITHUB_TOKEN;
  const vtKey = process.env.VT_API_KEY;
  const syncAppId = process.env.SYNC_APP_ID;
  const syncAppKey = process.env.SYNC_APP_PRIVATE_KEY;
  if (!token && !(syncAppId && syncAppKey)) {
    throw new RegistryError(codes.CONFIG, 'GITHUB_TOKEN or SYNC_APP_ID/SYNC_APP_PRIVATE_KEY is required');
  }
  if (!vtKey) throw new RegistryError(codes.CONFIG, 'VT_API_KEY is not configured; scan verification cannot be skipped');

  const root = process.cwd();
  const sources = await loadSources(root);
  const source = sources.find((item) => (
    (values['repository-id'] && item.repository.id === values['repository-id'])
    || (values['pack-id'] && item.pack_id === values['pack-id'])
  ));
  if (!source) throw new RegistryError(codes.SOURCE, 'No matching source record');
  if (!source.enabled) throw new RegistryError(codes.SOURCE, 'Source is disabled');

  const downloader = new HttpsDownloader();
  let github;
  if (syncAppId && syncAppKey) {
    github = new GitHubAppRouter({
      appId: syncAppId,
      privateKey: syncAppKey.replace(/\\n/gu, '\n'),
      downloader,
      repositoryNames: sources.map((item) => [item.repository.id, item.repository.full_name]),
    });
  } else {
    github = new GitHubClient({ token, downloader });
  }
  const vt = new VirusTotalClient({ downloader, apiKey: vtKey });
  const record = await verifyRelease({
    github,
    downloader,
    source,
    tag: values.tag ?? null,
    releaseId: values['release-id'] ?? null,
    vt,
    now: new Date(),
    keepWork: values['keep-work'],
  });
  if (values.out) {
    await writeFile(values.out, canonicalJSON(record));
    process.stdout.write(`${JSON.stringify({ ok: true, out: values.out, pack_id: record.pack_id, version: record.version }, null, 2)}\n`);
  } else {
    process.stdout.write(`${canonicalJSON(record).toString('utf8')}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? codes.INTERNAL, message: error.message, details: error.details } }, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
});
