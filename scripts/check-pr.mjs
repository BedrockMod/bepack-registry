#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { verifyRelease } from '../lib/release-verify.mjs';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import { canonicalJSON } from '../lib/strict-json.mjs';
import { parseArgs } from 'node:util';
import path from 'node:path';
import { GitHubClient } from '../lib/github.mjs';
import { GitHubAppRouter } from '../lib/github-router.mjs';
import { HttpsDownloader } from '../lib/download.mjs';
import { RegistryError, codes } from '../lib/errors.mjs';
import { buildCatalog } from '../lib/catalog.mjs';
import { loadReleases, loadWithdrawals } from '../lib/records.mjs';
import { loadSources, verifySourceProof } from '../lib/source.mjs';

const options = {
  base: { type: 'string' },
  head: { type: 'string' },
  root: { type: 'string' },
  offline: { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
};

function usage() {
  return 'Usage: node scripts/check-pr.mjs [--base origin/main] [--offline]\n'
    + 'Validates source/release/withdrawal records, source proof (online by default),\n'
    + 'same-version immutability against the base branch, and catalog generation.';
}

function git(args, encoding = 'utf8') {
  return execFileSync('git', args, { encoding, maxBuffer: 64 * 1024 * 1024 });
}

function readAtBase(base, file) {
  try {
    return git(['show', `${base}:${file}`], 'buffer');
  } catch {
    return null;
  }
}

function changedFiles(base, head = 'HEAD') {
  const output = git(['diff', '--name-status', `${base}...${head}`, '--', 'sources', 'releases', 'withdrawals']);
  const rows = [];
  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const [status, ...parts] = line.split('\t');
    const file = parts.at(-1);
    if (!file) continue;
    rows.push({ status, file });
  }
  return rows;
}

async function main() {
  const values = parseArgs({ options }).values;
  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const base = values.base ?? (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : 'origin/main');
  try {
    git(['rev-parse', '--verify', base]);
  } catch {
    throw new RegistryError(codes.ARGUMENT, `Base ref is not available: ${base}; pass --base`);
  }

  const root = values.root ?? process.cwd();
  const sources = await loadSources(root);
  const releaseMap = await loadReleases(root, sources);
  const releases = [...releaseMap.values()].flat();
  const withdrawals = await loadWithdrawals(root, releaseMap);
  const rows = changedFiles(base, values.head);
  const issues = [];
  const allChanged = git(['diff', '--name-only', `${base}...${values.head ?? 'HEAD'}`]).split('\n').filter(Boolean);
  if (rows.length && allChanged.some((file) => /^(?:lib|scripts|schemas|bridge|test|\.github)\/|^package(?:-lock)?\.json$/u.test(file))) issues.push('Data registration changes must not be mixed with trusted toolchain, schemas, workflow or policy modifications');

  for (const row of rows) {
    if (row.status === 'D') {
      issues.push(`${row.file}: registry records are append-only; deletion is not accepted`);
      continue;
    }
    if (row.file.startsWith('releases/') && (row.status.startsWith('M') || row.status.startsWith('R'))) {
      issues.push(`${row.file}: published release records are immutable`);
    }
  }

  const token = process.env.GITHUB_TOKEN ?? '';
  const syncAppId = process.env.SYNC_APP_ID;
  const syncAppKey = process.env.SYNC_APP_PRIVATE_KEY;
  const online = !values.offline;
  let github = null;
  if (online) {
    if (syncAppId && syncAppKey) {
      github = new GitHubAppRouter({
        appId: syncAppId,
        privateKey: syncAppKey.replace(/\\n/gu, '\n'),
        downloader: new HttpsDownloader(),
        repositoryNames: sources.map((source) => [source.repository.id, source.repository.full_name]),
      });
    } else if (token) {
      github = new GitHubClient({ token, downloader: new HttpsDownloader() });
    } else {
      // Fork pull requests do not receive secrets. Public proof repositories can
      // still be read anonymously; rate limits apply and online checks may be
      // retried by a maintainer when exhausted.
      github = new GitHubClient({ token: null, downloader: new HttpsDownloader() });
    }
  }
  if (online) {
    const changedSources = new Set(rows.filter((row) => row.file.startsWith('sources/') && row.status !== 'D').map((row) => row.file));
    for (const sourceFile of changedSources) {
      const source = sources.find((item) => `sources/${item.pack_id}.json` === sourceFile);
      if (!source) continue;
      try {
        await verifySourceProof(github, source);
      } catch (error) {
        issues.push(`${sourceFile}: source proof failed: ${error.message}`);
      }
    }
  }

  for (const source of sources) {
    const before = readAtBase(base, `sources/${source.pack_id}.json`);
    if (before) {
      const old = JSON.parse(before);
      if (old.repository.id !== source.repository.id) issues.push(`sources/${source.pack_id}.json: numeric repository identity is immutable`);
    }
  }

  for (const record of releases) {
    const baseBytes = readAtBase(base, `releases/${record.pack_id}/${record.version}.json`);
    if (baseBytes) {
      const current = await readFile(path.join(root, `releases/${record.pack_id}/${record.version}.json`));
      if (!baseBytes.equals(current)) {
        issues.push(`releases/${record.pack_id}/${record.version}.json: same-version record differs from ${base}`);
      }
    } else if (online) {
      try {
        if (!process.env.VT_API_KEY) throw new Error('VT_API_KEY is required for independent new-release verification; use trusted registry-verify job');
        const downloader = new HttpsDownloader();
        const vt = new VirusTotalClient({ downloader, apiKey: process.env.VT_API_KEY });
        const source = sources.find((item) => item.pack_id === record.pack_id);
        await verifySourceProof(github, source);
        const verified = await verifyRelease({ github, downloader, vt, source, releaseId: record.release.id });
        const comparable = (value) => { const copy = structuredClone(value); delete copy.verification.verified_at; return canonicalJSON(copy); };
        if (comparable(verified) !== comparable(record)) throw new Error('record differs from independently verified Release');
      } catch (error) { issues.push(`releases/${record.pack_id}/${record.version}.json: independent verification failed: ${error.message}`); }
    }
  }

  const catalog = await buildCatalog({ root });
  if (catalog.details.size !== new Set(releases.map((record) => record.pack_id)).size) {
    issues.push('catalog detail count does not match the number of packs with releases');
  }
  if (issues.length) {
    process.stderr.write(`${JSON.stringify({ ok: false, issues }, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }
  process.stdout.write(`${JSON.stringify({
    ok: true,
    base,
    sources: sources.length,
    releases: releases.length,
    withdrawals: withdrawals.size,
    changed_files: rows.length,
    catalog_packs: catalog.registry.packs.length,
    catalog_details: catalog.details.size,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? 'INTERNAL', message: error.message } }, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
});
