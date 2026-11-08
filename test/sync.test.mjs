import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJSON } from '../lib/strict-json.mjs';
import { loadReleases, loadWithdrawals } from '../lib/records.mjs';
import { loadSources } from '../lib/source.mjs';
import { syncReleaseSet } from '../lib/sync.mjs';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import {
  FixtureDownloader,
  FixtureGitHub,
  NOW,
  makeReleaseFixture,
  makeVtAnalysis,
  makeVtPayload,
} from './helpers/fixtures.mjs';

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'bepack-sync-'));
  await mkdir(path.join(root, 'sources'), { recursive: true });
  const fixture = makeReleaseFixture();
  await writeFile(path.join(root, 'sources', `${fixture.source.pack_id}.json`), canonicalJSON(fixture.source));
  const downloader = new FixtureDownloader(fixture);
  const analysisId = `analysis-${fixture.pkg.packageSha256.slice(0, 8)}`;
  downloader.add(
    `https://www.virustotal.com/api/v3/files/${fixture.pkg.packageSha256}`,
    Buffer.from(JSON.stringify(makeVtPayload(fixture.pkg.packageSha256, fixture.pkg.packageSize, { now: NOW }))),
  );
  downloader.add(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    Buffer.from(JSON.stringify(makeVtAnalysis(fixture.pkg.packageSha256, analysisId, { now: NOW }))),
  );
  downloader.add(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}/item`,
    Buffer.from(JSON.stringify(makeVtPayload(fixture.pkg.packageSha256, fixture.pkg.packageSize, { now: NOW }))),
  );
  const vt = new VirusTotalClient({ downloader, apiKey: 'fixture-key', clock: () => NOW });
  const github = new FixtureGitHub(fixture);
  return { root, fixture, downloader, vt, github };
}

test('syncs a new release, is idempotent, and marks a deleted release unavailable', async () => {
  const { root, fixture, downloader, vt, github } = await setup();
  try {
    const first = await syncReleaseSet({ github, downloader, vt, root, repositoryId: '123456', now: NOW });
    assert.equal(first.new_versions.length, 1);
    const recordPath = path.join(root, 'releases', fixture.pkg.manifest.id, `${fixture.pkg.manifest.version}.json`);
    const written = JSON.parse(await readFile(recordPath, 'utf8'));
    assert.equal(written.package.sha256, fixture.pkg.packageSha256);

    const second = await syncReleaseSet({ github, downloader, vt, root, repositoryId: '123456', now: NOW });
    assert.equal(second.unchanged.length, 1);
    assert.equal(second.new_versions.length, 0);

    github.listReleases = async () => [];
    const third = await syncReleaseSet({ github, downloader, vt, root, repositoryId: '123456', now: NOW });
    assert.equal(third.unavailable.length, 1);
    const sources = await loadSources(root);
    const releases = await loadReleases(root, sources);
    const withdrawals = await loadWithdrawals(root, releases);
    assert.equal(withdrawals.get(`${fixture.pkg.manifest.id}@${fixture.pkg.manifest.version}`).state, 'unavailable');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
