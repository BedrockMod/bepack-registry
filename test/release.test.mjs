import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { classifyReleaseChange, validateReleaseRecord } from '../lib/records.mjs';
import { verifyRelease } from '../lib/release-verify.mjs';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import {
  FixtureDownloader,
  FixtureGitHub,
  NOW,
  makeReleaseFixture,
  makeVtAnalysis,
  makeVtPayload,
} from './helpers/fixtures.mjs';

async function withWorkRoot(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bepack-release-'));
  try {
    return await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function makeVerifier(fixture) {
  const downloader = new FixtureDownloader(fixture);
  downloader.add(
    `https://www.virustotal.com/api/v3/files/${fixture.pkg.packageSha256}`,
    Buffer.from(JSON.stringify(makeVtPayload(fixture.pkg.packageSha256, fixture.pkg.packageSize, { now: NOW }))),
  );
  const analysisId = `analysis-${fixture.pkg.packageSha256.slice(0, 8)}`;
  downloader.add(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    Buffer.from(JSON.stringify(makeVtAnalysis(fixture.pkg.packageSha256, analysisId, { now: NOW }))),
  );
  downloader.add(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}/item`,
    Buffer.from(JSON.stringify(makeVtPayload(fixture.pkg.packageSha256, fixture.pkg.packageSize, { now: NOW }))),
  );
  const vt = new VirusTotalClient({ downloader, apiKey: 'fixture-key', clock: () => NOW });
  return { downloader, vt, github: new FixtureGitHub(fixture) };
}

test('independently validates five release assets and builds a release record', async () => {
  const fixture = makeReleaseFixture();
  const { downloader, vt, github } = makeVerifier(fixture);
  await withWorkRoot(async (workRoot) => {
    const record = await verifyRelease({
      github,
      downloader,
      source: fixture.source,
      releaseId: String(fixture.release.id),
      now: NOW,
      vt,
      workRoot,
    });
    assert.equal(record.pack_id, fixture.pkg.manifest.id);
    assert.equal(record.version, fixture.pkg.manifest.version);
    assert.equal(record.package.sha256, fixture.pkg.packageSha256);
    assert.equal(record.evidence.length, 1);
    assert.equal(record.verification.policy, 'bepack-official-v1');
    assert.equal(record.verification.scan_checked_at, record.evidence[0].analyzed_at);
    assert.doesNotThrow(() => validateReleaseRecord(record, {
      packId: fixture.source.pack_id,
      version: fixture.pkg.manifest.version,
      source: fixture.source,
    }));
    assert.equal(classifyReleaseChange(record, record), 'same');
  });
});

test('rejects a release when the package checksum is not byte-consistent', async () => {
  const fixture = makeReleaseFixture();
  const { downloader, vt, github } = makeVerifier(fixture);
  const packageAsset = fixture.assets.find((asset) => asset.name.endsWith('.bepack'));
  const original = fixture.contents.get(packageAsset.name);
  const tampered = Buffer.from(original);
  tampered[tampered.length - 1] ^= 0xff;
  downloader.add(packageAsset.browser_download_url, tampered);
  await withWorkRoot(async (workRoot) => {
    await assert.rejects(
      verifyRelease({ github, downloader, source: fixture.source, releaseId: String(fixture.release.id), now: NOW, vt, workRoot }),
      /size differs|SHA-256 differs|checksum/iu,
    );
  });
});

test('detects a same-version asset identity change instead of rebinding', async () => {
  const fixture = makeReleaseFixture();
  const { downloader, vt, github } = makeVerifier(fixture);
  const record = await withWorkRoot((workRoot) => verifyRelease({
    github, downloader, source: fixture.source, releaseId: String(fixture.release.id), now: NOW, vt, workRoot,
  }));
  const moved = structuredClone(record);
  moved.package.id = String(Number(record.package.id) + 1);
  assert.equal(classifyReleaseChange(record, moved), 'changed');
  const changedBytes = structuredClone(record);
  changedBytes.package.sha256 = 'f'.repeat(64);
  assert.equal(classifyReleaseChange(record, changedBytes), 'changed');
});

test('rejects a tag target that moves between the two reads', async () => {
  const fixture = makeReleaseFixture();
  const { downloader, vt, github } = makeVerifier(fixture);
  let calls = 0;
  const original = github.getTagCommit.bind(github);
  github.getTagCommit = async (...args) => {
    calls += 1;
    return calls === 1 ? original(...args) : 'b'.repeat(40);
  };
  await withWorkRoot(async (workRoot) => {
    await assert.rejects(
      verifyRelease({ github, downloader, source: fixture.source, releaseId: String(fixture.release.id), now: NOW, vt, workRoot }),
      /moved|changed/iu,
    );
  });
});
