import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildCatalog, writeCatalog } from '../lib/catalog.mjs';
import { validateReleaseRecord } from '../lib/records.mjs';
import { canonicalJSON } from '../lib/strict-json.mjs';
import { sha256 } from './helpers/zip.mjs';
import { NOW, makeReleaseFixture } from './helpers/fixtures.mjs';

async function makeRepo() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'bepack-catalog-'));
  await mkdir(path.join(root, 'sources'), { recursive: true });
  await mkdir(path.join(root, 'releases'), { recursive: true });
  await mkdir(path.join(root, 'withdrawals'), { recursive: true });
  return root;
}

async function addVersion(root, { packId, version, prerelease = false, source = null }) {
  const fixture = makeReleaseFixture({ packId, version, now: NOW });
  fixture.release.prerelease = prerelease;
  fixture.descriptor.generated_at = NOW.toISOString();
  const record = {
    schema_version: 1,
    pack_id: packId,
    version,
    version_set: fixture.pkg.versionSet,
    mode: 'full',
    name: fixture.pkg.manifest.name,
    description: fixture.pkg.manifest.description,
    author: fixture.pkg.manifest.author,
    license: fixture.pkg.manifest.license,
    package_schema_version: 1,
    repository: { id: fixture.source.repository.id, full_name: fixture.source.repository.full_name },
    release: {
      id: String(fixture.release.id),
      tag: fixture.release.tag_name,
      commit: fixture.descriptor.commit,
      published_at: fixture.release.published_at,
      url: fixture.release.html_url,
    },
    package: {
      id: String(fixture.assets.find((asset) => asset.name.endsWith('.bepack')).id),
      name: fixture.descriptor.package.name,
      url: fixture.assets.find((asset) => asset.name.endsWith('.bepack')).browser_download_url,
      size: fixture.pkg.packageSize,
      sha256: fixture.pkg.packageSha256,
    },
    manifest: {
      id: String(fixture.assets.find((asset) => asset.name === 'bepack.json').id),
      name: 'bepack.json',
      url: fixture.assets.find((asset) => asset.name === 'bepack.json').browser_download_url,
      size: fixture.pkg.manifestBytes.length,
      sha256: sha256(fixture.pkg.manifestBytes),
    },
    descriptor: {
      id: String(fixture.assets.find((asset) => asset.name === 'bepack-release.json').id),
      name: 'bepack-release.json',
      url: fixture.assets.find((asset) => asset.name === 'bepack-release.json').browser_download_url,
      size: fixture.descriptorBytes.length,
      sha256: sha256(fixture.descriptorBytes),
    },
    scan_report: {
      id: String(fixture.assets.find((asset) => asset.name === 'scan-report.json').id),
      name: 'scan-report.json',
      url: fixture.assets.find((asset) => asset.name === 'scan-report.json').browser_download_url,
      size: fixture.scan.bytes.length,
      sha256: sha256(fixture.scan.bytes),
    },
    targets: [{
      target: 'win-x64',
      platform: 'windows-x86_64',
      runtime: 'bedrock-client',
      requires: [],
      game_versions: ['1.21.0'],
      loaders: [{ type: 'none', version: null }],
      clients: [],
    }],
    executables: [],
    verification: {
      tool_version: 'bepack-registry-verifier/0.1.0',
      verified_at: NOW.toISOString(),
      policy: 'bepack-official-v1',
      scan_checked_at: NOW.toISOString(),
    },
    evidence: [{ sha256: fixture.pkg.packageSha256, analysis_id: `analysis-${fixture.pkg.packageSha256.slice(0, 8)}`, analyzed_at: NOW.toISOString(), malicious: 0, suspicious: 0 }],
  };
  validateReleaseRecord(record, { packId, version, source: source ?? fixture.source });
  const directory = path.join(root, 'releases', packId);
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, `${version}.json`), canonicalJSON(record));
  return { record, fixture };
}

async function addWithdrawal(root, packId, version, state = 'yanked') {
  const document = {
    schema_version: 1,
    pack_id: packId,
    version,
    state,
    reason: state === 'yanked' ? 'Withdrawn by a controlled fixture' : null,
    created_at: NOW.toISOString(),
    advisory_url: null,
  };
  if (state === 'active') document.reason = 'Re-reviewed by a controlled fixture';
  const directory = path.join(root, 'withdrawals', packId);
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, `${version}.json`), canonicalJSON(document));
}

test('builds content-addressed details and stable/prerelease summaries', async () => {
  const root = await makeRepo();
  try {
    const packId = 'example.adventure';
    const source = makeReleaseFixture({ packId }).source;
    await writeFile(path.join(root, 'sources', `${packId}.json`), canonicalJSON(source));
    await addVersion(root, { packId, version: '1.0.0', source });
    await addVersion(root, { packId, version: '1.1.0', source });
    await addVersion(root, { packId, version: '2.0.0-beta.1', prerelease: true, source });
    await addWithdrawal(root, packId, '1.0.0', 'yanked');

    const revision = '11111111-1111-4111-8111-111111111111';
    const catalog = await buildCatalog({ root, now: NOW, revision });
    assert.equal(catalog.registry.packs.length, 1);
    const entry = catalog.registry.packs[0];
    assert.equal(entry.id, packId);
    assert.equal(entry.latest, '1.1.0');
    assert.equal(entry.latest_prerelease, '2.0.0-beta.1');
    assert.equal(entry.mode, 'full');
    assert.equal(entry.state, 'active');
    assert.equal(entry.detail.sha256, sha256(catalog.details.get(entry.detail.path)));

    const out = path.join(root, 'out');
    await writeCatalog({ outDir: out, registryBytes: catalog.registryBytes, details: catalog.details });
    const written = JSON.parse(await readFile(path.join(out, entry.detail.path), 'utf8'));
    assert.deepEqual(written.versions.map((version) => version.version), ['2.0.0-beta.1', '1.1.0', '1.0.0']);
    assert.equal(written.versions.find((version) => version.version === '1.0.0').state, 'yanked');
    assert.equal(written.versions.find((version) => version.version === '1.1.0').state, 'active');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('keeps an all-withdrawn pack with null latest instead of hiding it', async () => {
  const root = await makeRepo();
  try {
    const packId = 'example.withdrawn';
    const source = makeReleaseFixture({ packId }).source;
    await writeFile(path.join(root, 'sources', `${packId}.json`), canonicalJSON(source));
    await addVersion(root, { packId, version: '0.1.0', source });
    await addWithdrawal(root, packId, '0.1.0', 'yanked');
    const catalog = await buildCatalog({ root, now: NOW, revision: '22222222-2222-4222-8222-222222222222' });
    const entry = catalog.registry.packs[0];
    assert.equal(entry.state, 'inactive');
    assert.equal(entry.latest, null);
    assert.equal(entry.latest_prerelease, null);
    assert.equal(entry.detail.path.startsWith('packs/'), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('omits a registered source that has no releases', async () => {
  const root = await makeRepo();
  try {
    const packId = 'example.empty';
    const source = makeReleaseFixture({ packId }).source;
    await writeFile(path.join(root, 'sources', `${packId}.json`), canonicalJSON(source));
    const catalog = await buildCatalog({ root, now: NOW, revision: '33333333-3333-4333-8333-333333333333' });
    assert.deepEqual(catalog.registry.packs, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
