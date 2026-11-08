import { canonicalJSON } from '../../lib/strict-json.mjs';
import { sha256, writeStoreZip } from './zip.mjs';

export const NOW = new Date('2026-11-08T12:00:00Z');

export function makePackage({ packId = 'example.adventure', version = '1.0.0', mode = 'full', versionSet = 'default' } = {}) {
  const manifest = {
    schema_version: 1,
    id: packId,
    name: 'Example Adventure',
    author: { name: 'Example Author' },
    description: 'A controlled fixture package used to test the registry verifier.',
    version,
    license: 'MIT',
    mode,
    game_version: '1.21.0',
    version_set: versionSet,
    targets: {
      windows: {
        enabled: true,
        variants: {
          'win-x64': {
            platform: 'windows-x86_64',
            runtime: 'bedrock-client',
            game_version: '1.21.0',
            loader: { type: 'none', version: null },
            client: null,
          },
        },
      },
    },
    dependencies: [],
    contents: [{ id: 'settings', category: 'config', path: 'payload/settings.json', targets: ['win-x64'], source: 'local', destination: 'settings.json' }],
  };
  const manifestBytes = Buffer.from(canonicalJSON(manifest));
  const versionSetDocument = { schema_version: 1, id: versionSet, dependencies: {}, targets: {} };
  const versionSetBytes = Buffer.from(canonicalJSON(versionSetDocument));
  const payloadBytes = Buffer.from('{"fixture":true}\n');
  const lock = {
    schema_version: 1,
    pack: { id: packId, version, version_set: versionSet },
    generated_at: '2026-11-01T00:00:00Z',
    files: [
      { path: 'payload/settings.json', size: payloadBytes.length, sha256: sha256(payloadBytes) },
      { path: 'bepack.json', size: manifestBytes.length, sha256: sha256(manifestBytes) },
      { path: `versions/${versionSet}.json`, size: versionSetBytes.length, sha256: sha256(versionSetBytes) },
    ],
    artifacts: [],
    configurations: [{
      id: 'win-x64',
      target: 'win-x64',
      game_version: '1.21.0',
      loader: { type: 'none', version: null },
      client: null,
      dependencies: [],
      contents: ['settings'],
      runtimes: { game: 'bedrock-1.21.0', loader: null },
    }],
    evidence: [],
    compatibility: [{ subject_type: "content", subject: "settings", target: "win-x64", entry: { games: { versions: ["1.21.0"] }, loader: null, client: null, evidence: { kind: "author", reference: "controlled fixture declaration" } }, evidence: [] }],
    runtimes: [{
      id: 'bedrock-1.21.0',
      kind: 'game',
      version: '1.21.0',
      platform: 'windows-x86_64',
      runtime: 'bedrock-client',
      provider: 'mojang',
      identity: 'bedrock-1.21.0',
      integrity: { kind: 'distribution-manifest', sha256: 'd'.repeat(64) },
    }],
  };
  lock.files.sort((a,b) => Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));
  const lockBytes = Buffer.from(canonicalJSON(lock));
  const zip = writeStoreZip([
    { name: 'payload/settings.json', data: payloadBytes },
    { name: 'bepack.json', data: manifestBytes },
    { name: `versions/${versionSet}.json`, data: versionSetBytes },
    { name: 'bepack.lock.json', data: lockBytes },
  ]);
  return {
    manifest,
    manifestBytes,
    versionSet,
    versionSetBytes,
    lock,
    lockBytes,
    zip,
    packageSha256: sha256(zip),
    packageSize: zip.length,
  };
}

export function makeScanReport(pkg, { now = NOW } = {}) {
  const analyzedAt = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  const report = {
    schema_version: 1,
    policy: 'bepack-official-v1',
    package_sha256: pkg.packageSha256,
    completed_at: analyzedAt,
    entries: [{
      subject: 'package',
      sha256: pkg.packageSha256,
      size: pkg.packageSize,
      analysis_id: `analysis-${pkg.packageSha256.slice(0, 8)}`,
      status: 'completed',
      malicious: 0,
      suspicious: 0,
      harmless: 1,
      undetected: 0,
      analyzed_at: analyzedAt,
    }],
  };
  return { report, bytes: Buffer.from(canonicalJSON(report)) };
}

export function makeReleaseFixture({ packId = 'example.adventure', version = '1.0.0', repositoryId = '123456', fullName = 'example/author-repo', commit = 'a'.repeat(40), now = NOW } = {}) {
  const pkg = makePackage({ packId, version });
  const scan = makeScanReport(pkg, { now });
  const tag = `v${version}`;
  const packageName = `${packId}-${version}.bepack`;
  const checksumBytes = Buffer.from(`${pkg.packageSha256}  ${packageName}\n`);
  const descriptor = {
    schema_version: 1,
    pack_id: packId,
    version,
    version_set: pkg.versionSet,
    mode: pkg.manifest.mode,
    package_schema_version: 1,
    repository: { id: repositoryId, full_name: fullName },
    tag,
    commit,
    generated_at: new Date(now.getTime() - 30 * 60 * 1000).toISOString(),
    tool: { version: 'source-abcdef123456', sha256: 'e'.repeat(64) },
    package: { name: packageName, size: pkg.packageSize, sha256: pkg.packageSha256 },
    manifest: { name: 'bepack.json', size: pkg.manifestBytes.length, sha256: sha256(pkg.manifestBytes) },
    scan_report: { name: 'scan-report.json', size: scan.bytes.length, sha256: sha256(scan.bytes) },
  };
  const descriptorBytes = Buffer.from(canonicalJSON(descriptor));
  const assetNames = ['bepack-release.json', 'bepack.json', 'scan-report.json', packageName, `${packageName}.sha256`];
  const contents = new Map([
    ['bepack-release.json', descriptorBytes],
    ['bepack.json', pkg.manifestBytes],
    ['scan-report.json', scan.bytes],
    [packageName, pkg.zip],
    [`${packageName}.sha256`, checksumBytes],
  ]);
  const assets = assetNames.map((name, index) => ({
    id: 9000 + index,
    name,
    size: contents.get(name).length,
    state: 'uploaded',
    content_type: 'application/octet-stream',
    browser_download_url: `https://github.com/${fullName}/releases/download/${tag}/${name}`,
  }));
  const repository = { id: Number(repositoryId), full_name: fullName, private: false, archived: false, default_branch: 'main' };
  const release = {
    id: 777000,
    tag_name: tag,
    draft: false,
    prerelease: false,
    published_at: new Date(now.getTime() - 40 * 60 * 1000).toISOString(),
    html_url: `https://github.com/${fullName}/releases/tag/${tag}`,
  };
  return {
    pkg,
    scan,
    descriptor,
    descriptorBytes,
    checksumBytes,
    assets,
    contents,
    repository,
    release,
    source: {
      schema_version: 1,
      pack_id: packId,
      repository: { id: repositoryId, full_name: fullName },
      contact: `https://github.com/${fullName}/issues`,
      enabled: true,
      proof: { path: '.bepack-registry.json', commit },
    },
  };
}

export class FixtureGitHub {
  constructor(fixture) {
    this.fixture = fixture;
    this.assets = fixture.assets.map((asset) => ({ ...asset }));
    this.release = { ...fixture.release };
    this.commit = fixture.descriptor.commit;
  }

  async getRepository(id) {
    if (String(id) !== String(this.fixture.repository.id)) throw new Error(`unexpected repository ${id}`);
    return this.fixture.repository;
  }

  async getRepositoryByName(name) {
    if (name !== this.fixture.repository.full_name) throw new Error(`unexpected repository ${name}`);
    return this.fixture.repository;
  }

  async getRelease(_fullName, id) {
    if (String(id) !== String(this.release.id)) throw new Error(`unexpected release ${id}`);
    return this.release;
  }

  async listReleases() {
    return [this.release];
  }

  async listReleaseAssets(_fullName, id) {
    if (String(id) !== String(this.release.id)) throw new Error(`unexpected release ${id}`);
    return this.assets;
  }

  async getTagCommit(_fullName, tag) {
    if (tag !== this.release.tag_name) throw new Error(`unexpected tag ${tag}`);
    return this.commit;
  }
}

export class FixtureDownloader {
  constructor(fixture) {
    this.urls = new Map();
    for (const asset of fixture.assets) this.urls.set(asset.browser_download_url, fixture.contents.get(asset.name));
  }

  add(url, bytes) {
    this.urls.set(url, bytes);
  }

  async fetchBytes(url, { maxBytes = Infinity } = {}) {
    const bytes = this.urls.get(url);
    if (!bytes) throw new Error(`fixture downloader has no ${url}`);
    if (bytes.length > maxBytes) throw new Error(`fixture body exceeds ${maxBytes}`);
    return { bytes, size: bytes.length, sha256: sha256(bytes), status: 200, headers: {}, url };
  }

  async downloadToFile(url, destination, { maxBytes = Infinity } = {}) {
    const bytes = this.urls.get(url);
    if (!bytes) throw new Error(`fixture downloader has no ${url}`);
    if (bytes.length > maxBytes) throw new Error(`fixture body exceeds ${maxBytes}`);
    const { writeFile } = await import('node:fs/promises');
    await writeFile(destination, bytes);
    return { path: destination, size: bytes.length, sha256: sha256(bytes), url };
  }
}

export function makeVtPayload(sha, size, { now = NOW } = {}) {
  const analyzedAt = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  return {
    data: {
      id: sha,
      type: 'file',
      attributes: {
        sha256: sha,
        size,
        last_analysis_date: Math.floor(new Date(analyzedAt).getTime() / 1000),
        last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 1, undetected: 0, failure: 0, 'type-unsupported': 0 },
        last_analysis_results: {
          FixtureEngine: { category: 'harmless', result: null, engine_name: 'FixtureEngine', engine_version: '1.0.0', engine_update: '20261101' },
        },
      },
    },
  };
}

export function makeVtAnalysis(sha, analysisId, { now = NOW } = {}) {
  const analyzedAt = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  return {
    data: {
      id: analysisId,
      type: 'analysis',
      attributes: {
        status: 'completed',
        date: Math.floor(new Date(analyzedAt).getTime() / 1000),
        stats: { malicious: 0, suspicious: 0, harmless: 1, undetected: 0, failure: 0, 'type-unsupported': 0 },
        results: {
          FixtureEngine: { category: 'harmless', result: null, engine_name: 'FixtureEngine', engine_version: '1.0.0', engine_update: '20261101' },
        },
      },
      relationships: { item: { data: { type: 'file', id: sha } } },
    },
  };
}
