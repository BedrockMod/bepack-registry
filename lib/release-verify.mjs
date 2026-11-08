import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  ASSET_NAMES, LIMITS, POLICY, PACKAGE_SCHEMA_VERSION, VERIFICATION_TOOL, VERIFIER_VERSION,
} from './constants.mjs';
import { COMMIT_PATTERN } from './constants.mjs';
import { RegistryError, codes } from './errors.mjs';
import { verifyPackage } from './package-verify.mjs';
import { parseStrictJSON } from './strict-json.mjs';
import { assertPublicHttpsUrl } from './url-safety.mjs';
import { safeId, safePackId, safeRelative, sha256Hex } from './paths.mjs';
import { parseSemver } from './semver.mjs';
import {
  Issues, exactKeys, isInteger, isObject, isNonEmptyString, checkHttps, checkSha256,
  checkTimestamp, checkGameVersion, versionRequirement,
} from './validate-common.mjs';
import { scanEvidence } from './virustotal.mjs';

const ASSET_KEYS = Object.freeze({
  descriptor: ASSET_NAMES.descriptor,
  manifest: ASSET_NAMES.manifest,
  scanReport: ASSET_NAMES.scanReport,
});

function releaseError(message, details = null) {
  return new RegistryError(codes.RELEASE, message, { details, exitCode: 2 });
}

function changedError(message, details = null) {
  return new RegistryError(codes.ASSET_CHANGED, message, { details, exitCode: 2 });
}

function expectedPackageName(packId, version) {
  return `${packId}-${version}.bepack`;
}

function parseTagVersion(tag) {
  if (typeof tag !== 'string' || !tag.startsWith('v')) throw releaseError('Release tag must look like v<semver>');
  const version = tag.slice(1);
  const parsed = parseSemver(version);
  if (!parsed) throw releaseError('Release tag is not a valid SemVer version');
  return { version, parsed };
}

function describeAsset(asset) {
  return { id: String(asset.id), name: asset.name, size: asset.size, url: asset.browser_download_url };
}

function assetSize(asset) {
  if (!isInteger(asset?.size)) throw changedError('Release asset has an invalid API size');
  return asset.size;
}

function validateAsset(asset, name, repositoryFullName) {
  if (!asset || typeof asset !== 'object') throw releaseError(`Release asset ${name} is missing`);
  if (asset.name !== name) throw releaseError(`Expected release asset ${name}, found ${asset.name}`);
  if (asset.state !== 'uploaded') throw releaseError(`Release asset ${name} is not uploaded`);
  if (!isInteger(asset.size) || asset.size < 0) throw releaseError(`Release asset ${name} has an invalid size`);
  if (typeof asset.id !== 'number' && !/^\d+$/u.test(String(asset.id))) throw releaseError(`Release asset ${name} has an invalid id`);
  const url = asset.browser_download_url;
  assertPublicHttpsUrl(url);
  const parsed = new URL(url);
  const expectedPrefix = `/${repositoryFullName}/releases/download/`.toLowerCase();
  if (parsed.hostname !== 'github.com' || !parsed.pathname.toLowerCase().startsWith(expectedPrefix)) {
    throw releaseError(`Release asset ${name} URL is not the repository's GitHub release download URL`);
  }
  if (parsed.username || parsed.password || parsed.hash) throw releaseError(`Release asset ${name} URL is not canonical`);
  return url;
}

async function downloadBytes(downloader, asset, name, maxBytes) {
  const url = asset.browser_download_url;
  const result = await downloader.fetchBytes(url, { maxBytes, headers: { accept: 'application/octet-stream' } });
  if (result.size !== asset.size) throw changedError(`Downloaded asset ${name} size differs from the API`, { name, expected: asset.size, actual: result.size });
  return result;
}

async function downloadFile(downloader, asset, name, destination, maxBytes) {
  const url = asset.browser_download_url;
  return downloader.downloadToFile(url, destination, { maxBytes, headers: { accept: 'application/octet-stream' } });
}

function validateChecksum(bytes, packageName, packageSha) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (text.includes('\r')) throw releaseError('The .bepack.sha256 file must use LF line endings');
  const match = /^([0-9a-f]{64}) {2}([^\n]+)\n$/u.exec(text);
  if (!match) throw releaseError('The .bepack.sha256 file must contain one checksum line with two spaces and LF');
  if (match[1] !== packageSha) throw releaseError('The .bepack.sha256 checksum does not match the package');
  if (match[2] !== packageName) throw releaseError('The .bepack.sha256 filename does not match the package name');
}

function validateDescriptor(bytes, { source, repository, release, tag, commit }) {
  let descriptor;
  try {
    descriptor = parseStrictJSON(bytes, { maxBytes: LIMITS.releaseDescriptorBytes });
  } catch (error) {
    throw releaseError(`bepack-release.json is not strict JSON: ${error.message}`);
  }
  const issues = new Issues('bepack-release.json');
  const required = [
    'schema_version', 'pack_id', 'version', 'version_set', 'mode', 'package_schema_version',
    'repository', 'tag', 'commit', 'generated_at', 'tool', 'package', 'manifest', 'scan_report',
  ];
  if (!exactKeys(descriptor, required, required, 'bepack-release.json', issues)) throw releaseError('Release descriptor is not an object');
  if (descriptor.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'bepack-release.json', '/schema_version');
  if (!safePackId(descriptor.pack_id)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid pack_id', 'bepack-release.json', '/pack_id');
  if (descriptor.pack_id !== source.pack_id) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor pack_id differs from the source record', 'bepack-release.json', '/pack_id');
  let parsed;
  try {
    parsed = parseSemver(descriptor.version);
  } catch {
    issues.add('BEPACK_MANIFEST_INVALID', 'Invalid version', 'bepack-release.json', '/version');
  }
  if (!safeId(descriptor.version_set)) issues.add('BEPACK_VERSION_SET_INVALID', 'Invalid version_set', 'bepack-release.json', '/version_set');
  if (!['full', 'modded', 'client', 'mods-only'].includes(descriptor.mode)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid mode', 'bepack-release.json', '/mode');
  if (descriptor.package_schema_version !== PACKAGE_SCHEMA_VERSION) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only package_schema_version 1 is supported', 'bepack-release.json', '/package_schema_version');
  if (exactKeys(descriptor.repository, ['id', 'full_name'], ['id', 'full_name'], '/repository', issues)) {
    if (descriptor.repository.id !== String(repository.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor repository id differs from the verified repository', 'bepack-release.json', '/repository/id');
    if (descriptor.repository.full_name !== repository.full_name) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor repository full_name differs from the verified repository', 'bepack-release.json', '/repository/full_name');
  }
  if (descriptor.tag !== tag) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor tag differs from the release tag', 'bepack-release.json', '/tag');
  if (descriptor.commit !== commit) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor commit differs from the tag target', 'bepack-release.json', '/commit');
  if (!COMMIT_PATTERN.test(descriptor.commit)) issues.add('BEPACK_MANIFEST_INVALID', 'Expected a 40-character lowercase commit SHA', 'bepack-release.json', '/commit');
  checkTimestamp(descriptor.generated_at, '/generated_at', issues);
  if (exactKeys(descriptor.tool, ['version', 'sha256'], ['version', 'sha256'], '/tool', issues)) {
    if (!isNonEmptyString(descriptor.tool.version) || descriptor.tool.version.length > 256) issues.add('BEPACK_MANIFEST_INVALID', 'tool.version must be a non-empty string', 'bepack-release.json', '/tool/version');
    checkSha256(descriptor.tool.sha256, '/tool/sha256', issues);
  }
  const packageName = expectedPackageName(descriptor.pack_id, descriptor.version);
  if (exactKeys(descriptor.package, ['name', 'size', 'sha256'], ['name', 'size', 'sha256'], '/package', issues)) {
    if (descriptor.package.name !== packageName) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor package name differs from <pack-id>-<version>.bepack', 'bepack-release.json', '/package/name');
    if (!isInteger(descriptor.package.size) || descriptor.package.size < 1 || descriptor.package.size > LIMITS.packageBytes) issues.add('BEPACK_RESOURCE_LIMIT', 'Descriptor package size is out of bounds', 'bepack-release.json', '/package/size');
    checkSha256(descriptor.package.sha256, '/package/sha256', issues);
  }
  if (exactKeys(descriptor.manifest, ['name', 'size', 'sha256'], ['name', 'size', 'sha256'], '/manifest', issues)) {
    if (descriptor.manifest.name !== ASSET_NAMES.manifest) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor manifest name must be bepack.json', 'bepack-release.json', '/manifest/name');
    if (!isInteger(descriptor.manifest.size) || descriptor.manifest.size < 1 || descriptor.manifest.size > LIMITS.manifestBytes) issues.add('BEPACK_RESOURCE_LIMIT', 'Descriptor manifest size is out of bounds', 'bepack-release.json', '/manifest/size');
    checkSha256(descriptor.manifest.sha256, '/manifest/sha256', issues);
  }
  if (exactKeys(descriptor.scan_report, ['name', 'size', 'sha256'], ['name', 'size', 'sha256'], '/scan_report', issues)) {
    if (descriptor.scan_report.name !== ASSET_NAMES.scanReport) issues.add('BEPACK_MANIFEST_INVALID', 'Descriptor scan report name must be scan-report.json', 'bepack-release.json', '/scan_report/name');
    if (!isInteger(descriptor.scan_report.size) || descriptor.scan_report.size < 1 || descriptor.scan_report.size > LIMITS.scanReportBytes) issues.add('BEPACK_RESOURCE_LIMIT', 'Descriptor scan report size is out of bounds', 'bepack-release.json', '/scan_report/size');
    checkSha256(descriptor.scan_report.sha256, '/scan_report/sha256', issues);
  }
  if (issues.length) throw releaseError('Release descriptor validation failed', { issues: issues.list });
  const tagInfo = parseTagVersion(tag);
  if (tagInfo.version !== descriptor.version) throw releaseError('Release tag does not match the descriptor version');
  if (tagInfo.parsed.prerelease.length > 0 && release.prerelease !== true) throw releaseError('A prerelease version must be flagged as a GitHub prerelease');
  if (tagInfo.parsed.prerelease.length === 0 && release.prerelease !== false) throw releaseError('A stable version must not be flagged as a GitHub prerelease');
  return { descriptor, parsed, packageName };
}

function validateScanReport(bytes, { packageSha, packageSize, expectedPlan, now }) {
  let report;
  try {
    report = parseStrictJSON(bytes, { maxBytes: LIMITS.scanReportBytes });
  } catch (error) {
    throw releaseError(`scan-report.json is not strict JSON: ${error.message}`);
  }
  const issues = new Issues('scan-report.json');
  const required = ['schema_version', 'policy', 'package_sha256', 'completed_at', 'entries'];
  if (!exactKeys(report, required, required, 'scan-report.json', issues)) throw releaseError('Scan report is not an object');
  if (report.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'scan-report.json', '/schema_version');
  if (report.policy !== POLICY) issues.add('BEPACK_MANIFEST_INVALID', `Scan policy must be ${POLICY}`, 'scan-report.json', '/policy');
  if (report.package_sha256 !== packageSha) issues.add('BEPACK_HASH_MISMATCH', 'Scan report package hash differs from the package', 'scan-report.json', '/package_sha256');
  checkSha256(report.package_sha256, '/package_sha256', issues);
  checkTimestamp(report.completed_at, '/completed_at', issues);
  if (!Array.isArray(report.entries) || report.entries.length === 0) {
    issues.add('BEPACK_SCAN_FAILED', 'Scan report entries must be a non-empty array', 'scan-report.json', '/entries');
  } else {
    const subjects = new Set();
    for (const [index, entry] of report.entries.entries()) {
      const field = `/entries/${index}`;
      if (!exactKeys(entry, ['subject', 'sha256', 'size', 'analysis_id', 'status', 'malicious', 'suspicious', 'harmless', 'undetected', 'analyzed_at'], ['subject', 'sha256', 'size', 'analysis_id', 'status', 'malicious', 'suspicious', 'harmless', 'undetected', 'analyzed_at'], field, issues)) continue;
      if (typeof entry.subject !== 'string' || entry.subject.length === 0) {
        issues.add('BEPACK_SCAN_FAILED', 'Scan subject is required', `scan-report.json${field}/subject`);
      } else {
        if (subjects.has(entry.subject)) issues.add('BEPACK_SCAN_FAILED', 'Duplicate scan subject', `scan-report.json${field}/subject`);
        subjects.add(entry.subject);
        if (entry.subject !== 'package') {
          const dependencyMatch = /^dependency\/([a-z0-9][a-z0-9._-]{0,63})\/([a-z0-9][a-z0-9._-]{0,63})$/u.exec(entry.subject);
          if (!dependencyMatch && !safeRelative(entry.subject, { prefix: 'payload' })) issues.add('BEPACK_SCAN_FAILED', 'Invalid scan subject', `scan-report.json${field}/subject`);
        }
      }
      checkSha256(entry.sha256, `${field}/sha256`, issues);
      if (!isInteger(entry.size) || entry.size < 0) issues.add('BEPACK_SCAN_FAILED', 'Scan size must be a non-negative integer', `scan-report.json${field}/size`);
      if (!isNonEmptyString(entry.analysis_id) || entry.analysis_id.length > 256) issues.add('BEPACK_SCAN_FAILED', 'analysis_id must be a non-empty string', `scan-report.json${field}/analysis_id`);
      if (entry.status !== 'completed') issues.add('BEPACK_SCAN_FAILED', 'Only completed analyses are accepted', `scan-report.json${field}/status`);
      if (entry.malicious !== 0 || entry.suspicious !== 0) issues.add('BEPACK_SCAN_FAILED', 'Malicious or suspicious detections are not publishable', `scan-report.json${field}`);
      if (!isInteger(entry.harmless) || !isInteger(entry.undetected) || entry.harmless + entry.undetected < 1) issues.add('BEPACK_SCAN_FAILED', 'At least one harmless or undetected engine is required', `scan-report.json${field}`);
      const analyzedMs = checkTimestamp(entry.analyzed_at, `${field}/analyzed_at`, issues);
      if (analyzedMs !== null && analyzedMs > now.getTime() + 5 * 60 * 1000) {
        issues.add('BEPACK_SCAN_FAILED', 'Analysis timestamp is in the future', `scan-report.json${field}/analyzed_at`);
      }
    }
    const expected = new Map(expectedPlan.map((entry) => [entry.subject, entry]));
    for (const [subject, entry] of expected) {
      const found = report.entries.find((candidate) => candidate.subject === subject);
      if (!found) {
        issues.add('BEPACK_SCAN_FAILED', 'Scan report omits a required subject', 'scan-report.json', '/entries', { subject });
        continue;
      }
      if (found.sha256 !== entry.sha256) issues.add('BEPACK_HASH_MISMATCH', 'Scan subject hash differs from the verified bytes', `scan-report.json/entries/${escapePointer(subject)}/sha256`);
      if (found.size !== entry.size) issues.add('BEPACK_SCAN_FAILED', 'Scan subject size differs from the verified bytes', `scan-report.json/entries/${escapePointer(subject)}/size`);
    }
    for (const entry of report.entries) {
      if (!expected.has(entry.subject)) issues.add('BEPACK_SCAN_FAILED', 'Scan report contains an unexpected subject', 'scan-report.json', '/entries', { subject: entry.subject });
    }
  }
  if (issues.length) throw releaseError('Scan report validation failed', { issues: issues.list });
  return report;
}

function escapePointer(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

function validateRuntimes(report) {
  if (!isObject(report)) throw releaseError('Scan report is not an object');
}

function stamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw releaseError('Invalid timestamp');
  return date.toISOString();
}

function assertFinalRecord(record, { repositoryId, fullName, packageSha, tag, commit }) {
  if (record.repository.id !== repositoryId || record.repository.full_name !== fullName) throw new RegistryError(codes.INTERNAL, 'Record repository mismatch');
  if (record.package.sha256 !== packageSha) throw new RegistryError(codes.INTERNAL, 'Record package hash mismatch');
  if (record.release.tag !== tag || record.release.commit !== commit) throw new RegistryError(codes.INTERNAL, 'Record release identity mismatch');
  if (!safePackId(record.pack_id) || !safeId(record.version_set)) throw new RegistryError(codes.INTERNAL, 'Record identity is invalid');
  assertPublicHttpsUrl(record.release.url);
  if (!record.evidence.length) throw new RegistryError(codes.INTERNAL, 'Record has no scan evidence');
  for (const entry of record.evidence) {
    if (!sha256Hex(entry.sha256) || !isInteger(entry.malicious) || !isInteger(entry.suspicious)) throw new RegistryError(codes.INTERNAL, 'Record evidence is invalid');
  }
}

async function verifyVt(vt, plan, now, analysisBySha) {
  if (!vt) throw new RegistryError(codes.CONFIG, 'VirusTotal client is not configured; a scan cannot be verified', { exitCode: 2 });
  const evidence = new Map();
  for (const entry of plan) {
    let result = evidence.get(entry.sha256);
    if (!result) {
      const analysisId = analysisBySha.get(entry.sha256);
      if (!analysisId) throw new RegistryError(codes.SCAN_FAILED, `Scan report has no analysis id for ${entry.subject}`, { exitCode: 2 });
      result = await vt.getFileReport(entry.sha256, { analysisId });
      evidence.set(entry.sha256, result);
    }
    if (result.analysis_id !== analysisBySha.get(entry.sha256)) throw new RegistryError(codes.SCAN_FAILED, `VirusTotal analysis id differs for ${entry.subject}`, { exitCode: 2 });
    if (result.size !== entry.size) throw new RegistryError(codes.SCAN_FAILED, `VirusTotal size differs for ${entry.subject}`, { details: { subject: entry.subject, expected: entry.size, actual: result.size }, exitCode: 2 });
    if (result.malicious !== 0 || result.suspicious !== 0) throw new RegistryError(codes.SCAN_FAILED, `VirusTotal reports detections for ${entry.subject}`, { exitCode: 2 });
    if (result.harmless + result.undetected < 1) throw new RegistryError(codes.SCAN_FAILED, `VirusTotal has no clean engine for ${entry.subject}`, { exitCode: 2 });
    if (new Date(result.analyzed_at).getTime() > now.getTime() + 5 * 60 * 1000) throw new RegistryError(codes.SCAN_FAILED, 'VirusTotal analysis timestamp is in the future', { exitCode: 2 });
  }
  return [...evidence.values()].sort((left, right) => left.sha256 < right.sha256 ? -1 : left.sha256 > right.sha256 ? 1 : 0);
}

export async function verifyRelease({
  github, downloader, source, releaseId = null, tag = null, expectedCommit = null,
  vt = null, now = new Date(), workRoot = null, keepWork = false,
}) {
  if (!github || !downloader) throw new TypeError('github and downloader are required');
  if (!source || !source.repository) throw new TypeError('source is required');
  if (!source.enabled) throw new RegistryError(codes.SOURCE, 'Source is disabled', { exitCode: 2 });
  if (source.repository.id === undefined) throw new RegistryError(codes.SOURCE, 'Source has no repository id', { exitCode: 2 });
  if (!Number.isFinite(now.getTime())) throw new TypeError('now must be a Date');

  const repositoryId = String(source.repository.id);
  const repository = await github.getRepository(repositoryId);
  if (String(repository.id) !== repositoryId) throw releaseError('GitHub returned a repository with a different id');
  if (repository.archived === true || repository.disabled === true) throw releaseError('Repository is archived or disabled');
  if (repository.private === true) throw releaseError('Repository must be public');
  if (source.repository.full_name && repository.full_name !== source.repository.full_name) {
    throw new RegistryError(codes.SOURCE, 'Source repository full_name is stale (rename or transfer); re-review is required', { exitCode: 2 });
  }
  const fullName = repository.full_name;

  let release;
  if (releaseId !== null && releaseId !== undefined) {
    release = await github.getRelease(fullName, String(releaseId));
  } else if (tag) {
    const releases = await github.listReleases(fullName);
    release = releases.find((candidate) => candidate && candidate.tag_name === tag);
    if (!release) throw releaseError(`Release tag ${tag} was not found`);
  } else {
    throw releaseError('releaseId or tag is required');
  }
  if (!release || (release.id === undefined)) throw releaseError('Release was not found');
  if (release.draft === true) throw releaseError('Draft releases are not publishable');
  if (releaseId !== null && releaseId !== undefined && String(release.id) !== String(releaseId)) throw releaseError('GitHub returned a different release');
  if (!tag) tag = release.tag_name;
  if (release.tag_name !== tag) throw releaseError('Release tag differs from the requested tag');
  if (!PACKAGE_SCHEMA_VERSION) throw new Error('unreachable');
  const tagInfo = parseTagVersion(tag);
  if (release.prerelease !== (tagInfo.parsed.prerelease.length > 0)) throw releaseError('GitHub prerelease flag disagrees with the tag SemVer');

  const assets = await github.listReleaseAssets(fullName, release.id);
  if (assets.length !== 5) throw releaseError(`A release must have exactly five assets, found ${assets.length}`);
  const byName = new Map();
  for (const asset of assets) {
    if (byName.has(asset.name)) throw releaseError(`Duplicate release asset name ${asset.name}`);
    byName.set(asset.name, asset);
  }
  const names = [ASSET_NAMES.descriptor, ASSET_NAMES.manifest, ASSET_NAMES.scanReport];
  const packageName = expectedPackageName(source.pack_id, tagInfo.version);
  names.push(packageName, `${packageName}.sha256`);
  for (const name of names) {
    if (!byName.has(name)) throw releaseError(`Release is missing required asset ${name}`);
    validateAsset(byName.get(name), name, fullName);
  }
  for (const name of byName.keys()) if (!names.includes(name)) throw releaseError(`Release has unexpected asset ${name}`);

  const tagCommit = await github.getTagCommit(fullName, tag);
  if (expectedCommit && tagCommit !== expectedCommit) throw changedError('Tag target differs from the expected commit', { expected: expectedCommit, actual: tagCommit });

  const work = workRoot ? await mkdtemp(path.join(workRoot, 'bepack-release-')) : await mkdtemp(path.join(os.tmpdir(), 'bepack-release-'));
  try {
    const descriptorAsset = byName.get(ASSET_NAMES.descriptor);
    const descriptorBytes = await downloadBytes(downloader, descriptorAsset, ASSET_NAMES.descriptor, LIMITS.releaseDescriptorBytes);
    const { descriptor, parsed, packageName: expectedName } = validateDescriptor(descriptorBytes.bytes, {
      source, repository, release, tag, commit: tagCommit,
    });

    const packageAsset = byName.get(expectedName);
    const checksumAsset = byName.get(`${expectedName}.sha256`);
    const manifestAsset = byName.get(ASSET_NAMES.manifest);
    const scanAsset = byName.get(ASSET_NAMES.scanReport);
    if (!packageAsset || !checksumAsset || !manifestAsset || !scanAsset) throw releaseError('Release asset set is incomplete');

    const packagePath = path.join(work, expectedName);
    const packageDownload = await downloadFile(downloader, packageAsset, expectedName, packagePath, LIMITS.packageBytes);
    if (packageDownload.size !== assetSize(packageAsset)) throw changedError('Downloaded package size differs from the release API', { expected: assetSize(packageAsset), actual: packageDownload.size });
    if (packageDownload.size !== descriptor.package.size) throw releaseError('Package size differs from the release descriptor');
    if (packageDownload.sha256 !== descriptor.package.sha256) throw releaseError('Package SHA-256 differs from the release descriptor');
    const packageSha = packageDownload.sha256;

    const manifestDownload = await downloadBytes(downloader, manifestAsset, ASSET_NAMES.manifest, LIMITS.manifestBytes);
    if (manifestDownload.size !== descriptor.manifest.size || manifestDownload.sha256 !== descriptor.manifest.sha256) throw releaseError('bepack.json copy differs from the release descriptor');
    const scanDownload = await downloadBytes(downloader, scanAsset, ASSET_NAMES.scanReport, LIMITS.scanReportBytes);
    if (scanDownload.size !== descriptor.scan_report.size || scanDownload.sha256 !== descriptor.scan_report.sha256) throw releaseError('scan-report.json differs from the release descriptor');
    const checksumDownload = await downloadBytes(downloader, checksumAsset, `${expectedName}.sha256`, 4096);
    validateChecksum(checksumDownload.bytes, expectedName, packageSha);

    let packageResult;
    try {
      packageResult = await verifyPackage(packagePath, {
        packageSha256: packageSha,
        packageSize: packageDownload.size,
        expected: {
          packId: descriptor.pack_id,
          version: descriptor.version,
          versionSet: descriptor.version_set,
          mode: descriptor.mode,
          packageSha256: descriptor.package.sha256,
        },
      });
    } catch (error) {
      if (error instanceof RegistryError) throw error;
      throw new RegistryError(codes.RELEASE, `Package verification failed: ${error.message}`, { cause: error, exitCode: 2 });
    }
    if (packageResult.mode === 'full' && !packageResult.manifest.contents.some((content) => content.targets.length > 0 && [...packageResult.files.keys()].some((name) => name === content.path || name.startsWith(`${content.path}/`)))) throw releaseError('Official full publication requires nonempty installable content');
    const packageManifest = packageResult.files.get(ASSET_NAMES.manifest);
    if (!packageManifest?.bytes) throw new RegistryError(codes.INTERNAL, 'Package verifier did not retain the manifest bytes');
    if (!packageManifest.bytes.equals(manifestDownload.bytes)) throw releaseError('bepack.json copy is not byte-identical to the package manifest');
    if (packageResult.id !== descriptor.pack_id || packageResult.version !== descriptor.version) throw releaseError('Package identity differs from the release descriptor');
    if (packageResult.manifest.version_set !== descriptor.version_set || packageResult.manifest.mode !== descriptor.mode) throw releaseError('Package version_set or mode differs from the release descriptor');

    // A descriptor or lock hash is not proof that a remote executable still
    // has those bytes. Download independently before accepting scan evidence.
    let remoteBytes = 0;
    for (const [index, artifact] of packageResult.lock.artifacts.entries()) {
      const dependency = packageResult.manifest.dependencies.find((item) => item.id === artifact.dependency);
      if (artifact.path || !['mod', 'client'].includes(dependency?.role)) continue;
      remoteBytes += artifact.size;
      if (remoteBytes > LIMITS.externalExecutableBytes) throw releaseError('External executable download budget exceeded');
      const downloaded = await downloader.downloadToFile(artifact.url, path.join(work, 'external-' + index), {
        maxBytes: Math.min(artifact.size + 1, LIMITS.externalExecutableBytes),
        headers: { accept: 'application/octet-stream' },
      });
      if (downloaded.size !== artifact.size || downloaded.sha256 !== artifact.sha256) {
        throw releaseError('External executable bytes differ from locked size or SHA-256', { artifact: artifact.id });
      }
    }

    const scanReport = validateScanReport(scanDownload.bytes, {
      packageSha,
      packageSize: packageDownload.size,
      expectedPlan: packageResult.scanPlan,
      now,
    });
    void scanReport;
    const analysisBySha = new Map();
    for (const entry of scanReport.entries) {
      const existing = analysisBySha.get(entry.sha256);
      if (existing && existing !== entry.analysis_id) throw releaseError('The same hash is tied to conflicting analysis ids');
      analysisBySha.set(entry.sha256, entry.analysis_id);
    }
    const vtEvidence = await verifyVt(vt, packageResult.scanPlan, now, analysisBySha);
    const scanCheckedAt = vtEvidence.reduce((latest, entry) => entry.analyzed_at > latest ? entry.analyzed_at : latest, vtEvidence[0].analyzed_at);

    if (new Date(descriptor.generated_at).getTime() > now.getTime() + 5 * 60 * 1000) throw releaseError('Descriptor generated_at is in the future');

    // Re-query the release and tag after all downloads. A moving release must
    // abort the record rather than publish mixed evidence.
    const finalRelease = await github.getRelease(fullName, release.id);
    const finalAssets = await github.listReleaseAssets(fullName, release.id);
    const finalCommit = await github.getTagCommit(fullName, tag);
    if (String(finalRelease.id) !== String(release.id) || finalRelease.tag_name !== tag || finalRelease.draft === true || finalRelease.prerelease !== release.prerelease) {
      throw changedError('Release metadata changed during verification');
    }
    if (finalCommit !== tagCommit) throw changedError('Tag target moved during verification', { expected: tagCommit, actual: finalCommit });
    if (finalAssets.length !== 5) throw changedError('Release asset set changed during verification');
    for (const name of names) {
      const initial = byName.get(name);
      const final = finalAssets.find((candidate) => candidate.name === name);
      if (!final || String(final.id) !== String(initial.id) || final.size !== initial.size) throw changedError(`Release asset ${name} changed during verification`);
    }

    const record = {
      schema_version: 1,
      pack_id: packageResult.id,
      version: packageResult.version,
      version_set: packageResult.manifest.version_set,
      mode: packageResult.mode,
      name: packageResult.manifest.name,
      description: packageResult.manifest.description,
      author: packageResult.manifest.author,
      license: packageResult.manifest.license,
      package_schema_version: PACKAGE_SCHEMA_VERSION,
      repository: { id: repositoryId, full_name: fullName },
      release: {
        id: String(release.id),
        tag,
        commit: tagCommit,
        published_at: stamp(release.published_at),
        url: release.html_url,
      },
      package: {
        id: String(packageAsset.id),
        name: expectedName,
        url: packageAsset.browser_download_url,
        size: packageDownload.size,
        sha256: packageSha,
      },
      manifest: {
        id: String(manifestAsset.id),
        name: ASSET_NAMES.manifest,
        url: manifestAsset.browser_download_url,
        size: manifestDownload.size,
        sha256: manifestDownload.sha256,
      },
      descriptor: {
        id: String(descriptorAsset.id),
        name: ASSET_NAMES.descriptor,
        url: descriptorAsset.browser_download_url,
        size: descriptorBytes.size,
        sha256: descriptorBytes.sha256,
      },
      scan_report: {
        id: String(scanAsset.id),
        name: ASSET_NAMES.scanReport,
        url: scanAsset.browser_download_url,
        size: scanDownload.size,
        sha256: scanDownload.sha256,
      },
      targets: packageResult.targets,
      executables: packageResult.scanPlan.filter((entry) => entry.subject !== 'package').map((entry) => ({ subject: entry.subject, sha256: entry.sha256, size: entry.size })),
      verification: {
        tool_version: VERIFICATION_TOOL,
        verified_at: now.toISOString(),
        policy: POLICY,
        scan_checked_at: scanCheckedAt,
      },
      evidence: vtEvidence.map(scanEvidence),
    };
    assertFinalRecord(record, { repositoryId, fullName, packageSha, tag, commit: tagCommit });
    return record;
  } finally {
    if (!keepWork) await rm(work, { recursive: true, force: true });
  }
}
