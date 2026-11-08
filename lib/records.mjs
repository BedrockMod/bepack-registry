import { readdir } from 'node:fs/promises';
import path from 'node:path';
import {
  LIMITS, POLICY, VERIFICATION_TOOL, WITHDRAWAL_STATES, COMMIT_PATTERN,
} from './constants.mjs';
import { RegistryError, codes } from './errors.mjs';
import { readStrictJSON } from './strict-json.mjs';
import { safeId, safePackId, sha256 } from './paths.mjs';
import { compareSemver, parseSemver } from './semver.mjs';
import {
  Issues, exactKeys, isInteger, isNonEmptyString, checkSha256, checkTimestamp,
  checkHttps, checkGameVersion, checkId, checkSemver,
} from './validate-common.mjs';

const RELEASE_REQUIRED = [
  'schema_version', 'pack_id', 'version', 'version_set', 'mode', 'name', 'description',
  'author', 'license', 'package_schema_version', 'repository', 'release', 'package',
  'manifest', 'descriptor', 'scan_report', 'targets', 'executables', 'verification', 'evidence',
];
const ASSET_FIELDS = ['id', 'name', 'url', 'size', 'sha256'];
const TARGET_REQUIRED = ['target', 'platform', 'runtime', 'requires', 'game_versions', 'loaders', 'clients'];
const MODES = ['full', 'modded', 'client', 'mods-only'];

function recordError(message, details = null) {
  return new RegistryError(codes.RELEASE, message, { details, exitCode: 2 });
}

function withdrawalError(message, details = null) {
  return new RegistryError(codes.IMMUTABLE, message, { details, exitCode: 2 });
}

function validateAuthor(author, issues) {
  if (!exactKeys(author, ['name', 'url', 'email'], ['name'], 'author', issues)) return;
  if (!isNonEmptyString(author.name) || author.name.length > 128) issues.add('BEPACK_MANIFEST_INVALID', 'author.name must be 1-128 characters', 'author/name');
  if (author.url !== undefined) checkHttps(author.url, 'author/url', issues);
  if (author.email !== undefined && (typeof author.email !== 'string' || author.email.length > 254)) issues.add('BEPACK_MANIFEST_INVALID', 'author.email is invalid', 'author/email');
}

function validateAsset(asset, field, expectedSize, issues) {
  if (!exactKeys(asset, ASSET_FIELDS, ASSET_FIELDS, field, issues)) return;
  if (!/^[1-9][0-9]{0,19}$/u.test(asset.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Asset id must be a positive decimal string', `${field}/id`);
  if (!isNonEmptyString(asset.name) || asset.name.length > 255) issues.add('BEPACK_MANIFEST_INVALID', 'Asset name is invalid', `${field}/name`);
  checkHttps(asset.url, `${field}/url`, issues);
  if (!isInteger(asset.size) || asset.size < 1 || asset.size > expectedSize) issues.add('BEPACK_RESOURCE_LIMIT', 'Asset size is out of bounds', `${field}/size`);
  checkSha256(asset.sha256, `${field}/sha256`, issues);
}

function validateTarget(target, index, issues) {
  const field = `targets/${index}`;
  if (!exactKeys(target, TARGET_REQUIRED, TARGET_REQUIRED, field, issues)) return;
  checkId(target.target, `${field}/target`, issues);
  checkId(target.platform, `${field}/platform`, issues);
  checkId(target.runtime, `${field}/runtime`, issues);
  if (!Array.isArray(target.requires) || target.requires.some((item) => !safeId(item)) || new Set(target.requires).size !== target.requires.length) {
    issues.add('BEPACK_MANIFEST_INVALID', 'target.requires must be unique ids', `${field}/requires`);
  }
  if (!Array.isArray(target.game_versions) || target.game_versions.length === 0) {
    issues.add('BEPACK_MANIFEST_INVALID', 'target.game_versions must be non-empty', `${field}/game_versions`);
  } else {
    const seen = new Set();
    for (const version of target.game_versions) {
      if (typeof version !== 'string' || !/^(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2,3}$/u.test(version)) {
        issues.add('BEPACK_MANIFEST_INVALID', 'Invalid game version', `${field}/game_versions`);
        continue;
      }
      if (seen.has(version)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate game version', `${field}/game_versions`);
      seen.add(version);
    }
  }
  if (!Array.isArray(target.loaders)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'target.loaders must be an array', `${field}/loaders`);
  } else {
    const seen = new Set();
    for (const [loaderIndex, loader] of target.loaders.entries()) {
      const loaderField = `${field}/loaders/${loaderIndex}`;
      if (!exactKeys(loader, ['type', 'version'], ['type', 'version'], loaderField, issues)) continue;
      checkId(loader.type, `${loaderField}/type`, issues);
      if (loader.type === 'none') {
        if (loader.version !== null) issues.add('BEPACK_MANIFEST_INVALID', 'Loader "none" must have a null version', `${loaderField}/version`);
      } else {
        checkSemver(loader.version, `${loaderField}/version`, issues);
      }
      const key = `${loader.type}@${loader.version}`;
      if (seen.has(key)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate loader', loaderField);
      seen.add(key);
    }
  }
  if (!Array.isArray(target.clients)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'target.clients must be an array', `${field}/clients`);
  } else {
    const seen = new Set();
    for (const [clientIndex, client] of target.clients.entries()) {
      const clientField = `${field}/clients/${clientIndex}`;
      if (!exactKeys(client, ['id', 'version', 'dependency'], ['id', 'version', 'dependency'], clientField, issues)) continue;
      checkId(client.id, `${clientField}/id`, issues);
      checkSemver(client.version, `${clientField}/version`, issues);
      if (client.dependency !== null) checkId(client.dependency, `${clientField}/dependency`, issues);
      const key = `${client.id}@${client.version}@${client.dependency ?? ''}`;
      if (seen.has(key)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate client', clientField);
      seen.add(key);
    }
  }
}

function validateEvidence(evidence, issues) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    issues.add('BEPACK_SCAN_FAILED', 'Evidence must be a non-empty array', 'evidence');
    return;
  }
  const hashes = new Set();
  for (const [index, item] of evidence.entries()) {
    const field = `evidence/${index}`;
    if (!exactKeys(item, ['sha256', 'analysis_id', 'analyzed_at', 'malicious', 'suspicious'], ['sha256', 'analysis_id', 'analyzed_at', 'malicious', 'suspicious'], field, issues)) continue;
    checkSha256(item.sha256, `${field}/sha256`, issues);
    if (hashes.has(item.sha256)) issues.add('BEPACK_SCAN_FAILED', 'Duplicate evidence hash', `${field}/sha256`);
    hashes.add(item.sha256);
    if (!isNonEmptyString(item.analysis_id) || item.analysis_id.length > 256) issues.add('BEPACK_SCAN_FAILED', 'analysis_id is invalid', `${field}/analysis_id`);
    checkTimestamp(item.analyzed_at, `${field}/analyzed_at`, issues);
    if (item.malicious !== 0 || item.suspicious !== 0) issues.add('BEPACK_SCAN_FAILED', 'Evidence contains detections', field);
  }
}

function validateVerification(verification, evidence, issues) {
  if (!exactKeys(verification, ['tool_version', 'verified_at', 'policy', 'scan_checked_at'], ['tool_version', 'verified_at', 'policy', 'scan_checked_at'], 'verification', issues)) return;
  if (!isNonEmptyString(verification.tool_version) || !verification.tool_version.startsWith('bepack-registry-verifier/')) issues.add('BEPACK_MANIFEST_INVALID', 'Unexpected verifier tool_version', 'verification/tool_version');
  checkTimestamp(verification.verified_at, 'verification/verified_at', issues);
  if (verification.policy !== POLICY) issues.add('BEPACK_MANIFEST_INVALID', `policy must be ${POLICY}`, 'verification/policy');
  checkTimestamp(verification.scan_checked_at, 'verification/scan_checked_at', issues);
  if (Array.isArray(evidence) && evidence.length) {
    const latest = evidence.map((item) => item.analyzed_at).filter((item) => typeof item === 'string').sort().at(-1);
    if (latest && verification.scan_checked_at !== latest) issues.add('BEPACK_SCAN_FAILED', 'scan_checked_at must equal the latest evidence timestamp', 'verification/scan_checked_at');
  }
}

export function validateReleaseRecord(record, { packId, version, source }) {
  const issues = new Issues(`releases/${packId}/${version}.json`);
  if (!exactKeys(record, RELEASE_REQUIRED, RELEASE_REQUIRED, 'release-record', issues)) throw recordError('Release record is not an object');
  if (record.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'schema_version');
  if (record.pack_id !== packId || !safePackId(record.pack_id)) issues.add('BEPACK_MANIFEST_INVALID', 'pack_id does not match the record path', 'pack_id');
  if (record.version !== version || !parseSemver(record.version)) issues.add('BEPACK_MANIFEST_INVALID', 'version does not match the record path', 'version');
  if (!safeId(record.version_set)) issues.add('BEPACK_VERSION_SET_INVALID', 'version_set is invalid', 'version_set');
  if (!MODES.includes(record.mode)) issues.add('BEPACK_MANIFEST_INVALID', 'mode is invalid', 'mode');
  if (!isNonEmptyString(record.name) || record.name.length > 128) issues.add('BEPACK_MANIFEST_INVALID', 'name is invalid', 'name');
  if (typeof record.description !== 'string' || record.description.length > 10000) issues.add('BEPACK_MANIFEST_INVALID', 'description is invalid', 'description');
  validateAuthor(record.author, issues);
  if (!isNonEmptyString(record.license) || record.license.length > 256) issues.add('BEPACK_LICENSE_INVALID', 'license is invalid', 'license');
  if (record.package_schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only package_schema_version 1 is supported', 'package_schema_version');

  if (!exactKeys(record.repository, ['id', 'full_name'], ['id', 'full_name'], 'repository', issues)) {
    // reported by exactKeys
  } else {
    if (!/^[1-9][0-9]{0,19}$/u.test(record.repository.id)) issues.add('BEPACK_MANIFEST_INVALID', 'repository.id is invalid', 'repository/id');
    if (record.repository.id !== source.repository.id || record.repository.full_name !== source.repository.full_name) issues.add('BEPACK_MANIFEST_INVALID', 'repository differs from the source record', 'repository');
  }

  if (exactKeys(record.release, ['id', 'tag', 'commit', 'published_at', 'url'], ['id', 'tag', 'commit', 'published_at', 'url'], 'release', issues)) {
    if (!/^[1-9][0-9]{0,19}$/u.test(record.release.id)) issues.add('BEPACK_MANIFEST_INVALID', 'release.id is invalid', 'release/id');
    if (record.release.tag !== `v${version}`) issues.add('BEPACK_MANIFEST_INVALID', 'release.tag does not match version', 'release/tag');
    if (!COMMIT_PATTERN.test(record.release.commit)) issues.add('BEPACK_MANIFEST_INVALID', 'release.commit must be a 40-character lowercase SHA', 'release/commit');
    checkTimestamp(record.release.published_at, 'release/published_at', issues);
    checkHttps(record.release.url, 'release/url', issues);
  }

  const packageName = `${packId}-${version}.bepack`;
  validateAsset(record.package, 'package', LIMITS.packageBytes, issues);
  validateAsset(record.manifest, 'manifest', LIMITS.manifestBytes, issues);
  validateAsset(record.descriptor, 'descriptor', LIMITS.releaseDescriptorBytes, issues);
  validateAsset(record.scan_report, 'scan_report', LIMITS.scanReportBytes, issues);
  if (record.package?.name !== packageName) issues.add('BEPACK_MANIFEST_INVALID', 'package.name is wrong', 'package/name');
  if (record.manifest?.name !== 'bepack.json') issues.add('BEPACK_MANIFEST_INVALID', 'manifest.name must be bepack.json', 'manifest/name');
  if (record.descriptor?.name !== 'bepack-release.json') issues.add('BEPACK_MANIFEST_INVALID', 'descriptor.name must be bepack-release.json', 'descriptor/name');
  if (record.scan_report?.name !== 'scan-report.json') issues.add('BEPACK_MANIFEST_INVALID', 'scan_report.name must be scan-report.json', 'scan_report/name');

  if (!Array.isArray(record.targets) || record.targets.length === 0) {
    issues.add('BEPACK_MANIFEST_INVALID', 'targets must be non-empty', 'targets');
  } else {
    record.targets.forEach((target, index) => validateTarget(target, index, issues));
  }
  if (!Array.isArray(record.executables)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'executables must be an array', 'executables');
  } else {
    for (const [index, item] of record.executables.entries()) {
      const field = `executables/${index}`;
      if (!exactKeys(item, ['subject', 'sha256', 'size'], ['subject', 'sha256', 'size'], field, issues)) continue;
      if (typeof item.subject !== 'string' || item.subject.length === 0) issues.add('BEPACK_MANIFEST_INVALID', 'executable subject is invalid', `${field}/subject`);
      checkSha256(item.sha256, `${field}/sha256`, issues);
      if (!isInteger(item.size) || item.size < 0) issues.add('BEPACK_MANIFEST_INVALID', 'executable size is invalid', `${field}/size`);
    }
  }
  validateVerification(record.verification, record.evidence, issues);
  validateEvidence(record.evidence, issues);
  if (issues.length) throw recordError('Release record validation failed', { issues: issues.list });
  return record;
}

export function validateWithdrawal(record, { packId, version }) {
  const issues = new Issues(`withdrawals/${packId}/${version}.json`);
  const required = ['schema_version', 'pack_id', 'version', 'state', 'reason', 'created_at', 'advisory_url'];
  if (!exactKeys(record, required, required, 'withdrawal', issues)) throw withdrawalError('Withdrawal is not an object');
  if (record.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'schema_version');
  if (record.pack_id !== packId || !safePackId(record.pack_id)) issues.add('BEPACK_MANIFEST_INVALID', 'pack_id does not match the record path', 'pack_id');
  if (record.version !== version || !parseSemver(record.version)) issues.add('BEPACK_MANIFEST_INVALID', 'version does not match the record path', 'version');
  if (!WITHDRAWAL_STATES.includes(record.state)) issues.add('BEPACK_MANIFEST_INVALID', 'Unknown withdrawal state', 'state');
  if (typeof record.reason !== 'string' || record.reason.length > 2000) issues.add('BEPACK_MANIFEST_INVALID', 'reason is invalid', 'reason');
  if (record.state !== 'active' && !record.reason.trim()) issues.add('BEPACK_MANIFEST_INVALID', 'A withdrawal must have a reason', 'reason');
  checkTimestamp(record.created_at, 'created_at', issues);
  if (record.advisory_url !== null && record.advisory_url !== undefined) checkHttps(record.advisory_url, 'advisory_url', issues);
  if (record.advisory_url === undefined) issues.add('BEPACK_MANIFEST_INVALID', 'advisory_url is required (nullable)', 'advisory_url');
  if (issues.length) throw withdrawalError('Withdrawal validation failed', { issues: issues.list });
  return record;
}

async function childDirectories(directory) {
  try {
    const entries = await readdir(directory, { withFileTypes: true });
    return entries.filter((entry) => entry.name !== '.gitkeep');
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

export async function loadReleases(root, sources) {
  const directory = path.join(root, 'releases');
  const byPack = new Map();
  for (const packEntry of await childDirectories(directory)) {
    if (!packEntry.isDirectory() || !safePackId(packEntry.name)) throw recordError(`Invalid releases directory ${packEntry.name}`);
    const source = sources.find((candidate) => candidate.pack_id === packEntry.name);
    if (!source) throw recordError(`Release directory ${packEntry.name} has no source record`);
    const versionEntries = await readdir(path.join(directory, packEntry.name), { withFileTypes: true });
    for (const versionEntry of versionEntries) {
      if (versionEntry.name === '.gitkeep') continue;
      if (!versionEntry.isFile() || !versionEntry.name.endsWith('.json')) throw recordError(`Unexpected release entry ${packEntry.name}/${versionEntry.name}`);
      const version = versionEntry.name.slice(0, -5);
      if (!parseSemver(version)) throw recordError(`Release filename is not a SemVer version: ${versionEntry.name}`);
      let record;
      try {
        record = await readStrictJSON(path.join(directory, packEntry.name, versionEntry.name), { maxBytes: LIMITS.releaseRecordBytes });
      } catch (error) {
        throw recordError(`Release ${packEntry.name}/${versionEntry.name} is not strict JSON: ${error.message}`);
      }
      validateReleaseRecord(record, { packId: packEntry.name, version, source });
      const list = byPack.get(packEntry.name) ?? [];
      list.push(record);
      byPack.set(packEntry.name, list);
    }
  }
  for (const list of byPack.values()) list.sort((left, right) => compareSemver(right.version, left.version));
  return byPack;
}

export async function loadWithdrawals(root, releases) {
  const directory = path.join(root, 'withdrawals');
  const map = new Map();
  const known = new Set();
  for (const list of releases.values()) for (const record of list) known.add(`${record.pack_id}@${record.version}`);
  for (const packEntry of await childDirectories(directory)) {
    if (!packEntry.isDirectory() || !safePackId(packEntry.name)) throw withdrawalError(`Invalid withdrawals directory ${packEntry.name}`);
    const versionEntries = await readdir(path.join(directory, packEntry.name), { withFileTypes: true });
    for (const versionEntry of versionEntries) {
      if (versionEntry.name === '.gitkeep') continue;
      if (!versionEntry.isFile() || !versionEntry.name.endsWith('.json')) throw withdrawalError(`Unexpected withdrawal entry ${packEntry.name}/${versionEntry.name}`);
      const version = versionEntry.name.slice(0, -5);
      if (!parseSemver(version)) throw withdrawalError(`Withdrawal filename is not a SemVer version: ${versionEntry.name}`);
      let record;
      try {
        record = await readStrictJSON(path.join(directory, packEntry.name, versionEntry.name), { maxBytes: LIMITS.withdrawalBytes });
      } catch (error) {
        throw withdrawalError(`Withdrawal ${packEntry.name}/${versionEntry.name} is not strict JSON: ${error.message}`);
      }
      validateWithdrawal(record, { packId: packEntry.name, version });
      if (!known.has(`${packEntry.name}@${version}`)) throw withdrawalError(`Withdrawal ${packEntry.name}@${version} has no release record`);
      const key = `${packEntry.name}@${version}`;
      if (map.has(key)) throw withdrawalError(`Duplicate withdrawal for ${key}`);
      map.set(key, record);
    }
  }
  return map;
}

export function releaseIdentity(record) {
  return JSON.stringify([
    record.repository?.id, record.release?.id, record.release?.tag, record.release?.commit,
    record.package?.id, record.package?.name, record.package?.size, record.package?.sha256,
    record.manifest?.id, record.manifest?.name, record.manifest?.size, record.manifest?.sha256,
    record.descriptor?.id, record.descriptor?.name, record.descriptor?.size, record.descriptor?.sha256,
    record.scan_report?.id, record.scan_report?.name, record.scan_report?.size, record.scan_report?.sha256,
  ]);
}

export function classifyReleaseChange(existing, incoming) {
  if (!existing) return 'new';
  return releaseIdentity(existing) === releaseIdentity(incoming) ? 'same' : 'changed';
}

export function withdrawalState(withdrawal) {
  if (!withdrawal) return 'active';
  return WITHDRAWAL_STATES.includes(withdrawal.state) ? withdrawal.state : 'unknown';
}

export function recordDigest(record) {
  return sha256(Buffer.from(JSON.stringify(record)));
}

export { VERIFICATION_TOOL };
