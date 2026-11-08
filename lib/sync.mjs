import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJSON } from './strict-json.mjs';
import { classifyReleaseChange, loadReleases, loadWithdrawals } from './records.mjs';
import { loadSources } from './source.mjs';
import { verifyRelease } from './release-verify.mjs';
import { parseSemver } from './semver.mjs';
import { codes } from './errors.mjs';

const PENDING_CODES = new Set([codes.NETWORK, codes.DOWNLOAD, codes.SCAN_PENDING, codes.CONFIG]);

function releasePath(root, packId, version) {
  return path.join(root, 'releases', packId, `${version}.json`);
}

function withdrawalPath(root, packId, version) {
  return path.join(root, 'withdrawals', packId, `${version}.json`);
}

function tagVersion(tag) {
  if (typeof tag !== 'string' || !tag.startsWith('v')) return null;
  return parseSemver(tag.slice(1));
}

function summarizeError(error) {
  return { code: error?.code ?? 'INTERNAL', message: error?.message ?? String(error) };
}

async function writeJSON(file, value, dryRun) {
  if (dryRun) return;
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, canonicalJSON(value));
}

/**
 * Re-fetch and verify registered releases. This deliberately trusts only the
 * source record and numeric repository id; tag/Release ids from a webhook are
 * hints and are matched against the live GitHub API here.
 */
export async function syncReleaseSet({
  github, downloader, vt = null, root = process.cwd(), repositoryId = null, tag = null,
  now = new Date(), dryRun = false, logger = () => {},
} = {}) {
  if (!github || !downloader) throw new TypeError('github and downloader are required');
  const sources = await loadSources(root);
  const releaseMap = await loadReleases(root, sources);
  const releases = [...releaseMap.values()].flat();
  const withdrawalMap = await loadWithdrawals(root, releaseMap);
  const existing = new Map(releases.map((record) => [`${record.pack_id}@${record.version}`, record]));
  const withdrawalByVersion = new Map(withdrawalMap);

  const selected = repositoryId === null ? sources.filter((source) => source.enabled) : sources.filter((source) => source.repository.id === String(repositoryId));
  if (repositoryId !== null && selected.length === 0) throw new Error(`No registered source for repository_id ${repositoryId}`);

  const summary = {
    fetched_at: now.toISOString(),
    repositories: selected.length,
    new_versions: [],
    unchanged: [],
    quarantined: [],
    unavailable: [],
    pending: [],
    failed: [],
  };

  for (const source of selected) {
    if (!source.enabled) {
      logger(`skip disabled source ${source.pack_id}`);
      continue;
    }
    let remoteReleases;
    try {
      remoteReleases = await github.listReleases(source.repository.full_name);
    } catch (error) {
      summary.failed.push({ pack_id: source.pack_id, stage: 'list-releases', ...summarizeError(error) });
      continue;
    }
    const publicReleases = remoteReleases.filter((release) => release.draft !== true);
    const seen = new Set();
    for (const release of publicReleases) {
      const version = tagVersion(release.tag_name);
      if (!version) continue;
      if (tag !== null && release.tag_name !== tag) continue;
      seen.add(version.version);
      const stable = version.stable;
      if (release.prerelease !== !stable) {
        summary.failed.push({
          pack_id: source.pack_id,
          version: version.version,
          stage: 'prerelease-flag',
          code: codes.RELEASE,
          message: 'GitHub prerelease flag disagrees with SemVer',
        });
        continue;
      }
      const key = `${source.pack_id}@${version.version}`;
      const current = existing.get(key);
      logger(`verify ${source.pack_id}@${version.version}`);
      try {
        const record = await verifyRelease({
          github, downloader, source, releaseId: String(release.id), now, vt,
        });
        if (current) {
          const change = classifyReleaseChange(current, record);
          if (change === 'same') {
            summary.unchanged.push({ pack_id: source.pack_id, version: version.version });
            continue;
          }
          const withdrawal = {
            schema_version: 1,
            pack_id: source.pack_id,
            version: version.version,
            state: 'quarantined',
            reason: 'Release assets changed after the immutable version record was published',
            created_at: now.toISOString(),
            advisory_url: null,
          };
          const previous = withdrawalByVersion.get(key);
          if (!previous || previous.state !== 'quarantined' || previous.reason !== withdrawal.reason) {
            await writeJSON(withdrawalPath(root, source.pack_id, version.version), withdrawal, dryRun);
            withdrawalByVersion.set(key, withdrawal);
          }
          summary.quarantined.push({ pack_id: source.pack_id, version: version.version, change });
          continue;
        }
        await writeJSON(releasePath(root, source.pack_id, version.version), record, dryRun);
        existing.set(key, record);
        summary.new_versions.push({ pack_id: source.pack_id, version: version.version, sha256: record.package.sha256 });
      } catch (error) {
        const item = { pack_id: source.pack_id, version: version.version, stage: 'verify', ...summarizeError(error) };
        if (PENDING_CODES.has(error?.code)) {
          summary.pending.push(item);
        } else if (current) {
          const withdrawal = {
            schema_version: 1,
            pack_id: source.pack_id,
            version: version.version,
            state: 'quarantined',
            reason: `The published release no longer verifies: ${error.code ?? 'verification failure'}`,
            created_at: now.toISOString(),
            advisory_url: null,
          };
          const previous = withdrawalByVersion.get(key);
          if (previous?.state !== 'quarantined') {
            await writeJSON(withdrawalPath(root, source.pack_id, version.version), withdrawal, dryRun);
            withdrawalByVersion.set(key, withdrawal);
          }
          summary.quarantined.push({ pack_id: source.pack_id, version: version.version, change: 'verification-failed' });
        } else {
          summary.failed.push(item);
        }
      }
    }

    if (tag !== null) continue;
    for (const record of releases) {
      if (record.pack_id !== source.pack_id || seen.has(record.version)) continue;
      const key = `${record.pack_id}@${record.version}`;
      const previous = withdrawalByVersion.get(key);
      if (previous && previous.state !== 'active') continue;
      const withdrawal = {
        schema_version: 1,
        pack_id: record.pack_id,
        version: record.version,
        state: 'unavailable',
        reason: 'The GitHub release is no longer publicly listed',
        created_at: now.toISOString(),
        advisory_url: null,
      };
      await writeJSON(withdrawalPath(root, record.pack_id, record.version), withdrawal, dryRun);
      withdrawalByVersion.set(key, withdrawal);
      summary.unavailable.push({ pack_id: record.pack_id, version: record.version });
    }
  }

  return summary;
}
