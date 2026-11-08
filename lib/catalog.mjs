import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { LIMITS, REGISTRY_ID } from './constants.mjs';
import { RegistryError, codes } from './errors.mjs';
import { canonicalJSON } from './strict-json.mjs';
import { sha256 } from './paths.mjs';
import { compareSemver, parseSemver } from './semver.mjs';
import { loadReleases, loadWithdrawals, withdrawalState } from './records.mjs';
import { loadSources } from './source.mjs';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function catalogError(message, details = null) {
  return new RegistryError(codes.CATALOG, message, { details, exitCode: 2 });
}

function maxTimestamp(left, right) {
  if (!left) return right;
  if (!right) return left;
  return new Date(left).getTime() >= new Date(right).getTime() ? left : right;
}

function latestBy(records, predicate) {
  return records.filter(predicate).sort((left, right) => compareSemver(right.version, left.version))[0] ?? null;
}

function detailVersion(record, withdrawal) {
  return {
    ...record,
    state: withdrawalState(withdrawal),
    reason: withdrawal?.reason ?? '',
    state_changed_at: withdrawal?.created_at ?? record.verification.verified_at,
    advisory_url: withdrawal?.advisory_url ?? null,
  };
}

export async function buildCatalog({ root, now = new Date(), revision = randomUUID() }) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');
  if (typeof revision !== 'string' || !UUID_RE.test(revision)) throw new RegistryError(codes.ARGUMENT, 'revision must be a UUID');
  const sources = await loadSources(root);
  const releases = await loadReleases(root, sources);
  const withdrawals = await loadWithdrawals(root, releases);
  const details = new Map();
  const packs = [];

  for (const source of sources) {
    const records = (releases.get(source.pack_id) ?? []).slice().sort((left, right) => compareSemver(right.version, left.version));
    if (!records.length) continue;
    const versions = records.map((record) => {
      const withdrawal = withdrawals.get(`${source.pack_id}@${record.version}`);
      const sourcePaused = !source.enabled && (!withdrawal || withdrawal.state === 'active');
      return detailVersion(record, sourcePaused ? { state: 'yanked', reason: 'Source disabled by registry maintainers', created_at: withdrawal?.created_at ?? record.verification.verified_at } : withdrawal);
    });
    const detail = {
      schema_version: 1,
      pack_id: source.pack_id,
      repository: { id: source.repository.id, full_name: source.repository.full_name },
      versions,
    };
    const bytes = Buffer.from(canonicalJSON(detail), 'utf8');
    if (bytes.length > LIMITS.detailBytes) throw catalogError(`Pack ${source.pack_id} detail exceeds ${LIMITS.detailBytes} bytes`, { pack_id: source.pack_id, size: bytes.length });
    const digest = sha256(bytes);
    const detailPath = `packs/${digest}.json`;
    const existing = details.get(detailPath);
    if (existing && !existing.equals(bytes)) throw catalogError('Detail hash collision');
    details.set(detailPath, bytes);

    const active = versions.filter((version) => version.state === 'active');
    const activeStable = active.filter((version) => parseSemver(version.version).stable);
    const activePrerelease = active.filter((version) => !parseSemver(version.version).stable);
    const latest = latestBy(activeStable, () => true);
    const latestPrerelease = latestBy(activePrerelease, () => true);
    const modeVersion = latest ?? latestPrerelease;
    const displayVersion = records.slice().sort((left, right) => {
      const byTime = new Date(right.verification.verified_at).getTime() - new Date(left.verification.verified_at).getTime();
      return byTime !== 0 ? byTime : compareSemver(right.version, left.version);
    })[0];
    const updatedAt = versions.map((version) => version.state_changed_at).reduce(maxTimestamp, null);

    packs.push({
      id: source.pack_id,
      name: displayVersion.name,
      description: displayVersion.description,
      author: displayVersion.author,
      license: displayVersion.license,
      mode: modeVersion ? modeVersion.mode : displayVersion.mode,
      latest: latest ? latest.version : null,
      latest_prerelease: latestPrerelease ? latestPrerelease.version : null,
      state: active.length ? 'active' : 'inactive',
      updated_at: updatedAt,
      detail: { path: detailPath, size: bytes.length, sha256: digest },
    });
  }

  packs.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  const registry = {
    schema_version: 1,
    registry_id: REGISTRY_ID,
    generated_at: now.toISOString(),
    revision,
    packs,
  };
  const bytes = Buffer.from(canonicalJSON(registry), 'utf8');
  if (bytes.length > LIMITS.registryBytes) throw catalogError(`registry.json exceeds ${LIMITS.registryBytes} bytes`, { size: bytes.length });
  return { registry, registryBytes: bytes, details };
}

async function writeIfChanged(file, bytes) {
  let existing = null;
  try {
    existing = await readFile(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (existing) {
    if (!existing.equals(bytes)) throw new RegistryError(codes.IMMUTABLE, `Refusing to overwrite ${file}`, { exitCode: 2 });
    return false;
  }
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${randomUUID()}`;
  await writeFile(temporary, bytes, { flag: 'wx' });
  await rename(temporary, file);
  return true;
}

/**
 * Write generated files into a catalog worktree. Detail files are immutable and
 * are never deleted; registry.json is replaced only after details are durable.
 */
export async function writeCatalog({ outDir, registryBytes, details }) {
  if (!outDir) throw new TypeError('outDir is required');
  const packDir = path.join(outDir, 'packs');
  await mkdir(packDir, { recursive: true });
  let detailsWritten = 0;
  for (const [relative, bytes] of [...details.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    if (!relative.startsWith('packs/')) throw catalogError('Detail path must be under packs/');
    if (await writeIfChanged(path.join(outDir, relative), bytes)) detailsWritten++;
  }
  const registryPath = path.join(outDir, 'registry.json');
  const temporary = `${registryPath}.tmp-${randomUUID()}`;
  await writeFile(temporary, registryBytes, { flag: 'wx' });
  try {
    await rename(temporary, registryPath);
  } catch (error) {
    // Windows rename does not always replace an existing file.
    if (['EEXIST', 'EPERM', 'EACCES'].includes(error.code)) {
      await rm(registryPath, { force: true });
      await rename(temporary, registryPath);
    } else {
      await rm(temporary, { force: true });
      throw error;
    }
  }
  return { detailsWritten };
}

export function catalogSummary(catalog) {
  return { packs: catalog.registry.packs.length, details: catalog.details.size, bytes: catalog.registryBytes.length, revision: catalog.registry.revision };
}
