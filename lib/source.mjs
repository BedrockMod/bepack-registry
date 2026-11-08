import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { COMMIT_PATTERN, LIMITS } from './constants.mjs';
import { RegistryError, codes } from './errors.mjs';
import { parseStrictJSON, readStrictJSON } from './strict-json.mjs';
import { safePackId } from './paths.mjs';
import { assertPublicHttpsUrl } from './url-safety.mjs';
import {
  Issues, exactKeys, isObject, isNonEmptyString, checkSha256, checkHttps,
} from './validate-common.mjs';

const REQUIRED = ['schema_version', 'pack_id', 'repository', 'contact', 'enabled', 'proof'];
const REPOSITORY_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/u;
const DECIMAL_RE = /^[1-9][0-9]{0,19}$/u;
const PROOF_PATH = '.bepack-registry.json';

function sourceError(message, details = null) {
  return new RegistryError(codes.SOURCE, message, { details, exitCode: 2 });
}

export function validateSource(value, { filePackId = null } = {}) {
  const issues = new Issues('source');
  if (!exactKeys(value, REQUIRED, REQUIRED, 'source', issues)) throw sourceError('Source is not an object');
  if (value.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'schema_version');
  if (!safePackId(value.pack_id)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid pack_id', 'pack_id');
  if (filePackId !== null && value.pack_id !== filePackId) issues.add('BEPACK_MANIFEST_INVALID', 'pack_id must match the source filename', 'pack_id');
  if (!exactKeys(value.repository, ['id', 'full_name'], ['id', 'full_name'], 'repository', issues)) {
    // exactKeys reports the shape; the remaining checks stay conditional.
  } else {
    if (typeof value.repository.id !== 'string' || !DECIMAL_RE.test(value.repository.id)) issues.add('BEPACK_MANIFEST_INVALID', 'repository.id must be a positive decimal string', 'repository/id');
    if (typeof value.repository.full_name !== 'string' || !REPOSITORY_RE.test(value.repository.full_name)) issues.add('BEPACK_MANIFEST_INVALID', 'repository.full_name must be owner/name', 'repository/full_name');
  }
  checkHttps(value.contact, 'contact', issues);
  if (typeof value.contact === 'string' && value.contact.length > 2048) issues.add('BEPACK_MANIFEST_INVALID', 'contact is too long', 'contact');
  if (typeof value.contact === 'string') {
    try {
      assertPublicHttpsUrl(value.contact);
    } catch {
      issues.add('BEPACK_MANIFEST_INVALID', 'contact must be a public HTTPS URL', 'contact');
    }
  }
  if (typeof value.enabled !== 'boolean') issues.add('BEPACK_MANIFEST_INVALID', 'enabled must be a boolean', 'enabled');
  if (!isObject(value.proof)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'proof must be an object', 'proof');
  } else {
    exactKeys(value.proof, ['path', 'commit'], ['path', 'commit'], 'proof', issues);
    if (value.proof.path !== PROOF_PATH) issues.add('BEPACK_MANIFEST_INVALID', `proof.path must be ${PROOF_PATH}`, 'proof/path');
    if (!COMMIT_PATTERN.test(value.proof.commit)) issues.add('BEPACK_MANIFEST_INVALID', 'proof.commit must be a 40-character lowercase SHA', 'proof/commit');
  }
  if (issues.length) throw sourceError('Source validation failed', { issues: issues.list });
  return value;
}

/**
 * Verify that the proof file exists at proof.commit and that the commit is an
 * ancestor of (or equal to) the repository's default branch tip.
 */
export async function verifySourceProof(github, source) {
  if (!github) throw new TypeError('github is required');
  const repositoryId = source.repository.id;
  const repository = await github.getRepository(repositoryId);
  if (String(repository.id) !== repositoryId) throw sourceError('GitHub returned a repository with a different id');
  if (repository.private === true) throw sourceError('Source repository must be public');
  if (repository.archived === true || repository.disabled === true) throw sourceError('Source repository is archived or disabled');
  if (repository.full_name !== source.repository.full_name) throw sourceError('Source repository full_name is stale; re-review is required');
  if (!isNonEmptyString(repository.default_branch)) throw sourceError('Source repository has no default branch');

  let proofBytes;
  try {
    proofBytes = await github.getFile(repository.full_name, source.proof.path, source.proof.commit);
  } catch (error) {
    throw sourceError('Could not read the proof file at proof.commit', { cause: error.message });
  }
  let proof;
  try {
    proof = parseStrictJSON(proofBytes, { maxBytes: LIMITS.sourceBytes });
  } catch (error) {
    throw sourceError(`Proof file is not strict JSON: ${error.message}`);
  }
  const issues = new Issues(PROOF_PATH);
  const required = ['schema_version', 'registry', 'pack_id', 'repository_id'];
  if (!exactKeys(proof, required, required, PROOF_PATH, issues)) throw sourceError('Proof file is not an object');
  if (proof.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'schema_version');
  if (proof.registry !== 'bepack-registry') issues.add('BEPACK_SOURCE_INVALID', 'Proof registry must be bepack-registry', 'registry');
  if (proof.pack_id !== source.pack_id) issues.add('BEPACK_SOURCE_INVALID', 'Proof pack_id differs from the source record', 'pack_id');
  if (proof.repository_id !== repositoryId) issues.add('BEPACK_SOURCE_INVALID', 'Proof repository_id differs from the source record', 'repository_id');
  if (issues.length) throw sourceError('Proof file validation failed', { issues: issues.list });

  const comparison = await github.compare(repository.full_name, repository.default_branch, source.proof.commit);
  if (!comparison || !['behind', 'identical'].includes(comparison.status)) {
    throw sourceError('proof.commit is not reachable from the default branch', { status: comparison?.status ?? 'unknown' });
  }
  return { repository, proof, comparisonStatus: comparison.status };
}

export async function loadSources(root) {
  const directory = path.join(root, 'sources');
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    throw sourceError('sources directory is not readable', { cause: error.message });
  }
  const sources = [];
  const repos = new Map();
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.name === '.gitkeep') continue;
    if (!entry.isFile()) throw sourceError(`Unexpected non-file entry in sources: ${entry.name}`);
    if (!entry.name.endsWith('.json')) throw sourceError(`Unexpected file in sources: ${entry.name}`);
    const packId = entry.name.slice(0, -5);
    if (!safePackId(packId)) throw sourceError(`Source filename is not a valid pack id: ${entry.name}`);
    let value;
    try {
      value = await readStrictJSON(path.join(directory, entry.name), { maxBytes: LIMITS.sourceBytes });
    } catch (error) {
      throw sourceError(`Source ${entry.name} is not strict JSON: ${error.message}`);
    }
    const source = validateSource(value, { filePackId: packId });
    if (repos.has(source.repository.id)) throw sourceError(`Repository ${source.repository.id} is already registered to another pack`, { pack_id: repos.get(source.repository.id), conflict: packId });
    repos.set(source.repository.id, packId);
    sources.push(source);
  }
  return sources;
}

export function findSource(sources, packId) {
  const source = sources.find((candidate) => candidate.pack_id === packId);
  if (!source) throw sourceError(`No source record for ${packId}`);
  return source;
}
