import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadSources, validateSource, verifySourceProof } from '../lib/source.mjs';
import { canonicalJSON } from '../lib/strict-json.mjs';
import { NOW, makeReleaseFixture } from './helpers/fixtures.mjs';

class ProofGitHub {
  constructor({ proof, repository, status = 'behind' }) {
    this.proof = proof;
    this.repository = repository;
    this.status = status;
  }

  async getRepository(id) {
    assert.equal(String(id), String(this.repository.id));
    return this.repository;
  }

  async getFile(_fullName, file, commit) {
    assert.equal(file, '.bepack-registry.json');
    assert.equal(commit, this.repository.proofCommit);
    return Buffer.from(canonicalJSON(this.proof));
  }

  async compare(_fullName, base, head) {
    assert.equal(base, this.repository.default_branch);
    assert.equal(head, this.repository.proofCommit);
    return { status: this.status };
  }
}

function proofFor(source) {
  return { schema_version: 1, registry: 'bepack-registry', pack_id: source.pack_id, repository_id: source.repository.id };
}

test('accepts a source whose proof commit is reachable from the default branch', async () => {
  const source = makeReleaseFixture().source;
  const repository = {
    id: Number(source.repository.id),
    full_name: source.repository.full_name,
    private: false,
    archived: false,
    default_branch: 'main',
    proofCommit: source.proof.commit,
  };
  const result = await verifySourceProof(new ProofGitHub({ proof: proofFor(source), repository }), source);
  assert.equal(result.comparisonStatus, 'behind');
});

test('rejects a proof commit that is not an ancestor of the default branch', async () => {
  const source = makeReleaseFixture().source;
  const repository = {
    id: Number(source.repository.id),
    full_name: source.repository.full_name,
    private: false,
    archived: false,
    default_branch: 'main',
    proofCommit: source.proof.commit,
  };
  await assert.rejects(
    verifySourceProof(new ProofGitHub({ proof: proofFor(source), repository, status: 'ahead' }), source),
    /reachable/iu,
  );
});

test('rejects a proof file with a different repository or pack identity', async () => {
  const source = makeReleaseFixture().source;
  const proof = proofFor(source);
  proof.repository_id = '999999';
  const repository = {
    id: Number(source.repository.id),
    full_name: source.repository.full_name,
    private: false,
    archived: false,
    default_branch: 'main',
    proofCommit: source.proof.commit,
  };
  await assert.rejects(verifySourceProof(new ProofGitHub({ proof, repository }), source), /validation/iu);
});

test('rejects a source record that does not match its filename', () => {
  const source = makeReleaseFixture().source;
  assert.throws(
    () => validateSource(source, { filePackId: 'example.other' }),
    (error) => error.details?.issues?.some((issue) => issue.message === 'pack_id must match the source filename') === true,
  );
});

test('rejects two source files claiming the same numeric repository', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'bepack-sources-'));
  try {
    await mkdir(path.join(root, 'sources'), { recursive: true });
    const first = makeReleaseFixture({ packId: 'example.one' }).source;
    const second = makeReleaseFixture({ packId: 'example.two' }).source;
    await writeFile(path.join(root, 'sources', `${first.pack_id}.json`), canonicalJSON(first));
    await writeFile(path.join(root, 'sources', `${second.pack_id}.json`), canonicalJSON(second));
    await assert.rejects(loadSources(root), /already registered/iu);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('source proof timestamp is not part of the source contract', () => {
  const source = makeReleaseFixture().source;
  const { proof } = source;
  assert.equal(Object.keys(proof).sort().join(','), 'commit,path');
  assert.equal(typeof NOW.toISOString(), 'string');
});
