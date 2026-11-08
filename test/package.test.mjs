import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { verifyPackage } from '../lib/package-verify.mjs';
import { makePackage } from './helpers/fixtures.mjs';
import { sha256, writeStoreZip } from './helpers/zip.mjs';

async function withPackage(pkg, callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bepack-package-'));
  try {
    const file = path.join(directory, 'fixture.bepack');
    await writeFile(file, pkg.zip);
    return await callback(file);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const expectedFor = (pkg) => ({
  packId: pkg.manifest.id,
  version: pkg.manifest.version,
  versionSet: pkg.versionSet,
  mode: pkg.manifest.mode,
  packageSha256: pkg.packageSha256,
});

test('independently verifies a controlled package and produces a scan plan', async () => {
  const pkg = makePackage();
  await withPackage(pkg, async (file) => {
    const result = await verifyPackage(file, {
      packageSha256: pkg.packageSha256,
      packageSize: pkg.packageSize,
      expected: expectedFor(pkg),
    });
    assert.equal(result.id, pkg.manifest.id);
    assert.equal(result.version, pkg.manifest.version);
    assert.equal(result.mode, 'full');
    assert.deepEqual(result.targets.map((target) => target.target), ['win-x64']);
    assert.equal(result.files.get('bepack.json').sha256, sha256(pkg.manifestBytes));
    assert.ok(result.files.get('bepack.json').bytes.equals(pkg.manifestBytes));
    assert.equal(result.scanPlan.length, 1);
    assert.equal(result.scanPlan[0].subject, 'package');
    assert.equal(result.scanPlan[0].sha256, pkg.packageSha256);
    assert.equal(result.scanPlan[0].size, pkg.packageSize);
  });
});

test('rejects a package whose declared lock hash does not match actual bytes', async () => {
  const pkg = makePackage();
  const tamperedManifest = Buffer.from(`${pkg.manifestBytes.toString('utf8').trimEnd()} `);
  const tamperedZip = writeStoreZip([
    { name: 'bepack.json', data: tamperedManifest },
    { name: 'versions/default.json', data: pkg.versionSetBytes },
    { name: 'bepack.lock.json', data: pkg.lockBytes },
  ]);
  const tampered = { ...pkg, zip: tamperedZip, packageSha256: sha256(tamperedZip), packageSize: tamperedZip.length };
  await withPackage(tampered, async (file) => {
    await assert.rejects(
      verifyPackage(file, { packageSha256: tampered.packageSha256, packageSize: tampered.packageSize, expected: expectedFor(tampered) }),
      /bepack\.lock\.json|HASH_MISMATCH|Package verification failed/u,
    );
  });
});

test('rejects ZIP entries with unsafe relative paths', async () => {
  const zip = writeStoreZip([{ name: '../escape.txt', data: 'x' }]);
  const pkg = { zip, packageSha256: sha256(zip), packageSize: zip.length };
  await withPackage(pkg, async (file) => {
    await assert.rejects(
      verifyPackage(file, { packageSha256: pkg.packageSha256, packageSize: pkg.packageSize, expected: { packId: 'a.b', version: '1.0.0', versionSet: 'default', mode: 'full', packageSha256: pkg.packageSha256 } }),
      /PATH_UNSAFE|unsafe|relative/iu,
    );
  });
});
