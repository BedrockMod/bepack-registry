import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { VirusTotalClient } from '../lib/virustotal.mjs';
import { GitHubClient } from '../lib/github.mjs';
import { verifyRelease } from '../lib/release-verify.mjs';
import { syncReleaseSet } from '../lib/sync.mjs';
import { buildCatalog } from '../lib/catalog.mjs';
import { canonicalJSON } from '../lib/strict-json.mjs';
import { parseSemver, compareSemver } from '../lib/semver.mjs';
import { codes } from '../lib/errors.mjs';
import { FixtureDownloader, FixtureGitHub, NOW, makeReleaseFixture, makeVtAnalysis, makeVtPayload } from './helpers/fixtures.mjs';

function setupVt(fixture, { analysis = null, file = null, item = null } = {}) {
  const downloader = new FixtureDownloader(fixture);
  const sha = fixture.pkg.packageSha256;
  const id = `analysis-${sha.slice(0, 8)}`;
  downloader.add(`https://www.virustotal.com/api/v3/files/${sha}`, Buffer.from(JSON.stringify(file ?? makeVtPayload(sha, fixture.pkg.packageSize))));
  downloader.add(`https://www.virustotal.com/api/v3/analyses/${id}`, Buffer.from(JSON.stringify(analysis ?? makeVtAnalysis(sha, id))));
  downloader.add(`https://www.virustotal.com/api/v3/analyses/${id}/item`, Buffer.from(JSON.stringify(item ?? makeVtPayload(sha, fixture.pkg.packageSize))));
  return { downloader, id, sha, vt: new VirusTotalClient({ downloader, apiKey: 'fixture', clock: () => NOW }) };
}

test('rejects an old analysis even when the author reports clean results', async () => {
  const f = makeReleaseFixture();
  const analysis = makeVtAnalysis(f.pkg.packageSha256, `analysis-${f.pkg.packageSha256.slice(0,8)}`, { now: new Date(NOW.getTime() - 8 * 86400000) });
  const { vt, sha, id } = setupVt(f, { analysis });
  await assert.rejects(vt.getFileReport(sha, { analysisId: id }), (e) => e.code === codes.SCAN_PENDING);
});

test('rejects independently fetched item bound to another file despite forged inline relationship', async () => {
  const f = makeReleaseFixture();
  const item = makeVtPayload('f'.repeat(64), f.pkg.packageSize);
  const { vt, sha, id } = setupVt(f, { item });
  await assert.rejects(vt.getFileReport(sha, { analysisId: id }), /analysis item/u);
});

test('accepts official item binding without optional analysis metadata', async () => {
  const f = makeReleaseFixture();
  const { vt, sha, id } = setupVt(f);
  assert.equal((await vt.getFileReport(sha, { analysisId: id })).sha256, sha);
});

test('rejects URL analysis item even with the expected id', async () => {
  const f = makeReleaseFixture();
  const item = makeVtPayload(f.pkg.packageSha256, f.pkg.packageSize); item.data.type = 'url';
  const { vt, sha, id } = setupVt(f, { item });
  await assert.rejects(vt.getFileReport(sha, { analysisId: id }), /analysis item/u);
});

test('rejects completed analysis with no clean engines even if latest report is clean', async () => {
  const f = makeReleaseFixture();
  const analysis = makeVtAnalysis(f.pkg.packageSha256, `analysis-${f.pkg.packageSha256.slice(0,8)}`);
  analysis.data.attributes.results = {};
  analysis.data.attributes.stats.harmless = 0;
  const { vt, sha, id } = setupVt(f, { analysis });
  await assert.rejects(vt.getFileReport(sha, { analysisId: id }), /no harmless/u);
});

test('refuses assets that have not finished uploading', async () => {
  const f = makeReleaseFixture();
  const { downloader, vt } = setupVt(f);
  const github = new FixtureGitHub(f);
  github.assets[0].state = 'starter';
  await assert.rejects(verifyRelease({ github, downloader, vt, source: f.source, releaseId: String(f.release.id), now: NOW }), /uploaded/u);
});

test('disabling a source suppresses latest while retaining immutable version details', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'registry-security-'));
  try {
    const f = makeReleaseFixture();
    const { downloader, vt } = setupVt(f);
    await mkdir(path.join(root,'sources'));
    await writeFile(path.join(root,'sources',`${f.source.pack_id}.json`),canonicalJSON(f.source));
    await syncReleaseSet({ github:new FixtureGitHub(f),downloader,vt,root,now:NOW });
    await mkdir(path.join(root,'withdrawals',f.source.pack_id),{recursive:true});
    await writeFile(path.join(root,'withdrawals',f.source.pack_id,'1.0.0.json'),canonicalJSON({schema_version:1,pack_id:f.source.pack_id,version:'1.0.0',state:'active',reason:'Earlier manually restored fixture',created_at:NOW.toISOString(),advisory_url:null}));
    f.source.enabled=false;
    await writeFile(path.join(root,'sources',`${f.source.pack_id}.json`),canonicalJSON(f.source));
    const c=await buildCatalog({root,now:NOW});
    assert.equal(c.registry.packs[0].latest,null);
    assert.equal(c.registry.packs[0].state,'inactive');
    assert.equal(JSON.parse([...c.details.values()][0]).versions[0].state,'yanked');
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('confirmed detections quarantine existing version and deletion does not weaken quarantine', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'registry-security-'));
  try {
    const f=makeReleaseFixture(); const {downloader,vt}=setupVt(f); const github=new FixtureGitHub(f);
    await mkdir(path.join(root,'sources'));
    await writeFile(path.join(root,'sources',`${f.source.pack_id}.json`),canonicalJSON(f.source));
    await syncReleaseSet({github,downloader,vt,root,now:NOW});
    const malicious={getFileReport:async()=>{throw Object.assign(new Error('detections'),{code:codes.SCAN_FAILED});}};
    const report=await syncReleaseSet({github,downloader,vt:malicious,root,now:NOW});
    assert.equal(report.quarantined.length,1); assert.equal(report.pending.length,0);
    github.listReleases=async()=>[];
    await syncReleaseSet({github,downloader,vt,root,now:NOW});
    const record=JSON.parse(await readFile(path.join(root,'withdrawals',f.source.pack_id,'1.0.0.json'),'utf8'));
    assert.equal(record.state,'quarantined');
  } finally {await rm(root,{recursive:true,force:true});}
});

test('follows same-origin pagination without duplicating API origin',async()=>{
  const seen=[];
  const client=new GitHubClient({downloader:{fetchBytes:async(url)=>{seen.push(url);return {status:200,bytes:Buffer.from('[{"id":1}]'),headers:seen.length===1?{link:'<https://api.github.com/repos/a/b/releases?page=2>; rel="next"'}:{}};}}});
  assert.equal((await client.listReleases('a/b')).length,2);
  assert.equal(seen[1],'https://api.github.com/repos/a/b/releases?page=2');
});

test('rejects foreign-origin pagination and never returns silently truncated pages',async()=>{
  const foreign=new GitHubClient({downloader:{fetchBytes:async()=>({status:200,bytes:Buffer.from('[]'),headers:{link:'<https://attacker.example/x>; rel="next"'}})}});
  await assert.rejects(foreign.listReleases('a/b'),/origin/u);
  const looping=new GitHubClient({downloader:{fetchBytes:async()=>({status:200,bytes:Buffer.from('[]'),headers:{link:'<https://api.github.com/x?page=2>; rel="next"'}})}});
  await assert.rejects(looping.paginate('/x',{maxPages:1}),/page budget/u);
});

test('preserves hyphens in SemVer prerelease identifiers and compares full identifier',()=>{
  assert.deepEqual(parseSemver('1.0.0-beta-one.1').prerelease,['beta-one','1']);
  assert.ok(compareSemver('1.0.0-beta-two','1.0.0-beta-one')>0);
});
