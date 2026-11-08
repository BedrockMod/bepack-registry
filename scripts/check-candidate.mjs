#!/usr/bin/env node
// Executed from the trusted base checkout. Never check out or run PR code.
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const { values } = parseArgs({ options: { base: { type: 'string' }, head: { type: 'string' } } });
if (!values.base || !values.head || !/^[0-9a-f]{40}$/u.test(values.head)) throw new Error('--base and --head (full commit SHA) are required');
const root = await mkdtemp(path.join(os.tmpdir(), 'registry-candidate-'));
const git = (args) => execFileSync('git', args, { maxBuffer: 16 * 1024 * 1024 });
try {
  const entries = git(['ls-tree', '-rz', values.head, '--', 'sources', 'releases', 'withdrawals']).toString('utf8').split('\0').filter(Boolean);
  if (entries.length > 10000) throw new Error('Candidate exceeds record count limit');
  let total = 0;
  for (const entry of entries) {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(entry);
    if (!match) throw new Error('Candidate data must contain regular files only');
    const [, , object, relative] = match;
    if (!/^(?:sources\/[a-z0-9.-]+\.json|(?:releases|withdrawals)\/[a-z0-9.-]+\/[0-9A-Za-z.+-]+\.json|(?:sources|releases|withdrawals)\/\.gitkeep)$/u.test(relative)) throw new Error(`Unexpected candidate data path: ${relative}`);
    const size = Number(git(['cat-file', '-s', object]).toString('utf8').trim());
    if (!Number.isSafeInteger(size) || size > 256 * 1024) throw new Error('Candidate record is oversized');
    total += size;
    if (total > 128 * 1024 * 1024) throw new Error('Candidate exceeds aggregate record budget');
    const bytes = git(['cat-file', 'blob', object]);
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { flag: 'wx' });
  }
  execFileSync(process.execPath, [fileURLToPath(new URL('./check-pr.mjs', import.meta.url)), '--root', root, '--base', values.base, '--head', values.head], { stdio: 'inherit' });
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = error.status || 2;
} finally {
  await rm(root, { recursive: true, force: true });
}
