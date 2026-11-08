#!/usr/bin/env node
import { buildCatalog } from '../lib/catalog.mjs';
import { parseStrictJSON } from '../lib/strict-json.mjs';
import { sha256, safeRelative } from '../lib/paths.mjs';

async function main() {
  const catalog = await buildCatalog({ root: process.cwd() });
  const parsed = parseStrictJSON(catalog.registryBytes, { maxBytes: 8 * 1024 * 1024 });
  if (parsed.schema_version !== 1 || parsed.registry_id !== 'bepack-registry') {
    throw new Error('registry header is invalid');
  }
  if (!Array.isArray(parsed.packs)) throw new Error('registry packs is not an array');
  for (const entry of parsed.packs) {
    safeRelative(entry.detail.path, { prefix: 'packs/' });
    const bytes = catalog.details.get(entry.detail.path);
    if (!Buffer.isBuffer(bytes)) throw new Error(`missing detail ${entry.detail.path}`);
    if (sha256(bytes) !== entry.detail.sha256) throw new Error(`detail hash mismatch ${entry.detail.path}`);
    if (bytes.length !== entry.detail.size) throw new Error(`detail size mismatch ${entry.detail.path}`);
  }
  process.stdout.write(`${JSON.stringify({
    ok: true,
    packs: parsed.packs.length,
    details: catalog.details.size,
    registry_bytes: catalog.registryBytes.length,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: error.message }, null, 2)}\n`);
  process.exitCode = 1;
});
