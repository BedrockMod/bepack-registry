#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { buildCatalog, writeCatalog } from '../lib/catalog.mjs';
import { RegistryError, codes } from '../lib/errors.mjs';

const options = {
  out: { type: 'string' },
  revision: { type: 'string' },
  help: { type: 'boolean', default: false },
};

function usage() {
  return 'Usage: node scripts/build-registry.mjs --out <dir> [--revision <uuid>]\n'
    + 'Builds registry.json and content-addressed packs/<sha256>.json. Exit 0 ok, 2 invalid records, 1 internal.';
}

async function main() {
  const values = parseArgs({ options }).values;
  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!values.out) throw new RegistryError(codes.ARGUMENT, '--out is required');
  const revision = values.revision ?? randomUUID();
  const catalog = await buildCatalog({ root: process.cwd(), now: new Date(), revision });
  await writeCatalog({ outDir: values.out, registryBytes: catalog.registryBytes, details: catalog.details });
  process.stdout.write(`${JSON.stringify({
    ok: true,
    out: values.out,
    revision,
    packs: catalog.registry.packs.length,
    details: catalog.details.size,
    bytes: catalog.registryBytes.length,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error.code ?? codes.INTERNAL, message: error.message } }, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
});
