// Fixed policy identifiers for this registry implementation. These are data
// contract version numbers, not product versions of CopperGolem.
export const REGISTRY_ID = 'bepack-registry';
export const REGISTRY_SCHEMA_VERSION = 1;
export const SOURCE_SCHEMA_VERSION = 1;
export const RELEASE_RECORD_SCHEMA_VERSION = 1;
export const WITHDRAWAL_SCHEMA_VERSION = 1;
export const PACK_HISTORY_SCHEMA_VERSION = 1;
export const PACKAGE_SCHEMA_VERSION = 1;

// Tool identity is written into every release record. Bump it whenever the
// verification semantics change; never derive it from an unverified download.
export const VERIFIER_VERSION = '0.1.0';
export const VERIFICATION_TOOL = `bepack-registry-verifier/${VERIFIER_VERSION}`;
export const POLICY = 'bepack-official-v1';

// Consumer-facing limits from the registry design. These are hard publish
// limits, not suggestions: exceeding one aborts the catalog build and leaves
// the previous complete snapshot untouched.
export const LIMITS = Object.freeze({
  registryBytes: 8 * 1024 * 1024,
  detailBytes: 4 * 1024 * 1024,
  sourceBytes: 64 * 1024,
  releaseRecordBytes: 256 * 1024,
  withdrawalBytes: 64 * 1024,
  releaseDescriptorBytes: 1024 * 1024,
  scanReportBytes: 16 * 1024 * 1024,
  manifestBytes: 4 * 1024 * 1024,
  lockBytes: 64 * 1024 * 1024,
  checksumBytes: 4096,
  packageBytes: 2 * 1024 * 1024 * 1024,
  downloadedAssetBytes: 1024 * 1024 * 1024,
  externalExecutableBytes: 1024 * 1024 * 1024,
  zipEntries: 100000,
  zipTotalUncompressedBytes: 32 * 1024 * 1024 * 1024,
  zipSingleFileUncompressedBytes: 8 * 1024 * 1024 * 1024,
  zipCompressionRatio: 1000,
  httpBodyBytes: 64 * 1024 * 1024,
  webhookBodyBytes: 1024 * 1024,
  scanAgeMs: 7 * 24 * 60 * 60 * 1000,
});

// The five public Release assets. Names for the package and its checksum are
// derived from the pack ID and version; the other three are fixed.
export const ASSET_NAMES = Object.freeze({
  descriptor: 'bepack-release.json',
  manifest: 'bepack.json',
  scanReport: 'scan-report.json',
});

export const WITHDRAWAL_STATES = Object.freeze([
  'active',
  'yanked',
  'quarantined',
  'unavailable',
]);

export const INSTALLABLE_STATES = Object.freeze(['active']);

export const PACK_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$/u;
export const ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
export const SEMVER_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/u;
export const GAME_VERSION_PATTERN = /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2,3}$/u;
export const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
export const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
