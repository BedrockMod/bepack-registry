// Stable public error codes for CLI, CI and the workbench backend. Codes are
// never localized; human messages and JSON Pointers are separate fields.
export class RegistryError extends Error {
  constructor(code, message, { details = null, exitCode = 2, cause = null } = {}) {
    super(message, { cause });
    this.name = 'RegistryError';
    this.code = code;
    this.details = details;
    this.exitCode = exitCode;
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

export const codes = Object.freeze({
  ARGUMENT: 'REGISTRY_ARGUMENT_INVALID',
  SOURCE: 'REGISTRY_SOURCE_INVALID',
  RELEASE: 'REGISTRY_RELEASE_INVALID',
  ASSET_CHANGED: 'REGISTRY_ASSET_CHANGED',
  DOWNLOAD: 'REGISTRY_DOWNLOAD_FAILED',
  NETWORK: 'REGISTRY_NETWORK_ERROR',
  SSRF: 'REGISTRY_SSRF_BLOCKED',
  LIMIT: 'REGISTRY_RESOURCE_LIMIT',
  SCAN_PENDING: 'REGISTRY_SCAN_PENDING',
  SCAN_FAILED: 'REGISTRY_SCAN_FAILED',
  CATALOG: 'REGISTRY_CATALOG_INVALID',
  IMMUTABLE: 'REGISTRY_IMMUTABILITY_VIOLATION',
  CONFIG: 'REGISTRY_CONFIG_MISSING',
  INTERNAL: 'REGISTRY_INTERNAL_ERROR',
});

export function fail(code, message, options = {}) {
  throw new RegistryError(code, message, options);
}

export function errorOf(error) {
  if (error instanceof RegistryError) return error;
  return new RegistryError(codes.INTERNAL, error?.message ?? String(error), {
    exitCode: 1,
    cause: error,
  });
}
