import parseLicense from 'spdx-expression-parse';
import { GAME_VERSION_PATTERN, SEMVER_PATTERN } from './constants.mjs';
import { safeId, safePackId, sha256Hex } from './paths.mjs';
import { parseSemver } from './semver.mjs';

export class Issues {
  constructor(file = '') {
    this.file = file;
    this.list = [];
  }

  add(code, message, field = '', extra = {}) {
    this.list.push({ severity: 'error', code, message, file: this.file, field, ...extra });
  }

  get length() {
    return this.list.length;
  }

  get valid() {
    return this.list.length === 0;
  }
}

export const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
export const isInteger = (value) => Number.isSafeInteger(value) && value >= 0;
export const isNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0;

export function exactKeys(value, allowed, required, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (!isObject(value)) {
    issues.add(code, 'Expected an object', field);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key) && key !== 'extensions') {
      issues.add(code, `Unknown field ${key}`, `${field}/${escapePointer(key)}`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) issues.add(code, `Missing required field ${key}`, `${field}/${escapePointer(key)}`);
  }
  return true;
}

export function escapePointer(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

export function checkHttps(value, field, issues, { fragment = false, code = 'BEPACK_MANIFEST_INVALID' } = {}) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || (!fragment && url.hash)) throw new Error();
    return true;
  } catch {
    issues.add(code, 'Expected an absolute HTTPS URL without credentials' + (fragment ? '' : ' or fragment'), field);
    return false;
  }
}

export function checkStringArray(value, field, issues, { min = 0, code = 'BEPACK_MANIFEST_INVALID' } = {}) {
  if (!Array.isArray(value) || value.length < min || value.some((item) => typeof item !== 'string' || !item)) {
    issues.add(code, `Expected an array of non-empty strings${min ? ` with at least ${min} item(s)` : ''}`, field);
    return false;
  }
  if (new Set(value).size !== value.length) issues.add(code, 'Duplicate array entries', field);
  return true;
}

export function checkPackId(value, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (!safePackId(value)) issues.add(code, 'Invalid pack ID', field);
}

export function checkId(value, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (!safeId(value)) issues.add(code, 'Invalid ID', field);
}

export function checkSemver(value, field, issues, code = 'BEPACK_MANIFEST_INVALID', { allowPrerelease = true } = {}) {
  const parsed = parseSemver(value);
  if (!parsed || (!allowPrerelease && !parsed.stable)) issues.add(code, 'Invalid SemVer', field);
}

export function checkGameVersion(value, field, issues, { nullable = false, code = 'BEPACK_MANIFEST_INVALID' } = {}) {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || !GAME_VERSION_PATTERN.test(value)) {
    issues.add(code, 'Invalid game version', field);
  }
}

export function checkSha256(value, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (!sha256Hex(value)) issues.add(code, 'Expected a lowercase SHA-256', field);
}

export function checkTimestamp(value, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (typeof value !== 'string') {
    issues.add(code, 'Expected a UTC RFC 3339 timestamp', field);
    return null;
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/u.exec(value);
  if (!match) {
    issues.add(code, 'Expected a UTC RFC 3339 timestamp', field);
    return null;
  }
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const time = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), Number(`0.${fraction || '0'}`) * 1000);
  const date = new Date(time);
  if (!Number.isFinite(time)
    || date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== Number(month) - 1
    || date.getUTCDate() !== Number(day) || date.getUTCHours() !== Number(hour)
    || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second)) {
    issues.add(code, 'Invalid timestamp', field);
    return null;
  }
  return time;
}

export function checkLicense(value, field, issues, { licenseFile = null, code = 'BEPACK_LICENSE_INVALID' } = {}) {
  if (typeof value !== 'string' || !value.trim()) {
    issues.add(code, 'A non-empty SPDX expression or LicenseRef is required', field);
    return;
  }
  let valid = true;
  try {
    parseLicense(value);
  } catch {
    valid = false;
    issues.add(code, 'Invalid SPDX expression or LicenseRef', field);
  }
  if (valid && value.includes('LicenseRef-') && !licenseFile) {
    issues.add(code, 'A custom license requires license_file', field);
  }
}

export function versionRequirement(value, field, issues, code = 'BEPACK_MANIFEST_INVALID') {
  if (!isObject(value)) {
    issues.add(code, 'Expected a VersionRequirement object', field);
    return;
  }
  if (Object.hasOwn(value, 'exact')) {
    if (Object.keys(value).length !== 1) issues.add(code, 'Exact VersionRequirement has extra fields', field);
    checkSemver(value.exact, `${field}/exact`, issues, code);
    return;
  }
  const range = value.range;
  if (!isObject(range)) {
    issues.add(code, 'Expected exact or range VersionRequirement', field);
    return;
  }
  exactKeys(range, ['min', 'max', 'include_min', 'include_max'], ['min', 'max', 'include_min', 'include_max'], `${field}/range`, issues, code);
  const numeric = (item) => typeof item === 'string' && /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2,3}$/u.test(item);
  if (!numeric(range.min) || !numeric(range.max)) {
    issues.add(code, 'Range bounds must be numeric versions', `${field}/range`);
    return;
  }
  if (![true, false].includes(range.include_min) || ![true, false].includes(range.include_max)) {
    issues.add(code, 'Range inclusivity must be boolean', `${field}/range`);
  }
  const left = range.min.split('.').map(BigInt);
  const right = range.max.split('.').map(BigInt);
  if (left.length !== right.length) {
    issues.add(code, 'Range bounds must have equal segment counts', field);
    return;
  }
  let comparison = 0;
  for (let index = 0; index < left.length; index++) {
    if (left[index] < right[index]) { comparison = -1; break; }
    if (left[index] > right[index]) { comparison = 1; break; }
  }
  if (comparison > 0 || (comparison === 0 && (!range.include_min || !range.include_max))) {
    issues.add(code, 'Version range is empty or reversed', field);
  }
}

export function semverPattern(value) {
  return typeof value === 'string' && SEMVER_PATTERN.test(value);
}
