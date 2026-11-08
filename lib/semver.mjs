import { SEMVER_PATTERN } from './constants.mjs';

// Minimal SemVer 2.0.0 parser for the v1 subset: MAJOR.MINOR.PATCH with an
// optional prerelease. Build metadata is forbidden by the package standard.
export function parseSemver(value) {
  if (typeof value !== 'string' || !SEMVER_PATTERN.test(value)) return null;
  const separator = value.indexOf('-');
  const core = separator < 0 ? value : value.slice(0, separator);
  const prerelease = separator < 0 ? '' : value.slice(separator + 1);
  const numbers = core.split('.').map(Number);
  return {
    version: value,
    numbers,
    prerelease: prerelease ? prerelease.split('.') : [],
    stable: prerelease === '',
  };
}

function compareIdentifier(left, right) {
  const leftNumeric = /^\d+$/u.test(left);
  const rightNumeric = /^\d+$/u.test(right);
  if (leftNumeric && rightNumeric) return Number(left) - Number(right);
  if (leftNumeric) return -1;
  if (rightNumeric) return 1;
  return left < right ? -1 : left > right ? 1 : 0;
}

export function compareSemver(left, right) {
  const a = typeof left === 'string' ? parseSemver(left) : left;
  const b = typeof right === 'string' ? parseSemver(right) : right;
  if (!a || !b) throw new Error('Cannot compare invalid SemVer');
  for (let index = 0; index < 3; index++) {
    if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] - b.numbers[index];
  }
  if (!a.prerelease.length && !b.prerelease.length) return 0;
  if (!a.prerelease.length) return 1;
  if (!b.prerelease.length) return -1;
  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index++) {
    if (a.prerelease[index] === undefined) return -1;
    if (b.prerelease[index] === undefined) return 1;
    const result = compareIdentifier(a.prerelease[index], b.prerelease[index]);
    if (result !== 0) return result;
  }
  return 0;
}

export function sortVersionsDescending(versions) {
  return [...versions].sort((left, right) => compareSemver(right, left));
}

// VersionRequirement from the v1 standard: exact string or numeric interval.
export function versionSatisfies(version, requirement) {
  if (!requirement || typeof requirement !== 'object') return false;
  if (requirement.exact !== undefined) return version === requirement.exact;
  const range = requirement.range;
  if (!range) return false;
  const numeric = (value) => /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2,3}$/u.test(value);
  if (!numeric(version) || !numeric(range.min) || !numeric(range.max)) return false;
  const parts = (value) => value.split('.').map(BigInt);
  const a = parts(version);
  const min = parts(range.min);
  const max = parts(range.max);
  if (a.length !== min.length || min.length !== max.length) return false;
  const compare = (left, right) => {
    for (let index = 0; index < left.length; index++) {
      if (left[index] < right[index]) return -1;
      if (left[index] > right[index]) return 1;
    }
    return 0;
  };
  return compare(a, min) >= (range.include_min ? 0 : 1)
    && compare(a, max) <= (range.include_max ? 0 : -1);
}
