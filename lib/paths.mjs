import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ID_PATTERN, PACK_ID_PATTERN } from './constants.mjs';

// Unicode 17.0 default full case folding (C + F mappings, Turkic T excluded).
// The data is bundled with its license so ZIP path collision checks do not
// depend on a package manager or network at verification time.
const foldingBytes = readFileSync(new URL('./data/CaseFolding-17.0.0.txt', import.meta.url));
const FOLDING_SHA256 = 'ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183';
if (createHash('sha256').update(foldingBytes).digest('hex') !== FOLDING_SHA256) {
  throw new Error('Unicode case-folding data integrity mismatch');
}
const folding = new Map();
for (const line of foldingBytes.toString('utf8').split('\n')) {
  const match = /^([0-9A-F]+); ([CF]); ([0-9A-F ]+);/u.exec(line);
  if (match) {
    folding.set(
      Number.parseInt(match[1], 16),
      String.fromCodePoint(...match[3].trim().split(' ').map((value) => Number.parseInt(value, 16))),
    );
  }
}

export function caseFold(value) {
  return Array.from(value, (character) => folding.get(character.codePointAt(0)) ?? character)
    .join('')
    .normalize('NFC');
}

const RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;
const FORBIDDEN = /[\x00-\x1f\x7f-\x9f<>:"|?*\\]/u;

// Package and payload paths: forward slashes, relative, NFC, no link or device
// semantics, no Windows-reserved segment, bounded UTF-8 bytes.
export function safeRelative(value, { prefix, dot = false } = {}) {
  if (dot && value === '.') return true;
  if (typeof value !== 'string' || !value || !value.isWellFormed()) return false;
  if (value !== value.normalize('NFC')) return false;
  if (Buffer.byteLength(value, 'utf8') > 1024) return false;
  const parts = value.split('/');
  if (parts.length > 32) return false;
  if (prefix && !value.startsWith(`${prefix}/`)) return false;
  return parts.every((part) => part && part !== '.' && part !== '..'
    && Buffer.byteLength(part, 'utf8') <= 255
    && !FORBIDDEN.test(part)
    && !/[ .]$/u.test(part)
    && !RESERVED.test(part));
}

export function safePackId(value) {
  return typeof value === 'string' && value.length <= 128 && PACK_ID_PATTERN.test(value);
}

export function safeId(value) {
  return typeof value === 'string' && ID_PATTERN.test(value) && value !== '.' && value !== '..';
}

export function decimalId(value) {
  return typeof value === 'string' && /^(?:0|[1-9]\d*)$/u.test(value) && value.length <= 20;
}

export function sha256Hex(value) {
  return /^[0-9a-f]{64}$/u.test(value);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

// Reject path pairs that only differ by case/Unicode folding. This mirrors the
// installer's collision rule and applies to all ZIP regular files.
export function checkCollision(names) {
  const map = new Map();
  for (const name of names) {
    const key = caseFold(name);
    const previous = map.get(key);
    if (previous !== undefined && previous !== name) {
      return { previous, name };
    }
    map.set(key, name);
  }
  return null;
}
