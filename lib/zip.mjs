import { open } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { createInflateRaw } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';
import { RegistryError, codes } from './errors.mjs';
import { caseFold, safeRelative } from './paths.mjs';
import { LIMITS } from './constants.mjs';

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function bad(message, details = null) {
  return new RegistryError(codes.RELEASE, `Invalid .bepack container: ${message}`, { details });
}

function readUInt64(buffer, offset) {
  const value = buffer.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw bad('ZIP64 field exceeds JavaScript safe integer range');
  return Number(value);
}

function readExtraFields(buffer) {
  const fields = new Map();
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const id = buffer.readUInt16LE(offset);
    const size = buffer.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + size > buffer.length) throw bad('Truncated ZIP extra field');
    fields.set(id, buffer.subarray(offset, offset + size));
    offset += size;
  }
  if (offset !== buffer.length) throw bad('Malformed ZIP extra field padding');
  return fields;
}

async function readAt(handle, position, length) {
  const buffer = Buffer.alloc(length);
  let read = 0;
  while (read < length) {
    const { bytesRead } = await handle.read(buffer, read, length - read, position + read);
    if (!bytesRead) throw bad('Unexpected end of file');
    read += bytesRead;
  }
  return buffer;
}

function decodeName(bytes, flags) {
  // The format requires UTF-8 names. Reject legacy CP437 packets instead of
  // guessing a lossy interpretation. Writers may omit the UTF-8 flag for pure
  // ASCII, which still decodes and round-trips as UTF-8.
  let name;
  try {
    name = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw bad('ZIP entry name is not valid UTF-8');
  }
  if (name.includes('\u0000')) throw bad('ZIP entry name contains NUL');
  return name;
}

export async function inspectZip(file, {
  maxEntries = LIMITS.zipEntries,
  maxTotalBytes = LIMITS.zipTotalUncompressedBytes,
  maxSingleBytes = LIMITS.zipSingleFileUncompressedBytes,
  maxRatio = LIMITS.zipCompressionRatio,
  maxCentralBytes = 64 * 1024 * 1024,
} = {}) {
  const handle = await open(file, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw bad('Package is not a regular file');
    const size = stat.size;
    if (size < 22) throw bad('File is too small to be a ZIP archive');
    const tailLength = Math.min(size, 22 + 65535);
    const tail = await readAt(handle, size - tailLength, tailLength);
    let eocdOffset = -1;
    for (let index = tail.length - 22; index >= 0; index--) {
      if (tail.readUInt32LE(index) === EOCD && tail.readUInt16LE(index + 20) === tail.length - index - 22) {
        eocdOffset = index;
        break;
      }
    }
    if (eocdOffset < 0) throw bad('End of central directory not found');
    const eocd = tail.subarray(eocdOffset);
    const disk = eocd.readUInt16LE(4);
    const centralDisk = eocd.readUInt16LE(6);
    const diskEntries = eocd.readUInt16LE(8);
    const totalEntries16 = eocd.readUInt16LE(10);
    let centralSize = eocd.readUInt32LE(12);
    let centralOffset = eocd.readUInt32LE(16);
    let totalEntries = totalEntries16;
    if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries16) {
      throw bad('Multi-disk ZIP archives are forbidden');
    }
    const absoluteEocd = size - tailLength + eocdOffset;
    if (totalEntries16 === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
      if (absoluteEocd < 20) throw bad('ZIP64 locator missing');
      const locator = await readAt(handle, absoluteEocd - 20, 20);
      if (locator.readUInt32LE(0) !== ZIP64_LOCATOR) throw bad('ZIP64 locator signature missing');
      if (locator.readUInt32LE(4) !== 0 || locator.readUInt32LE(16) !== 1) throw bad('Spanned ZIP64 archive is forbidden');
      const zip64Offset = readUInt64(locator, 8);
      if (zip64Offset >= absoluteEocd) throw bad('ZIP64 EOCD offset out of range');
      const header = await readAt(handle, zip64Offset, 56);
      if (header.readUInt32LE(0) !== ZIP64_EOCD) throw bad('ZIP64 EOCD signature missing');
      if (header.readUInt32LE(16) !== 0 || header.readUInt32LE(20) !== 0) throw bad('Multi-disk ZIP64 archive is forbidden');
      if (header.readBigUInt64LE(24) !== header.readBigUInt64LE(32)) throw bad('ZIP64 entry counts disagree');
      totalEntries = readUInt64(header, 32);
      centralSize = readUInt64(header, 40);
      centralOffset = readUInt64(header, 48);
    }
    if (totalEntries > maxEntries) throw new RegistryError(codes.LIMIT, `ZIP contains more than ${maxEntries} entries`);
    if (centralSize > maxCentralBytes) throw new RegistryError(codes.LIMIT, 'ZIP central directory exceeds limit');
    if (centralOffset + centralSize > absoluteEocd) throw bad('Central directory overlaps EOCD');
    const central = await readAt(handle, centralOffset, centralSize);
    const entries = [];
    const names = new Set();
    const folded = new Map();
    let offset = 0;
    let totalUncompressed = 0;
    for (let index = 0; index < totalEntries; index++) {
      if (offset + 46 > central.length) throw bad('Truncated central directory');
      if (central.readUInt32LE(offset) !== CENTRAL) throw bad('Central directory entry signature mismatch');
      const madeBy = central.readUInt16LE(offset + 4);
      const needed = central.readUInt16LE(offset + 6);
      const flags = central.readUInt16LE(offset + 8);
      const method = central.readUInt16LE(offset + 10);
      const crc = central.readUInt32LE(offset + 16);
      let compressedSize = central.readUInt32LE(offset + 20);
      let uncompressedSize = central.readUInt32LE(offset + 24);
      const nameLength = central.readUInt16LE(offset + 28);
      const extraLength = central.readUInt16LE(offset + 30);
      const commentLength = central.readUInt16LE(offset + 32);
      const diskStart = central.readUInt16LE(offset + 34);
      const externalAttributes = central.readUInt32LE(offset + 38);
      let localOffset = central.readUInt32LE(offset + 42);
      const end = offset + 46 + nameLength + extraLength + commentLength;
      if (end > central.length) throw bad('Central directory entry exceeds directory');
      const nameBytes = central.subarray(offset + 46, offset + 46 + nameLength);
      const extra = readExtraFields(central.subarray(offset + 46 + nameLength, offset + 46 + nameLength + extraLength));
      offset = end;
      const name = decodeName(nameBytes, flags);
      if (flags & 0x0001 || flags & 0x0040 || flags & 0x2000) throw bad('Encrypted ZIP entries are forbidden');
      if (needed > 63) throw bad(`Unsupported ZIP version ${needed}`);
      if (![0, 8].includes(method)) throw bad(`Compression method ${method} is forbidden`);
      if (diskStart !== 0) throw bad('Multi-disk ZIP entry is forbidden');
      if (name.endsWith('/')) {
        if (uncompressedSize !== 0 || compressedSize !== 0) throw bad('Directory entry has data');
        if (!safeRelative(name.slice(0, -1))) throw bad(`Unsafe directory path ${name}`);
      } else if (!safeRelative(name)) {
        throw new RegistryError(codes.RELEASE, `Unsafe package path ${name}`, { details: { path: name } });
      }
      const zip64 = extra.get(0x0001);
      if (zip64) {
        let cursor = 0;
        if (uncompressedSize === 0xffffffff) {
          if (zip64.length < cursor + 8) throw bad('Truncated ZIP64 size field');
          uncompressedSize = readUInt64(zip64, cursor);
          cursor += 8;
        }
        if (compressedSize === 0xffffffff) {
          if (zip64.length < cursor + 8) throw bad('Truncated ZIP64 compressed size field');
          compressedSize = readUInt64(zip64, cursor);
          cursor += 8;
        }
        if (localOffset === 0xffffffff) {
          if (zip64.length < cursor + 8) throw bad('Truncated ZIP64 offset field');
          localOffset = readUInt64(zip64, cursor);
        }
      }
      if (uncompressedSize > maxSingleBytes) throw new RegistryError(codes.LIMIT, `ZIP entry ${name} exceeds single-file limit`);
      if (compressedSize === 0 && uncompressedSize > 0) throw bad(`ZIP entry ${name} has impossible compression`);
      if (compressedSize > 0 && uncompressedSize / compressedSize > maxRatio && uncompressedSize > 1024 * 1024) {
        throw new RegistryError(codes.LIMIT, `ZIP entry ${name} exceeds compression ratio limit`);
      }
      totalUncompressed += uncompressedSize;
      if (totalUncompressed > maxTotalBytes) throw new RegistryError(codes.LIMIT, 'ZIP total uncompressed size exceeds limit');
      if (names.has(name)) throw bad(`Duplicate ZIP entry ${name}`);
      names.add(name);
      if (!name.endsWith('/')) {
        const key = caseFold(name);
        if (folded.has(key)) throw bad(`Case-folding path collision between ${folded.get(key)} and ${name}`);
        folded.set(key, name);
      }
      entries.push({
        name,
        directory: name.endsWith('/'),
        flags,
        method,
        crc,
        compressedSize,
        uncompressedSize,
        localOffset,
        externalAttributes,
        madeBy,
      });
    }
    if (offset !== central.length) throw bad('Central directory has trailing data');
    for (const entry of entries) {
      const mode = (entry.externalAttributes >>> 16) & 0xffff;
      if (mode) {
        const type = mode & 0o170000;
        if (entry.directory) {
          if (type !== 0o040000) throw bad(`Directory entry ${entry.name} has non-directory mode`);
        } else if (type !== 0o100000) {
          throw new RegistryError(codes.RELEASE, `Package entry ${entry.name} is not a regular file`);
        }
      }
      if (entry.directory) continue;
      if (entry.uncompressedSize < 0) throw bad('Negative size');
    }
    // A file path cannot also be a directory prefix of another entry. Walk the
    // sorted names once instead of comparing every pair.
    const sortedNames = [...names].sort();
    for (let index = 0; index < sortedNames.length; index++) {
      const name = sortedNames[index];
      if (name.endsWith('/')) continue;
      const next = sortedNames[index + 1];
      if (next && next.startsWith(`${name}/`)) throw bad(`File and directory conflict at ${name}`);
    }
    return { file, handle, size, entries, centralOffset, centralSize };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

export async function readEntry(zip, entry, { capture = false, maxCapture = 64 * 1024 * 1024 } = {}) {
  const handle = zip.handle;
  const local = await readAt(handle, entry.localOffset, 30);
  if (local.readUInt32LE(0) !== LOCAL) throw bad(`Local header missing for ${entry.name}`);
  const flags = local.readUInt16LE(6);
  const method = local.readUInt16LE(8);
  const nameLength = local.readUInt16LE(26);
  const extraLength = local.readUInt16LE(28);
  if (flags !== entry.flags || method !== entry.method) throw bad(`Local header disagrees with central directory for ${entry.name}`);
  if (flags & 0x0008) {
    // Data descriptor follows the data; the central directory still holds the
    // authoritative sizes. Nothing extra is needed for random access.
  }
  const nameBytes = await readAt(handle, entry.localOffset + 30, nameLength);
  const localName = decodeName(nameBytes, flags);
  if (localName !== entry.name) throw bad(`Local name mismatch for ${entry.name}`);
  const dataStart = entry.localOffset + 30 + nameLength + extraLength;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > zip.centralOffset) throw bad(`Data of ${entry.name} overlaps central directory`);
  if (entry.compressedSize === 0 && entry.uncompressedSize === 0) {
    if (entry.crc !== 0) throw bad(`CRC mismatch for empty entry ${entry.name}`);
    return { size: 0, sha256: createHash('sha256').digest('hex'), bytes: capture ? Buffer.alloc(0) : null };
  }
  const hash = createHash('sha256');
  const captured = capture ? [] : null;
  let outputSize = 0;
  let runningCrc = 0xffffffff;
  const sink = new Writable({
    write(chunk, encoding, callback) {
      outputSize += chunk.length;
      if (outputSize > entry.uncompressedSize) {
        callback(new RegistryError(codes.LIMIT, `ZIP entry ${entry.name} expands beyond its declared size`));
        return;
      }
      hash.update(chunk);
      for (const byte of chunk) runningCrc = CRC_TABLE[(runningCrc ^ byte) & 0xff] ^ (runningCrc >>> 8);
      if (captured) {
        if (outputSize > maxCapture) {
          callback(new RegistryError(codes.LIMIT, `Capture limit exceeded for ${entry.name}`));
          return;
        }
        captured.push(chunk);
      }
      callback();
    },
  });
  try {
    if (entry.method === 0) {
      if (entry.compressedSize !== entry.uncompressedSize) throw bad(`Stored entry ${entry.name} has unequal sizes`);
      await pipeline(createReadStream(zip.file, { fd: handle.fd, autoClose: false, start: dataStart, end: dataEnd - 1 }), sink);
    } else {
      await pipeline(
        createReadStream(zip.file, { fd: handle.fd, autoClose: false, start: dataStart, end: dataEnd - 1 }),
        createInflateRaw(),
        sink,
      );
    }
  } catch (error) {
    if (error instanceof RegistryError) throw error;
    throw bad(`Failed to read ${entry.name}: ${error.message}`);
  }
  if (outputSize !== entry.uncompressedSize) throw bad(`Size mismatch for ${entry.name}: ${outputSize} != ${entry.uncompressedSize}`);
  if (((runningCrc ^ 0xffffffff) >>> 0) !== entry.crc) throw bad(`CRC mismatch for ${entry.name}`);
  const bytes = captured ? Buffer.concat(captured, outputSize) : null;
  return { size: outputSize, sha256: hash.digest('hex'), bytes };
}

export async function verifyAllEntries(zip, { captureNames = new Set(), maxCapture = 64 * 1024 * 1024 } = {}) {
  const files = new Map();
  for (const entry of zip.entries) {
    if (entry.directory) continue;
    const captureSet = captureNames instanceof Set ? captureNames : new Set(captureNames);
    const result = await readEntry(zip, entry, { capture: captureSet.has(entry.name), maxCapture });
    files.set(entry.name, { ...result, crc: entry.crc, method: entry.method, compressedSize: entry.compressedSize });
  }
  return files;
}

export async function closeZip(zip) {
  await zip.handle.close();
}
