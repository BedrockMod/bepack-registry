import { open, readFile } from 'node:fs/promises';

// A strict JSON reader for untrusted registry data. It rejects BOM, duplicate
// keys, invalid UTF-8, non-object roots, trailing bytes and excessive nesting
// before JSON.parse can silently accept a last-key-wins document.
export function parseStrictJSON(bytes, { maxBytes = 4 * 1024 * 1024, maxDepth = 128 } = {}) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Expected bytes');
  if (bytes.length > maxBytes) throw new Error(`JSON exceeds byte limit of ${maxBytes}`);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error('UTF-8 BOM is forbidden');
  }
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let index = 0;
  const whitespace = () => {
    while (index < text.length && /[\x20\x09\x0a\x0d]/u.test(text[index])) index++;
  };
  const fail = (message) => {
    throw new Error(`${message} at byte offset ${index}`);
  };
  function string() {
    const start = index++;
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') {
        const parsed = JSON.parse(text.slice(start, index));
        if (!parsed.isWellFormed()) fail('Unpaired Unicode surrogate');
        return parsed;
      }
      if (character === '\\') index++;
    }
    fail('Unterminated string');
    return '';
  }
  function value(depth) {
    if (depth > maxDepth) fail('JSON nesting limit exceeded');
    whitespace();
    if (text[index] === '{') {
      index++;
      whitespace();
      const keys = new Set();
      if (text[index] === '}') {
        index++;
        return;
      }
      while (index < text.length) {
        if (text[index] !== '"') fail('Object key expected');
        const key = string();
        if (keys.has(key)) fail(`Duplicate key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (text[index++] !== ':') fail('Colon expected');
        value(depth + 1);
        whitespace();
        if (text[index] === '}') {
          index++;
          return;
        }
        if (text[index++] !== ',') fail('Comma expected');
        whitespace();
      }
      fail('Unterminated object');
    }
    if (text[index] === '[') {
      index++;
      whitespace();
      if (text[index] === ']') {
        index++;
        return;
      }
      while (index < text.length) {
        value(depth + 1);
        whitespace();
        if (text[index] === ']') {
          index++;
          return;
        }
        if (text[index++] !== ',') fail('Comma expected');
        whitespace();
      }
      fail('Unterminated array');
    }
    if (text[index] === '"') {
      string();
      return;
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(index));
    if (!match) fail('JSON value expected');
    index += match[0].length;
  }
  value(0);
  whitespace();
  if (index !== text.length) fail('Trailing JSON bytes');
  const result = JSON.parse(text);
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    fail('Root must be an object');
  }
  return result;
}

export async function readStrictJSON(file, options = {}) {
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
  const handle = await open(file, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Not a regular file');
    if (stat.size > maxBytes) throw new Error(`JSON exceeds byte limit of ${maxBytes}`);
    const buffer = Buffer.alloc(stat.size);
    let read = 0;
    while (read < buffer.length) {
      const { bytesRead } = await handle.read(buffer, read, buffer.length - read, null);
      if (!bytesRead) break;
      read += bytesRead;
    }
    if (read !== buffer.length) throw new Error('File changed while reading');
    return parseStrictJSON(buffer, options);
  } finally {
    await handle.close();
  }
}

// Read without a size assumption, then enforce the caller's limit. Used for
// downloaded data where Content-Length is untrusted.
export async function readBounded(file, maxBytes) {
  const bytes = await readFile(file);
  if (bytes.length > maxBytes) throw new Error(`File exceeds byte limit of ${maxBytes}`);
  return bytes;
}

export function canonicalJSON(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}
