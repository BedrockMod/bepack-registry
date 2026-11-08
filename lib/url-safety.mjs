import net from 'node:net';
import dns from 'node:dns';
import { RegistryError, codes } from './errors.mjs';

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];

function ipv4ToBigInt(address) {
  return address.split('.').reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

function ipv4InCidr(address, base, bits) {
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(32 - bits);
  return (ipv4ToBigInt(address) & mask) === (ipv4ToBigInt(base) & mask);
}

export function isBlockedIpv4(address) {
  return ipv4InCidr(address, '0.0.0.0', 8)
    || ipv4InCidr(address, '10.0.0.0', 8)
    || ipv4InCidr(address, '100.64.0.0', 10)
    || ipv4InCidr(address, '127.0.0.0', 8)
    || ipv4InCidr(address, '169.254.0.0', 16)
    || ipv4InCidr(address, '172.16.0.0', 12)
    || ipv4InCidr(address, '192.0.0.0', 24)
    || ipv4InCidr(address, '192.0.2.0', 24)
    || ipv4InCidr(address, '192.168.0.0', 16)
    || ipv4InCidr(address, '198.18.0.0', 15)
    || ipv4InCidr(address, '198.51.100.0', 24)
    || ipv4InCidr(address, '203.0.113.0', 24)
    || ipv4InCidr(address, '224.0.0.0', 4)
    || ipv4InCidr(address, '240.0.0.0', 4);
}

function expandIpv6(address) {
  let value = address.toLowerCase();
  const zone = value.indexOf('%');
  if (zone !== -1) value = value.slice(0, zone);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/u.exec(value);
  if (mapped) return { mapped: mapped[1] };
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) return null;
  return { groups: groups.map((group) => Number.parseInt(group, 16)) };
}

export function isBlockedIpv6(address) {
  const expanded = expandIpv6(address);
  if (!expanded) return true;
  if (expanded.mapped) return isBlockedIpv4(expanded.mapped);
  const [g0, g1, g2, g3, g4, g5, g6, g7] = expanded.groups;
  const allZero = expanded.groups.every((group) => group === 0);
  if (allZero) return true;
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) return true;
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  if (g0 === 0x2002) return true; // 6to4
  if (g0 === 0x0064 && g1 === 0xff9b) return true; // NAT64
  if ((g0 & 0xfff0) === 0x3ff0) return true; // 3fff::/20 documentation (RFC 9637)
  return false;
}

export function isBlockedAddress(address) {
  const version = net.isIP(address);
  if (version === 4) return isBlockedIpv4(address);
  if (version === 6) return isBlockedIpv6(address);
  return true;
}

export function assertPublicHttpsUrl(value, { allowFragment = false, label = 'URL' } = {}) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new RegistryError(codes.SOURCE, `${label} must be an absolute HTTPS URL`);
  }
  if (url.protocol !== 'https:') throw new RegistryError(codes.SOURCE, `${label} must use HTTPS`);
  if (url.username || url.password) throw new RegistryError(codes.SOURCE, `${label} must not contain credentials`);
  if (!allowFragment && url.hash) throw new RegistryError(codes.SOURCE, `${label} must not contain a fragment`);
  if (!url.hostname || url.hostname.length > 253) throw new RegistryError(codes.SOURCE, `${label} has an invalid host`);
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new RegistryError(codes.SSRF, `${label} points to a local host`);
  }
  if (net.isIP(host) && isBlockedAddress(host)) {
    throw new RegistryError(codes.SSRF, `${label} points to a non-public IP address`);
  }
  if (url.port && (Number(url.port) < 1 || Number(url.port) > 65535)) {
    throw new RegistryError(codes.SOURCE, `${label} has an invalid port`);
  }
  return url;
}

// Resolve every address and fail if any record is private. The connection then
// pins one validated address through the custom lookup callback, so a second
// DNS answer cannot redirect the socket to a private range.
export async function resolvePublicHost(hostname, { lookup = dns.promises.lookup } = {}) {
  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) throw new RegistryError(codes.SSRF, 'Blocked IP address');
    return [{ address: hostname, family: net.isIP(hostname) }];
  }
  let addresses;
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw new RegistryError(codes.NETWORK, `DNS resolution failed for ${hostname}`, { exitCode: 3, cause: error });
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new RegistryError(codes.NETWORK, `DNS resolution returned no address for ${hostname}`, { exitCode: 3 });
  }
  for (const record of addresses) {
    if (isBlockedAddress(record.address)) {
      throw new RegistryError(codes.SSRF, `DNS for ${hostname} includes a non-public address`);
    }
  }
  return addresses;
}

export function isSameOrigin(left, right) {
  try {
    const a = new URL(left);
    const b = new URL(right);
    return a.protocol === b.protocol && a.host === b.host;
  } catch {
    return false;
  }
}
