import { RegistryError, codes } from './errors.mjs';
import { LIMITS, POLICY } from './constants.mjs';

const VT_BASE = 'https://www.virustotal.com/api/v3';
const SEVEN_DAYS_MS = LIMITS.scanAgeMs;

function scanError(code, message, details = null) {
  return new RegistryError(code, message, { details, exitCode: 2 });
}

function requireSha256(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw scanError(codes.SCAN_FAILED, 'VirusTotal report has no valid SHA-256');
  }
  return value;
}

function integer(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw scanError(codes.SCAN_FAILED, `VirusTotal report has an invalid ${field}`);
  }
  return value;
}

function getJson(response) {
  try {
    const payload = JSON.parse(response.bytes.toString('utf8'));
    if (!payload || typeof payload !== 'object') throw new Error('not an object');
    return payload;
  } catch {
    throw scanError(codes.SCAN_FAILED, 'VirusTotal returned invalid JSON');
  }
}

function statsOf(attributes, field) {
  const stats = attributes?.[field];
  if (!stats || typeof stats !== 'object') throw scanError(codes.SCAN_FAILED, `VirusTotal report has no ${field}`);
  return {
    malicious: integer(stats.malicious, 'malicious count'),
    suspicious: integer(stats.suspicious, 'suspicious count'),
    harmless: integer(stats.harmless, 'harmless count'),
    undetected: integer(stats.undetected, 'undetected count'),
    failure: integer(stats.failure ?? 0, 'failure count'),
    type_unsupported: integer(stats['type-unsupported'] ?? 0, 'type-unsupported count'),
  };
}

function countEngines(results) {
  if (!results || typeof results !== 'object') throw scanError(codes.SCAN_FAILED, 'VirusTotal report has no per-engine results');
  let clean = 0;
  let bad = 0;
  for (const result of Object.values(results)) {
    if (!result || typeof result !== 'object') continue;
    if (result.category === 'harmless' || result.category === 'undetected') clean += 1;
    if (result.category === 'malicious' || result.category === 'suspicious') bad += 1;
  }
  return { clean, bad, total: Object.keys(results).length };
}

/**
 * Query the official VirusTotal v3 API. A 404 is a pending scan, never a clean
 * result. Evidence is derived from the file report and one completed analysis,
 * not from scan-report.json's booleans.
 */
export class VirusTotalClient {
  constructor({ downloader, apiKey, baseUrl = VT_BASE, maxBytes = 8 * 1024 * 1024, clock = () => new Date() } = {}) {
    if (!downloader) throw new TypeError('downloader is required');
    if (typeof apiKey !== 'string' || !apiKey) throw new TypeError('apiKey is required');
    this.downloader = downloader;
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
    this.maxBytes = maxBytes;
    this.clock = clock;
    this.cache = new Map();
  }

  async request(path) {
    try {
      return await this.downloader.fetchBytes(`${this.baseUrl}${path}`, {
        maxBytes: this.maxBytes,
        headers: { 'x-apikey': this.apiKey, accept: 'application/json' },
      });
    } catch (error) {
      const status = error?.details?.status;
      if (status === 404) throw scanError(codes.SCAN_PENDING, 'VirusTotal has not completed an analysis for this hash');
      if (status === 401 || status === 403) throw scanError(codes.CONFIG, 'VirusTotal rejected the API key or quota');
      throw error;
    }
  }

  async getFileReport(sha256, { analysisId = null } = {}) {
    requireSha256(sha256);
    if (typeof analysisId !== 'string' || analysisId.length === 0 || analysisId.length > 256) {
      throw scanError(codes.SCAN_FAILED, 'A VirusTotal analysis id is required for evidence');
    }
    const cacheKey = `${sha256}:${analysisId}`;
    if (this.cache.has(cacheKey)) return this.cache.get(cacheKey);

    const filePayload = getJson(await this.request(`/files/${sha256}`));
    const file = filePayload.data;
    if (!file || typeof file !== 'object' || file.type !== 'file' || file.id !== sha256) throw scanError(codes.SCAN_FAILED, 'VirusTotal file ID differs from the queried hash');
    const fileAttributes = file.attributes;
    if (!fileAttributes || typeof fileAttributes !== 'object') throw scanError(codes.SCAN_FAILED, 'VirusTotal file report has no attributes');
    if (requireSha256(fileAttributes.sha256) !== sha256) throw scanError(codes.SCAN_FAILED, 'VirusTotal report SHA-256 differs');
    const size = integer(fileAttributes.size, 'file size');
    const lastStats = statsOf(fileAttributes, 'last_analysis_stats');
    const lastEngines = countEngines(fileAttributes.last_analysis_results);

    const analysisPayload = getJson(await this.request(`/analyses/${encodeURIComponent(analysisId)}`));
    const analysis = analysisPayload.data;
    if (!analysis || typeof analysis !== 'object' || analysis.type !== 'analysis' || analysis.id !== analysisId) {
      throw scanError(codes.SCAN_FAILED, 'VirusTotal analysis response does not match the requested id');
    }
    // Official analyses-object item relationship returns the analysed File/URL.
    // Fetch it separately: a claimed relationship inside an author report is not evidence.
    const itemPayload = getJson(await this.request(`/analyses/${encodeURIComponent(analysisId)}/item`));
    const item = itemPayload.data;
    if (!item || item.type !== 'file' || item.id !== sha256
      || (item.attributes?.sha256 !== undefined && item.attributes.sha256 !== sha256)
      || (item.attributes?.size !== undefined && item.attributes.size !== size)) {
      throw scanError(codes.SCAN_FAILED, 'VirusTotal analysis item does not belong to the queried file');
    }
    const fileInfo = analysisPayload.meta?.file_info;
    if (fileInfo && (fileInfo.sha256 !== sha256 || (fileInfo.size !== undefined && fileInfo.size !== size))) {
      throw scanError(codes.SCAN_FAILED, 'VirusTotal optional meta.file_info conflicts with the queried file');
    }
    const attributes = analysis.attributes;
    if (!attributes || typeof attributes !== 'object') throw scanError(codes.SCAN_FAILED, 'VirusTotal analysis has no attributes');
    if (attributes.status !== 'completed') throw scanError(codes.SCAN_PENDING, 'VirusTotal analysis is not completed');
    const analysisStats = statsOf(attributes, 'stats');
    const analysisEngines = countEngines(attributes.results);

    const malicious = Math.max(lastStats.malicious, analysisStats.malicious);
    const suspicious = Math.max(lastStats.suspicious, analysisStats.suspicious);
    const harmless = Math.max(lastStats.harmless, analysisStats.harmless);
    const undetected = Math.max(lastStats.undetected, analysisStats.undetected);
    const badEngines = Math.max(lastEngines.bad, analysisEngines.bad);
    const cleanEngines = Math.max(lastEngines.clean, analysisEngines.clean);
    if (malicious > 0 || suspicious > 0 || badEngines > 0) {
      throw scanError(codes.SCAN_FAILED, 'VirusTotal reports malicious or suspicious detections', { malicious, suspicious, badEngines });
    }
    if (analysisStats.harmless + analysisStats.undetected < 1 || analysisEngines.clean < 1 || harmless + undetected < 1 || cleanEngines < 1) {
      throw scanError(codes.SCAN_FAILED, 'VirusTotal has no harmless or undetected engine result', { harmless, undetected, cleanEngines });
    }

    const analyzedAtSeconds = attributes.date;
    if (!Number.isSafeInteger(analyzedAtSeconds) || analyzedAtSeconds <= 0) throw scanError(codes.SCAN_FAILED, 'VirusTotal analysis has no timestamp');
    const analyzedAt = new Date(analyzedAtSeconds * 1000);
    const now = this.clock();
    if (analyzedAt.getTime() > now.getTime() + 5 * 60 * 1000) throw scanError(codes.SCAN_FAILED, 'VirusTotal analysis timestamp is in the future');
    if (now.getTime() - analyzedAt.getTime() > SEVEN_DAYS_MS) throw scanError(codes.SCAN_PENDING, 'VirusTotal analysis is older than seven days');

    const report = {
      sha256,
      size,
      malicious,
      suspicious,
      harmless,
      undetected,
      failure: Math.max(lastStats.failure, analysisStats.failure),
      type_unsupported: Math.max(lastStats.type_unsupported, analysisStats.type_unsupported),
      analyzed_at: analyzedAt.toISOString(),
      analysis_id: String(analysis.id),
      policy: POLICY,
      engines: { clean: cleanEngines, bad: badEngines, total: Math.max(lastEngines.total, analysisEngines.total) },
    };
    this.cache.set(cacheKey, report);
    return report;
  }
}

export function scanEvidence(report) {
  return {
    sha256: report.sha256,
    analysis_id: report.analysis_id,
    analyzed_at: report.analyzed_at,
    malicious: report.malicious,
    suspicious: report.suspicious,
  };
}
