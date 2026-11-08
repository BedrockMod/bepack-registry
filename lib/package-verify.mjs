import { parseStrictJSON } from './strict-json.mjs';
import { inspectZip, verifyAllEntries, closeZip, readEntry } from './zip.mjs';
import { RegistryError, codes } from './errors.mjs';
import { LIMITS, PACKAGE_SCHEMA_VERSION, SEMVER_PATTERN } from './constants.mjs';
import { safeId, safePackId, safeRelative, sha256Hex, checkCollision } from './paths.mjs';
import { versionSatisfies, parseSemver } from './semver.mjs';
import {
  Issues, exactKeys, isObject, isInteger, isNonEmptyString, escapePointer, checkHttps,
  checkStringArray, checkPackId, checkId, checkSemver, checkGameVersion, checkSha256,
  checkTimestamp, checkLicense, versionRequirement,
} from './validate-common.mjs';

const MODES = ['full', 'modded', 'client', 'mods-only'];
const CATEGORIES = ['resource-pack', 'behavior-pack', 'world', 'config', 'll-plugin', 'native-mod', 'client-component'];
const EXECUTABLE_CATEGORIES = new Set(['ll-plugin', 'native-mod', 'client-component']);
const ROLES = ['content', 'mod', 'client'];
const SLOTS = ['resource-packs', 'behavior-packs', 'worlds', 'configs', 'plugins', 'native-mods', 'client-components'];
const PLATFORMS = ['windows-x86_64', 'windows-aarch64', 'android-arm64', 'linux-x86_64'];
const RUNTIMES = ['bedrock-client', 'bedrock-server', 'external-client'];
const BUILTIN_GROUPS = ['windows', 'android', 'linux', 'bds'];

function packageError(message, issues) {
  return new RegistryError(codes.RELEASE, message, {
    details: { issues: issues.slice(0, 40) },
  });
}

function sortedPaths(values) {
  return [...values].sort((left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')));
}

function pathUnder(filePath, directory) {
  return filePath === directory || filePath.startsWith(`${directory}/`);
}

function contentFileSet(files, contentPath) {
  if (files.has(contentPath)) return [contentPath];
  const prefix = `${contentPath}/`;
  return [...files.keys()].filter((name) => name.startsWith(prefix));
}

function validateMounts(mounts, field, issues) {
  if (!Array.isArray(mounts)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'Expected mounts array', field);
    return;
  }
  const destinations = new Set();
  for (const [index, mount] of mounts.entries()) {
    const at = `${field}/${index}`;
    if (!exactKeys(mount, ['source', 'slot', 'destination'], ['source', 'slot', 'destination'], at, issues)) continue;
    if (mount.source !== '.' && !safeRelative(mount.source, { dot: true })) {
      issues.add('BEPACK_PATH_UNSAFE', 'Unsafe mount source', `${at}/source`);
    }
    if (!SLOTS.includes(mount.slot)) issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'Unknown install slot', `${at}/slot`);
    if (!safeRelative(mount.destination)) issues.add('BEPACK_PATH_UNSAFE', 'Unsafe mount destination', `${at}/destination`);
    const key = `${mount.slot}\u0000${mount.destination}`;
    if (destinations.has(key)) issues.add('BEPACK_DESTINATION_CONFLICT', 'Duplicate mount destination', at);
    destinations.add(key);
  }
}

function validateCompatibilityEntry(entry, field, targetIds, issues) {
  if (!exactKeys(entry, ['games', 'loader', 'client', 'evidence'], ['games', 'loader', 'client', 'evidence'], field, issues)) return;
  const games = entry.games;
  if (!isObject(games)) {
    issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'games must be an object', `${field}/games`);
  } else {
    const hasVersions = Object.hasOwn(games, 'versions');
    const hasUnconstrained = Object.hasOwn(games, 'unconstrained');
    if (hasVersions === hasUnconstrained) {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'games requires exactly one of versions or unconstrained', `${field}/games`);
    } else if (hasVersions) {
      if (!Array.isArray(games.versions) || games.versions.length === 0) {
        issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'games.versions must be non-empty', `${field}/games/versions`);
      } else {
        for (const [index, version] of games.versions.entries()) {
          checkGameVersion(version, `${field}/games/versions/${index}`, issues);
        }
        if (new Set(games.versions).size !== games.versions.length) {
          issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Duplicate game versions', `${field}/games/versions`);
        }
      }
    } else if (games.unconstrained !== true) {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'unconstrained must be true', `${field}/games/unconstrained`);
    }
  }
  if (entry.loader !== null) {
    if (!exactKeys(entry.loader, ['type', 'version'], ['type', 'version'], `${field}/loader`, issues)) {
      // continue
    } else {
      if (typeof entry.loader.type !== 'string' || !entry.loader.type) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid loader type', `${field}/loader/type`);
      versionRequirement(entry.loader.version, `${field}/loader/version`, issues);
    }
  }
  if (entry.client !== null) {
    if (exactKeys(entry.client, ['id', 'version'], ['id', 'version'], `${field}/client`, issues)) {
      checkId(entry.client.id, `${field}/client/id`, issues);
      versionRequirement(entry.client.version, `${field}/client/version`, issues);
    }
  }
  if (exactKeys(entry.evidence, ['kind', 'reference'], ['kind', 'reference'], `${field}/evidence`, issues)) {
    if (!['upstream', 'manifest', 'author'].includes(entry.evidence.kind)) {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Invalid evidence kind', `${field}/evidence/kind`);
    }
    if (typeof entry.evidence.reference !== 'string') {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Evidence reference must be a string', `${field}/evidence/reference`);
    } else if (/^https:/iu.test(entry.evidence.reference)) {
      checkHttps(entry.evidence.reference, `${field}/evidence/reference`, issues, { fragment: true });
    } else if (!safeRelative(entry.evidence.reference)) {
      issues.add('BEPACK_PATH_UNSAFE', 'Evidence reference must be HTTPS or a safe package path', `${field}/evidence/reference`);
    }
  }
  if (targetIds && targetIds.length) {
    // The caller checks that all applicable targets are covered.
  }
}

function validateCompatibility(value, ownerTargets, field, issues, targetIds) {
  if (!isObject(value) || !isObject(value.targets)) {
    issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'compatibility.targets must be an object', `${field}/targets`);
    return;
  }
  for (const key of Object.keys(value)) {
    if (!['targets', 'extensions'].includes(key)) issues.add('BEPACK_MANIFEST_INVALID', `Unknown compatibility field ${key}`, field);
  }
  const keys = Object.keys(value.targets);
  if (new Set(keys).size !== keys.length) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Duplicate compatibility targets', `${field}/targets`);
  for (const target of keys) {
    if (!targetIds.has(target)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility references an unknown target', `${field}/targets/${escapePointer(target)}`);
    if (!ownerTargets.includes(target)) {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility target is outside the subject target set', `${field}/targets/${escapePointer(target)}`);
    }
    validateCompatibilityEntry(value.targets[target], `${field}/targets/${escapePointer(target)}`, null, issues);
  }
  for (const target of ownerTargets) {
    if (!Object.hasOwn(value.targets, target)) {
      issues.add('BEPACK_COMPATIBILITY_UNKNOWN', `Missing compatibility for target ${target}`, `${field}/targets/${escapePointer(target)}`);
    }
  }
}

function validateManifest(manifest, issues) {
  const context = {
    targets: new Map(),
    enabled: new Set(),
    dependencies: new Map(),
    contents: new Map(),
    licenseFiles: new Set(),
    requires: [],
  };
  if (!exactKeys(manifest, [
    'schema_version', 'id', 'name', 'author', 'description', 'version', 'license', 'license_file',
    'mode', 'game_version', 'version_set', 'targets', 'dependencies', 'contents', 'repository',
    'launcher', 'requires',
  ], ['schema_version', 'id', 'name', 'author', 'description', 'version', 'license', 'mode', 'game_version', 'version_set', 'targets', 'dependencies', 'contents'], 'bepack.json', issues)) {
    return context;
  }
  if (manifest.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'bepack.json', '/schema_version');
  checkPackId(manifest.id, '/id', issues);
  if (typeof manifest.name !== 'string' || !manifest.name.trim() || manifest.name.trim().length > 128) {
    issues.add('BEPACK_MANIFEST_INVALID', 'name must be non-empty after trimming and at most 128 characters', 'bepack.json', '/name');
  }
  if (exactKeys(manifest.author, ['name', 'url', 'email'], ['name'], '/author', issues)) {
    if (!isNonEmptyString(manifest.author.name)) issues.add('BEPACK_MANIFEST_INVALID', 'author.name is required', 'bepack.json', '/author/name');
    if (manifest.author.url !== undefined) checkHttps(manifest.author.url, '/author/url', issues);
    if (manifest.author.email !== undefined && typeof manifest.author.email !== 'string') issues.add('BEPACK_MANIFEST_INVALID', 'author.email must be a string', 'bepack.json', '/author/email');
  }
  if (typeof manifest.description !== 'string' || manifest.description.length > 10000) {
    issues.add('BEPACK_MANIFEST_INVALID', 'description must be a string of at most 10000 characters', 'bepack.json', '/description');
  }
  checkSemver(manifest.version, '/version', issues);
  checkLicense(manifest.license, '/license', issues, { licenseFile: manifest.license_file });
  if (manifest.license_file !== undefined) {
    if (!safeRelative(manifest.license_file, { prefix: 'licenses' })) issues.add('BEPACK_PATH_UNSAFE', 'license_file must be under licenses/', 'bepack.json', '/license_file');
    else context.licenseFiles.add(manifest.license_file);
  }
  if (!MODES.includes(manifest.mode)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid mode', 'bepack.json', '/mode');
  checkGameVersion(manifest.game_version, '/game_version', issues, { nullable: true });
  checkId(manifest.version_set, '/version_set', issues);
  if (manifest.repository !== undefined) checkHttps(manifest.repository, '/repository', issues, { fragment: true });
  if (manifest.launcher !== undefined) {
    if (exactKeys(manifest.launcher, ['min'], ['min'], '/launcher', issues)) {
      checkSemver(manifest.launcher.min, '/launcher/min', issues, 'BEPACK_MANIFEST_INVALID', { allowPrerelease: false });
    }
  }
  if (manifest.requires !== undefined) {
    checkStringArray(manifest.requires, '/requires', issues);
    context.requires = manifest.requires;
  }

  const groups = isObject(manifest.targets) ? manifest.targets : null;
  if (!groups) {
    issues.add('BEPACK_MANIFEST_INVALID', 'targets must be an object', 'bepack.json', '/targets');
  } else {
    let enabledGroups = 0;
    for (const group of Object.keys(groups)) {
      if (!BUILTIN_GROUPS.includes(group) && !group.startsWith('x-')) {
        issues.add('BEPACK_MANIFEST_INVALID', `Unknown target collection ${group}`, 'bepack.json', `/targets/${escapePointer(group)}`);
      }
      const collection = groups[group];
      if (!exactKeys(collection, ['enabled', 'variants'], ['enabled', 'variants'], `/targets/${escapePointer(group)}`, issues)) continue;
      if (typeof collection.enabled !== 'boolean') issues.add('BEPACK_MANIFEST_INVALID', 'enabled must be boolean', 'bepack.json', `/targets/${escapePointer(group)}/enabled`);
      if (collection.enabled) enabledGroups++;
      if (!isObject(collection.variants) || Object.keys(collection.variants).length === 0) {
        issues.add('BEPACK_MANIFEST_INVALID', 'variants must be a non-empty object', 'bepack.json', `/targets/${escapePointer(group)}/variants`);
        continue;
      }
      const pairs = new Set();
      for (const [targetId, variant] of Object.entries(collection.variants)) {
        const field = `/targets/${escapePointer(group)}/variants/${escapePointer(targetId)}`;
        checkId(targetId, field, issues);
        if (!exactKeys(variant, ['platform', 'runtime', 'game_version', 'loader', 'client', 'requires'], ['platform', 'runtime', 'game_version', 'loader', 'client'], field, issues)) continue;
        if (!PLATFORMS.includes(variant.platform) && !String(variant.platform).startsWith('x-')) issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'Unknown platform', `bepack.json${field}/platform`);
        if (!RUNTIMES.includes(variant.runtime) && !String(variant.runtime).startsWith('x-')) issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'Unknown runtime', `bepack.json${field}/runtime`);
        checkGameVersion(variant.game_version, `${field}/game_version`, issues, { nullable: true });
        const pair = `${variant.platform}/${variant.runtime}`;
        if (pairs.has(pair)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate platform/runtime in collection', `bepack.json${field}`);
        pairs.add(pair);
        if (context.targets.has(targetId)) issues.add('BEPACK_MANIFEST_INVALID', 'Target IDs must be globally unique', `bepack.json${field}`);
        if (variant.requires !== undefined) checkStringArray(variant.requires, `${field}/requires`, issues);
        if (group === 'windows' && (!String(variant.platform).startsWith('windows') || variant.runtime !== 'bedrock-client')) issues.add('BEPACK_MANIFEST_INVALID', 'windows targets require a Windows bedrock-client variant', `bepack.json${field}`);
        if (group === 'android' && (variant.platform !== 'android-arm64' || variant.runtime !== 'bedrock-client')) issues.add('BEPACK_MANIFEST_INVALID', 'android targets require Android bedrock-client', `bepack.json${field}`);
        if (group === 'linux' && (variant.platform !== 'linux-x86_64' || variant.runtime !== 'external-client')) issues.add('BEPACK_MANIFEST_INVALID', 'linux targets require external-client', `bepack.json${field}`);
        if (group === 'bds' && (variant.runtime !== 'bedrock-server' || !['windows-x86_64', 'linux-x86_64'].includes(variant.platform))) issues.add('BEPACK_MANIFEST_INVALID', 'bds targets require a Windows or Linux bedrock-server variant', `bepack.json${field}`);
        if (variant.loader === null || !exactKeys(variant.loader, ['type', 'version'], ['type', 'version'], `${field}/loader`, issues)) {
          issues.add('BEPACK_MANIFEST_INVALID', 'loader is required', `bepack.json${field}/loader`);
        } else if (variant.loader.type === 'none') {
          if (variant.loader.version !== null) issues.add('BEPACK_MANIFEST_INVALID', 'loader none requires version null', `bepack.json${field}/loader/version`);
        } else if (variant.loader.type === 'levilamina' || String(variant.loader.type).startsWith('x-')) {
          versionRequirement(variant.loader.version, `${field}/loader/version`, issues);
        } else {
          issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'Unknown loader type', `bepack.json${field}/loader/type`);
        }
        if (variant.client !== null) {
          if (exactKeys(variant.client, ['id', 'dependency', 'version'], ['id', 'dependency', 'version'], `${field}/client`, issues)) {
            checkId(variant.client.id, `${field}/client/id`, issues);
            checkId(variant.client.dependency, `${field}/client/dependency`, issues);
            versionRequirement(variant.client.version, `${field}/client/version`, issues);
          }
        }
        if (variant.runtime === 'external-client' && variant.client === null) {
          issues.add('BEPACK_MANIFEST_INVALID', 'external-client requires a client declaration', `bepack.json${field}/client`);
        }
        context.targets.set(targetId, { ...variant, group, requires: variant.requires ?? [] });
        if (collection.enabled) context.enabled.add(targetId);
      }
    }
    if (enabledGroups === 0) issues.add('BEPACK_TARGET_UNAVAILABLE', 'At least one target collection must be enabled', 'bepack.json', '/targets');
  }

  const combination = manifest;
  const combinationDependencies = combination.dependencies;
  if (!Array.isArray(combinationDependencies)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'dependencies must be an array', 'bepack.json', '/dependencies');
  } else {
    for (const [index, dependency] of combinationDependencies.entries()) {
      const field = `/dependencies/${index}`;
      if (!exactKeys(dependency, ['id', 'source', 'resolver', 'version', 'license', 'license_file', 'license_url', 'redistribution_confirmed', 'bundled', 'targets', 'role', 'compatibility', 'direct'], ['id', 'source', 'resolver', 'version', 'license', 'bundled', 'targets', 'role'], field, issues)) continue;
      checkId(dependency.id, `${field}/id`, issues);
      if (context.dependencies.has(dependency.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate dependency ID', `bepack.json${field}/id`);
      if (typeof dependency.source !== 'string' || !checkHttps(dependency.source, `${field}/source`, issues)) {
        // already reported
      }
      if (!['bepack-metadata', 'direct'].includes(dependency.resolver) && !String(dependency.resolver).startsWith('x-')) issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Unknown resolver', `bepack.json${field}/resolver`);
      versionRequirement(dependency.version, `${field}/version`, issues);
      checkLicense(dependency.license, `${field}/license`, issues, { licenseFile: dependency.license_file });
      if (dependency.license_file !== undefined) {
        if (!safeRelative(dependency.license_file, { prefix: 'licenses' })) issues.add('BEPACK_PATH_UNSAFE', 'license_file must be under licenses/', `bepack.json${field}/license_file`);
        else context.licenseFiles.add(dependency.license_file);
      }
      if (dependency.license_url !== undefined) checkHttps(dependency.license_url, `${field}/license_url`, issues, { fragment: true });
      if (typeof dependency.bundled !== 'boolean') issues.add('BEPACK_MANIFEST_INVALID', 'bundled must be boolean', `bepack.json${field}/bundled`);
      if (dependency.bundled === true && dependency.redistribution_confirmed !== true) issues.add('BEPACK_LICENSE_INVALID', 'Bundled dependency requires redistribution_confirmed=true', `bepack.json${field}/redistribution_confirmed`);
      if (!Array.isArray(dependency.targets) || dependency.targets.length === 0 || dependency.targets.some((target) => !context.targets.has(target))) {
        issues.add('BEPACK_MANIFEST_INVALID', 'dependency targets must reference known targets', `bepack.json${field}/targets`);
      } else if (new Set(dependency.targets).size !== dependency.targets.length) {
        issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate dependency targets', `bepack.json${field}/targets`);
      }
      if (!ROLES.includes(dependency.role)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid dependency role', `bepack.json${field}/role`);
      if (manifest.mode === 'full' && ['mod', 'client'].includes(dependency.role)) issues.add('BEPACK_MANIFEST_INVALID', 'full mode forbids mod/client dependencies', `bepack.json${field}/role`);
      if (dependency.resolver === 'direct') {
        if (exactKeys(dependency.direct, ['size', 'sha256', 'format', 'mounts'], ['size', 'sha256', 'format', 'mounts'], `${field}/direct`, issues)) {
          if (!isInteger(dependency.direct.size)) issues.add('BEPACK_MANIFEST_INVALID', 'direct.size must be a non-negative integer', `bepack.json${field}/direct/size`);
          checkSha256(dependency.direct.sha256, `${field}/direct/sha256`, issues);
          if (!['file', 'zip-tree'].includes(dependency.direct.format)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid direct format', `bepack.json${field}/direct/format`);
          validateMounts(dependency.direct.mounts, `${field}/direct/mounts`, issues);
          if (dependency.direct.format === 'file' && Array.isArray(dependency.direct.mounts) && dependency.direct.mounts.some((mount) => mount.source !== '.')) {
            issues.add('BEPACK_MANIFEST_INVALID', 'file format requires mount source "."', `bepack.json${field}/direct/mounts`);
          }
        }
      } else if (dependency.direct !== undefined) {
        issues.add('BEPACK_MANIFEST_INVALID', 'direct is only allowed for resolver=direct', `bepack.json${field}/direct`);
      }
      if (dependency.compatibility !== undefined) validateCompatibility(dependency.compatibility, dependency.targets ?? [], `${field}/compatibility`, issues, new Set(context.targets.keys()));
      context.dependencies.set(dependency.id, dependency);
    }
  }

  if (!Array.isArray(manifest.contents)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'contents must be an array', 'bepack.json', '/contents');
  } else {
    for (const [index, content] of manifest.contents.entries()) {
      const field = `/contents/${index}`;
      if (!exactKeys(content, ['id', 'category', 'path', 'targets', 'source', 'dependency', 'destination', 'compatibility', 'replaces'], ['id', 'category', 'path', 'targets', 'source', 'destination'], field, issues)) continue;
      checkId(content.id, `${field}/id`, issues);
      if (context.contents.has(content.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate content ID', `bepack.json${field}/id`);
      if (!CATEGORIES.includes(content.category)) issues.add('BEPACK_CONTENT_INVALID', 'Invalid content category', `bepack.json${field}/category`);
      if (!safeRelative(content.path, { prefix: 'payload' })) issues.add('BEPACK_PATH_UNSAFE', 'content.path must be under payload/', `bepack.json${field}/path`);
      if (!safeRelative(content.destination)) issues.add('BEPACK_PATH_UNSAFE', 'Unsafe content destination', `bepack.json${field}/destination`);
      if (!Array.isArray(content.targets) || content.targets.length === 0 || content.targets.some((target) => !context.targets.has(target))) {
        issues.add('BEPACK_MANIFEST_INVALID', 'content targets must reference known targets', `bepack.json${field}/targets`);
      } else if (new Set(content.targets).size !== content.targets.length) {
        issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate content targets', `bepack.json${field}/targets`);
      }
      if (!['local', 'instance', 'dependency'].includes(content.source)) issues.add('BEPACK_CONTENT_INVALID', 'Invalid content source', `bepack.json${field}/source`);
      if (content.source === 'dependency') {
        const dependency = context.dependencies.get(content.dependency);
        if (!dependency?.bundled) issues.add('BEPACK_MANIFEST_INVALID', 'Dependency content must reference a bundled dependency', `bepack.json${field}/dependency`);
        else if (Array.isArray(content.targets) && content.targets.some((target) => !dependency.targets.includes(target))) issues.add('BEPACK_MANIFEST_INVALID', 'Dependency content targets must be covered by the dependency', `bepack.json${field}/targets`);
      } else if (content.dependency !== undefined) {
        issues.add('BEPACK_MANIFEST_INVALID', 'dependency is only allowed for source=dependency', `bepack.json${field}/dependency`);
      }
      if (content.category === 'config') {
        // A config must be a single file; this is checked against the ZIP.
      }
      if (content.compatibility !== undefined) validateCompatibility(content.compatibility, content.targets ?? [], `${field}/compatibility`, issues, new Set(context.targets.keys()));
      context.contents.set(content.id, content);
    }
    for (const content of context.contents.values()) {
      if (content.replaces === undefined) continue;
      const shared = context.contents.get(content.replaces);
      if (!shared || shared.replaces !== undefined || shared.id === content.id) {
        issues.add('BEPACK_CONTENT_INVALID', 'replaces must reference a non-replacing content', `bepack.json/contents/${escapePointer(content.id)}/replaces`);
        continue;
      }
      if (shared.category !== content.category || shared.destination !== content.destination) {
        issues.add('BEPACK_CONTENT_INVALID', 'Replacement must share category and destination', `bepack.json/contents/${escapePointer(content.id)}/replaces`);
      }
      if (shared.targets.length <= content.targets.length || content.targets.some((target) => !shared.targets.includes(target))) {
        issues.add('BEPACK_CONTENT_INVALID', 'Replacement must be more specific than the shared content', `bepack.json/contents/${escapePointer(content.id)}/replaces`);
      }
    }
  }

  // Mode semantics against the effective merged target set are checked after
  // the version-set merge.
  return context;
}

function mergeCombination(manifest, context, issues) {
  const combination = isObject(context.versionSet) ? context.versionSet : null;
  if (!combination) return new Map();
  const effective = new Map();
  if (!exactKeys(combination, ['schema_version', 'id', 'dependencies', 'targets'], ['schema_version', 'id', 'dependencies', 'targets'], 'versions/active.json', issues)) return effective;
  if (combination.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'versions/active.json', '/schema_version');
  if (combination.id !== manifest.version_set) issues.add('BEPACK_VERSION_SET_INVALID', 'Combination ID must equal version_set', 'versions/active.json', '/id');
  if (!isObject(combination.dependencies)) issues.add('BEPACK_VERSION_SET_INVALID', 'dependencies must be an object', 'versions/active.json', '/dependencies');
  if (!isObject(combination.targets)) issues.add('BEPACK_VERSION_SET_INVALID', 'targets must be an object', 'versions/active.json', '/targets');
  for (const target of context.targets.keys()) {
    const base = context.targets.get(target);
    const override = combination.targets?.[target] ?? {};
    if (!isObject(override)) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Target override must be an object', `versions/active.json/targets/${escapePointer(target)}`);
      continue;
    }
    for (const key of Object.keys(override)) {
      if (!['game_version', 'loader', 'client'].includes(key)) issues.add('BEPACK_VERSION_SET_INVALID', `Unknown target override ${key}`, `versions/active.json/targets/${escapePointer(target)}`);
    }
    if (override.game_version !== undefined) {
      checkGameVersion(override.game_version, `/targets/${escapePointer(target)}/game_version`, issues, { code: 'BEPACK_VERSION_SET_INVALID' });
      if (manifest.mode === 'mods-only') issues.add('BEPACK_VERSION_SET_INVALID', 'mods-only must not bind a game version', `versions/active.json/targets/${escapePointer(target)}/game_version`);
    }
    const loader = override.loader ?? base.loader;
    const client = override.client ?? base.client;
    const gameVersion = override.game_version ?? base.game_version ?? manifest.game_version;
    const variant = { ...base, loader, client, game_version: gameVersion };
    effective.set(target, variant);
    if (manifest.mode === 'full' && (loader.type !== 'none' || client !== null)) issues.add('BEPACK_MANIFEST_INVALID', 'full mode requires loader none and client null', `versions/active.json/targets/${escapePointer(target)}`);
    if (manifest.mode === 'modded' && (loader.type !== 'levilamina' || client !== null)) issues.add('BEPACK_MANIFEST_INVALID', 'modded mode requires levilamina and client null', `versions/active.json/targets/${escapePointer(target)}`);
    if (manifest.mode === 'client' && client === null) issues.add('BEPACK_MANIFEST_INVALID', 'client mode requires a client declaration', `versions/active.json/targets/${escapePointer(target)}`);
    if (manifest.mode === 'mods-only' && gameVersion !== null) issues.add('BEPACK_MANIFEST_INVALID', 'mods-only must not bind a game version', `versions/active.json/targets/${escapePointer(target)}`);
    if (manifest.mode !== 'mods-only' && gameVersion === null) issues.add('BEPACK_MANIFEST_INVALID', 'Bound modes require a concrete game_version', `versions/active.json/targets/${escapePointer(target)}`);
    if (client !== null) {
      const dependency = context.dependencies.get(client.dependency);
      if (!dependency || dependency.role !== 'client' || !dependency.targets.includes(target)) {
        issues.add('BEPACK_MANIFEST_INVALID', 'client dependency must be role=client and cover the target', `versions/active.json/targets/${escapePointer(target)}/client`);
      }
      const selected = combination.dependencies?.[client.dependency];
      if (!selected || !versionSatisfies(selected, client.version)) {
        issues.add('BEPACK_VERSION_SET_INVALID', 'client dependency requires an exact satisfying selection', `versions/active.json/targets/${escapePointer(target)}/client`);
      }
    }
  }
  for (const [dependencyId, selected] of Object.entries(combination.dependencies ?? {})) {
    const dependency = context.dependencies.get(dependencyId);
    if (!dependency) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Combination references an unknown dependency', `versions/active.json/dependencies/${escapePointer(dependencyId)}`);
      continue;
    }
    if (typeof selected !== 'string' || !SEMVER_PATTERN.test(selected)) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Combination selections must be exact SemVer strings', `versions/active.json/dependencies/${escapePointer(dependencyId)}`);
      continue;
    }
    if (!versionSatisfies(selected, dependency.version)) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Selected version does not satisfy the dependency requirement', `versions/active.json/dependencies/${escapePointer(dependencyId)}`);
    }
  }
  for (const [dependencyId, dependency] of context.dependencies) {
    if (dependency.targets.some((target) => context.enabled.has(target)) && !Object.hasOwn(combination.dependencies ?? {}, dependencyId)) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Missing exact selection for an applicable dependency', `versions/active.json/dependencies/${escapePointer(dependencyId)}`);
    }
  }
  return effective;
}

function applicableContents(context, target) {
  const all = [...context.contents.values()].filter((content) => content.targets.includes(target));
  const replaced = new Set(all.filter((content) => content.replaces !== undefined).map((content) => content.replaces));
  return all.filter((content) => !replaced.has(content.id));
}

function validateLock(manifest, context, effective, lock, files, issues) {
  if (!exactKeys(lock, [
    'schema_version', 'pack', 'generated_at', 'files', 'artifacts', 'configurations',
    'evidence', 'compatibility', 'runtimes', 'tested',
  ], ['schema_version', 'pack', 'generated_at', 'files', 'artifacts', 'configurations', 'evidence', 'compatibility', 'runtimes'], 'bepack.lock.json', issues)) return;
  if (lock.schema_version !== 1) issues.add('BEPACK_SCHEMA_UNSUPPORTED', 'Only schema_version 1 is supported', 'bepack.lock.json', '/schema_version');
  if (exactKeys(lock.pack, ['id', 'version', 'version_set'], ['id', 'version', 'version_set'], '/pack', issues)) {
    if (lock.pack.id !== manifest.id) issues.add('BEPACK_VERSION_SET_INVALID', 'lock.pack.id differs from manifest', 'bepack.lock.json', '/pack/id');
    if (lock.pack.version !== manifest.version) issues.add('BEPACK_VERSION_SET_INVALID', 'lock.pack.version differs from manifest', 'bepack.lock.json', '/pack/version');
    if (lock.pack.version_set !== manifest.version_set) issues.add('BEPACK_VERSION_SET_INVALID', 'lock.pack.version_set differs from manifest', 'bepack.lock.json', '/pack/version_set');
  }
  checkTimestamp(lock.generated_at, '/generated_at', issues);
  if (!Array.isArray(lock.files)) {
    issues.add('BEPACK_MANIFEST_INVALID', 'lock.files must be an array', 'bepack.lock.json', '/files');
    return;
  }
  const actual = new Map();
  for (const [name, entry] of files) {
    if (!entry.directory && name !== 'bepack.lock.json') actual.set(name, entry);
  }
  const declared = new Map();
  let previous = null;
  for (const [index, entry] of lock.files.entries()) {
    const field = `/files/${index}`;
    if (!exactKeys(entry, ['path', 'size', 'sha256'], ['path', 'size', 'sha256'], field, issues)) continue;
    if (!safeRelative(entry.path)) {
      issues.add('BEPACK_PATH_UNSAFE', 'Unsafe locked path', `bepack.lock.json${field}/path`);
      continue;
    }
    if (previous !== null && Buffer.compare(Buffer.from(previous, 'utf8'), Buffer.from(entry.path, 'utf8')) >= 0) {
      issues.add('BEPACK_MANIFEST_INVALID', 'lock.files must be sorted and unique by path bytes', `bepack.lock.json${field}/path`);
    }
    previous = entry.path;
    if (declared.has(entry.path)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate locked path', `bepack.lock.json${field}/path`);
    declared.set(entry.path, entry);
    if (entry.path === 'bepack.lock.json') issues.add('BEPACK_MANIFEST_INVALID', 'The lock must not list itself', `bepack.lock.json${field}/path`);
    const real = actual.get(entry.path);
    if (!real) {
      issues.add('BEPACK_FILE_MISSING', 'Locked file is absent from the package', `bepack.lock.json${field}/path`, { path: entry.path });
      continue;
    }
    if (entry.size !== real.size) issues.add('BEPACK_HASH_MISMATCH', 'Locked size differs from package entry', `bepack.lock.json${field}/size`, { path: entry.path });
    if (entry.sha256 !== real.sha256) issues.add('BEPACK_HASH_MISMATCH', 'Locked SHA-256 differs from package entry', `bepack.lock.json${field}/sha256`, { path: entry.path });
  }
  for (const name of actual.keys()) {
    if (!declared.has(name)) issues.add('BEPACK_FILE_UNDECLARED', 'Package file is not listed in the lock', 'bepack.lock.json', '/files', { path: name });
  }

  const artifacts = new Map();
  if (!Array.isArray(lock.artifacts)) issues.add('BEPACK_MANIFEST_INVALID', 'artifacts must be an array', 'bepack.lock.json', '/artifacts');
  else for (const [index, artifact] of lock.artifacts.entries()) {
    const field = `/artifacts/${index}`;
    if (!exactKeys(artifact, ['id', 'dependency', 'version', 'format', 'size', 'sha256', 'url', 'path', 'mounts'], ['id', 'dependency', 'version', 'format', 'size', 'sha256', 'mounts'], field, issues)) continue;
    checkId(artifact.id, `${field}/id`, issues);
    if (artifacts.has(artifact.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate artifact ID', `bepack.lock.json${field}/id`);
    const dependency = context.dependencies.get(artifact.dependency);
    if (!dependency) issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Artifact references an unknown dependency', `bepack.lock.json${field}/dependency`);
    if (typeof artifact.version !== 'string' || !SEMVER_PATTERN.test(artifact.version)) issues.add('BEPACK_MANIFEST_INVALID', 'Artifact version must be exact SemVer', `bepack.lock.json${field}/version`);
    if (!['file', 'zip-tree'].includes(artifact.format)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid artifact format', `bepack.lock.json${field}/format`);
    if (!isInteger(artifact.size)) issues.add('BEPACK_MANIFEST_INVALID', 'Artifact size must be a non-negative integer', `bepack.lock.json${field}/size`);
    checkSha256(artifact.sha256, `${field}/sha256`, issues);
    validateMounts(artifact.mounts, `${field}/mounts`, issues);
    if (artifact.format === 'file' && Array.isArray(artifact.mounts) && artifact.mounts.some((mount) => mount.source !== '.')) {
      issues.add('BEPACK_MANIFEST_INVALID', 'file artifacts require mount source "."', `bepack.lock.json${field}/mounts`);
    }
    const hasUrl = artifact.url !== undefined;
    const hasPath = artifact.path !== undefined;
    if (hasUrl === hasPath) issues.add('BEPACK_MANIFEST_INVALID', 'Artifact requires exactly one of url or path', `bepack.lock.json${field}`);
    if (dependency) {
      if (artifact.version !== undefined && dependency.version && !versionSatisfies(artifact.version, dependency.version)) issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Artifact version does not satisfy dependency', `bepack.lock.json${field}/version`);
      if (dependency.bundled && !hasPath) issues.add('BEPACK_MANIFEST_INVALID', 'Bundled dependency artifact requires path', `bepack.lock.json${field}/path`);
      if (!dependency.bundled && !hasUrl) issues.add('BEPACK_MANIFEST_INVALID', 'Unbundled dependency artifact requires url', `bepack.lock.json${field}/url`);
    }
    if (hasPath) {
      if (!safeRelative(artifact.path, { prefix: 'payload' })) issues.add('BEPACK_PATH_UNSAFE', 'Bundled artifact path must be under payload/', `bepack.lock.json${field}/path`);
      const real = actual.get(artifact.path);
      if (!real) issues.add('BEPACK_FILE_MISSING', 'Bundled artifact path is absent', `bepack.lock.json${field}/path`);
      else {
        if (artifact.size !== real.size) issues.add('BEPACK_HASH_MISMATCH', 'Bundled artifact size mismatch', `bepack.lock.json${field}/size`);
        if (artifact.sha256 !== real.sha256) issues.add('BEPACK_HASH_MISMATCH', 'Bundled artifact hash mismatch', `bepack.lock.json${field}/sha256`);
      }
    }
    if (hasUrl) {
      checkHttps(artifact.url, `${field}/url`, issues);
      if (artifact.url.includes('#')) issues.add('BEPACK_MANIFEST_INVALID', 'Artifact URL must not have a fragment', `bepack.lock.json${field}/url`);
    }
    artifacts.set(artifact.id, artifact);
  }

  const configurations = new Map();
  const usedArtifacts = new Set();
  const usedDependencies = new Set();
  const usedContents = new Set();
  const usedCompatibility = new Set();
  const boundGames = new Set();
  if (!Array.isArray(lock.configurations) || lock.configurations.length === 0) {
    issues.add('BEPACK_VERSION_SET_INVALID', 'configurations must be a non-empty array', 'bepack.lock.json', '/configurations');
  } else for (const [index, configuration] of lock.configurations.entries()) {
    const field = `/configurations/${index}`;
    if (!exactKeys(configuration, ['id', 'target', 'game_version', 'loader', 'client', 'dependencies', 'contents', 'runtimes'], ['id', 'target', 'game_version', 'loader', 'client', 'dependencies', 'contents', 'runtimes'], field, issues)) continue;
    checkId(configuration.id, `${field}/id`, issues);
    if (configurations.has(configuration.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate configuration ID', `bepack.lock.json${field}/id`);
    configurations.set(configuration.id, configuration);
    const variant = context.targets.get(configuration.target);
    if (!variant || !context.enabled.has(configuration.target)) {
      issues.add('BEPACK_TARGET_UNAVAILABLE', 'Configuration target is unknown or disabled', `bepack.lock.json${field}/target`);
      continue;
    }
    checkGameVersion(configuration.game_version, `${field}/game_version`, issues, { code: 'BEPACK_VERSION_SET_INVALID' });
    const effectiveVariant = effective.get(configuration.target);
    if (manifest.mode !== 'mods-only' && effectiveVariant && configuration.game_version !== effectiveVariant.game_version) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration game version differs from the bound target', `bepack.lock.json${field}/game_version`);
    }
    if (manifest.mode === 'mods-only') {
      const key = `${configuration.target}\u0000${configuration.game_version}`;
      if (boundGames.has(key)) issues.add('BEPACK_VERSION_SET_INVALID', 'Duplicate configuration for target/game', `bepack.lock.json${field}`);
      boundGames.add(key);
    }
    if (exactKeys(configuration.loader, ['type', 'version'], ['type', 'version'], `${field}/loader`, issues)) {
      if (configuration.loader.type === 'none') {
        if (configuration.loader.version !== null) issues.add('BEPACK_VERSION_SET_INVALID', 'loader none requires version null', `bepack.lock.json${field}/loader/version`);
      } else if (typeof configuration.loader.version !== 'string' || !SEMVER_PATTERN.test(configuration.loader.version)) {
        issues.add('BEPACK_VERSION_SET_INVALID', 'Non-none loader requires an exact version', `bepack.lock.json${field}/loader/version`);
      }
      if (effectiveVariant && effectiveVariant.loader) {
        if (configuration.loader.type !== effectiveVariant.loader.type) issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration loader type differs from target', `bepack.lock.json${field}/loader/type`);
        if (configuration.loader.type !== 'none' && !versionSatisfies(configuration.loader.version, effectiveVariant.loader.version)) {
          issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration loader version does not satisfy the target', `bepack.lock.json${field}/loader/version`);
        }
      }
    }
    if (configuration.client !== null) {
      if (exactKeys(configuration.client, ['id', 'version', 'dependency'], ['id', 'version', 'dependency'], `${field}/client`, issues)) {
        if (typeof configuration.client.version !== 'string' || !SEMVER_PATTERN.test(configuration.client.version)) issues.add('BEPACK_VERSION_SET_INVALID', 'Client version must be exact', `bepack.lock.json${field}/client/version`);
        if (effectiveVariant?.client) {
          if (configuration.client.id !== effectiveVariant.client.id || configuration.client.dependency !== effectiveVariant.client.dependency) issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration client differs from target', `bepack.lock.json${field}/client`);
          if (!versionSatisfies(configuration.client.version, effectiveVariant.client.version)) issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration client version does not satisfy the target', `bepack.lock.json${field}/client/version`);
        }
      }
    } else if (effectiveVariant?.client) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration must declare the target client', `bepack.lock.json${field}/client`);
    } else if (effectiveVariant && effectiveVariant.client === null && configuration.client !== null) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration declares a client for a client-less target', `bepack.lock.json${field}/client`);
    }

    const applicable = [...context.dependencies.values()].filter((dependency) => dependency.targets.includes(configuration.target));
    const selectedDependencies = new Map();
    if (!Array.isArray(configuration.dependencies)) {
      issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration dependencies must be an array', `bepack.lock.json${field}/dependencies`);
    } else for (const [dependencyIndex, entry] of configuration.dependencies.entries()) {
      const at = `${field}/dependencies/${dependencyIndex}`;
      if (!exactKeys(entry, ['id', 'version', 'assets'], ['id', 'version', 'assets'], at, issues)) continue;
      const dependency = context.dependencies.get(entry.id);
      if (!dependency || !applicable.includes(dependency)) {
        issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Configuration lists an inapplicable or unknown dependency', `bepack.lock.json${at}/id`);
        continue;
      }
      if (selectedDependencies.has(entry.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate dependency in configuration', `bepack.lock.json${at}/id`);
      selectedDependencies.set(entry.id, entry);
      usedDependencies.add(entry.id);
      if (entry.version !== context.versionSet?.dependencies?.[entry.id]) issues.add('BEPACK_VERSION_SET_INVALID', 'Configuration dependency version differs from the combination', `bepack.lock.json${at}/version`);
      if (!Array.isArray(entry.assets)) {
        issues.add('BEPACK_MANIFEST_INVALID', 'assets must be an array', `bepack.lock.json${at}/assets`);
        continue;
      }
      for (const assetId of entry.assets) {
        const artifact = artifacts.get(assetId);
        if (!artifact) {
          issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Configuration references an unknown artifact', `bepack.lock.json${at}/assets`);
          continue;
        }
        if (artifact.dependency !== entry.id || artifact.version !== entry.version) issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Artifact dependency/version mismatch', `bepack.lock.json${at}/assets`);
        usedArtifacts.add(assetId);
      }
      const ownsContent = [...context.contents.values()].some((content) => content.source === 'dependency' && content.dependency === entry.id && content.targets.includes(configuration.target));
      if (entry.assets.length === 0 && !(dependency.bundled && ownsContent)) {
        issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Dependency has no assets and is not covered by content', `bepack.lock.json${at}/assets`);
      }
    }
    for (const dependency of applicable) {
      if (!selectedDependencies.has(dependency.id)) issues.add('BEPACK_DEPENDENCY_UNRESOLVED', 'Configuration omits an applicable dependency', `bepack.lock.json${field}/dependencies`, { dependency: dependency.id });
    }
    const expectedContents = applicableContents(context, configuration.target);
    if (!Array.isArray(configuration.contents)) {
      issues.add('BEPACK_CONTENT_INVALID', 'Configuration contents must be an array', `bepack.lock.json${field}/contents`);
    } else {
      const set = new Set(configuration.contents);
      if (set.size !== configuration.contents.length) issues.add('BEPACK_CONTENT_INVALID', 'Duplicate content ID in configuration', `bepack.lock.json${field}/contents`);
      for (const contentId of configuration.contents) {
        const content = context.contents.get(contentId);
        if (!content || !expectedContents.includes(content)) issues.add('BEPACK_CONTENT_INVALID', 'Configuration references an inapplicable content', `bepack.lock.json${field}/contents`);
        else usedContents.add(contentId);
      }
      for (const content of expectedContents) {
        if (!set.has(content.id)) issues.add('BEPACK_CONTENT_INVALID', 'Configuration omits an applicable content', `bepack.lock.json${field}/contents`, { content: content.id });
      }
    }
    if (!exactKeys(configuration.runtimes, ['game', 'loader'], ['game', 'loader'], `${field}/runtimes`, issues)) {
      // continue
    }
  }

  if (!Array.isArray(lock.runtimes) || lock.runtimes.length === 0) {
    issues.add('BEPACK_RUNTIME_UNRESOLVED', 'runtimes must be a non-empty array', 'bepack.lock.json', '/runtimes');
  }
  const runtimes = new Map();
  if (Array.isArray(lock.runtimes)) for (const [index, runtime] of lock.runtimes.entries()) {
    const field = `/runtimes/${index}`;
    if (!exactKeys(runtime, ['id', 'kind', 'version', 'platform', 'runtime', 'provider', 'identity', 'integrity'], ['id', 'kind', 'version', 'platform', 'runtime', 'provider', 'identity', 'integrity'], field, issues)) continue;
    checkId(runtime.id, `${field}/id`, issues);
    if (runtimes.has(runtime.id)) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Duplicate runtime ID', `bepack.lock.json${field}/id`);
    runtimes.set(runtime.id, runtime);
    if (!['game', 'loader'].includes(runtime.kind)) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Invalid runtime kind', `bepack.lock.json${field}/kind`);
    if (runtime.kind === 'loader' && exactKeys(runtime.integrity, ['kind', 'sha256'], ['kind', 'sha256'], `${field}/integrity`, issues) && runtime.integrity.kind !== 'artifact') issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Loader runtime must use artifact integrity', `bepack.lock.json${field}/integrity/kind`);
    if (typeof runtime.version !== 'string' || !runtime.version) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Runtime version must be an exact string', `bepack.lock.json${field}/version`);
    for (const property of ['platform', 'runtime', 'provider', 'identity']) {
      if (typeof runtime[property] !== 'string' || !runtime[property]) issues.add('BEPACK_RUNTIME_UNRESOLVED', `Runtime ${property} must be a non-empty string`, `bepack.lock.json${field}/${property}`);
    }
    if (exactKeys(runtime.integrity, ['kind', 'sha256'], ['kind', 'sha256'], `${field}/integrity`, issues)) {
      if (!['artifact', 'distribution-manifest'].includes(runtime.integrity.kind)) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Invalid runtime integrity kind', `bepack.lock.json${field}/integrity/kind`);
      checkSha256(runtime.integrity.sha256, `${field}/integrity/sha256`, issues);
    }
  }
  const referencedRuntimes = new Set();
  for (const configuration of configurations.values()) {
    if (!isObject(configuration.runtimes)) continue;
    const variant = effective.get(configuration.target);
    const game = runtimes.get(configuration.runtimes.game);
    if (configuration.runtimes.game !== undefined) {
      if (!game) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Configuration references an unknown game runtime', `bepack.lock.json/configurations/${escapePointer(configuration.id)}/runtimes/game`);
      else {
        referencedRuntimes.add(configuration.runtimes.game);
        if (game.kind !== 'game') issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Game runtime slot references a non-game runtime', `bepack.lock.json/runtimes/${escapePointer(game.id)}`);
        if (game.version !== configuration.game_version) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Game runtime version differs from the configuration', `bepack.lock.json/runtimes/${escapePointer(game.id)}/version`);
        if (variant && (game.platform !== variant.platform || game.runtime !== variant.runtime)) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Game runtime platform/runtime differs from the target', `bepack.lock.json/runtimes/${escapePointer(game.id)}`);
      }
    }
    if (configuration.runtimes.loader === null) {
      if (configuration.loader?.type !== 'none') issues.add('BEPACK_RUNTIME_UNRESOLVED', 'loader runtime must be null only for loader none', `bepack.lock.json/configurations/${escapePointer(configuration.id)}/runtimes/loader`);
    } else {
      const loader = runtimes.get(configuration.runtimes.loader);
      if (!loader) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Configuration references an unknown loader runtime', `bepack.lock.json/configurations/${escapePointer(configuration.id)}/runtimes/loader`);
      else {
        referencedRuntimes.add(configuration.runtimes.loader);
        if (loader.kind !== 'loader') issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Loader runtime slot references a non-loader runtime', `bepack.lock.json/runtimes/${escapePointer(loader.id)}`);
        if (loader.version !== configuration.loader?.version || loader.runtime !== variant?.runtime || loader.platform !== variant?.platform) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Loader runtime differs from the configuration', `bepack.lock.json/runtimes/${escapePointer(loader.id)}`);
      }
    }
  }
  for (const id of runtimes.keys()) {
    if (!referencedRuntimes.has(id)) issues.add('BEPACK_RUNTIME_UNRESOLVED', 'Unreferenced runtime record', 'bepack.lock.json', '/runtimes', { runtime: id });
  }

  const evidence = new Map();
  if (!Array.isArray(lock.evidence)) issues.add('BEPACK_MANIFEST_INVALID', 'evidence must be an array', 'bepack.lock.json', '/evidence');
  else for (const [index, item] of lock.evidence.entries()) {
    const field = `/evidence/${index}`;
    if (!exactKeys(item, ['id', 'kind', 'url', 'sha256', 'retrieved_at'], ['id', 'kind', 'url', 'sha256', 'retrieved_at'], field, issues)) continue;
    checkId(item.id, `${field}/id`, issues);
    if (evidence.has(item.id)) issues.add('BEPACK_MANIFEST_INVALID', 'Duplicate evidence ID', `bepack.lock.json${field}/id`);
    if (!['dependency-metadata', 'runtime-catalog'].includes(item.kind)) issues.add('BEPACK_MANIFEST_INVALID', 'Invalid evidence kind', `bepack.lock.json${field}/kind`);
    checkHttps(item.url, `${field}/url`, issues);
    checkSha256(item.sha256, `${field}/sha256`, issues);
    checkTimestamp(item.retrieved_at, `${field}/retrieved_at`, issues);
    evidence.set(item.id, item);
  }

  if (!Array.isArray(lock.compatibility)) issues.add('BEPACK_MANIFEST_INVALID', 'compatibility must be an array', 'bepack.lock.json', '/compatibility');
  else {
    const keys = new Set();
    for (const [index, item] of lock.compatibility.entries()) {
      const field = `/compatibility/${index}`;
      if (!exactKeys(item, ['subject_type', 'subject', 'target', 'entry', 'evidence'], ['subject_type', 'subject', 'target', 'entry', 'evidence'], field, issues)) continue;
      if (!['dependency', 'content'].includes(item.subject_type)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Invalid compatibility subject_type', `bepack.lock.json${field}/subject_type`);
      const subject = item.subject_type === 'dependency' ? context.dependencies.get(item.subject) : context.contents.get(item.subject);
      if (!subject) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility subject does not exist', `bepack.lock.json${field}/subject`);
      if (!context.enabled.has(item.target)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility target is not enabled', `bepack.lock.json${field}/target`);
      if (!subject?.targets?.includes(item.target)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility target is outside the subject target set', `bepack.lock.json${field}/target`);
      const key = `${item.subject_type}\u0000${item.subject}\u0000${item.target}`;
      if (keys.has(key)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Duplicate compatibility snapshot', `bepack.lock.json${field}`);
      keys.add(key);
      validateCompatibilityEntry(item.entry, `${field}/entry`, null, issues);
      if (!Array.isArray(item.evidence)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'evidence must be an array', `bepack.lock.json${field}/evidence`);
      else for (const evidenceId of item.evidence) if (!evidence.has(evidenceId)) issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Compatibility references unknown evidence', `bepack.lock.json${field}/evidence`);
      usedCompatibility.add(key);
    }
    for (const configuration of configurations.values()) {
      for (const dependencyId of usedDependencies) {
        const dependency = context.dependencies.get(dependencyId);
        if (dependency?.targets.includes(configuration.target) && !keys.has(`dependency\u0000${dependencyId}\u0000${configuration.target}`)) {
          issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Missing dependency compatibility snapshot', 'bepack.lock.json', '/compatibility', { dependency: dependencyId, target: configuration.target });
        }
      }
      for (const contentId of usedContents) {
        const content = context.contents.get(contentId);
        if (content?.targets.includes(configuration.target) && !keys.has(`content\u0000${contentId}\u0000${configuration.target}`)) {
          issues.add('BEPACK_COMPATIBILITY_UNKNOWN', 'Missing content compatibility snapshot', 'bepack.lock.json', '/compatibility', { content: contentId, target: configuration.target });
        }
      }
    }
  }

  if (lock.tested !== undefined) {
    if (!Array.isArray(lock.tested) || lock.tested.some((id) => !configurations.has(id))) issues.add('BEPACK_MANIFEST_INVALID', 'tested must reference configuration IDs', 'bepack.lock.json', '/tested');
  }

  // Every enabled target must be covered by the lock.
  const configuredTargets = new Set([...configurations.values()].map((configuration) => configuration.target));
  for (const target of context.enabled) {
    if (!configuredTargets.has(target)) issues.add('BEPACK_TARGET_UNAVAILABLE', 'Enabled target has no configuration', 'bepack.lock.json', '/configurations', { target });
  }
  for (const artifactId of artifacts.keys()) {
    if (!usedArtifacts.has(artifactId)) {
      const artifact = artifacts.get(artifactId);
      const ownedByContent = [...context.contents.values()].some((content) => content.source === 'dependency' && content.dependency === artifact.dependency);
      if (!(artifact.path && ownedByContent)) issues.add('BEPACK_FILE_UNDECLARED', 'Artifact is not used by any configuration or content', 'bepack.lock.json', '/artifacts', { artifact: artifactId });
    }
  }

  // Payload and license closure.
  const usedPaths = new Set();
  for (const content of context.contents.values()) {
    for (const name of contentFileSet(actual, content.path)) usedPaths.add(name);
  }
  for (const artifact of artifacts.values()) if (artifact.path) usedPaths.add(artifact.path);
  for (const license of context.licenseFiles) usedPaths.add(license);
  for (const name of actual.keys()) {
    if (name.startsWith('payload/') && !usedPaths.has(name)) issues.add('BEPACK_FILE_UNDECLARED', 'Payload file is not used by any content or artifact', 'bepack.lock.json', '/files', { path: name });
  }
  for (const name of actual.keys()) {
    if (name.startsWith('licenses/') && !usedPaths.has(name)) issues.add('BEPACK_FILE_UNDECLARED', 'License file is not referenced', 'bepack.lock.json', '/files', { path: name });
  }
}

function computeScanPlan(manifest, context, lock, artifacts, files, packageSha256, packageSize) {
  const plan = new Map();
  if (packageSha256) plan.set('package', { subject: 'package', sha256: packageSha256, size: packageSize ?? null });
  for (const content of context.contents.values()) {
    if (!EXECUTABLE_CATEGORIES.has(content.category)) continue;
    for (const name of contentFileSet(files, content.path)) {
      const entry = files.get(name);
      if (entry) plan.set(name, { subject: name, sha256: entry.sha256, size: entry.size });
    }
  }
  for (const dependency of context.dependencies.values()) {
    if (!['mod', 'client'].includes(dependency.role)) continue;
    for (const artifact of artifacts.values()) {
      if (artifact.dependency !== dependency.id) continue;
      if (artifact.path) {
        const entry = files.get(artifact.path);
        if (entry) plan.set(artifact.path, { subject: artifact.path, sha256: entry.sha256, size: entry.size });
      } else {
        const subject = `dependency/${dependency.id}/${artifact.id}`;
        plan.set(subject, { subject, sha256: artifact.sha256, size: artifact.size });
      }
    }
  }
  return [...plan.values()].sort((left, right) => left.subject < right.subject ? -1 : left.subject > right.subject ? 1 : 0);
}

function summarizeTargets(context, effective, lock, files) {
  const byTarget = new Map();
  for (const configuration of lock.configurations ?? []) {
    if (!byTarget.has(configuration.target)) byTarget.set(configuration.target, []);
    byTarget.get(configuration.target).push(configuration);
  }
  return [...context.enabled].sort().map((target) => {
    const variant = effective.get(target) ?? context.targets.get(target);
    const configs = byTarget.get(target) ?? [];
    const gameVersions = [...new Set(configs.map((configuration) => configuration.game_version))].sort();
    const loaders = [...new Map(configs.map((configuration) => [`${configuration.loader.type}\u0000${configuration.loader.version}`, configuration.loader])).values()];
    const clients = [...new Map(configs.filter((configuration) => configuration.client).map((configuration) => [`${configuration.client.id}\u0000${configuration.client.version}\u0000${configuration.client.dependency}`, configuration.client])).values()];
    return {
      target,
      platform: variant.platform,
      runtime: variant.runtime,
      requires: [...new Set([...(context.requires ?? []), ...(variant.requires ?? [])])].sort(),
      game_versions: gameVersions,
      loaders,
      clients,
    };
  });
}

export async function verifyPackage(file, { expected = null, packageSha256 = null, packageSize = null } = {}) {
  const zip = await inspectZip(file, { maxTotalBytes: LIMITS.zipTotalUncompressedBytes });
  try {
    const entryMap = new Map(zip.entries.filter((entry) => !entry.directory).map((entry) => [entry.name, entry]));
    if (!entryMap.has('bepack.json')) throw packageError('Package is missing bepack.json', []);
    const manifestEntry = await readEntry(zip, entryMap.get('bepack.json'), { capture: true, maxCapture: LIMITS.manifestBytes });
    let manifest;
    try {
      manifest = parseStrictJSON(manifestEntry.bytes, { maxBytes: LIMITS.manifestBytes });
    } catch (error) {
      throw packageError(`bepack.json is not strict JSON: ${error.message}`, []);
    }
    if (!safeId(manifest.version_set)) throw packageError('bepack.json has an invalid version_set', []);
    const setPath = `versions/${manifest.version_set}.json`;
    if (!entryMap.has(setPath)) throw packageError(`Package is missing ${setPath}`, []);
    if (!entryMap.has('bepack.lock.json')) throw packageError('Package is missing bepack.lock.json', []);
    const files = await verifyAllEntries(zip, {
      captureNames: new Set(['bepack.json', setPath, 'bepack.lock.json']),
      maxCapture: Math.max(LIMITS.lockBytes, LIMITS.manifestBytes),
    });
    const issues = new Issues('bepack');
    // Root namespace closure.
    for (const name of files.keys()) {
      if (name === 'bepack.json' || name === 'bepack.lock.json') continue;
      if (name === setPath) continue;
      if (name.startsWith('payload/') || name.startsWith('licenses/')) continue;
      if (name.startsWith('versions/')) {
        issues.add('BEPACK_FILE_UNDECLARED', 'Only the active version set may appear under versions/', 'bepack', '/versions', { path: name });
        continue;
      }
      issues.add('BEPACK_FILE_UNDECLARED', 'Unexpected root package file', 'bepack', '/', { path: name });
    }
    let versionSet;
    let lock;
    try {
      versionSet = parseStrictJSON(files.get(setPath).bytes, { maxBytes: LIMITS.manifestBytes });
    } catch (error) {
      throw packageError(`${setPath} is not strict JSON: ${error.message}`, []);
    }
    try {
      lock = parseStrictJSON(files.get('bepack.lock.json').bytes, { maxBytes: LIMITS.lockBytes, maxDepth: 128 });
    } catch (error) {
      throw packageError(`bepack.lock.json is not strict JSON: ${error.message}`, []);
    }
    const context = validateManifest(manifest, issues);
    context.versionSet = versionSet;
    const effective = mergeCombination(manifest, context, issues);
    // Content path existence and file/directory category checks need the ZIP.
    for (const content of context.contents.values()) {
      if (!entryMap.has(content.path) && ![...entryMap.keys()].some((name) => name.startsWith(`${content.path}/`))) {
        issues.add('BEPACK_FILE_MISSING', 'Content path is absent from the package', 'bepack.json', `/contents/${escapePointer(content.id)}/path`);
        continue;
      }
      const isDirectory = !entryMap.has(content.path);
      if (content.category === 'config' && isDirectory) issues.add('BEPACK_CONTENT_INVALID', 'config content must be a single file', 'bepack.json', `/contents/${escapePointer(content.id)}/path`);
      if (['resource-pack', 'behavior-pack', 'world'].includes(content.category) && !isDirectory) {
        issues.add('BEPACK_CONTENT_INVALID', 'Pack/world content must be a normalized directory, not an archive', 'bepack.json', `/contents/${escapePointer(content.id)}/path`);
      }
      if (content.category === 'config' && content.source === 'dependency') issues.add('BEPACK_CONTENT_INVALID', 'config content cannot be owned by a dependency', 'bepack.json', `/contents/${escapePointer(content.id)}`);
      for (const target of content.targets ?? []) {
        const variant = effective.get(target);
        if (!variant) continue;
        if (content.category === 'll-plugin' && (variant.runtime !== 'bedrock-server' || variant.loader.type !== 'levilamina')) issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'll-plugin requires BDS with Levilamina', 'bepack.json', `/contents/${escapePointer(content.id)}/targets`);
        if (content.category === 'native-mod' && variant.runtime === 'bedrock-server') issues.add('BEPACK_CONTENT_INVALID', 'native-mod cannot target a server runtime', 'bepack.json', `/contents/${escapePointer(content.id)}/targets`);
        if (content.category === 'client-component' && variant.client === null) issues.add('BEPACK_CAPABILITY_UNSUPPORTED', 'client-component requires a client target', 'bepack.json', `/contents/${escapePointer(content.id)}/targets`);
      }
    }
    for (const license of context.licenseFiles) {
      if (!entryMap.has(license)) issues.add('BEPACK_FILE_MISSING', 'Referenced license file is absent', 'bepack.json', '/license_file', { path: license });
    }
    if (issues.length === 0) validateLock(manifest, context, effective, lock, files, issues);
    if (issues.length) throw packageError('Package verification failed', issues.list);
    if (expected) {
      const expectedIssues = new Issues('bepack');
      if (expected.packId && expected.packId !== manifest.id) expectedIssues.add('BEPACK_MANIFEST_INVALID', 'Pack ID differs from release descriptor', '/id');
      if (expected.version && expected.version !== manifest.version) expectedIssues.add('BEPACK_MANIFEST_INVALID', 'Version differs from release descriptor', '/version');
      if (expected.versionSet && expected.versionSet !== manifest.version_set) expectedIssues.add('BEPACK_VERSION_SET_INVALID', 'version_set differs from release descriptor', '/version_set');
      if (expected.mode && expected.mode !== manifest.mode) expectedIssues.add('BEPACK_MANIFEST_INVALID', 'mode differs from release descriptor', '/mode');
      if (expected.packageSha256 && packageSha256 && expected.packageSha256 !== packageSha256) expectedIssues.add('BEPACK_HASH_MISMATCH', 'Package SHA-256 differs from release descriptor', '/package/sha256');
      if (expectedIssues.length) throw packageError('Package does not match the release descriptor', expectedIssues.list);
    }
    const artifacts = new Map((lock.artifacts ?? []).map((artifact) => [artifact.id, artifact]));
    const scanPlan = computeScanPlan(manifest, context, lock, artifacts, files, packageSha256, packageSize);
    const targets = summarizeTargets(context, effective, lock, files);
    return {
      manifest,
      versionSet,
      lock,
      files,
      targets,
      scanPlan,
      mode: manifest.mode,
      id: manifest.id,
      version: manifest.version,
    };
  } finally {
    await closeZip(zip);
  }
}
