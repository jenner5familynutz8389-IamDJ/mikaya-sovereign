'use strict';

/* Read-only observations. System properties are identifiers, not attestation. */
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const PROPERTIES = Object.freeze({
  model: 'ro.product.model',
  productBoard: 'ro.product.board',
  boardPlatform: 'ro.board.platform',
  androidRelease: 'ro.build.version.release',
  apiLevel: 'ro.build.version.sdk',
  abiList: 'ro.product.cpu.abilist',
  primaryAbi: 'ro.product.cpu.abi',
});

// Reference observations from the mobile-edge review. Never substitute these
// values for missing, different, or inaccessible device properties.
const DOCUMENTED_TARGETS = Object.freeze([
  Object.freeze({
    id: 'f110-pro', model: 'F110 Pro', productBoard: 'e393_qc_f10_w_6835_v0',
    boardPlatform: 'mt6835', apiLevel: 35,
  }),
  Object.freeze({
    id: 'moto-g-power-5g-2023', model: 'moto g power 5G - 2023',
    productBoard: 'devonn', boardPlatform: 'mt6855', apiLevel: 34,
  }),
]);

function systemProperty(name) {
  if (!Object.values(PROPERTIES).includes(name)) throw new Error('Property is not allowlisted');
  return execFileSync('/system/bin/getprop', [name], {
    encoding: 'utf8', timeout: 1500, maxBuffer: 4096,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function probePath(filePath) {
  if (!filePath) return { exists: false, type: null, readable: false, error: 'PATH_UNAVAILABLE' };
  try {
    const stat = fs.lstatSync(filePath);
    const type = stat.isSymbolicLink() ? 'symbolic-link'
      : stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : 'other';
    let readable = false;
    try { fs.accessSync(filePath, fs.constants.R_OK); readable = true; } catch {}
    return { exists: true, type, readable, error: null };
  } catch (error) {
    return { exists: false, type: null, readable: false, error: error.code || 'UNAVAILABLE' };
  }
}

function cleanProperty(value) {
  if (typeof value !== 'string') throw new Error('Property reader returned a non-string');
  const normalized = value.trim();
  if (normalized.length > 512 || /[\x00-\x1f\x7f]/.test(normalized)) {
    throw new Error('Property value is not a bounded printable string');
  }
  return normalized || null;
}

function inspectAndroid(options = {}) {
  const propertyReader = options.propertyReader || systemProperty;
  const fsProbe = options.fsProbe || probePath;
  const environment = options.environment || process.env;
  const sourceRoot = options.sourceRoot || path.resolve(__dirname, '../../..');
  const nodeVersion = options.nodeVersion || process.versions.node;
  const runtimeArch = options.runtimeArch || process.arch;
  const runtimePlatform = options.runtimePlatform || process.platform;
  const generatedAt = options.generatedAt || new Date().toISOString();
  // Injected observations are always labelled; fixture tests cannot accidentally
  // be represented as a physical-device execution in this report.
  const evidenceKind = options.propertyReader ? 'fixture-or-injected-observation' : 'local-observation';
  const observed = {};
  const propertyErrors = [];
  for (const [field, property] of Object.entries(PROPERTIES)) {
    try { observed[field] = cleanProperty(propertyReader(property)); }
    catch (error) {
      observed[field] = null;
      propertyErrors.push({ property, code: error.code || 'PROPERTY_UNAVAILABLE' });
    }
  }
  const sdk = observed.apiLevel && /^\d+$/.test(observed.apiLevel) ? Number(observed.apiLevel) : null;
  const nodeMatch = /^v?(\d+)\./.exec(String(nodeVersion));
  const nodeMajor = nodeMatch ? Number(nodeMatch[1]) : null;
  const abiList = (observed.abiList || observed.primaryAbi || '').split(',').map(x => x.trim()).filter(Boolean);
  const target = DOCUMENTED_TARGETS.find(t => t.model === observed.model) || null;
  const differences = target ? ['productBoard', 'boardPlatform', 'apiLevel'].filter(field => {
    const actual = field === 'apiLevel' ? sdk : observed[field];
    return actual !== target[field];
  }) : [];
  let classification = 'unreviewed';
  if (target) classification = differences.length ? 'requires-review' : 'documented-profile-match';
  const prefix = typeof environment.PREFIX === 'string' && path.isAbsolute(environment.PREFIX)
    ? environment.PREFIX : null;
  const userHome = typeof environment.HOME === 'string' && path.isAbsolute(environment.HOME)
    ? environment.HOME : null;
  const locations = [
    ['termux-prefix', prefix],
    ['termux-bin', prefix && path.join(prefix, 'bin')],
    ['termux-lib', prefix && path.join(prefix, 'lib')],
    ['home', userHome],
    ['collaboration-source', path.join(sourceRoot, 'engineering/federation/collaboration')],
    ['collaboration-entrypoint', path.join(sourceRoot, 'engineering/federation/collaboration/gateway-adapter.cjs')],
    ['android-preflight', path.join(sourceRoot, 'engineering/federation/collaboration/android-preflight.cjs')],
    ['owner-authorization-source', path.join(sourceRoot, 'engineering/federation/live/owner-authorization.cjs')],
    ['local-evidence-source', path.join(sourceRoot, 'engineering/federation/mobile-edge/local-evidence-gateway.cjs')],
    ['local-evidence-command', prefix && path.join(prefix, 'bin/mikaya-local-evidence')],
    ['local-evidence-service-directory', prefix && path.join(prefix, 'var/service/mikaya-mobile-evidence')],
  ].map(([name, filePath]) => ({ name, path: filePath, ...fsProbe(filePath) }));
  const blockers = [];
  const warnings = [];
  if (!nodeMajor || nodeMajor < 22) blockers.push('NODE_22_OR_NEWER_REQUIRED');
  if (!observed.model || !sdk) blockers.push('ANDROID_IDENTITY_PROPERTIES_UNAVAILABLE');
  if (runtimeArch !== 'arm64' || !abiList.includes('arm64-v8a')) blockers.push('ARM64_RUNTIME_AND_ABI_REQUIRED');
  if (![34, 35].includes(sdk)) blockers.push('ANDROID_API_REQUIRES_COMPATIBILITY_TEST');
  if (!prefix) blockers.push('ABSOLUTE_TERMUX_PREFIX_REQUIRED');
  for (const label of ['termux-prefix', 'termux-bin', 'termux-lib']) {
    const entry = locations.find(item => item.name === label);
    if (!entry.exists || !entry.readable || entry.type !== 'directory') blockers.push(`${label.toUpperCase().replace(/-/g, '_')}_UNAVAILABLE`);
  }
  if (classification !== 'documented-profile-match') warnings.push('DEVICE_PROFILE_REQUIRES_OWNER_REVIEW');
  if (propertyErrors.length) warnings.push('SOME_ANDROID_PROPERTIES_COULD_NOT_BE_READ');
  if (!locations.find(item => item.name === 'collaboration-entrypoint').exists) warnings.push('COLLABORATION_ENTRYPOINT_NOT_PRESENT');
  if (!locations.find(item => item.name === 'local-evidence-command').exists) warnings.push('EXISTING_LOCAL_EVIDENCE_COMMAND_NOT_FOUND_AT_PREFIX');
  if (evidenceKind !== 'local-observation') warnings.push('INJECTED_OBSERVATIONS_ARE_NOT_PHYSICAL_DEVICE_EVIDENCE');
  return {
    schema: 'mikaya.collaboration.android-preflight.v1',
    generatedAt,
    evidenceKind,
    propertySource: options.propertyReader ? 'injected-property-reader' : '/system/bin/getprop',
    readOnly: true,
    mutations: { files: false, keys: false, services: false, network: false },
    device: {
      model: observed.model,
      productBoard: observed.productBoard,
      boardPlatform: observed.boardPlatform,
      androidRelease: observed.androidRelease,
      apiLevel: sdk,
      abiList,
      primaryAbi: observed.primaryAbi,
      profile: { id: target ? target.id : null, classification, differingFields: differences },
    },
    runtime: { nodeVersion, nodeMajor, minimumNodeMajor: 22, architecture: runtimeArch, platform: runtimePlatform },
    paths: locations,
    propertyErrors,
    compatibility: {
      documentedAndroidApis: [34, 35],
      sourceRuntimeUsable: blockers.length === 0,
      profileReviewNeeded: classification !== 'documented-profile-match',
      blockers, warnings,
    },
    boundaries: {
      hardwareAttestation: false,
      peerApproval: false,
      ownerAuthorization: false,
      collaborationAdmission: 'NOT_EVALUATED',
      existingEvidencePort: 4188,
      existingEvidenceServiceRunning: 'NOT_INSPECTED',
    },
  };
}

function runCli(argv = process.argv.slice(2)) {
  if (argv.some(arg => !['--strict', '--help', '-h'].includes(arg))) {
    process.stderr.write('Usage: android-preflight.cjs [--strict]\n');
    return 2;
  }
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write('Read-only Android and source availability report. --strict exits 2 for runtime or device-profile review blockers. This command never grants peer admission.\n');
    return 0;
  }
  const result = inspectAndroid();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return argv.includes('--strict') && (!result.compatibility.sourceRuntimeUsable || result.compatibility.profileReviewNeeded) ? 2 : 0;
}

if (require.main === module) process.exitCode = runCli();
module.exports = { inspectAndroid, runCli, DOCUMENTED_TARGETS, PROPERTIES };
