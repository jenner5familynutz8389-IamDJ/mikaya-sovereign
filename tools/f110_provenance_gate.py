#!/usr/bin/env python3
"""Fail-closed F110 Android 15 owner-source provenance gate (no device writes)."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

SOURCE_MANIFESTS = (
    ('engineering/ahava-v2/SOURCE_MANIFEST.json', 'sha256', 'engineering/ahava-v2/', 9),
    ('engineering/f110-runtime/SOURCE_MANIFEST.json', 'files', 'engineering/f110-runtime/', 20),
    ('engineering/f110-runtime/FUNCTIONAL_PROVENANCE_APPENDIX.json', 'files', 'engineering/f110-runtime/', 4),
)
PROFILE = 'engineering/f110-android15/BUILD_PROFILE.json'
OBSERVED = 'engineering/f110-android15/F110_OBSERVED_REDACTED.json'
GATES = 'docs/audit/F110_EVIDENCE_REGISTER_20261023.json'
CONTRACTS = 'docs/audit/F110_DEEP_57_GATE_VERIFICATION_CONTRACT_20261025.json'
HISTORY = 'docs/audit/MIKAYA_AUDIT_CLASSIFICATION_INTEGRITY_20261023.json'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
REVISION = re.compile(r'[0-9a-f]{40}\Z')


def _record(errors, code, source, **details):
    errors.append({'code': code, 'source': source, **details})


def _resolve(repo: Path, relative: str, errors: list):
    """Reject absolute/traversal/symlink paths, even if they resolve inside repo."""
    if not isinstance(relative, str) or '\\' in relative:
        _record(errors, 'UNSAFE_PATH', str(relative))
        return None
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or '.' in path.parts or '..' in path.parts:
        _record(errors, 'UNSAFE_PATH', relative)
        return None
    target = repo
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            _record(errors, 'UNSAFE_PATH', relative, reason='SYMLINK')
            return None
    try:
        if not target.resolve().is_relative_to(repo.resolve()):
            _record(errors, 'UNSAFE_PATH', relative)
            return None
    except OSError:
        _record(errors, 'UNSAFE_PATH', relative)
        return None
    return target


def _load(repo, relative, errors):
    target = _resolve(repo, relative, errors)
    if target is None:
        return None
    if not target.is_file():
        _record(errors, 'MISSING_FILE', relative)
        return None
    try:
        value = json.loads(target.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise ValueError('JSON root must be an object')
        return value
    except (OSError, ValueError, UnicodeError) as exc:
        _record(errors, 'BAD_JSON', relative, detail=str(exc)[:200])
        return None


def inspect_repository(root: str | Path, revision: str | None = None) -> dict:
    """Verify committed bytes and contract counts; never claim OEM signatures."""
    repo = Path(root).resolve()
    errors = []
    revision_verified = False
    if revision is not None:
        if not REVISION.fullmatch(revision):
            _record(errors, 'REVISION', 'git-revision', detail='expected 40 lowercase hex digits')
        elif not (repo / '.git').exists():
            _record(errors, 'GIT_CHECKOUT_MISSING', str(repo),
                    detail='cannot bind claimed commit to source without a Git checkout')
        else:
            try:
                top = subprocess.run(['git', '-C', str(repo), 'rev-parse', '--show-toplevel'],
                                     text=True, capture_output=True, timeout=8, check=True).stdout.strip()
                head = subprocess.run(['git', '-C', str(repo), 'rev-parse', '--verify', 'HEAD'],
                                      text=True, capture_output=True, timeout=8, check=True).stdout.strip()
                if Path(top).resolve() != repo or not hmac.compare_digest(head, revision):
                    _record(errors, 'REVISION_MISMATCH', 'git-revision',
                            detail='claimed revision does not match checkout HEAD')
                else:
                    revision_verified = True
            except (OSError, subprocess.SubprocessError) as exc:
                _record(errors, 'GIT_REVISION_UNREADABLE', str(repo), detail=str(exc)[:160])
    if not repo.is_dir():
        _record(errors, 'MISSING_REPOSITORY', str(repo))
    checked = []
    for manifest_path, field, prefix, expected_count in SOURCE_MANIFESTS:
        manifest = _load(repo, manifest_path, errors)
        if manifest is None:
            continue
        entries = manifest.get(field)
        if not isinstance(entries, dict) or len(entries) != expected_count:
            _record(errors, 'MANIFEST_COUNT', manifest_path, expected=expected_count,
                    found=len(entries) if isinstance(entries, dict) else None)
            if not isinstance(entries, dict):
                continue
        for name, sha in entries.items():
            candidate = name if field == 'sha256' else prefix + str(name)
            if not isinstance(name, str) or not candidate.startswith(prefix):
                _record(errors, 'UNSAFE_PATH', str(candidate))
                continue
            if not isinstance(sha, str) or DIGEST.fullmatch(sha) is None:
                _record(errors, 'BAD_DIGEST', candidate)
                continue
            file = _resolve(repo, candidate, errors)
            if file is None:
                continue
            if not file.is_file():
                _record(errors, 'MISSING_FILE', candidate)
                continue
            try:
                hashed = hashlib.sha256()
                with file.open('rb') as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        hashed.update(chunk)
                digest = hashed.hexdigest()
            except OSError as exc:
                _record(errors, 'UNREADABLE_FILE', candidate, detail=str(exc)[:160])
                continue
            if not hmac.compare_digest(digest, sha):
                _record(errors, 'SHA256_MISMATCH', candidate,
                        expected=sha, actual=digest)
            else:
                checked.append(candidate)

    profile = _load(repo, PROFILE, errors)
    observation = _load(repo, OBSERVED, errors)
    if profile is not None and observation is not None:
        device = profile.get('device', {})
        android = profile.get('android_platform', {})
        vendor = profile.get('observed_vendor', {})
        policy = profile.get('release_policy', {})
        correct_profile = (
            isinstance(device, dict) and device.get('soc') == 'mt6835'
            and device.get('board') == 'e393_qc_f10_w_6835_v0'
            and isinstance(android, dict) and android.get('release') == '15'
            and type(android.get('sdk')) is int and android['sdk'] == 35
            and android.get('aosp_ref') == 'android-15.0.0_r1'
            and isinstance(vendor, dict) and type(vendor.get('sdk')) is int and vendor['sdk'] == 33
            and isinstance(policy, dict) and policy.get('flash_authorized') is False
            and policy.get('oem_signing_verified') is False
            and observation.get('ro.board.platform') == 'mt6835'
            and observation.get('ro.build.version.release') == '15'
            and observation.get('ro.build.version.sdk') == '35'
            and observation.get('ro.vendor.build.version.sdk') == '33'
        )
        if not correct_profile:
            _record(errors, 'PLATFORM_IDENTITY', PROFILE,
                    detail='F110 MT6835 Android 15/API35 and actual vendor API33 required')

    evidence = _load(repo, GATES, errors)
    contracts = _load(repo, CONTRACTS, errors)
    expected_ids = [f'F110-G{i:03d}' for i in range(1, 58)]
    ids1 = ([r.get('id') for r in evidence['acceptance_matrix_rows']]
            if evidence is not None and isinstance(evidence.get('acceptance_matrix_rows'), list)
            and all(isinstance(r, dict) for r in evidence['acceptance_matrix_rows']) else [])
    ids2 = ([r.get('id') for r in contracts['contracts']]
            if contracts is not None and isinstance(contracts.get('contracts'), list)
            and all(isinstance(r, dict) for r in contracts['contracts']) else [])
    if ids1 != expected_ids or ids2 != expected_ids:
        _record(errors, 'GATE_INDEX', GATES, evidence_count=len(ids1), contract_count=len(ids2))
    if contracts is not None and contracts.get('counts', {}).get('executed_by_this_addendum') != 0:
        _record(errors, 'GATE_EXECUTION_MISLABEL', CONTRACTS)

    historical = _load(repo, HISTORY, errors)
    if historical is not None:
        counts = historical.get('original_results')
        ownership = historical.get('classification')
        if (historical.get('individual_test_executions') != 248
                or counts != {'PASS': 234, 'FAIL': 12, 'DISCOVERY_ERROR': 2}
                or ownership != {'OWNER_USERSPACE': 86, 'OEM_HARDWARE_GATE': 87,
                                 'SHARED_INTEGRATION': 75}):
            _record(errors, 'HISTORICAL_TEST_RECORD', HISTORY,
                    detail='preserve original pass/fail/owner counts; do not convert to new results')

    return {
        'schema': 'mikaya.f110.provenance-gate.v1',
        'status': 'SOURCE_PROVENANCE_PASS' if not errors else 'SOURCE_PROVENANCE_FAIL',
        'review_revision': revision,
        'revision_verified': revision_verified,
        'file_count': len(checked),
        'expected_source_files': 33,
        'gate_count': len(ids1) if ids1 == ids2 == expected_ids else 0,
        'historical_test_executions': historical.get('individual_test_executions') if historical else None,
        'android_platform_sdk': 35 if profile is not None and observation is not None
            and not any(e['code'] == 'PLATFORM_IDENTITY' for e in errors) else None,
        'oem_firmware_verified': False,
        'physical_device_tested': False,
        'oem_signing_proven': False,
        'errors': errors,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='F110 source SHA/provenance preflight; no device write')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--revision', default=None)
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args(argv)
    result = inspect_repository(args.root, args.revision)
    data = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(data, encoding='utf-8')
    print(data, end='')
    return 0 if result['status'] == 'SOURCE_PROVENANCE_PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
