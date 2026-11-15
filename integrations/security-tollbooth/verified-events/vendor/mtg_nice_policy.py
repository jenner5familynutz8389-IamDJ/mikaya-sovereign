#!/usr/bin/env python3
"""MIKAYA Thermal Governance: user-space optional workload gate.

Uses Android's public NDK thermal severity API, not privileged HAL knobs.
Raises niceness ONLY on jobs launched through this wrapper.
"""
from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import time

NICE_INCREASE = 15
CHECK_SECONDS = 10
HOLD_EXIT = 75


def read_status() -> int | None:
    """Return Android thermal severity 0..6, or None on any error."""
    try:
        # Absolute system library avoids Termux's unrelated libandroid stub.
        android = ctypes.CDLL("/system/lib64/libandroid.so")
        android.AThermal_acquireManager.restype = ctypes.c_void_p
        manager = android.AThermal_acquireManager()
        if not manager:
            return None
        try:
            android.AThermal_getCurrentThermalStatus.argtypes = [ctypes.c_void_p]
            android.AThermal_getCurrentThermalStatus.restype = ctypes.c_int
            status = android.AThermal_getCurrentThermalStatus(manager)
        finally:
            android.AThermal_releaseManager.argtypes = [ctypes.c_void_p]
            android.AThermal_releaseManager(manager)
        return status if isinstance(status, int) and 0 <= status <= 6 else None
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def decision(status: int | None) -> str:
    # Strictly optional workloads: moderate (2) or higher is HOLD.
    return "ALLOW" if type(status) is int and status in (0, 1) else "HOLD"


def _child_nice() -> None:
    # Positive niceness is lower CPU scheduling priority, not more CPU.
    os.nice(NICE_INCREASE)


def _signal_child(p: subprocess.Popen, signum: int) -> None:
    try:
        os.killpg(p.pid, signum)
    except ProcessLookupError:
        pass


def _run(args: list[str]) -> int:
    if not args or args == ["--"]:
        print("Usage: mikaya-nice run -- COMMAND [ARG...]", file=sys.stderr)
        return 2
    if args[0] == "--":
        args = args[1:]
    if not args:
        return 2
    status = read_status()
    if decision(status) != "ALLOW":
        print(f"MIKAYA_MTG HOLD severity={status!r}: optional job not started.", flush=True)
        return HOLD_EXIT
    try:
        child = subprocess.Popen(
            args, start_new_session=True, preexec_fn=_child_nice
        )
    except (OSError, ValueError) as exc:
        print(f"MIKAYA_MTG START_ERROR {type(exc).__name__}", file=sys.stderr)
        return 1
    paused = False
    cooldown_samples = 0
    try:
        while True:
            completed = child.poll()
            if completed is not None:
                return completed
            observed = read_status()
            if decision(observed) == "HOLD":
                cooldown_samples = 0
                if not paused:
                    _signal_child(child, signal.SIGSTOP)
                    paused = True
                    print(f"MIKAYA_MTG PAUSED severity={observed!r}", flush=True)
            elif paused:
                cooldown_samples += 1
                if cooldown_samples >= 2:
                    _signal_child(child, signal.SIGCONT)
                    paused = False
                    cooldown_samples = 0
                    print("MIKAYA_MTG RESUMED after two safe readings", flush=True)
            time.sleep(CHECK_SECONDS)
    except KeyboardInterrupt:
        # Own process group only. Never signal Android services/agent.
        if paused:
            _signal_child(child, signal.SIGCONT)
        _signal_child(child, signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _signal_child(child, signal.SIGKILL)
        return 130


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in ("help", "-h", "--help"):
        print("Usage: mikaya-nice status | run -- COMMAND [ARGS]")
        print("Only OPTIONAL jobs started with 'run' are managed. OEM controls untouched.")
        return 0
    if args[0] == "status":
        severity = read_status()
        policy = decision(severity)
        print(json.dumps({
            "name": "MIKAYA Thermal Governance (MTG)",
            "android_thermal_severity": severity,
            "decision_for_optional_jobs": policy,
            "nice_increase": NICE_INCREASE,
            "resume_requires": "two consecutive samples with severity 0 or 1",
            "poll_interval_seconds": CHECK_SECONDS,
            "factory_throttling_modified": False,
            "adb_required": False
        }, indent=2))
        return 0 if policy == "ALLOW" else HOLD_EXIT
    if args[0] == "run":
        return _run(args[1:])
    print("Unknown command (use status or run).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
