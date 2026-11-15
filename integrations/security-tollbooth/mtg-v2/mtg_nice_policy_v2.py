#!/usr/bin/env python3
"""Versioned MTG optional-job owner; public NDK only, no global policy changes."""
from __future__ import annotations
import ctypes
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

NICE_INCREASE = 15  # Legacy JSON field; V2 enforces a minimum niceness of 15.
CHECK_SECONDS = 10
HOLD_EXIT = 75
MAX_WALL_SECONDS = 21600
READ_SECONDS = 3
PREFIX = "/data/data/com.termux/files/usr"
STANDARD_PRELOAD = PREFIX + "/lib/libtermux-exec.so"
WALL_ENV = "MIKAYA_MTG_MAX_WALL_SECONDS"


def decision(status):
    return "ALLOW" if type(status) is int and status in (0, 1) else "HOLD"


def probe_environment(sdk, original):
    """Return an isolated copy, or HOLD; never mutate the caller environment."""
    preload = original.get("LD_PRELOAD", "")
    if preload not in ("", STANDARD_PRELOAD):
        return None
    env = dict(original)
    if sdk == 34:
        env["LD_LIBRARY_PATH"] = "/system/lib64:" + PREFIX + "/lib"
        if preload == STANDARD_PRELOAD:
            env.pop("LD_PRELOAD", None)
    return env


def _native_status():
    try:
        android = ctypes.CDLL("/system/lib64/libandroid.so")
        android.AThermal_acquireManager.argtypes = []
        android.AThermal_acquireManager.restype = ctypes.c_void_p
        android.AThermal_getCurrentThermalStatus.argtypes = [ctypes.c_void_p]
        android.AThermal_getCurrentThermalStatus.restype = ctypes.c_int
        android.AThermal_releaseManager.argtypes = [ctypes.c_void_p]
        android.AThermal_releaseManager.restype = None
        manager = android.AThermal_acquireManager()
        if not manager:
            return None
        try:
            value = android.AThermal_getCurrentThermalStatus(manager)
        finally:
            android.AThermal_releaseManager(manager)
        return value if type(value) is int and 0 <= value <= 6 else None
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def _child_setup(parent):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(2)
    os.nice(max(0, NICE_INCREASE - os.getpriority(os.PRIO_PROCESS, 0)))


class CleanupHold(RuntimeError):
    pass


def wait_supported():
    return all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID", "WEXITED", "WNOHANG"))


class OwnedChild:
    """Keep the unreaped leader PID reserved until its own group is cleaned."""
    def __init__(self, argv, *, env=None, capture=False):
        parent = os.getpid()
        self.process = subprocess.Popen(
            argv, env=env, stdin=subprocess.DEVNULL if capture else None,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.DEVNULL if capture else None,
            start_new_session=True, preexec_fn=lambda: _child_setup(parent),
            close_fds=True,
        )
        self.closed = False
        self.reservation_lost = False

    def completed(self):
        # Never Popen.poll/wait before group cleanup: descendants may outlive leader.
        try:
            result = os.waitid(os.P_PID, self.process.pid,
                               os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as exc:
            self.reservation_lost = True
            raise CleanupHold("owned child wait reservation changed") from exc
        if result is None:
            return None
        return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status

    def send(self, signum):
        if not self.closed:
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                pass

    def close(self, *, grace=1):
        if self.closed:
            return True
        if self.reservation_lost:
            if self.process.stdout is not None:
                self.process.stdout.close()
            return False
        ok = True
        # TERM before CONT lets a stopped job receive its pending termination promptly.
        for signum in (signal.SIGTERM, signal.SIGCONT):
            try:
                self.send(signum)
            except OSError:
                ok = False
        end = time.monotonic() + grace
        while time.monotonic() < end:
            time.sleep(max(0, min(0.05, end - time.monotonic())))
        try:
            self.send(signal.SIGKILL)
        except OSError:
            ok = False
        try:
            self.process.wait(timeout=1)
            self.closed = True
        except subprocess.TimeoutExpired:
            ok = False
        finally:
            if self.process.stdout is not None:
                self.process.stdout.close()
        return ok and self.closed



class Control:
    def __init__(self, *, handlers=True):
        self.handlers = handlers
        self.stopped = 0
        self.probe = self.job = None
        self.readfd, self.writefd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.previous = {}

    def _wake(self, signum, _frame):
        if signum != signal.SIGCHLD and not self.stopped:
            self.stopped = signum
        try:
            os.write(self.writefd, b"x")
        except (BlockingIOError, OSError):
            pass

    def __enter__(self):
        if self.handlers:
            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD):
                self.previous[signum] = signal.signal(signum, self._wake)
        return self

    def drain(self):
        try:
            while os.read(self.readfd, 4096):
                pass
        except BlockingIOError:
            pass

    def wait(self, seconds):
        select.select([self.readfd], [], [], max(0, seconds))
        self.drain()

    def wait_until(self, deadline):
        while not self.stopped and time.monotonic() < deadline:
            self.wait(deadline - time.monotonic())

    def __exit__(self, *_):
        clean = True
        try:
            # A probe cleanup failure must never skip cleanup of the owned job.
            for owned, grace in ((self.probe, 0), (self.job, 1)):
                if owned is not None:
                    try:
                        clean = owned.close(grace=grace) and clean
                    except (OSError, ChildProcessError):
                        clean = False
        finally:
            for signum, previous in self.previous.items():
                signal.signal(signum, previous)
            os.close(self.readfd)
            os.close(self.writefd)
        if not clean:
            raise CleanupHold("owned group cleanup requires explicit review")



def _probe_command(control, argv, env, deadline):
    if control.stopped or time.monotonic() >= deadline:
        return None
    # An external ignored/custom SIGCHLD handler could reap before our reservation check.
    if not control.handlers and signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        return None
    owned = None
    try:
        # Handlers only flag/wake: a signal during Popen cannot skip assignment.
        owned = OwnedChild(argv, env=env, capture=True)
        control.probe = owned
        fd = owned.process.stdout.fileno()
        os.set_blocking(fd, False)
        output = bytearray()
        eof = False
        while not control.stopped and time.monotonic() < deadline:
            if owned.completed() is not None and eof:
                return bytes(output) if owned.completed() == 0 else None
            ready, _, _ = select.select(
                [control.readfd] + ([] if eof else [fd]), [], [],
                min(0.02, max(0, deadline - time.monotonic())) if eof and not control.handlers
                else max(0, deadline - time.monotonic()),
            )
            if control.readfd in ready:
                control.drain()
            if fd in ready:
                chunk = os.read(fd, 4097 - len(output))
                if not chunk:
                    eof = True
                output.extend(chunk)
                if len(output) > 4096:
                    return None
        return None
    except (OSError, ValueError, subprocess.SubprocessError, ChildProcessError):
        return None
    finally:
        clean = owned is None or owned.close(grace=0)
        control.probe = None if clean else owned
        if not clean:
            raise CleanupHold("owned probe cleanup requires explicit review")


def read_status(control=None, deadline=None):
    if not wait_supported():
        return None
    if control is None:
        try:
            with Control(handlers=False) as own:
                return read_status(own, deadline)
        except CleanupHold:
            return None
    end = min(time.monotonic() + READ_SECONDS,
              deadline if deadline is not None else float("inf"))
    original = dict(os.environ)
    if probe_environment(34, original) is None:
        return None
    # Public property query uses the fixed Android system executable, not a shell.
    raw = _probe_command(control, ["/system/bin/getprop", "ro.build.version.sdk"],
                         {"PATH": "/system/bin", "LANG": "C.UTF-8"},
                         min(end, time.monotonic() + 1))
    if raw is None or len(raw) > 16 or not re.fullmatch(rb"[0-9]{2}\n?", raw):
        return None
    sdk = int(raw.strip())
    if not 29 <= sdk <= 99:
        return None
    env = probe_environment(sdk, original)
    raw = _probe_command(control, [sys.executable, "-I", "-S", str(Path(__file__).resolve()),
                                  "_thermal_probe"], env, end)
    try:
        value = json.loads(raw) if raw is not None else None
        status = value["android_thermal_severity"]
        return status if (type(value) is dict and set(value) == {"android_thermal_severity"}
                          and type(status) is int and 0 <= status <= 6) else None
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None


def wall_bound():
    raw = os.environ.get(WALL_ENV, str(MAX_WALL_SECONDS))
    if not re.fullmatch(r"[0-9]{1,5}", raw):
        raise ValueError("invalid optional-run wall bound")
    seconds = int(raw)
    if not 1 <= seconds <= MAX_WALL_SECONDS:
        raise ValueError("invalid optional-run wall bound")
    return seconds


def _run_owned(args, *, _reader=None, _interval=CHECK_SECONDS, _max_wall=None):
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        print("Usage: mikaya-nice run -- COMMAND [ARG...]", file=sys.stderr)
        return 2
    if not wait_supported():
        print("MIKAYA_MTG HOLD owned-group wait support unavailable", flush=True)
        return HOLD_EXIT
    try:
        maximum = wall_bound() if _max_wall is None else _max_wall
        if type(maximum) is not int or not 1 <= maximum <= MAX_WALL_SECONDS:
            raise ValueError()
    except ValueError:
        print("MIKAYA_MTG CONFIG_HOLD invalid optional-run wall bound", flush=True)
        return 2
    deadline = time.monotonic() + maximum
    with Control() as control:
        reader = _reader or (lambda: read_status(control, deadline))
        for sample in range(2):
            if control.stopped:
                return 128 + control.stopped
            if time.monotonic() >= deadline:
                return HOLD_EXIT
            observed = reader()
            if control.stopped:
                return 128 + control.stopped
            if decision(observed) != "ALLOW":
                print(f"MIKAYA_MTG HOLD severity={observed!r}: optional job not started.", flush=True)
                return HOLD_EXIT
            if sample == 0:
                control.wait_until(min(deadline, time.monotonic() + _interval))
        if control.stopped or time.monotonic() >= deadline:
            return 128 + control.stopped if control.stopped else HOLD_EXIT
        try:
            control.job = OwnedChild(args)
        except (OSError, ValueError, subprocess.SubprocessError):
            print("MIKAYA_MTG START_ERROR", file=sys.stderr)
            return 1
        paused = False
        safe_samples = 0
        next_check = time.monotonic() + _interval
        while True:
            if control.stopped:
                return 128 + control.stopped
            completed = control.job.completed()
            if completed is not None:
                return completed
            now = time.monotonic()
            if now >= deadline:
                print("MIKAYA_MTG WALL_HOLD optional job stopped", flush=True)
                return HOLD_EXIT
            if now < next_check:
                control.wait(min(next_check, deadline) - now)
                continue
            observed = reader()
            if control.stopped:
                return 128 + control.stopped
            if decision(observed) != "ALLOW":
                safe_samples = 0
                if not paused:
                    control.job.send(signal.SIGSTOP)
                    paused = True
                    print(f"MIKAYA_MTG PAUSED severity={observed!r}", flush=True)
            elif paused:
                safe_samples += 1
                if safe_samples >= 2:
                    control.job.send(signal.SIGCONT)
                    paused = False
                    safe_samples = 0
                    print("MIKAYA_MTG RESUMED after two safe readings", flush=True)
            next_check = time.monotonic() + _interval


def _run(args, **fixtures):
    try:
        return _run_owned(args, **fixtures)
    except CleanupHold:
        print("MIKAYA_MTG CLEANUP_HOLD owned group requires explicit review", flush=True)
        return HOLD_EXIT


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args == ["_thermal_probe"]:
        value = _native_status()
        print(json.dumps({"android_thermal_severity": value}))
        return 0 if value is not None else HOLD_EXIT
    if not args or args[0] in ("help", "-h", "--help"):
        print("Usage: mikaya-nice status | run -- COMMAND [ARGS]")
        print("Only OPTIONAL jobs started with 'run' are managed. OEM controls untouched.")
        return 0
    if args[0] == "status":
        try:
            with Control() as control:
                severity = read_status(control)
                if control.stopped:
                    return 128 + control.stopped
        except CleanupHold:
            print("MIKAYA_MTG CLEANUP_HOLD owned probe requires explicit review",
                  file=sys.stderr)
            severity = None
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
    try:
        raise SystemExit(main())
    except CleanupHold:
        print("MIKAYA_MTG CLEANUP_HOLD owned group requires explicit review", flush=True)
        raise SystemExit(HOLD_EXIT)
