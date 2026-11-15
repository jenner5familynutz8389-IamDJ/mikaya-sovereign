# Versioned MTG V2 optional-job owner

This versioned, generic Termux optional-job owner preserves the existing status/run interface and adds bounded measurement-child and owned-process lifecycle handling. Publishing this source creates no daemon and installs no policy, environment, service, permission, thermal setting or boot change. The original policy with SHA-256 `6d41877fa3e288cf17cfab8b7b323090a001eacc0770108404aa3e7c18cad933` remains a separate version; this package does not migrate it or change existing adapters.

## Compatible interface

The source supports the existing commands:

    python mtg_nice_policy_v2.py status
    python mtg_nice_policy_v2.py run -- COMMAND [ARG...]

Status retains the original **eight JSON fields**, return 0 for observed severity 0/1, and return 75 with HOLD for hot, unknown, unavailable or failed cleanup. Cleanup diagnostics go to stderr, preserving JSON stdout. The legacy nice_increase field stays 15; V2 sets a **minimum niceness of 15**, preserving an already lower scheduling priority. Optional command stdin remains inherited; fixed measurement probes use DEVNULL.

Startup hot/unknown returns 75 immediately without starting the command. Safe startup requires two actual severity 0/1 readings separated by ten seconds. Once running, checks use the original ten-second interval. Severity 2 or above or unknown pauses only the created job group. Two fresh safe readings resume the same child. No retry or replacement child is launched.

The optional-run wall deadline defaults to **21,600 seconds (six hours)**, counting startup gaps, active work and paused HOLD. The environment key is:

    MIKAYA_MTG_MAX_WALL_SECONDS

Only an integer from 1 through 21600 is accepted. It can shorten the bound and cannot disable it. At expiry termination starts; group shutdown/reaping is separately bounded. This does not promise hard real-time scheduling from the operating system.

## Public Android measurement and SDK 34 compatibility

The actual measurement remains Android's public NDK thermal API through the absolute system libandroid.so, with explicit acquire/get-status/release ctypes prototypes. No dumpsys, DUMP permission, root, privileged HAL or Binder replacement is used.

Each read has a shared three-second deadline. A fixed /system/bin/getprop query reads the public SDK property in a minimal per-query environment; its sub-budget is one second. A separate isolated Python child calls the NDK API using the remaining deadline. Output is bounded. Missing API, native crash, malformed/oversized output, nonzero result or deadline maps to unknown/HOLD.

Only SDK 34's measurement child receives:

    LD_LIBRARY_PATH=/system/lib64:/data/data/com.termux/files/usr/lib

An absent/empty preload is accepted. If LD_PRELOAD is exactly the standard Termux libtermux-exec.so path, only that known preload is removed from this child. Unknown, combined, whitespace-altered or aliased preload settings HOLD; they are never stripped and silently trusted. Other accepted SDK versions retain their ordinary measurement-child environment. The caller's environment and the optional command's environment remain unchanged.

## Owned lifecycle

TERM, INT and HUP flag cancellation and wake the controller without throwing between Popen and ownership assignment. Each probe and optional job has a newly created session/group, a child priority floor and parent-death signal. No shared remote-control group is signaled.

The optional leader is retained with waitid(WNOWAIT), including natural exit, until its own group receives TERM, CONT and then bounded KILL before final reap. This avoids reusing a free leader PID to signal a foreign group and cleans ordinary same-group descendants. A blocked probe is killed/reaped independently; its cleanup failure cannot skip job cleanup. Lost wait ownership refuses further group signaling. Missing wait support or a conflicting external child reaper holds safely.

This covers **attached foreground commands and their original group**. Commands deliberately using setpgid/setsid, daemonizing, changing ownership or managing nested sessions need their own matching cleanup contract. An external SIGKILL or kernel-uninterruptible process cannot be turned into a universal cleanup/sandbox guarantee. Failed cleanup is explicitly HOLD, not success. A new dedicated CLI process owns its child-reaping hooks; this is not a general supervisor to embed beside an unrelated child reaper.

## Verification and native selection

Twenty host test methods passed, exercising real Linux children, signals, paused groups, ignored TERM, natural leader exit with a surviving same-group descendant, startup and paused wall expiry, spawn-return cancellation, blocked probes, actual nice floors 0→15 and 15→15, strict loader copies, EOF races, lost wait ownership and status JSON on cleanup failure.

Lifecycle test thermal values and shortened intervals are explicitly **synthetic host fixtures**. The executable CLI offers no fake severity/ALLOW switch. The host status check actually returns unknown/HOLD. These checks do not establish native Android sensor acceptance or a safe cold job execution.

Native installation and acceptance are separate operator-selected actions. This publication contains no installer, launcher change, active configuration or private operational receipt. Native acceptance is not established by the host checks recorded here. An operator must independently verify exact installed source/launcher bytes and actual status/run rejection or execution behavior under current readings. Keep the original source/version and prior receipts; do not replace a global policy or force a cold observation to make acceptance pass.

## Source and public export

The runtime and host test files retain their independently reviewed bytes. `SOURCE_PROVENANCE.json` records their hashes; `VERIFICATION.json` distinguishes the recorded host checks from native acceptance. `PACKAGE_MANIFEST.json` hashes the five other public files. Private helpers, configurations, device inventories, credentials and raw operational receipts are excluded. This source is Linux/Android specific and is not a portable sandbox or a general replacement supervisor.
