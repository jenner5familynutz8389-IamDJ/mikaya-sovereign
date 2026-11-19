# Direct transport deployment — November 19, 2026

This is an active execution record. Final handset deployment evidence is being collected in the owner-authorized engineering session.

## Implemented and executed

The current source adds mutually authenticated TLS 1.3, certificate and application-key pins, TLS exporter binding, persisted owner controls, durable replay enforcement, independent signed receipt ledgers, exact nonmonetary accounting, and a supervised private-address service.

The corrected workspace acceptance run executed **129/129 tests**, with zero failures, skips, cancellations or todos. Its 27-file executed source inventory is:

```text
d544a1f5b9ec6fa38a8ff093a18f396508ee446712e4401a59a46523bf1f8e8b
```

## Actual Android incompatibility found and fixed

The first expanded physical run executed all 124 cases on both F110 and Motorola: 77 passed and 47 failed on each phone. The shared cause was Android refusing the receipt ledger's hard-link commit operation with EACCES. The retained failure logs were not discarded or described as passing.

The revised ledger uses exclusive final-path creation, a durable append lock, and file/directory synchronization. Incomplete writes or failed synchronization preserve the record and lock for explicit recovery. Four added regressions cover denied hard links, partial writes, failed synchronization, and a competing final-path writer. The next physical run passed 128/128 on F110 and 119/128 on Motorola. The remaining nine Motorola failures were isolated to the lifecycle controller: its actual procfs command line repeats the Node executable before the script path. The controller now recognizes exactly that observed Android form while rejecting arbitrary prefixes and mismatched state. One regression was added. Both phones are executing the final 129-case source; final deployment results will replace this in-progress status.

## Deployment scope

Deployment targets are the owner's F110 Pro and Motorola. Each device generated its own new local application/TLS keys; only signed public pairing manifests were exchanged. The explicit fixture policy accounts in NONMONETARY_COMPUTE_UNIT, without asserting monetary settlement, mining rewards, or wallet authority. ACT-side execution and manufacturer hardware attestation are separate evidence.

See [DIRECT_TRANSPORT.md](DIRECT_TRANSPORT.md) for commands and security boundaries, [LEDGER_RECEIPTS.md](LEDGER_RECEIPTS.md) for persistence/accounting semantics, and [EXECUTED_VALIDATION_20261119.md](EXECUTED_VALIDATION_20261119.md) for the earlier historical 75-case owner-carried baseline.
