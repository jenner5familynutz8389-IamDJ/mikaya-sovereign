# Security and release gates
- Device-local Ed25519 signatures and AES-256-GCM ciphertext are independent of Android bootloader signing.
- SHA-256 chunk digests protect integrity; encrypted data must still be retained to restore contents.
- The append-only correction ledger is NOT distributed blockchain consensus.
- Peer HTTP MUST remain within an owner-authenticated private encrypted network; the bearer secret must not be published.
- Physical Android boot, SELinux/vendor HAL integration, OTA and rollback handling require OEM build review and signing.
- Accessible-storage SHA-256 inventory does not establish protected Android partition integrity.
- No credentials or personal telemetry are included here.
