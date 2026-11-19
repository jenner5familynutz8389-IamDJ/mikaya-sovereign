# MIKAYA-SOVEREIGN / AHAVA

Public-source snapshot of the owner-controlled Sovereign Duty, Sentinel, AHAVA distribution and signed event-spine project.

## Tested on two Android devices
- Independent device-generated Ed25519 signing identities.
- AES-256-GCM encrypted chunks with SHA-256 content identifiers.
- Signed manifests verified for FOSSiBOT F110 Pro and Motorola Moto G Power 5G 2023 (devonn).
- Bidirectional private-network object replication and restored sample bytes.
- Append-only correction records and signed local checkpoints.
- Startup health-watch scripts prepared. A physical reboot/cold-start test is NOT yet certified.

## GitSync
On FOSSiBOT, sign into GitSync with your GitHub account, select the option for an EXISTING LOCAL REPOSITORY, and select the folder containing this README. The remote repository is jenner5familynutz8389-IamDJ/mikaya-sovereign. Sync/push only after inspecting the changes.

## Security
Only this curated source folder belongs on public GitHub. Do not add the private Termux home, signing keys, mesh secret, personal telemetry, proprietary firmware images, or recovery secrets. The code is intended to run behind a private encrypted overlay, not an exposed HTTP server.

The public health-watch example substitutes localhost for the owner's private device IP. Adjust per authorized deployment.

Signed user-space source is NOT an OEM-signed boot/vendor image for a locked Android device.

## Reviewed source and evidence

The [mobile-edge review update](engineering/federation/mobile-edge/README.md) adds an owner-local signed evidence interface, stricter ACT ingress checks, and verified AHAVA resume. The standalone evidence service is installed on both phones at `127.0.0.1:4188`, with fresh signed native captures recorded in the [November 18 acceptance report](engineering/federation/mobile-edge/NATIVE_ACCEPTANCE_20261118.md). The source passed 209 local tests; saved public-key proofs can be verified independently. These results are separate from the historical two-phone replication above. ACT admission remains HOLD, and the revised AHAVA pull path has not yet been deployed to the active phone mesh or physically benchmarked.

See the [current source index](docs/CURRENT_SOURCE_INDEX_20261115.md) for the reviewed runtime, collaboration, Android input-contract and research sources. Repository publication, device acceptance and external partner admission remain separate recorded states.

The [public source boundary](docs/oem/PUBLIC_GITHUB_SOURCE_BOUNDARY_20261115.md) records the intentional Android HOLD when private provenance or external AOSP/OEM inputs are unavailable.
