# ACT-Omega optional backend — candidate implementation and verification contract

Source reviewed on November 8, 2026: ACT's public repository `bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-`, branch `vesper_production`, especially `00_control/cloudflare_edge/worker_continuum_do.js`, `00_control/cloudflare_edge/wrangler.toml` and `02_gateway_deno/server.ts`. This is an independent project; do not copy its code, deploy to ACT's Cloudflare account or infer consent from a public API.

## Findings and boundary

- ACT advertises public MCP discovery at `https://mcp.act-omega-net.dev/mcp` and Cloudflare Worker/D1/DO components; published Deno HTTP gateway source offers another potential backend.
- One published Cloudflare worker implementation responds to most `tools/call` methods using constant `TOOL_CALLED_OK` responses. Thus MCP discovery and tool-call success are **not verifiable remote computation**.
- The HTTP/WebSocket Deno gateway includes Windows-specific model paths. Deployment, uptime and AI model claims must be measured independently.
- GitHub repository access and ACT live-node enrollment are different things. ACT repository permission and identity must be authenticated separately.

## Minimum interoperable ACT-owned service

ACT should run its own peer service implementing the existing `federation-node.cjs` signed envelope for `/v1/hello` and the bounded `/v1/task` route. It may implement an adapter between its engine and MIKAYA's two established capabilities (`compute.dot.v1`, `compute.sha256.v1`). MIKAYA independently recomputes and verifies returned results. ACT owns its private key, endpoint, compute service, wallet, data and revocation controls.

A valid task requires a nonce-bound, signed owner request, explicit limited capability, an ACT-signed reply covering the digest of the actual result and a correct deterministic computation. `act-backend-compat.cjs` checks the public envelope **offline**; it never grants rights or sends requests over the network. No public "tool called" status, database table count, reported model weight total, or generic success flag counts as work evidence.

No ACT peer has completed authenticated external physical enrollment yet. Before backend activation, the signed invite/reply, independently verified hardware credential, owner-signed limited grant, private authenticated network route, worker identity and replay protections **all must pass**. Payments/L402 and chain acknowledgments are separate and currently disabled.

## Tests

```bash
node --test engineering/federation/live/tests/test_act_backend_compat.cjs
node --test engineering/federation/live/tests/*.cjs
node --test engineering/federation/live/evidence-brief/tests/*.cjs
```

Passing unit tests prove the **contract logic** with synthetic keys. They do not prove ACT owns the public endpoint, runs the right hardware or has accepted MIKAYA's invitation. The user’s real phone-to-phone network stays independent.
