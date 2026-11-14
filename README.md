# Proof Gatekeeper agent — Agent Games (zkVerify, Season 01)

An autonomous agent for the Proof Gatekeeper track: it receives signed
task envelopes, verifies them, decides APPROVE/REJECT against the 7
documented trap varieties, and responds within the 60-second window.
Node.js stdlib only (plus `snarkjs` for proving). No secrets in this repo.

## Status (2026-11-15)

| Piece | State |
|---|---|
| Decision logic (7 traps + boundaries) | Implemented, 17/17 local checks green (Node + Workers builds) |
| HMAC verify + response signing | Implemented, tested (Node crypto + Web Crypto cross-checked) |
| Idempotency cache + seen-set (persistent) | Implemented, tested (JSON file locally, KV on Workers) |
| Chain confirmation | STUB — echoes payload VK; production needs Kurier/zkVerifyJS |
| Preflight handshake | Implemented (GET/POST /preflight + preflight envelope), tested |
| Groth16 proving | BLOCKED on circuit input schema (see below) |
| Public HTTPS endpoint | Cloudflare Workers build (`src/worker.mjs` + KV); deploy pending owner auth |
| Registration / preflight / practice | NOT DONE — needs the owner |

## Cloudflare Workers build

`src/worker.mjs` is the same decision logic as `src/server.mjs`,
adapted for Workers: Web Crypto HMAC (`worker-hmac.mjs`), KV-backed
seen-set + idempotency cache (`worker-store.mjs`), no filesystem, no
proving (snarkjs does not run in Workers, and the circuit input schema
is still unknown). Responses are always the event page's 3-key shape.
Deploy: `wrangler kv namespace create SEEN`, fill the id into
`wrangler.toml`, set `HMAC_SECRET` via `wrangler secret put` (after
registration shows it — exactly once, never commit it), then
`wrangler deploy`. A missing secret fails closed per request (500 on
`/task` and `/preflight`, `/health` stays up).

## The honest gaps

1. **Circuit input schema unknown.** The platform publishes the
   `gatekeeper.wasm` + `gatekeeper_final.zkey` + `vkHash` (nPublic = 13),
   but the signal names/meanings for `groth16.fullProve` are not in the
   public docs found. `src/prover.mjs` refuses to guess
   (`CIRCUIT_INPUT_SCHEMA_UNKNOWN`). Fill in `buildCircuitInput()` once
   the schema is confirmed from the platform starter prompt / dashboard
   docs. Likewise, the response proof format is disputed: the starter
   prompt says `{decision, reason_code, proof, public_signals}` (+
   `proof_tx`), the event page shows only `{decision, reason_code,
   proof_tx}`. The server defaults to the 3-field shape;
   `GK_ATTACH_PROOF=1` enables the prompt's shape. Practice mode decides.
   NOTE: artifact URLs under `/artifacts/` (seen in a rendered-page
   extract) return 404; the working URLs are the `/circuits/` ones from
   `/api/circuit-info` — use those.
2. **No stable public HTTPS endpoint here.** The rules require a public
   HTTPS address (no localhost, no custom ports) and forfeit tasks when
   the agent is offline. This VM has no public IP/domain and restarts
   unpredictably. Deployment needs real hosting (VPS / cloud) under the
   owner's account.
3. **Chain confirmation is a stub.** `src/chain.mjs` must be replaced
   with a real Kurier (`https://kurier.xyz` API key) or zkVerifyJS query
   before competing. `CHAIN_MODE=production` throws until it is wired in,
   so a fake confirmation can never run silently.

## Judgement calls (documented, verify in practice mode)

- Check precedence when several traps coincide: chain → VK → reuse →
  expiry → threshold → recipient → amount (docs don't specify).
- A proof is marked "seen" only when its task is APPROVED (the reuse
  trap says "already accepted").
- `INVALID_TASK` is our own reason code for malformed envelopes and
  unconfirmed proofs; it is not one of the 7 documented codes.
- HMAC header assumed to be hex HMAC-SHA256 over the raw body
  (`sha256=` prefix also accepted). Confirm at registration.

## Run locally

```sh
npm install
node download-artifacts.mjs   # official .wasm + .zkey (gitignored)
npm test                      # boots the server, runs all local checks
HMAC_SECRET=<secret> npm start
```

## Env vars

`PORT` (3000), `HMAC_SECRET` (required), `SEEN_FILE` (`./data/store.json`),
`CHAIN_MODE` (`stub`/`production`), `GK_ATTACH_PROOF` (`1` = attach proof
fields — keep off until the format is confirmed), `PROOF_BUDGET_MS`
(50000), `GK_WASM`/`GK_ZKEY`/`GK_VK` (artifact overrides).

## Scoring (from the event page)

Correct decision +12 · wrong APPROVE −6 · wrong REJECT −3 ·
timeout −2 · missing/invalid proof −2 · reliability bonus +0..+5/round.
8 tasks/day, 13–20 Nov 2026, 16:00–02:00 IST (17:30–03:30 WIB), cumulative.
