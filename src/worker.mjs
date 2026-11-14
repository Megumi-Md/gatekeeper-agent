// Gatekeeper agent — Cloudflare Workers build.
//
// Same decision semantics as src/server.mjs (Node build): raw body ->
// HMAC verify -> parse -> envelope checks -> idempotency cache ->
// chain confirm -> decide -> persist -> sign + respond. Fail closed at
// every step. Differences from the Node build:
//   * HMAC via Web Crypto (worker-hmac.mjs); seen-set + idempotency
//     cache in KV (worker-store.mjs); no filesystem, no process env.
//   * No proving: snarkjs + circuit artifacts do not run in Workers,
//     and the circuit input schema is still unknown, so there is no
//     GK_ATTACH_PROOF here. Responses are always the event page's
//     3-key shape {decision, reason_code, proof_tx}.
//   * A missing HMAC_SECRET fails closed per request (500) instead of
//     exiting at boot — /health stays up so a deploy can be verified
//     before the secret is set at agent registration time.
//   * KV is eventually consistent (see worker-store.mjs).
//
// Env (wrangler):
//   HMAC_SECRET  secret — set via `wrangler secret put HMAC_SECRET`
//                or the Cloudflare dashboard AFTER agent registration
//                shows it (exactly once). Never commit it.
//   SEEN         KV namespace binding (wrangler.toml).
//   CHAIN_MODE   "stub" (default) | "production" (throws until wired).
import { decide, REASON } from "./decide.mjs";
import { signHex, verifyHex } from "./worker-hmac.mjs";
import { kvStore } from "./worker-store.mjs";
import { confirmProof } from "./worker-chain.mjs";

const MAX_BODY = 1024 * 1024; // 1 MiB
const CLOCK_SKEW_MS = 5000;
const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function plainJson(status, obj) {
  return Response.json(obj, { status });
}

async function signedJson(status, obj, secret) {
  const body = JSON.stringify(obj);
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": await signHex(secret, body),
    },
  });
}

async function handleTask(request, env) {
  const t0 = Date.now();
  const secret = env.HMAC_SECRET;
  if (!secret) return plainJson(500, { error: "hmac secret not configured" });
  if (!env.SEEN) return plainJson(500, { error: "kv binding not configured" });
  const store = kvStore(env.SEEN);

  const rawBuf = await request.arrayBuffer();
  if (rawBuf.byteLength > MAX_BODY) return plainJson(413, { error: "body too large" });
  const raw = new Uint8Array(rawBuf);
  if (!(await verifyHex(secret, raw, request.headers.get("x-agent-games-signature")))) {
    log({ event: "reject", reason: "bad_signature" });
    return plainJson(401, { error: "bad signature" });
  }
  let envelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return plainJson(400, { error: "invalid json" });
  }

  // Preflight handshake delivered as a task envelope: answer the
  // handshake shape, signed. (Best-effort detection — the platform's
  // exact preflight marker is unconfirmed; GET/POST /preflight is the
  // primary handler.)
  if ((typeof envelope.type === "string" && envelope.type.includes("preflight")) || envelope.mode === "preflight") {
    return signedJson(200, { ok: true, protocolVersion: "v1" }, secret);
  }

  const taskId = typeof envelope.task_id === "string" ? envelope.task_id : null;
  if (!taskId || !envelope.input || typeof envelope.input !== "object") {
    return plainJson(400, { error: "missing task_id or input" });
  }

  // Idempotency: the platform may retry a delivery; replay the exact
  // cached response instead of deciding twice.
  const cached = await store.getResponse(taskId);
  if (cached !== null) {
    log({ event: "replay", task_id: taskId, ms: Date.now() - t0 });
    return new Response(cached, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": await signHex(secret, cached),
      },
    });
  }

  const finish = async (result) => {
    const bodyObj = {
      decision: result.decision,
      reason_code: result.reason_code,
      proof_tx: result.proof_tx,
    };
    const body = JSON.stringify(bodyObj);
    if (result.decision === "APPROVE" && result.proof_tx) {
      await store.markSeen(String(result.proof_tx).toLowerCase());
    }
    await store.putResponse(taskId, body);
    log({
      event: "decision", task_id: taskId, decision: result.decision,
      reason_code: result.reason_code, ms: Date.now() - t0,
      checks: result.checks, proof: "not-attached (workers)",
    });
    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": await signHex(secret, body),
      },
    });
  };

  // Envelope type check (only when the field is present).
  if (envelope.type && envelope.type !== GATEKEEPER_TYPE) {
    return finish({ decision: "REJECT", reason_code: REASON.INVALID, proof_tx: envelope.input.proof_tx ?? null, checks: ["unexpected envelope type"] });
  }
  // Timestamp validity: never work on an already-expired task.
  if (envelope.deadline_at) {
    const dl = Date.parse(envelope.deadline_at);
    if (Number.isNaN(dl)) {
      return finish({ decision: "REJECT", reason_code: REASON.INVALID, proof_tx: envelope.input.proof_tx ?? null, checks: ["unparseable deadline_at"] });
    }
    if (Date.now() > dl + CLOCK_SKEW_MS) {
      return finish({ decision: "REJECT", reason_code: REASON.INVALID, proof_tx: envelope.input.proof_tx ?? null, checks: ["deadline_at already passed"] });
    }
  }

  let chain;
  try {
    chain = await confirmProof(envelope, { mode: env.CHAIN_MODE || "stub" });
  } catch (err) {
    log({ event: "chain_error", task_id: taskId, error: String(err && err.message) });
    return finish({ decision: "REJECT", reason_code: REASON.INVALID, proof_tx: envelope.input.proof_tx ?? null, checks: ["chain confirmation failed"] });
  }

  // decide() checks exactly one proof_tx (the input's); prefetch it
  // from KV and answer through a Set-like adapter.
  const proofTxLower = typeof envelope.input.proof_tx === "string" ? envelope.input.proof_tx.trim().toLowerCase() : "";
  const seenBefore = proofTxLower ? await store.hasSeen(proofTxLower) : false;
  const seenProofs = { has: (v) => v === proofTxLower && seenBefore };
  const result = decide(envelope.input, { seenProofs, chain });
  return finish(result);
}

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (request.method === "GET" && (path === "/health" || path === "/")) {
        return plainJson(200, { ok: true, service: "gatekeeper-agent", runtime: "cloudflare-workers" });
      }
      if (path === "/preflight") {
        // Preflight handshake (platform starter prompt): signed
        // {ok, protocolVersion}. Unauthenticated so the platform can
        // probe liveness; the RESPONSE is still signed with the HMAC
        // secret, so without the secret this fails closed (500).
        if (!env.HMAC_SECRET) return plainJson(500, { error: "hmac secret not configured" });
        return signedJson(200, { ok: true, protocolVersion: "v1" }, env.HMAC_SECRET);
      }
      if (request.method === "POST" && (path === "/task" || path === "/")) {
        return await handleTask(request, env);
      }
      return plainJson(404, { error: "not found" });
    } catch (err) {
      log({ event: "error", error: String((err && err.stack) || err) });
      return plainJson(500, { error: "internal" });
    }
  },
};
