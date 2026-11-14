// Gatekeeper agent HTTP server (Node stdlib only).
//
// POST /task (and POST /) — signed task envelope from the platform.
// GET  /health (and GET /) — unauthenticated health check.
//
// Env:
//   PORT            listen port (default 3000)
//   HMAC_SECRET     REQUIRED — 32-byte secret issued at agent registration
//   SEEN_FILE       persistent store path (default ./data/store.json)
//   CHAIN_MODE      stub (default) | production (see chain.mjs)
//   GK_ATTACH_PROOF "1" to attach {proof, public_signals} (the starter
//                   prompt's shape) — DEFAULT OFF. The event page's
//                   "Required response" shows only {decision,
//                   reason_code, proof_tx}; the two specs disagree and
//                   strict validators reject unknown fields. Keep OFF
//                   until practice mode confirms the format.
//   PROOF_BUDGET_MS soft budget for proving within the 60s window
//                   (default 50000).
//
// Flow: raw body -> HMAC verify -> parse -> envelope checks ->
// idempotency cache -> chain confirm -> decide -> (optional prove) ->
// persist -> sign + respond. Fail closed at every step.
import { createServer } from "node:http";
import { decide, REASON } from "./decide.mjs";
import { signHex, verifyHex } from "./hmac.mjs";
import { loadStore, saveStore } from "./seen.mjs";
import { confirmProof } from "./chain.mjs";
import { proveDecision, ProverSkipped } from "./prover.mjs";

const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.HMAC_SECRET;
const SEEN_FILE = process.env.SEEN_FILE || "./data/store.json";
const ATTACH_PROOF = process.env.GK_ATTACH_PROOF === "1";
const PROOF_BUDGET_MS = Number(process.env.PROOF_BUDGET_MS || 50000);
const MAX_BODY = 1024 * 1024; // 1 MiB
const CLOCK_SKEW_MS = 5000;
const GATEKEEPER_TYPE = "agent-games.proof-gatekeeper.v1";

if (!SECRET) {
  console.error("FATAL: HMAC_SECRET env is required (never commit the secret)");
  process.exit(1);
}

const store = loadStore(SEEN_FILE);

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function sendJson(res, status, obj, { sign = false } = {}) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = signHex(SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function handleTask(req, res) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    return sendJson(res, 413, { error: "body too large" });
  }
  if (!verifyHex(SECRET, raw, req.headers["x-agent-games-signature"])) {
    log({ event: "reject", reason: "bad_signature" });
    return sendJson(res, 401, { error: "bad signature" });
  }
  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "invalid json" });
  }

  // Preflight handshake delivered as a task envelope: answer the
  // handshake shape, signed. (Best-effort detection — the platform's
  // exact preflight marker is unconfirmed; GET/POST /preflight is the
  // primary handler.)
  if ((typeof envelope.type === "string" && envelope.type.includes("preflight")) || envelope.mode === "preflight") {
    return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, { sign: true });
  }

  const taskId = typeof envelope.task_id === "string" ? envelope.task_id : null;
  if (!taskId || !envelope.input || typeof envelope.input !== "object") {
    return sendJson(res, 400, { error: "missing task_id or input" });
  }

  // Idempotency: the platform may retry a delivery; replay the exact
  // cached response instead of deciding twice.
  if (Object.prototype.hasOwnProperty.call(store.responses, taskId)) {
    const cached = store.responses[taskId];
    log({ event: "replay", task_id: taskId, ms: Date.now() - t0 });
    return sendJson(res, 200, JSON.parse(cached), { sign: true });
  }

  const finish = (result, extra = {}) => {
    const { _log, ...attach } = extra;
    const bodyObj = {
      decision: result.decision,
      reason_code: result.reason_code,
      proof_tx: result.proof_tx,
      ...attach,
    };
    const body = JSON.stringify(bodyObj);
    if (result.decision === "APPROVE" && result.proof_tx) {
      store.seen.add(String(result.proof_tx).toLowerCase());
    }
    store.responses[taskId] = body;
    saveStore(SEEN_FILE, store);
    log({
      event: "decision", task_id: taskId, decision: result.decision,
      reason_code: result.reason_code, ms: Date.now() - t0,
      checks: result.checks, ...extra._log,
    });
    const headers = {
      "content-type": "application/json",
      "x-agent-games-signature": signHex(SECRET, body),
    };
    res.writeHead(200, headers);
    res.end(body);
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
    chain = await confirmProof(envelope);
  } catch (err) {
    log({ event: "chain_error", task_id: taskId, error: String(err && err.message) });
    return finish({ decision: "REJECT", reason_code: REASON.INVALID, proof_tx: envelope.input.proof_tx ?? null, checks: ["chain confirmation failed"] });
  }

  const result = decide(envelope.input, { seenProofs: store.seen, chain });

  // Proof: only for provable tasks (PROOF_REUSED tasks have no proof to
  // submit), only when the attach format is enabled, only within budget.
  let proofLog = { proof: "not-attached" };
  let extra = {};
  if (ATTACH_PROOF && result.reason_code !== REASON.REUSED && Date.now() - t0 < PROOF_BUDGET_MS) {
    try {
      const p = await proveDecision(envelope, result);
      // Shape per the platform starter prompt: {decision, reason_code,
      // proof, public_signals} (+ proof_tx). NOTE: the event page's
      // "Required response" block shows only {decision, reason_code,
      // proof_tx} — the two specs disagree; practice mode decides.
      extra = { proof: p.proof, public_signals: p.publicSignals };
      proofLog = { proof: "attached", proof_ms: p.ms, verified_locally: p.verified };
    } catch (err) {
      proofLog = { proof: "skipped", reason: err instanceof ProverSkipped ? err.reason : String(err && err.message) };
    }
  }
  return finish(result, { ...extra, _log: proofLog });
}

const server = createServer((req, res) => {
  const path = (req.url || "/").split("?")[0];
  if (req.method === "GET" && (path === "/health" || path === "/")) {
    return sendJson(res, 200, { ok: true, service: "gatekeeper-agent", uptime_ms: Math.round(process.uptime() * 1000) });
  }
  if (path === "/preflight") {
    // Preflight handshake (platform starter prompt): signed
    // {ok, protocolVersion}. Unauthenticated so the platform can probe
    // liveness; the RESPONSE is still signed with the HMAC secret.
    if (req.method === "POST") req.resume();
    return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, { sign: true });
  }
  if (req.method === "POST" && (path === "/task" || path === "/")) {
    return handleTask(req, res).catch((err) => {
      log({ event: "error", error: String(err && err.stack || err) });
      if (!res.headersSent) sendJson(res, 500, { error: "internal" });
    });
  }
  return sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  log({ event: "listening", port: PORT, attach_proof: ATTACH_PROOF, chain_mode: process.env.CHAIN_MODE || "stub" });
});
