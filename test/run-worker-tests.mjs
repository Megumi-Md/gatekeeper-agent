// Workers-build tests: call the fetch handler directly with a mock KV
// namespace, mirroring every case in test/run-tests.mjs. HMAC is
// cross-checked against the Node implementation: the test signs with
// node:crypto (src/hmac.mjs) and the Worker verifies with Web Crypto,
// and response signatures from the Worker are verified with node:crypto.
// Any drift between the two HMAC implementations fails loudly here.
// Run: node test/run-worker-tests.mjs   (exit 0 = all green)
import assert from "node:assert/strict";
import worker from "../src/worker.mjs";
import { signHex, verifyHex } from "../src/hmac.mjs";

const SECRET = "test-secret-do-not-use-in-production";
const VK_A = `0x${"7d".repeat(32)}`;
const VK_B = `0x${"a4".repeat(32)}`;
const ADDR = `0x${"de".repeat(20)}`;
const ADDR_OTHER = `0x${"be".repeat(20)}`;
let n = 0;

function mockKV() {
  const m = new Map();
  return {
    async get(k) { const v = m.get(k); return v === undefined ? null : v; },
    async put(k, v) { m.set(k, v); },
  };
}

const env = { HMAC_SECRET: SECRET, SEEN: mockKV(), CHAIN_MODE: "stub" };

function taskInput(over = {}) {
  return {
    registered_vk: VK_A,
    proof_vk: VK_A,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: "500",
    max_transfer: "1000",
    proof_tx: `0x${"c1".repeat(32)}`,
    ...over,
  };
}

function envelope(task_id, input, over = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id,
    mode: "competition",
    issued_at: new Date(Date.now() - 1000).toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
    ...over,
  };
}

async function post(pathname, bodyObj, { secret = SECRET, rawBody = null, useEnv = env } = {}) {
  const raw = rawBody ?? JSON.stringify(bodyObj);
  const req = new Request(`https://worker.test${pathname}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": signHex(secret, raw),
    },
    body: raw,
  });
  const res = await worker.fetch(req, useEnv, {});
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: safeJson(text) };
}

async function get(pathname, useEnv = env) {
  const res = await worker.fetch(new Request(`https://worker.test${pathname}`), useEnv, {});
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: safeJson(text) };
}

function safeJson(t) { try { return JSON.parse(t); } catch { return null; } }

function check(name, fn) {
  n += 1;
  fn();
  console.log(`  PASS ${n}. ${name}`);
}

// 1. Valid condition -> APPROVE
{
  const t0 = Date.now();
  const r = await post("/task", envelope("t-valid", taskInput()));
  const ms = Date.now() - t0;
  check(`valid -> APPROVE/VALID_CONDITION (${ms}ms, exact 3-key response, signed)`, () => {
    assert.equal(r.status, 200);
    assert.deepEqual(Object.keys(r.json).sort(), ["decision", "proof_tx", "reason_code"]);
    assert.equal(r.json.decision, "APPROVE");
    assert.equal(r.json.reason_code, "VALID_CONDITION");
    assert.ok(verifyHex(SECRET, r.text, r.headers.get("x-agent-games-signature")));
    assert.ok(ms < 2000, `too slow: ${ms}ms`);
  });
}

// 2. VK substitution
{
  const r = await post("/task", envelope("t-vk", taskInput({ proof_vk: VK_B, proof_tx: `0x${"c2".repeat(32)}` })));
  check("vk substitution -> REJECT/VK_SUBSTITUTION", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "VK_SUBSTITUTION");
  });
}

// 3. Threshold mismatch
{
  const r = await post("/task", envelope("t-thr", taskInput({ public_balance: "999", proof_tx: `0x${"c3".repeat(32)}` })));
  check("threshold -> REJECT/THRESHOLD_MISMATCH", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "THRESHOLD_MISMATCH");
  });
}

// 4. Proof reuse: approve first, then same proof_tx in a new task
{
  const proofTx = `0x${"c4".repeat(32)}`;
  const first = await post("/task", envelope("t-reuse-1", taskInput({ proof_tx: proofTx })));
  assert.equal(first.json.decision, "APPROVE");
  const second = await post("/task", envelope("t-reuse-2", taskInput({ proof_tx: proofTx })));
  check("proof reuse -> REJECT/PROOF_REUSED", () => {
    assert.equal(second.json.decision, "REJECT");
    assert.equal(second.json.reason_code, "PROOF_REUSED");
  });
}

// 5. Expired condition
{
  const r = await post("/task", envelope("t-exp", taskInput({ current_block: 19842202, proof_tx: `0x${"c5".repeat(32)}` })));
  check("expired -> REJECT/EXPIRED_CONDITION", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "EXPIRED_CONDITION");
  });
}

// 6. Recipient mismatch
{
  const r = await post("/task", envelope("t-rcpt", taskInput({ recipient: ADDR_OTHER, proof_tx: `0x${"c6".repeat(32)}` })));
  check("recipient -> REJECT/RECIPIENT_MISMATCH", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "RECIPIENT_MISMATCH");
  });
}

// 7. Amount overflow
{
  const r = await post("/task", envelope("t-amt", taskInput({ amount: "1001", proof_tx: `0x${"c7".repeat(32)}` })));
  check("overflow -> REJECT/AMOUNT_OVERFLOW", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "AMOUNT_OVERFLOW");
  });
}

// 8. Boundary values: balance == minimum, amount == cap, block == expiry -> APPROVE
{
  const r = await post("/task", envelope("t-edge", taskInput({
    public_balance: "1000", amount: "1000", current_block: 19842201, proof_tx: `0x${"c8".repeat(32)}`,
  })));
  check("boundaries (==) -> APPROVE", () => {
    assert.equal(r.json.decision, "APPROVE");
    assert.equal(r.json.reason_code, "VALID_CONDITION");
  });
}

// 9. Bad HMAC -> 401, no decision recorded
{
  const r = await post("/task", envelope("t-badhmac", taskInput({ proof_tx: `0x${"c9".repeat(32)}` })), { secret: "wrong-secret" });
  check("bad HMAC -> 401", () => assert.equal(r.status, 401));
}

// 10. Idempotent replay: same task_id returns the identical body
{
  const first = await post("/task", envelope("t-replay", taskInput({ proof_tx: `0x${"ca".repeat(32)}` })));
  const second = await post("/task", envelope("t-replay", taskInput({ proof_tx: `0x${"ca".repeat(32)}` })));
  check("replay same task_id -> identical cached body", () => {
    assert.equal(second.status, 200);
    assert.equal(second.text, first.text);
  });
}

// 11. Malformed JSON -> 400
{
  const r = await post("/task", null, { rawBody: "{not json" });
  check("malformed JSON -> 400", () => assert.equal(r.status, 400));
}

// 12. Missing field -> REJECT/INVALID_TASK (fail closed)
{
  const input = taskInput({ proof_tx: `0x${"cb".repeat(32)}` });
  delete input.minimum;
  const r = await post("/task", envelope("t-missing", input));
  check("missing field -> REJECT/INVALID_TASK", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "INVALID_TASK");
  });
}

// 13. Expired deadline_at -> REJECT/INVALID_TASK
{
  const r = await post("/task", envelope("t-past", taskInput({ proof_tx: `0x${"cc".repeat(32)}` }),
    { deadline_at: new Date(Date.now() - 60000).toISOString() }));
  check("past deadline_at -> REJECT/INVALID_TASK", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "INVALID_TASK");
  });
}

// 14. Proof not confirmed on-chain (stub hook) -> REJECT/INVALID_TASK
{
  const r = await post("/task", envelope("t-noproof", taskInput({ proof_tx: "0xmissing" })));
  check("unconfirmed proof -> REJECT/INVALID_TASK", () => {
    assert.equal(r.json.decision, "REJECT");
    assert.equal(r.json.reason_code, "INVALID_TASK");
  });
}

// 15. GET /preflight -> signed handshake shape
{
  const r = await get("/preflight");
  check("GET /preflight -> signed {ok, protocolVersion v1}", () => {
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
    assert.ok(verifyHex(SECRET, r.text, r.headers.get("x-agent-games-signature")));
  });
}

// 16. Preflight-marked envelope -> handshake shape, signed
{
  const r = await post("/task", { type: "agent-games.preflight.v1", task_id: "pf-1", mode: "preflight", input: {} });
  check("preflight envelope -> signed handshake shape", () => {
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
    assert.ok(verifyHex(SECRET, r.text, r.headers.get("x-agent-games-signature")));
  });
}

// 17. Missing HMAC_SECRET fails closed (500 on signed paths, /health stays up)
{
  const noSecretEnv = { SEEN: mockKV(), CHAIN_MODE: "stub" };
  const t = await post("/task", envelope("t-nosecret", taskInput()), { useEnv: noSecretEnv });
  const p = await get("/preflight", noSecretEnv);
  const h = await get("/health", noSecretEnv);
  check("no HMAC_SECRET -> /task 500, /preflight 500, /health 200", () => {
    assert.equal(t.status, 500);
    assert.equal(p.status, 500);
    assert.equal(h.status, 200);
    assert.equal(h.json.service, "gatekeeper-agent");
  });
}

console.log(`\nALL ${n} CHECKS PASSED`);
