// Local end-to-end tests: boots the real server, POSTs signed synthetic
// tasks covering every documented trap variety, and asserts decisions,
// reason codes, HMAC behaviour, idempotent replay, and timing.
// Run: node test/run-tests.mjs   (exit 0 = all green)
import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signHex, verifyHex } from "../src/hmac.mjs";
import { proveDecision, ProverSkipped } from "../src/prover.mjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 3456;
const SECRET = "test-secret-do-not-use-in-production";
const SEEN_FILE = path.join(mkdtempSync(path.join(tmpdir(), "gk-test-")), "store.json");
const BASE = `http://127.0.0.1:${PORT}`;
const VK_A = `0x${"7d".repeat(32)}`;
const VK_B = `0x${"a4".repeat(32)}`;
const ADDR = `0x${"de".repeat(20)}`;
const ADDR_OTHER = `0x${"be".repeat(20)}`;
let n = 0;

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

async function post(pathname, bodyObj, { secret = SECRET, rawBody = null } = {}) {
  const raw = rawBody ?? JSON.stringify(bodyObj);
  const res = await fetch(`${BASE}${pathname}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": signHex(secret, raw),
    },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: safeJson(text) };
}

function safeJson(t) { try { return JSON.parse(t); } catch { return null; } }

function check(name, fn) {
  n += 1;
  fn();
  console.log(`  PASS ${n}. ${name}`);
}

async function waitHealth(proc) {
  const t0 = Date.now();
  while (Date.now() - t0 < 8000) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("server did not come up");
}

const server = spawn("node", ["src/server.mjs"], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), HMAC_SECRET: SECRET, SEEN_FILE, CHAIN_MODE: "stub" },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverOut = "";
server.stdout.on("data", (d) => { serverOut += d; });
server.stderr.on("data", (d) => { serverOut += d; });

try {
  await waitHealth(server);
  console.log("server up; running cases...\n");

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
    const raw = "{not json";
    const res = await fetch(`${BASE}/task`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-agent-games-signature": signHex(SECRET, raw) },
      body: raw,
    });
    check("malformed JSON -> 400", () => assert.equal(res.status, 400));
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

  // GET /preflight -> signed handshake shape
  {
    const res = await fetch(`${BASE}/preflight`);
    const text = await res.text();
    check("GET /preflight -> signed {ok, protocolVersion v1}", () => {
      assert.equal(res.status, 200);
      assert.deepEqual(safeJson(text), { ok: true, protocolVersion: "v1" });
      assert.ok(verifyHex(SECRET, text, res.headers.get("x-agent-games-signature")));
    });
  }

  // Preflight-marked envelope -> handshake shape, signed
  {
    const r = await post("/task", { type: "agent-games.preflight.v1", task_id: "pf-1", mode: "preflight", input: {} });
    check("preflight envelope -> signed handshake shape", () => {
      assert.equal(r.status, 200);
      assert.deepEqual(r.json, { ok: true, protocolVersion: "v1" });
      assert.ok(verifyHex(SECRET, r.text, r.headers.get("x-agent-games-signature")));
    });
  }

  // Prover refuses to guess the circuit input schema
  {
    let err = null;
    try {
      await proveDecision(envelope("t-prove", taskInput()), { decision: "APPROVE", reason_code: "VALID_CONDITION" });
    } catch (e) { err = e; }
    check("prover throws CIRCUIT_INPUT_SCHEMA_UNKNOWN (no fabricated inputs)", () => {
      assert.ok(err instanceof ProverSkipped);
      assert.equal(err.reason, "CIRCUIT_INPUT_SCHEMA_UNKNOWN");
    });
  }

  console.log(`\nALL ${n} CHECKS PASSED`);
} finally {
  server.kill("SIGTERM");
  await new Promise((r) => server.on("exit", r));
}
