// Pure Gatekeeper decision logic — no I/O, no secrets, no clock reads.
// Implements the 7 documented trap varieties from the Proof Gatekeeper
// event page (https://agentgames.zkverify.io/events/proof-gatekeeper):
//   VALID_CONDITION (~50%), VK_SUBSTITUTION (~13%), PROOF_REUSED (~11%),
//   THRESHOLD_MISMATCH (~8%), EXPIRED_CONDITION / RECIPIENT_MISMATCH /
//   AMOUNT_OVERFLOW (~6% each).
//
// Precedence is OUR choice — the docs do not specify one for tasks that
// carry several traps at once (the published frequencies sum to ~100%,
// implying single-trap tasks). Order: chain -> VK -> reuse -> expiry ->
// threshold -> recipient -> amount. Fail closed on anything malformed.
//
// INVALID_TASK is our own reason code for malformed envelopes and
// proofs the chain cannot confirm; it is not one of the 7 documented
// codes. It is used only when no documented code applies.

export const REASON = Object.freeze({
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  REUSED: "PROOF_REUSED",
  THRESHOLD: "THRESHOLD_MISMATCH",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID: "INVALID_TASK",
});

const HEX40 = /^0x[0-9a-fA-F]{40}$/;

function normAddr(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

function toBig(v) {
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
    if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
  } catch { /* fall through */ }
  return null;
}

function isHex(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v.trim());
}

// input: the task's `input` object (see the sample payload on the event
// page). chain: { found: boolean, vk: string|null } — result of
// confirming proof_tx on zkVerify (see chain.mjs). seenProofs: a Set of
// proof_tx values from tasks this agent previously APPROVED (the reuse
// trap text says "already accepted", so only approvals mark a proof seen).
// Returns { decision, reason_code, proof_tx, checks }.
export function decide(input, { seenProofs, chain }) {
  const proofTx = input && typeof input.proof_tx === "string" ? input.proof_tx : null;
  const checks = [];
  const reject = (reason_code, detail) => {
    checks.push(detail);
    return { decision: "REJECT", reason_code, proof_tx: proofTx, checks };
  };
  const approve = () => {
    checks.push("all checks passed");
    return { decision: "APPROVE", reason_code: REASON.VALID, proof_tx: proofTx, checks };
  };

  if (!input || typeof input !== "object") return reject(REASON.INVALID, "missing input object");

  const required = [
    "registered_vk", "proof_vk", "minimum", "public_balance",
    "expiry_block", "current_block", "recipient", "condition_recipient",
    "amount", "max_transfer", "proof_tx",
  ];
  for (const f of required) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      return reject(REASON.INVALID, `missing field: ${f}`);
    }
  }
  if (!isHex(input.registered_vk) || !isHex(input.proof_vk)) {
    return reject(REASON.INVALID, "vk fields must be 0x hex");
  }
  if (!isHex(proofTx)) return reject(REASON.INVALID, "proof_tx must be 0x hex");
  if (!HEX40.test(normAddr(input.recipient)) || !HEX40.test(normAddr(input.condition_recipient))) {
    return reject(REASON.INVALID, "recipient fields must be 0x addresses");
  }
  const minimum = toBig(input.minimum);
  const balance = toBig(input.public_balance);
  const expiry = toBig(input.expiry_block);
  const current = toBig(input.current_block);
  const amount = toBig(input.amount);
  const cap = toBig(input.max_transfer);
  if ([minimum, balance, expiry, current, amount, cap].some((v) => v === null)) {
    return reject(REASON.INVALID, "numeric fields must be integers");
  }

  // 1. Chain confirmation (checklist item 02).
  if (!chain || chain.found !== true) {
    return reject(REASON.INVALID, "proof_tx not confirmed on-chain");
  }
  checks.push("proof confirmed on-chain");

  // 2. VK substitution: the chain VK must equal the registered condition VK.
  // Prefer the chain-reported VK; fall back to the payload's proof_vk.
  const chainVk = typeof chain.vk === "string" ? chain.vk.trim().toLowerCase() : "";
  const payloadVk = input.proof_vk.trim().toLowerCase();
  const registeredVk = input.registered_vk.trim().toLowerCase();
  const effectiveVk = chainVk || payloadVk;
  if (effectiveVk !== registeredVk || payloadVk !== registeredVk) {
    return reject(REASON.VK, "proof vk != registered condition vk");
  }
  checks.push("vk matches registered condition vk");

  // 3. Proof reuse: a proof accepted before must not gain re-entry.
  if (seenProofs && seenProofs.has(proofTx.trim().toLowerCase())) {
    return reject(REASON.REUSED, "proof_tx already accepted in a previous task");
  }
  checks.push("proof_tx not previously accepted");

  // 4. Expiry: current block past the condition's expiry block.
  if (current > expiry) {
    return reject(REASON.EXPIRED, "current_block > expiry_block");
  }
  checks.push("condition not expired");

  // 5. Threshold: public balance must meet the required minimum.
  if (balance < minimum) {
    return reject(REASON.THRESHOLD, "public_balance < minimum");
  }
  checks.push("public_balance >= minimum");

  // 6. Recipient: proof recipient must match the condition recipient.
  if (normAddr(input.recipient) !== normAddr(input.condition_recipient)) {
    return reject(REASON.RECIPIENT, "recipient != condition_recipient");
  }
  checks.push("recipient matches condition");

  // 7. Amount overflow: requested amount must not exceed the single-transfer cap.
  if (amount > cap) {
    return reject(REASON.OVERFLOW, "amount > max_transfer");
  }
  checks.push("amount <= max_transfer");

  return approve();
}
