// On-chain proof confirmation (checklist item 02).
//
// PRODUCTION: replace `confirmProof` with a real query — Kurier REST
// (API key from https://kurier.xyz, poll job-status to Finalized) or
// zkVerifyJS direct chain reads — that returns { found, vk } for a
// proof_tx, where vk is the verification key the chain associates with
// that proof. The decision logic compares it to the registered
// condition VK; never trust the payload alone.
//
// LOCAL STUB (default): treats every well-formed proof_tx as confirmed
// and echoes the payload's proof_vk as the chain VK, so the 7 decision
// checks can be tested end to end without chain access. A proof_tx of
// exactly "0xmissing" simulates "not found on-chain" for tests.
// Set CHAIN_MODE=stub (default) or CHAIN_MODE=production (throws until
// a real implementation is wired in — no silent fake confirmations).
export async function confirmProof(task, { mode = process.env.CHAIN_MODE || "stub" } = {}) {
  const proofTx = task?.input?.proof_tx;
  if (mode === "production") {
    throw new Error("CHAIN_NOT_IMPLEMENTED: wire Kurier/zkVerifyJS confirmation here");
  }
  if (typeof proofTx !== "string" || !/^0x[0-9a-fA-F]+$/.test(proofTx.trim())) {
    return { found: false, vk: null };
  }
  if (proofTx.trim().toLowerCase() === "0xmissing") {
    return { found: false, vk: null };
  }
  return { found: true, vk: task.input.proof_vk ?? null };
}
