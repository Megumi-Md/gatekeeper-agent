// On-chain proof confirmation for the Workers build.
// Same stub semantics as src/chain.mjs, minus process.env: mode comes
// from the Worker's env binding. PRODUCTION throws until a real
// Kurier/zkVerifyJS confirmation is wired in — no silent fake
// confirmations. A proof_tx of exactly "0xmissing" simulates
// "not found on-chain" for tests.
export async function confirmProof(task, { mode = "stub" } = {}) {
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
