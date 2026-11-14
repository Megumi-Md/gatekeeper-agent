// KV-backed store for the Workers build: seen proof references +
// idempotency cache. Same semantics as src/seen.mjs (Node, JSON file):
// a proof_tx is marked seen only when its task was APPROVED, and a
// retried task_id gets the exact cached response body, not a fresh
// decision. Keys: `seen:<lowercase proof_tx>` -> "1",
// `resp:<task_id>` -> response body string. No TTL — the competition
// runs days, at 8 tasks/day the namespace stays tiny. KV is eventually
// consistent; with sequential platform retries at this volume, a stale
// read causing a double decision is unlikely, and the platform
// re-checks proofs itself.
export function kvStore(kv) {
  return {
    async getResponse(taskId) {
      return kv.get(`resp:${taskId}`);
    },
    async putResponse(taskId, body) {
      await kv.put(`resp:${taskId}`, body);
    },
    async hasSeen(proofTxLower) {
      return (await kv.get(`seen:${proofTxLower}`)) !== null;
    },
    async markSeen(proofTxLower) {
      await kv.put(`seen:${proofTxLower}`, "1");
    },
  };
}
