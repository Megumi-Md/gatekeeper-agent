// Persistent local store: seen proof references + idempotency cache.
// The platform may retry a delivery after a network failure, and task
// IDs are idempotency keys — a retried task_id must get the exact cached
// response, not a fresh decision (a fresh decision could flip to
// PROOF_REUSED once the first decision marked the proof seen).
// Single JSON file, atomic write via tmp + rename. Fine at 8 tasks/day.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import path from "node:path";

export function loadStore(file) {
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    return {
      seen: new Set((data.seen || []).map((s) => String(s).toLowerCase())),
      responses: data.responses || {},
    };
  } catch {
    return { seen: new Set(), responses: {} };
  }
}

export function saveStore(file, store) {
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify({
    seen: [...store.seen],
    responses: store.responses,
  }, null, 1));
  renameSync(tmp, file);
}
