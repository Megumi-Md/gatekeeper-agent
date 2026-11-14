// Groth16 proof generation for Gatekeeper responses (snarkjs, local).
//
// STATUS: plumbing is implemented, but the circuit's INPUT SCHEMA is
// unknown — the platform publishes the .zkey/.wasm + vkHash but the
// signal names/meanings for groth16.fullProve are not in the public
// docs found so far (nPublic = 13 per the exported verification key).
// buildCircuitInput() therefore throws CIRCUIT_INPUT_SCHEMA_UNKNOWN
// instead of fabricating inputs. A wrong input mapping would produce
// proofs the platform rejects (-2 per task), so nothing here guesses.
// Once the schema is confirmed (starter prompt / dashboard docs), fill
// in buildCircuitInput() and the rest of this module works unchanged.
//
// Artifacts (official, from /api/circuit-info):
//   gatekeeper vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
//   wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
//   zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
// Run: node download-artifacts.mjs
import { accessSync, constants, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");

export class ProverSkipped extends Error {
  constructor(reason, detail) {
    super(`${reason}: ${detail}`);
    this.name = "ProverSkipped";
    this.reason = reason;
  }
}

export function artifactPaths() {
  return {
    wasm: process.env.GK_WASM || path.join(ROOT, "artifacts", "gatekeeper.wasm"),
    zkey: process.env.GK_ZKEY || path.join(ROOT, "artifacts", "gatekeeper_final.zkey"),
    vk: process.env.GK_VK || path.join(ROOT, "artifacts", "gatekeeper_vk.json"),
  };
}

export function artifactsPresent() {
  const p = artifactPaths();
  try {
    accessSync(p.wasm, constants.R_OK);
    accessSync(p.zkey, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

// Map a task + decision to the circuit's input signals.
// THROWS until the schema is confirmed — see the header note.
export function buildCircuitInput(_task, _decisionResult) {
  throw new ProverSkipped(
    "CIRCUIT_INPUT_SCHEMA_UNKNOWN",
    "signal names/meanings for the gatekeeper circuit are not documented publicly; " +
    "confirm from the platform starter prompt / dashboard docs before proving"
  );
}

// Generate + locally verify a Groth16 proof for a READY input object.
// Returns { proof, publicSignals, ms, verified }.
export async function generateProof(input, { wasm, zkey, vk } = artifactPaths()) {
  const t0 = Date.now();
  const { groth16 } = await import("snarkjs");
  const { proof, publicSignals } = await groth16.fullProve(input, wasm, zkey);
  let verified = null;
  try {
    const vkJson = JSON.parse(readFileSync(vk, "utf8"));
    verified = await groth16.verify(vkJson, publicSignals, proof);
  } catch {
    verified = null; // no local VK available; the platform re-verifies anyway
  }
  return { proof, publicSignals, ms: Date.now() - t0, verified };
}

// Full path: artifacts -> input mapping -> prove -> local verify.
// Throws ProverSkipped with .reason when proving is not possible.
export async function proveDecision(task, decisionResult) {
  if (!artifactsPresent()) {
    throw new ProverSkipped("ARTIFACTS_MISSING", "run: node download-artifacts.mjs");
  }
  const input = buildCircuitInput(task, decisionResult);
  return generateProof(input);
}
