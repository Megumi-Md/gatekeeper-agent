// HMAC-SHA256 helpers for the Workers build (Web Crypto).
// Same wire format as src/hmac.mjs (Node): lowercase hex HMAC-SHA256
// over the RAW body bytes, in the x-agent-games-signature header; a
// "sha256=" prefix is also accepted on verify. The two implementations
// are cross-checked by test/run-worker-tests.mjs (Node signs, Worker
// verifies, and vice versa) so a drift between them fails loudly.
const te = new TextEncoder();

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function importKey(secret) {
  return globalThis.crypto.subtle.importKey(
    "raw",
    te.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signHex(secret, rawBody) {
  const key = await importKey(secret);
  const data = typeof rawBody === "string" ? te.encode(rawBody) : rawBody;
  const sig = await globalThis.crypto.subtle.sign("HMAC", key, data);
  return bytesToHex(new Uint8Array(sig));
}

export async function verifyHex(secret, rawBody, header) {
  if (typeof header !== "string" || !secret) return false;
  const given = header.trim().replace(/^sha256=/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(given)) return false;
  const expected = await signHex(secret, rawBody);
  // Constant-time compare (no timingSafeEqual in Workers).
  const a = hexToBytes(given.toLowerCase());
  const b = hexToBytes(expected);
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
