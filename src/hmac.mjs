// HMAC-SHA256 helpers for the x-agent-games-signature header.
// The platform signs every task delivery and requires every response to
// be signed with the 32-byte secret issued at agent registration (shown
// exactly once; never commit it — pass it via HMAC_SECRET env).
// Header format assumption: lowercase hex HMAC-SHA256 over the RAW body
// bytes; a "sha256=" prefix is also accepted on verify. Confirm against
// the dashboard docs at registration time.
import { createHmac, timingSafeEqual } from "node:crypto";

export function signHex(secret, rawBody) {
  const buf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  return createHmac("sha256", secret).update(buf).digest("hex");
}

export function verifyHex(secret, rawBody, header) {
  if (typeof header !== "string" || !secret) return false;
  const given = header.trim().replace(/^sha256=/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(given)) return false;
  const expected = signHex(secret, rawBody);
  return timingSafeEqual(Buffer.from(given, "hex"), Buffer.from(expected, "hex"));
}
