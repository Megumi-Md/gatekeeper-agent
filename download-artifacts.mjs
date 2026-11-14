// Download the official Gatekeeper circuit artifacts (documented at
// https://agentgames.zkverify.io/api/circuit-info) into ./artifacts/.
// Dependency fetch only: two fixed URLs from the platform's own JSON.
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { get } from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "artifacts");
const FILES = [
  ["gatekeeper.wasm", "https://agentgames.zkverify.io/circuits/gatekeeper.wasm"],
  ["gatekeeper_final.zkey", "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey"],
];

function fetchTo(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    get(url, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects < 5) {
        return resolve(fetchTo(res.headers.location, dest, redirects + 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const hash = createHash("sha256");
      const out = createWriteStream(dest);
      let bytes = 0;
      res.on("data", (c) => { bytes += c.length; hash.update(c); });
      res.pipe(out);
      out.on("finish", () => resolve({ bytes, sha256: hash.digest("hex") }));
      out.on("error", reject);
      res.on("error", reject);
    }).on("error", reject);
  });
}

await mkdir(DIR, { recursive: true });
for (const [name, url] of FILES) {
  const dest = path.join(DIR, name);
  const { bytes, sha256 } = await fetchTo(url, dest);
  console.log(`${name}: ${bytes} bytes sha256=${sha256}`);
}
console.log("done");
