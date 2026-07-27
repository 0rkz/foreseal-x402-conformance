/**
 * emit-preimage.ts — write the `payperbyte.io/x402-anchor/receipt/v2-sig` preimage files for both tiers.
 *
 *   npm run anchor:preimage            # print the commitments
 *   npm run anchor:preimage -- out/    # also write <tier>.preimage.bin
 *
 * The Python emitter (conformance/anchor_preimage.py) must produce byte-identical files:
 *   diff <(npm run -s anchor:preimage -- /tmp/a) <(python3 conformance/anchor_preimage.py --write /tmp/b)
 *   cmp /tmp/a/delivery.preimage.bin /tmp/b/delivery.preimage.bin
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { anchorPreimageV2, anchorCommitment, type Tier } from "./anchorPreimage.js";
import { type Attestation } from "./verify.js";

const vec = JSON.parse(readFileSync(new URL("../conformance/vector.json", import.meta.url).pathname, "utf8"));
const cap = JSON.parse(readFileSync(new URL("../fixtures/live-receipt.json", import.meta.url).pathname, "utf8"));
const embedded: Attestation = JSON.parse(cap.body).attestation;

const outDir = process.argv[2] ?? null;
const tiers: Record<string, [string, string]> = {
  delivery: [vec.meta.genuine_delivery_eip712_digest, vec.meta.delivery_publisher_recovered],
  provenance: [vec.meta.genuine_provenance_eip712_digest, vec.meta.provenance_signer_recovered],
};

if (outDir) mkdirSync(outDir, { recursive: true });
for (const [tier, [digest, signer]] of Object.entries(tiers)) {
  const pre = anchorPreimageV2(tier as Tier, digest as `0x${string}`, signer);
  const commitment = anchorCommitment(pre);
  console.log(`[${tier}] preimage ${pre.length} B  commitment ${commitment}`);
  const expected = vec.meta[`genuine_${tier}_anchor_commitment_v2`];
  if (expected && expected !== commitment) {
    console.error(`    MISMATCH vs vector.json: ${expected}`);
    process.exit(1);
  }
  if (outDir) {
    const p = `${outDir.replace(/\/$/, "")}/${tier}.preimage.bin`;
    writeFileSync(p, pre);
    console.log(`    wrote ${p}`);
  }
}
console.log("\nTS ANCHOR-PREIMAGE PASS");
