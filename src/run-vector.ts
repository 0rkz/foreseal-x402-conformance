/**
 * run-vector.ts — TS consumer of conformance/vector.json. Re-verifies every case with the real
 * verifier and asserts the produced verdict matches the vector's `expect` block field-for-field.
 * The Python runner (conformance/run_vector.py) asserts the SAME file — cross-impl parity.
 *
 *   npm run vector
 */
import { readFileSync } from "node:fs";
import {
  verifyDeliveryReceipt,
  verifyProvenanceReceipt,
  type Attestation,
  type Verdict,
  type VerifyOpts,
} from "./verify.js";

const vecPath = new URL("../conformance/vector.json", import.meta.url).pathname;
const vec = JSON.parse(readFileSync(vecPath, "utf8"));

const FIELDS: (keyof Verdict)[] = [
  "verified",
  "hashMatch",
  "lengthMatch",
  "domainOk",
  "recovered",
  "publisherMatch",
  "attesterMatch",
  "expired",
  "eip712Digest",
  "anchorInput",
];

function eq(a: unknown, b: unknown): boolean {
  if (a == null || b == null) return a === b;
  if (typeof a === "string" && typeof b === "string") return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

async function main(): Promise<number> {
  let fails = 0;
  let n = 0;
  for (const c of vec.cases as any[]) {
    n++;
    const opts: VerifyOpts = {
      expectedPublisher: c.expected_publisher,
      nowSeconds: c.now_seconds,
      verifyDomain: c.verify_domain ?? undefined,
    };
    const bytes = new TextEncoder().encode(c.body);
    const v: Verdict =
      c.tier === "delivery"
        ? await verifyDeliveryReceipt(bytes, c.header as Attestation, opts)
        : await verifyProvenanceReceipt(c.body, c.header as Attestation, opts);

    const mismatches: string[] = [];
    for (const f of FIELDS) {
      if (!eq((v as any)[f], c.expect[f])) mismatches.push(`${f}: got ${JSON.stringify((v as any)[f])} != expect ${JSON.stringify(c.expect[f])}`);
    }
    // sanity: adversarial cases (everything except the two genuine* cases) MUST be rejected
    const mustReject = !c.name.startsWith("genuine");
    if (mustReject && v.verified) mismatches.push(`SECURITY: adversarial case '${c.name}' VERIFIED but must be rejected`);

    if (mismatches.length === 0) {
      console.log(`PASS  [${c.tier}] ${c.name}  (verified=${v.verified})`);
    } else {
      fails++;
      console.log(`FAIL  [${c.tier}] ${c.name}`);
      for (const m of mismatches) console.log(`        ${m}`);
    }
  }
  console.log(`\nTS VECTOR ${fails === 0 ? "PASS" : "FAIL"} — ${n - fails}/${n} cases match`);
  return fails === 0 ? 0 : 1;
}

main().then((code) => process.exit(code));
