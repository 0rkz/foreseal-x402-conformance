/**
 * cli.ts — verify a captured PayPerByte receipt fully OFFLINE and print the anchor hand-off.
 *
 *   npm run verify                       # verifies fixtures/live-receipt.json
 *   npm run verify -- path/to/capture.json
 *
 * Input = the capture written by x402-gateway/examples/agent-client/ts/verify-attestation.ts:
 *   { body: "<exact wire bytes>", attestation: {<X-BYTE-Attestation header>}, ... }
 * Makes NO network calls. Recovers the signer in-script (never trusts a hardcoded address).
 */
import { readFileSync } from "node:fs";
import { verifyDeliveryReceipt, verifyProvenanceReceipt, type Verdict, type Attestation } from "./verify.js";

function show(title: string, v: Verdict): void {
  console.log(`\n=== ${title} ===`);
  console.log(`  verified      : ${v.verified ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`  hashMatch     : ${v.hashMatch}   lengthMatch: ${v.lengthMatch}   domainOk: ${v.domainOk}`);
  console.log(`  recovered     : ${v.recovered ?? "(none)"}`);
  console.log(`  publisherMatch: ${v.publisherMatch}   expired: ${v.expired}`);
  console.log(`  eip712_digest : ${v.eip712Digest ?? "(none)"}`);
  console.log(`  anchor_input  : ${v.anchorInput ?? "(none)"}   <- SHA-256(digest‖sig), hand to the anchor leg`);
  console.log(`  reason        : ${v.reason}`);
}

async function main(): Promise<number> {
  const path = process.argv[2] ?? new URL("../fixtures/live-receipt.json", import.meta.url).pathname;
  const cap = JSON.parse(readFileSync(path, "utf8"));

  const body: string = cap.body;
  const bodyBytes = new TextEncoder().encode(body);
  const deliveryAtt: Attestation = cap.attestation;
  const now = Math.floor(Date.now() / 1000);

  console.log(`[verify] file        : ${path}`);
  console.log(`[verify] body bytes  : ${bodyBytes.length}`);
  console.log(`[verify] delivery pub : ${deliveryAtt.publisher ?? deliveryAtt.signer}  (recovering to confirm...)`);

  const delivery = await verifyDeliveryReceipt(bodyBytes, deliveryAtt, { nowSeconds: now });
  show("DELIVERY tier (X-BYTE-Attestation header — signed payload = the whole body)", delivery);

  // The provenance receipt is embedded in the body; verify it too if present.
  let embedded: Attestation | undefined;
  try {
    embedded = JSON.parse(body).attestation;
  } catch {
    embedded = undefined;
  }
  if (embedded && embedded.signature) {
    const prov = await verifyProvenanceReceipt(body, embedded, { nowSeconds: now });
    show("PROVENANCE tier (embedded — signed payload = the `answer` slice via extractTopLevelValue)", prov);
  } else {
    console.log("\n(no embedded provenance attestation in this body — delivery tier only)");
  }

  // Provenance (who signed which exact bytes, under the frozen domain) is TIMELESS — it is exactly
  // what an existence-anchor makes durable. Freshness (`expired`) only governs whether it is safe to
  // ACT on the receipt LIVE. A captured/archived receipt is normally past its short deadline; that
  // does NOT invalidate the provenance or the anchor hand-off. So key the anchor decision on
  // provenance holding, and report freshness separately.
  const provenanceHolds =
    delivery.hashMatch &&
    delivery.lengthMatch &&
    delivery.domainOk &&
    delivery.publisherMatch &&
    delivery.attesterMatch !== false;

  if (provenanceHolds) {
    console.log(
      `\n[verify] RESULT: PROVENANCE HOLDS — these exact bytes were signed by ${delivery.recovered} under the frozen BYTE Library/421614 domain.`,
    );
    console.log(`[verify] anchor_input : ${delivery.anchorInput}  — valid to hand to the external anchor leg.`);
    if (delivery.expired) {
      console.log(
        "[verify] note         : the receipt's short freshness deadline has passed (expected for an archived capture). Anchoring is precisely what gives it durability past the live window. Do NOT act on it as a LIVE verdict.",
      );
    }
    console.log("[verify] scope        : provenance / tamper-evidence only — says nothing about whether the data is correct.");
    return 0;
  }
  console.log("\n[verify] RESULT: FAIL — provenance does NOT hold (see reason above). Nothing to anchor.");
  return 1;
}

main().then((code) => process.exit(code));
