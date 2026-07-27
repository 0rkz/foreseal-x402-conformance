/**
 * generate_vector.ts — produce conformance/vector.json from the live receipt.
 *
 * The genuine case is the real captured receipt; the four adversarial cases are single, transparent
 * mutations of it. Each case's `expect` block is produced by running the REAL verifier (src/verify.ts)
 * — the TS implementation is the oracle, exactly like sdk/typescript's parity-vector producer. Both
 * the TS runner (src/run-vector.ts) and the Python runner (conformance/run_vector.py) then consume this
 * file and must reproduce every `expect` field-for-field.
 *
 *   npm run vector:generate
 */
import { readFileSync, writeFileSync } from "node:fs";
import { anchorPreimage, anchorPreimageV2, anchorCommitment } from "../src/anchorPreimage.js";
import {
  verifyDeliveryReceipt,
  verifyProvenanceReceipt,
  eip712Digest,
  anchorInput,
  EXPECTED_DOMAIN,
  type Attestation,
  type Verdict,
  type VerifyOpts,
} from "../src/verify.js";

const capPath = new URL("../fixtures/live-receipt.json", import.meta.url).pathname;
const cap = JSON.parse(readFileSync(capPath, "utf8"));
const body: string = cap.body;
const delivery: Attestation = cap.attestation;
const embedded: Attestation = JSON.parse(body).attestation;
const deadline = Number(delivery.deadline);

// A foreign address (standard anvil key #1) used as the "wrong attester" pin — clearly not our signer.
const FOREIGN = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

// Tamper: flip the human-visible verdict in the body (same length → only the hash breaks, cleanly).
function tamperBody(b: string): string {
  for (const [from, to] of [
    ['"verdict":"ALLOW"', '"verdict":"BLOCK"'],
    ['"verdict":"WARN"', '"verdict":"PASS"'],
    ['"verdict":"BLOCK"', '"verdict":"ALLOW"'],
  ] as const) {
    if (b.includes(from)) return b.replace(from, to);
  }
  // fallback: flip the first digit of "score"
  return b.replace(/("score":)(\d)/, (_m, p, d) => p + ((Number(d) + 1) % 10));
}

interface Case {
  name: string;
  tier: "delivery" | "provenance";
  description: string;
  body: string;
  body_encoding: "utf8";
  header: Attestation;
  verify_domain: Record<string, unknown> | null;
  expected_publisher: string | null;
  now_seconds: number;
  expect?: Record<string, unknown>;
}

const nowGood = deadline - 1; // within the receipt's freshness window (after issuance, before expiry)
const genuinePublisher = (delivery.publisher ?? delivery.signer)!;
const provenanceSigner = (embedded.publisher ?? embedded.signer)!;

const cases: Case[] = [
  {
    name: "genuine",
    tier: "delivery",
    description:
      "The live X-BYTE-Attestation header receipt, unmodified. keccak256(whole body)==payloadHash; recovers to the delivery publisher under the frozen domain; unexpired AT THE PINNED EVALUATION TIME (now_seconds = deadline-1; see disclosure.freshness — the receipt's deadline has since passed in real time). EXPECT: verified.",
    body,
    body_encoding: "utf8",
    header: delivery,
    verify_domain: null,
    expected_publisher: genuinePublisher,
    now_seconds: nowGood,
  },
  {
    name: "tampered_body",
    tier: "delivery",
    description:
      "The verdict inside the body was flipped (same byte length). keccak256 no longer matches payloadHash. EXPECT: hashMatch=false → rejected. This is the core tamper-evidence property.",
    body: tamperBody(body),
    body_encoding: "utf8",
    header: delivery,
    verify_domain: null,
    expected_publisher: genuinePublisher,
    now_seconds: nowGood,
  },
  {
    name: "wrong_attester",
    tier: "delivery",
    description:
      "Genuine bytes + signature, but pinned to a DIFFERENT expected attester. Recovery still matches the header's own publisher, but not the pin. EXPECT: attesterMatch=false → rejected.",
    body,
    body_encoding: "utf8",
    header: delivery,
    verify_domain: null,
    expected_publisher: FOREIGN,
    now_seconds: nowGood,
  },
  {
    name: "expired",
    tier: "delivery",
    description:
      "Genuine receipt evaluated at now > deadline. EXPECT: expired=true → rejected (freshness).",
    body,
    body_encoding: "utf8",
    header: delivery,
    verify_domain: null,
    expected_publisher: genuinePublisher,
    now_seconds: Number(delivery.deadline) + 1,
  },
  {
    name: "forked_domain",
    tier: "delivery",
    description:
      "Same genuine bytes + signature, but verified under a FORKED domain (chainId 1 instead of 421614). The signature is cryptographically bound to the frozen chainId, so it recovers to a STRANGER, not the publisher. EXPECT: publisherMatch=false → rejected. Proves the frozen domain is load-bearing.",
    body,
    body_encoding: "utf8",
    header: delivery,
    verify_domain: { ...EXPECTED_DOMAIN, chainId: 1 },
    expected_publisher: genuinePublisher,
    now_seconds: nowGood,
  },
  {
    name: "genuine_provenance",
    tier: "provenance",
    description:
      "The embedded provenance receipt: keccak256(answer-slice via extractTopLevelValue)==embedded payloadHash; recovers to the data provider. EXPECT: verified. Demonstrates the answer-slice (insertion-order compact JSON) form.",
    body,
    body_encoding: "utf8",
    header: embedded,
    verify_domain: null,
    expected_publisher: provenanceSigner,
    now_seconds: nowGood,
  },
  {
    name: "tampered_provenance",
    tier: "provenance",
    description:
      "Same single-byte-class mutation as tampered_body, but checked against the PROVENANCE tier. The flipped verdict sits at byte ~182 of the body — INSIDE the 2095-byte `answer` slice — so keccak256(slice) no longer matches the embedded payloadHash. EXPECT: hashMatch=false → rejected. Proves the answer-slice tier is tamper-evident in its own right, not merely covered by the delivery tier.",
    body: tamperBody(body),
    body_encoding: "utf8",
    header: embedded,
    verify_domain: null,
    expected_publisher: provenanceSigner,
    now_seconds: nowGood,
  },
  {
    name: "wrong_provider",
    tier: "provenance",
    description:
      "Genuine bytes + embedded signature, pinned to a DIFFERENT expected provider. Recovery still matches the embedded receipt's own signer, but not the pin. EXPECT: attesterMatch=false → rejected. The provenance-tier analogue of wrong_attester: the recovered identity comes from the signature, never from the pin.",
    body,
    body_encoding: "utf8",
    header: embedded,
    verify_domain: null,
    expected_publisher: FOREIGN,
    now_seconds: nowGood,
  },
  {
    name: "expired_provenance",
    tier: "provenance",
    description:
      "Genuine embedded receipt evaluated at now > its OWN deadline (the embedded deadline differs from the delivery one). EXPECT: expired=true → rejected. Note the scope split: expiry is a freshness policy, not a provenance failure — the signature stays valid forever, which is exactly why anchoring is what makes it durable.",
    body,
    body_encoding: "utf8",
    header: embedded,
    verify_domain: null,
    expected_publisher: provenanceSigner,
    now_seconds: Number(embedded.deadline) + 1,
  },
];

function optsFor(c: Case): VerifyOpts {
  return {
    expectedPublisher: c.expected_publisher,
    nowSeconds: c.now_seconds,
    verifyDomain: c.verify_domain ?? undefined,
  };
}

function expectFrom(v: Verdict): Record<string, unknown> {
  return {
    verified: v.verified,
    hashMatch: v.hashMatch,
    lengthMatch: v.lengthMatch,
    domainOk: v.domainOk,
    recovered: v.recovered,
    publisherMatch: v.publisherMatch,
    attesterMatch: v.attesterMatch,
    expired: v.expired,
    eip712Digest: v.eip712Digest,
    anchorInput: v.anchorInput,
  };
}

const genuineDigest = eip712Digest(delivery);
const genuineAnchor = anchorInput(genuineDigest, delivery.signature);
const provenanceDigest = eip712Digest(embedded);
const provenanceAnchor = anchorInput(provenanceDigest, embedded.signature);

async function main(): Promise<void> {
  for (const c of cases) {
    const bytes = new TextEncoder().encode(c.body);
    const v =
      c.tier === "delivery"
        ? await verifyDeliveryReceipt(bytes, c.header, optsFor(c))
        : await verifyProvenanceReceipt(c.body, c.header, optsFor(c));
    c.expect = expectFrom(v);
  }

  const out = {
    meta: {
      note: "Conformance vector for a live PayPerByte EIP-712 PayloadAttestation receipt. TS (viem) produced; both the TS and Python runners must reproduce every `expect` field. Genuine = the real captured receipt; adversarial cases are single mutations of it, all EXPECT rejection.",
      producer: "foreseal-eip712-anchored-receipt/conformance/generate_vector.ts (viem)",
      feed: "address-reputation ($0.10 x402, self-screen of our own Safe — no third-party data)",
      captured_at: cap.capturedAt,
      settlement_tx: `https://basescan.org/tx/${cap.settle?.transaction ?? ""}`,
      attestation_domain: EXPECTED_DOMAIN,
      pay_rail_network: "eip155:8453 (Base mainnet USDC) — SETTLEMENT ONLY, distinct from the attestation domain",
      delivery_publisher_recovered: genuinePublisher,
      provenance_signer_recovered: provenanceSigner,
      genuine_delivery_eip712_digest: genuineDigest,
      genuine_delivery_anchor_input: genuineAnchor,
      // M2: the provenance tier's values were reachable only from inside a case's `expect`, while
      // the delivery tier's were surfaced here — asymmetric for the tier the counterparty re-checks.
      genuine_provenance_eip712_digest: provenanceDigest,
      genuine_provenance_anchor_input: provenanceAnchor,
      // foreseal-receipt-anchor/v1 — the bytes an external anchor actually stamps, and the
      // SHA-256 it therefore commits to. See disclosure.anchor_preimage.
      genuine_delivery_anchor_commitment_v2: anchorCommitment(
        anchorPreimageV2("delivery", genuineDigest, genuinePublisher)),
      genuine_provenance_anchor_commitment_v2: anchorCommitment(
        anchorPreimageV2("provenance", provenanceDigest, provenanceSigner)),
      // superseded v1 (fused digest‖sig) — retained for lineage, not what gets stamped
      genuine_delivery_anchor_commitment_v1: anchorCommitment(
        anchorPreimage(genuineDigest, delivery.signature, { name: EXPECTED_DOMAIN.name, chainId: EXPECTED_DOMAIN.chainId })),
    },
    disclosure: {
      two_hashes:
        "TWO hashes, never conflated. (1) receipt payloadHash = keccak256(payload bytes). (2) anchor_input = SHA-256(eip712_digest ‖ signature). keccak256 is the receipt's own integrity hash; SHA-256 is only the hand-off to the anchor leg.",
      two_tiers:
        "TWO receipts per response, same frozen domain, BOTH keccak256 but over different byte ranges. DELIVERY tier (X-BYTE-Attestation header, signer = PayPerByte attester): payload = the ENTIRE response body. PROVENANCE tier (embedded in the body, signer = the data provider): payload = the `answer` value, sliced byte-exact via extractTopLevelValue (insertion-order compact JSON, ensure_ascii=True — never re-serialized).",
      domain_split:
        "The EIP-712 attestation domain is Arbitrum Sepolia testnet chainId 421614 (a FROZEN signing namespace, pre-audit — not a settlement rail). The USDC payment rail is Base mainnet chainId 8453. These are deliberately different chains; do not conflate the signing domain with the pay rail.",
      scope:
        "PROVENANCE / tamper-evidence ONLY. This proves which key signed these exact bytes (and, once anchored, that they existed before time T). It says NOTHING about whether the data is correct — that is a separate 'recompute-and-match' correctness concern, kept out of scope here.",
      anchor_leg:
        "The external existence-anchor (e.g. an OpenTimestamps/Bitcoin proof over anchor_input) is NOT part of this artifact and is NOT built here. This side computes anchor_input and stops. Nothing here asserts a settled Bitcoin timestamp or an inclusion proof — that is the anchor leg's job.",
      freshness:
        `TIME IS PINNED, DELIBERATELY AND DISCLOSED. A conformance vector cannot depend on wall-clock time, so each case carries an explicit now_seconds and the genuine cases are evaluated at deadline-1 (${nowGood}). IN REAL TIME THE RECEIPT'S DEADLINE HAS PASSED (delivery deadline ${deadline} = ${new Date(deadline * 1000).toISOString()}). Do NOT read "verified: true" here as "this receipt is currently live" — it means "these bytes verify when evaluated inside their freshness window". Run the offline CLI (npm run verify) at real wall-clock and it correctly prints expired: true. The distinction is the point of the artifact: a signature's PROVENANCE is timeless — it proves forever which key signed these exact bytes — while a deadline is a short-lived freshness POLICY. Anchoring is what turns the timeless part into something durably checkable after expiry.`,
      forked_domain_note:
        "The forked_domain case verifies the genuine signature under chainId 1: it recovers to a different address than under 421614, empirically demonstrating the signature is cryptographically bound to the frozen chainId (not merely a string-compare).",
      // M5: the artifact proves recovered == the address the receipt NAMES. That the named addresses
      // are "the PayPerByte attester" / "the data provider" is a label, bound out-of-band.
      anchor_preimage:
        "WHAT AN ANCHOR ACTUALLY STAMPS is `foreseal-receipt-anchor/v1`: exactly four LF-terminated lines — the tag, `domain=eip155:<chainId> <name>`, `digest=0x<eip712_digest>`, `sig=0x<signature>` — and the commitment is SHA-256 over those bytes (meta.genuine_*_anchor_commitment). `anchor_input` (SHA-256 over the raw 32-byte digest ‖ 65-byte signature) is the earlier bare-digest form and is retained as an intermediate; it is NOT what gets stamped. The format exists because `ots stamp` takes files, not digests: handed a bare hex value the natural move is to stamp the ASCII hex, which commits the wrong thing. Format specified by Markovian Protocol as the interop shape; the domain line is human-readable context, not a security boundary — the EIP-712 digest already commits to the full domain separator.",
      identity:
        "Recovery proves INTERNAL CONSISTENCY only: the signature recovers to the address the attestation itself names (meta.delivery_publisher_recovered / meta.provenance_signer_recovered), and matches a pin only when the caller supplies one out-of-band. The binding of those addresses to the labels 'PayPerByte attester' and 'data provider' is out-of-band — this artifact does not prove those identity bindings.",
    },
    cases,
  };

  const outPath = new URL("./vector.json", import.meta.url).pathname;
  writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
  const nPass = cases.filter((c) => (c.expect as any).verified).length;
  console.log(`[generate] wrote ${outPath}`);
  console.log(`[generate] ${cases.length} cases: ${nPass} verified, ${cases.length - nPass} expected-reject`);
}

main().then(() => process.exit(0));
