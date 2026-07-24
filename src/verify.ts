/**
 * verify.ts — offline verifier for a PayPerByte EIP-712 PayloadAttestation receipt.
 *
 * ZERO network. Given the exact wire bytes + the attestation, it proves three things and emits the
 * hand-off to an external existence-anchor:
 *   (a) keccak256(exact wire bytes) === attestation.payloadHash   (+ payloadLength === byte length)
 *   (b) EIP-712 recover under the FROZEN "BYTE Library" domain === the named publisher
 *   (c) anchor_input = SHA-256(eip712_digest ‖ signature)         (<-- fed to the anchor leg)
 *
 * SCOPE: provenance / tamper-evidence ONLY. This proves *which key signed these exact bytes* (and,
 * once anchored, *that they existed before time T*). It says NOTHING about whether the data is
 * correct — that is a separate concern (a "recompute-and-match" correctness leg), kept out of here.
 *
 * TWO TIERS (see README): a live x402 response carries two PayloadAttestation receipts under the same
 * frozen domain — a DELIVERY receipt in the `X-BYTE-Attestation` header (signed payload = the ENTIRE
 * response body) and a PROVENANCE receipt embedded in the body (signed payload = the `answer` value,
 * sliced byte-exact via extractTopLevelValue). Both are verifiable here.
 *
 * By BYTEDev Inc — PayPerByte (x402 data) / ForeSeal (verification). Attestation domain is Arbitrum
 * Sepolia testnet (421614), a frozen signing namespace; the USDC pay rail is Base mainnet (8453).
 */
import {
  keccak256,
  hashTypedData,
  recoverTypedDataAddress,
  sha256,
  concat,
  getAddress,
  type Hex,
  type Address,
  type TypedDataDomain,
} from "viem";
import { extractTopLevelValue } from "./canonical.js";

/** FROZEN attestation domain — consensus-critical, NEVER renamed or env-overridden here.
 *  Source of truth: contracts/src/library/DataStreamLib.sol — EIP712("BYTE Library","1"),
 *  deployed on Arbitrum Sepolia (chainId 421614) at 0x44729bB148F46d8Db509E47b0453edc271e06e95.
 *  Confirmed identical across the Solidity typehash, both SDKs, the gateway, and the MCP server. */
export const EXPECTED_DOMAIN = {
  name: "BYTE Library",
  version: "1",
  chainId: 421614, // Arbitrum Sepolia (testnet, pre-audit) — a signing namespace, NOT a settlement rail
  verifyingContract: "0x44729bB148F46d8Db509E47b0453edc271e06e95",
} as const;

export const PAYLOAD_ATTESTATION_TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

export interface Attestation {
  domain: { name: string; version: string; chainId: number; verifyingContract: string };
  /** delivery-tier header carries `publisher`; provenance-tier embedded carries `signer`. Same field. */
  publisher?: string;
  signer?: string;
  payloadHash: Hex;
  payloadLength: number;
  deadline: number;
  signature: Hex;
}

export interface Verdict {
  verified: boolean;
  hashMatch: boolean;
  lengthMatch: boolean;
  domainOk: boolean;
  recovered: Address | null;
  /** recovered === the attestation's own named signer (internal consistency) */
  publisherMatch: boolean;
  /** recovered === an out-of-band pinned attester; null when no pin was supplied */
  attesterMatch: boolean | null;
  expired: boolean;
  eip712Digest: Hex | null;
  /** SHA-256(eip712_digest ‖ signature) — the value handed to the external anchor leg */
  anchorInput: Hex | null;
  reason: string;
}

export interface VerifyOpts {
  /** the address the signature must recover to (out-of-band pin). Omit to skip the pin check. */
  expectedPublisher?: string | null;
  /** UNIX seconds "now"; if given and > deadline the receipt is expired. Omit to skip freshness. */
  nowSeconds?: number;
  /** TEST/DEMONSTRATION knob only — the domain the verifier recovers under. Defaults to the FROZEN
   *  EXPECTED_DOMAIN. Production verification is ALWAYS frozen; the conformance vector's forked_domain
   *  case passes a forked domain here to show the signature is cryptographically bound to 421614. */
  verifyDomain?: TypedDataDomain;
}

function signerOf(att: Attestation): string {
  return (att.publisher ?? att.signer ?? "").toLowerCase();
}

function domainMatchesFrozen(d: Attestation["domain"]): boolean {
  return (
    !!d &&
    d.name === EXPECTED_DOMAIN.name &&
    d.version === EXPECTED_DOMAIN.version &&
    Number(d.chainId) === EXPECTED_DOMAIN.chainId &&
    (d.verifyingContract ?? "").toLowerCase() === EXPECTED_DOMAIN.verifyingContract.toLowerCase()
  );
}

/** EIP-712 digest of a PayloadAttestation under `domain` (default: the frozen domain). */
export function eip712Digest(att: Attestation, domain: TypedDataDomain = EXPECTED_DOMAIN): Hex {
  return hashTypedData({
    domain,
    types: PAYLOAD_ATTESTATION_TYPES,
    primaryType: "PayloadAttestation",
    message: {
      publisher: getAddress(signerOf(att)),
      payloadHash: att.payloadHash,
      payloadLength: BigInt(att.payloadLength),
      deadline: BigInt(att.deadline),
    },
  });
}

/** anchor_input = SHA-256( eip712_digest(32B) ‖ signature(65B) ). This is the ONLY hand-off to the
 *  external existence-anchor (e.g. an OpenTimestamps/Bitcoin proof). NOTE the deliberate hash split:
 *  the receipt's payloadHash is keccak256; anchor_input is SHA-256. Never conflate them. */
export function anchorInput(digest: Hex, signature: Hex): Hex {
  return sha256(concat([digest, signature]));
}

async function verifyOverBytes(
  payloadBytes: Uint8Array,
  att: Attestation,
  opts: VerifyOpts,
): Promise<Verdict> {
  const expectedPublisher = opts.expectedPublisher ?? null;
  const recoverDomain = opts.verifyDomain ?? EXPECTED_DOMAIN;

  const hashMatch = keccak256(payloadBytes).toLowerCase() === att.payloadHash.toLowerCase();
  const lengthMatch = payloadBytes.length === Number(att.payloadLength);
  const domainOk = domainMatchesFrozen(att.domain);
  const expired = typeof opts.nowSeconds === "number" ? opts.nowSeconds > Number(att.deadline) : false;

  let recovered: Address | null = null;
  let digest: Hex | null = null;
  let anchor: Hex | null = null;
  try {
    digest = eip712Digest(att, recoverDomain);
    anchor = anchorInput(digest, att.signature);
    recovered = await recoverTypedDataAddress({
      domain: recoverDomain,
      types: PAYLOAD_ATTESTATION_TYPES,
      primaryType: "PayloadAttestation",
      message: {
        publisher: getAddress(signerOf(att)),
        payloadHash: att.payloadHash,
        payloadLength: BigInt(att.payloadLength),
        deadline: BigInt(att.deadline),
      },
      signature: att.signature,
    });
  } catch {
    recovered = null;
  }

  const publisherMatch = recovered != null && recovered.toLowerCase() === signerOf(att);
  const attesterMatch =
    expectedPublisher == null
      ? null
      : recovered != null && recovered.toLowerCase() === expectedPublisher.toLowerCase();

  const verified =
    hashMatch && lengthMatch && domainOk && publisherMatch && attesterMatch !== false && !expired;

  let reason: string;
  if (verified) {
    reason =
      "verified: keccak256(exact wire bytes) == payloadHash, recovers to the named publisher under the frozen BYTE Library/421614 domain, unexpired — provenance holds (safe to anchor); says nothing about data correctness";
  } else if (!hashMatch) {
    reason = "REJECT: keccak256(exact wire bytes) != payloadHash — the bytes were altered after signing";
  } else if (!lengthMatch) {
    reason = "REJECT: payloadLength != actual byte length";
  } else if (!domainOk) {
    reason = "REJECT: attestation domain is not the frozen BYTE Library/421614 domain";
  } else if (recovered == null) {
    reason = "REJECT: signature did not recover (malformed)";
  } else if (!publisherMatch) {
    reason = "REJECT: signature recovers to a different address than the named publisher (or a forked domain was used)";
  } else if (attesterMatch === false) {
    reason = "REJECT: recovers to a real signer but NOT the pinned attester";
  } else if (expired) {
    reason = "REJECT: attestation deadline has passed (expired)";
  } else {
    reason = "REJECT";
  }

  return {
    verified,
    hashMatch,
    lengthMatch,
    domainOk,
    recovered: recovered ? (recovered.toLowerCase() as Address) : null,
    publisherMatch,
    attesterMatch,
    expired,
    eip712Digest: digest,
    anchorInput: anchor,
    reason,
  };
}

/** DELIVERY tier: the X-BYTE-Attestation header. Signed payload = the ENTIRE response body bytes. */
export async function verifyDeliveryReceipt(
  bodyBytes: Uint8Array,
  att: Attestation,
  opts: VerifyOpts = {},
): Promise<Verdict> {
  return verifyOverBytes(bodyBytes, att, opts);
}

/** PROVENANCE tier: the attestation embedded in the body. Signed payload = the `answer` value,
 *  sliced byte-exact out of the raw body via extractTopLevelValue (NO re-serialize). */
export async function verifyProvenanceReceipt(
  bodyText: string,
  att: Attestation,
  opts: VerifyOpts = {},
): Promise<Verdict> {
  const slice = extractTopLevelValue(bodyText, "answer");
  if (slice == null) {
    return {
      verified: false,
      hashMatch: false,
      lengthMatch: false,
      domainOk: domainMatchesFrozen(att.domain),
      recovered: null,
      publisherMatch: false,
      attesterMatch: opts.expectedPublisher == null ? null : false,
      expired: false,
      eip712Digest: null,
      anchorInput: null,
      reason: "REJECT: could not slice the `answer` value from the body (malformed envelope)",
    };
  }
  return verifyOverBytes(new TextEncoder().encode(slice), att, opts);
}
