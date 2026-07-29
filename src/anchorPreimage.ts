/**
 * anchorPreimage.ts — the exact bytes an external existence-anchor stamps.
 *
 * CURRENT: `payperbyte.io/x402-anchor/receipt/v2-sig` (anchorPreimageV2) — commits the SIGNER,
 * carries the signature alongside, so existence-in-time is checkable without trusting the key and
 * the key is checkable without re-deriving the anchor. The separation mirrors rootcommit/SPEC_SIG.md
 * in MarkovianProtocol/tlog-bitcoin-anchor. SUPERSEDED: `foreseal-receipt-anchor/v1` (anchorPreimage)
 * — the fused digest+sig shape, retained only for lineage (meta.genuine_delivery_anchor_commitment_v1)
 * and the negative-test battery.
 *
 * WHY A FILE FORMAT AND NOT A BARE DIGEST. `ots stamp` takes files, not digests. Hand a stamper a
 * hex digest and the natural move is to write that hex into a file and stamp it — which commits
 * SHA-256(the ASCII hex), not the value you meant. Defining the preimage as a format removes the
 * ambiguity: the stamp commits to the format, not to an ASCII accident.
 *
 * FORMAT (v2-sig) — exactly four LF-terminated lines, no blank lines, no trailing content:
 *
 *   payperbyte.io/x402-anchor/receipt/v2-sig\n
 *   tier=<delivery|provenance>\n
 *   digest=0x<eip712_digest, 32 bytes hex>\n
 *   signer=0x<EIP-55 address the receipt recovers to>\n
 *
 * The commitment is SHA-256 over exactly those bytes. Stamp the file; `ots info <file>.ots` prints
 * that same SHA-256 back, which is the whole digest-binding check and needs no node and no calendar.
 *
 * NO DOMAIN LINE, NO SIGNATURE LINE: the EIP-712 digest already commits to the full domain
 * separator (name, version, chainId, verifyingContract), so a domain line adds no security
 * boundary; and the signature travels alongside the preimage (in the manifest) rather than inside
 * it — that separation is the point of v2-sig.
 */
import { sha256, getAddress, type Hex } from "viem";

export const ANCHOR_PREIMAGE_TAG = "foreseal-receipt-anchor/v1"; // superseded — lineage + negative tests only

/** v2-sig. Tag follows Markovian's `domain/purpose/object/version` convention on a domain we
 *  actually control (they suggested foreseal.io; it does not resolve, and minting a format
 *  identifier on a domain we do not own would age badly). */
export const ANCHOR_PREIMAGE_TAG_V2 = "payperbyte.io/x402-anchor/receipt/v2-sig";

export type Tier = "delivery" | "provenance";

/**
 * v2-sig preimage — four LF-terminated lines:
 *
 *   payperbyte.io/x402-anchor/receipt/v2-sig\n
 *   tier=<delivery|provenance>\n
 *   digest=0x<eip712_digest, 32 bytes hex>\n
 *   signer=0x<EIP-55 address the receipt recovers to>\n
 *
 * The SIGNATURE IS NOT IN THE PREIMAGE. That is the whole point of v2-sig, per Markovian's
 * rootcommit/v2-sig: commit the signER, carry the signATURE alongside. Splitting them means a
 * third party can check existence-in-time without trusting our key, and check our key without
 * re-deriving the anchor. v1 (below) fused `SHA-256(digest ‖ sig)` and is superseded.
 *
 * The receipt's own EIP-712 PayloadAttestation signature is the "who" layer — it recovers to
 * `signer`, so no additional signature is minted. The EIP-712 digest already commits to the full
 * domain separator (name, version, chainId, verifyingContract), so dropping v1's `domain=` line
 * loses no binding — the domain is inside `digest`.
 */
export function anchorPreimageV2(tier: Tier, digest: Hex, signer: string): Uint8Array {
  if (tier !== "delivery" && tier !== "provenance") throw new Error(`unknown tier: ${tier}`);
  const checksummed = getAddress(signer); // EIP-55 form; throws on a malformed address
  // viem's getAddress does NOT reject a bad checksum — it silently re-checksums whatever it is
  // given, so a mistyped signer would be normalised into a valid-looking preimage and stamped,
  // committing an address nobody meant. The EIP-55 checksum exists precisely to catch that typo,
  // so honour it: accept the checksummed form or all-lowercase (which carries no checksum to
  // violate), reject any other casing. Matches conformance/anchor_preimage.py exactly — the
  // cross-impl v2 negative battery pins the two together.
  if (signer !== checksummed && signer !== signer.toLowerCase()) {
    throw new Error(`signer ${signer} has a bad EIP-55 checksum (expected ${checksummed})`);
  }
  const lines = [
    ANCHOR_PREIMAGE_TAG_V2,
    `tier=${tier}`,
    `digest=${requireHex("digest", digest, 32)}`,
    `signer=${checksummed}`,
  ];
  return new TextEncoder().encode(lines.map((l) => l + "\n").join(""));
}

export interface AnchorDomain {
  name: string;
  chainId: number;
}

function requireHex(label: string, v: string, byteLen: number): string {
  const s = v.toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(s) || (s.length - 2) / 2 !== byteLen) {
    throw new Error(`${label} must be 0x-prefixed ${byteLen}-byte hex, got ${v.length} chars`);
  }
  return s;
}

/** The exact stamped bytes. Fails closed on a malformed digest or signature rather than
 *  emitting a preimage that would anchor a value nobody can reproduce. */
export function anchorPreimage(digest: Hex, signature: Hex, domain: AnchorDomain): Uint8Array {
  // The format's entire claim is "exactly four LF-terminated lines" — a newline in the domain name
  // would silently emit five. chainId via BigInt so a large value never renders in exponent form.
  if (/[\r\n]/.test(domain.name)) throw new Error("domain name must not contain CR or LF");
  if (!Number.isInteger(domain.chainId) || domain.chainId < 0) throw new Error("chainId must be a non-negative integer");
  const lines = [
    ANCHOR_PREIMAGE_TAG,
    `domain=eip155:${BigInt(domain.chainId).toString()} ${domain.name}`,
    `digest=${requireHex("digest", digest, 32)}`,
    `sig=${requireHex("sig", signature, 65)}`,
  ];
  return new TextEncoder().encode(lines.map((l) => l + "\n").join(""));
}

/** SHA-256 over the preimage bytes — the value Bitcoin ends up committing to. */
export function anchorCommitment(preimage: Uint8Array): Hex {
  return sha256(preimage);
}
