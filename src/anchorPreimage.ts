/**
 * anchorPreimage.ts — `foreseal-receipt-anchor/v1`: the exact bytes an external existence-anchor
 * stamps for one PayPerByte EIP-712 receipt.
 *
 * WHY A FILE FORMAT AND NOT A BARE DIGEST. `ots stamp` takes files, not digests. Hand a stamper a
 * hex digest and the natural move is to write that hex into a file and stamp it — which commits
 * SHA-256(the ASCII hex), not the value you meant. Defining the preimage as a format removes the
 * ambiguity: the stamp commits to the format, not to an ASCII accident.
 *
 * FORMAT (v1) — exactly four LF-terminated lines, no blank lines, no trailing content:
 *
 *   foreseal-receipt-anchor/v1\n
 *   domain=eip155:<chainId> <domain name>\n
 *   digest=0x<eip712_digest, 32 bytes hex>\n
 *   sig=0x<signature, 65 bytes hex>\n
 *
 * The commitment is SHA-256 over exactly those bytes. Stamp the file; `ots info <file>.ots` prints
 * that same SHA-256 back, which is the whole digest-binding check and needs no node and no calendar.
 *
 * Format specified by Markovian Protocol (2026-07-25) as the interop shape for tlog-bitcoin-anchor,
 * deliberately carrying OUR tag rather than theirs — the point of the format is domain separation
 * and versioning, not whose name is on it.
 *
 * NOTE ON THE DOMAIN LINE: it is human-readable context, NOT a security boundary. The EIP-712
 * digest already commits to the full domain separator (name, version, chainId, verifyingContract),
 * so a mutated domain line cannot make a wrong receipt verify — it would simply disagree with the
 * digest it sits beside. It is there so the stamped bytes are self-describing to someone reading
 * the preimage years later with no other context.
 */
import { sha256, type Hex } from "viem";

export const ANCHOR_PREIMAGE_TAG = "foreseal-receipt-anchor/v1";

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
  const lines = [
    ANCHOR_PREIMAGE_TAG,
    `domain=eip155:${domain.chainId} ${domain.name}`,
    `digest=${requireHex("digest", digest, 32)}`,
    `sig=${requireHex("sig", signature, 65)}`,
  ];
  return new TextEncoder().encode(lines.map((l) => l + "\n").join(""));
}

/** SHA-256 over the preimage bytes — the value Bitcoin ends up committing to. */
export function anchorCommitment(preimage: Uint8Array): Hex {
  return sha256(preimage);
}
