#!/usr/bin/env python3
"""anchor_preimage.py — Python side of `foreseal-receipt-anchor/v1`.

Independent of the TypeScript emitter (src/anchorPreimage.ts) and must produce BYTE-IDENTICAL
files. Cross-impl agreement is the point: a preimage format only works as an interop shape if two
implementations written separately land on the same bytes.

Format — exactly four LF-terminated lines, no blank lines, no trailing content:

    foreseal-receipt-anchor/v1\n
    domain=eip155:<chainId> <domain name>\n
    digest=0x<eip712_digest, 32 bytes hex>\n
    sig=0x<signature, 65 bytes hex>\n

Commitment = SHA-256 over exactly those bytes. `ots stamp <file>` then commits that value, and
`ots info <file>.ots` prints it back offline.

    python3 conformance/anchor_preimage.py            # emit + verify both tiers, cross-check TS
    python3 conformance/anchor_preimage.py --write DIR # also write the .bin files
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

TAG = "foreseal-receipt-anchor/v1"
HERE = Path(__file__).resolve().parent
REPO = HERE.parent

def _require_hex(label: str, v: str, byte_len: int) -> str:
    """Fail closed. Uses re.fullmatch with an EXACT nibble count — deliberately not `^...$` with a
    floor-division length test, which accepted two malformed classes the TS emitter rejected:
    an odd nibble count (floor division rounded it away) and a trailing newline (Python's `$`
    matches before a final \\n, which would have emitted a FIVE-line preimage)."""
    s = v.lower()
    if not re.fullmatch(r"0x[0-9a-f]{%d}" % (byte_len * 2), s):
        raise ValueError(f"{label} must be 0x-prefixed {byte_len}-byte hex, got {v!r}")
    return s


def anchor_preimage(digest: str, signature: str, name: str, chain_id: int) -> bytes:
    """The exact stamped bytes. Fails closed on malformed input."""
    if "\n" in name or "\r" in name:
        raise ValueError("domain name must not contain CR or LF")
    if not isinstance(chain_id, int) or chain_id < 0:
        raise ValueError("chainId must be a non-negative integer")
    lines = [
        TAG,
        f"domain=eip155:{chain_id} {name}",
        f"digest={_require_hex('digest', digest, 32)}",
        f"sig={_require_hex('sig', signature, 65)}",
    ]
    return "".join(l + "\n" for l in lines).encode("utf-8")


def anchor_commitment(preimage: bytes) -> str:
    return "0x" + hashlib.sha256(preimage).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", metavar="DIR", help="also write <tier>.preimage.bin into DIR")
    args = ap.parse_args()

    vec = json.loads((HERE / "vector.json").read_text())
    cap = json.loads((REPO / "fixtures" / "live-receipt.json").read_text())
    dom = vec["meta"]["attestation_domain"]
    tiers = {
        "delivery": (vec["meta"]["genuine_delivery_eip712_digest"], cap["attestation"]["signature"]),
        "provenance": (
            vec["meta"]["genuine_provenance_eip712_digest"],
            json.loads(cap["body"])["attestation"]["signature"],
        ),
    }

    rc = 0
    for tier, (digest, sig) in tiers.items():
        pre = anchor_preimage(digest, sig, dom["name"], int(dom["chainId"]))
        commit = anchor_commitment(pre)
        print(f"[{tier}] preimage {len(pre)} B  commitment {commit}")
        print("    " + repr(pre.decode()).replace("\\n", "\\n\n      ")[:0] or "", end="")
        expected = vec["meta"].get(f"genuine_{tier}_anchor_commitment")
        if expected and expected != commit:
            print(f"    MISMATCH vs vector.json: {expected}")
            rc = 1
        if args.write:
            out = Path(args.write) / f"{tier}.preimage.bin"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(pre)
            print(f"    wrote {out} ({len(pre)} B)")
    print("\nPY ANCHOR-PREIMAGE " + ("PASS" if rc == 0 else "FAIL"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
