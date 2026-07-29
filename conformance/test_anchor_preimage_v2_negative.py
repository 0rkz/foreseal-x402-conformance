#!/usr/bin/env python3
"""Cross-impl NEGATIVE tests for `payperbyte.io/x402-anchor/receipt/v2-sig` — the CURRENT shape.

Companion to test_anchor_preimage_negative.py, which covers the superseded v1. Same reasoning: the
happy path was never going to reveal a divergence, because both emitters agree on a well-formed
receipt. What decides whether a preimage format survives contact with a second implementation is
whether the two agree on REJECTION — a preimage one side emits and the other refuses is a preimage
someone will hand to `ots stamp`, and the anchor it produces is then permanently wrong.

v2-sig moved the risk. v1 validated two hex fields; v2 validates a tier enum and an ADDRESS, and an
address carries an EIP-55 checksum that exists for exactly one reason: catching a typo. So this
battery leans on the signer line.

It caught a real one (2026-07-28): viem's `getAddress` accepts a mixed-case address whose EIP-55
checksum is wrong and silently re-checksums it, while the Python emitter rejects it. A mistyped
signer would have been normalised into a valid-looking preimage and stamped — committing an address
the operator never meant, with no way to un-anchor it. TypeScript now fails closed, matching Python.

Unlike the v1 battery this compares the emitted BYTES on every accepted case, not just accept/reject
agreement: two impls can both accept and still disagree on what they wrote.

    python3 conformance/test_anchor_preimage_v2_negative.py   # exit 0 iff both agree AND are correct
"""
import json
import subprocess
import sys

# The genuine delivery-tier values from vector.json / the live receipt.
GOOD_D = "0x2a34c5db45d5cb816e1b5efee2fa6a28a013712469291b5a91a35f6f22406629"
GOOD_S = "0x77c86a1B0A0F4F2b0d3d6F4E5c6B7A8d9E0F1a2B"  # placeholder shape; overridden below

sys.path.insert(0, "conformance")
from anchor_preimage import anchor_preimage_v2 as py_emit  # noqa: E402

# Pull the real signer + digest so the "ok" cases exercise production values, not invented ones.
import pathlib  # noqa: E402

_vec = json.loads((pathlib.Path("conformance") / "vector.json").read_text())
GOOD_D = _vec["meta"]["genuine_delivery_eip712_digest"]
GOOD_S = _vec["meta"]["delivery_publisher_recovered"]

# Break the checksum without changing the address: flip the case of one alpha nibble.
_alpha = next(i for i, c in enumerate(GOOD_S) if i > 1 and c.isalpha())
BAD_CHECKSUM = (
    GOOD_S[:_alpha]
    + (GOOD_S[_alpha].lower() if GOOD_S[_alpha].isupper() else GOOD_S[_alpha].upper())
    + GOOD_S[_alpha + 1:]
)

#      name                       tier          digest              signer               accept?
cases = {
    "ok_genuine":               ("delivery",   GOOD_D,             GOOD_S,               True),
    "ok_provenance_tier":       ("provenance", GOOD_D,             GOOD_S,               True),
    "ok_signer_lowercase":      ("delivery",   GOOD_D,             GOOD_S.lower(),       True),
    "ok_digest_uppercase":      ("delivery",   GOOD_D.upper(),     GOOD_S,               True),
    "signer_bad_checksum":      ("delivery",   GOOD_D,             BAD_CHECKSUM,         False),
    "signer_all_uppercase":     ("delivery",   GOOD_D,             "0x" + GOOD_S[2:].upper(), False),
    "signer_short":             ("delivery",   GOOD_D,             GOOD_S[:-1],          False),
    "signer_long":              ("delivery",   GOOD_D,             GOOD_S + "a",         False),
    "signer_no_0x":             ("delivery",   GOOD_D,             GOOD_S[2:],           False),
    "signer_trailing_newline":  ("delivery",   GOOD_D,             GOOD_S + "\n",        False),
    "signer_embedded_lf":       ("delivery",   GOOD_D,             GOOD_S[:10] + "\n" + GOOD_S[10:], False),
    "signer_nonhex":            ("delivery",   GOOD_D,             GOOD_S[:-1] + "z",    False),
    "signer_empty":             ("delivery",   GOOD_D,             "",                   False),
    "tier_wrong_case":          ("Delivery",   GOOD_D,             GOOD_S,               False),
    "tier_unknown":             ("settlement", GOOD_D,             GOOD_S,               False),
    "tier_empty":               ("",           GOOD_D,             GOOD_S,               False),
    "tier_newline":             ("delivery\n", GOOD_D,             GOOD_S,               False),
    "digest_odd_nibble":        ("delivery",   GOOD_D + "a",       GOOD_S,               False),
    "digest_trailing_newline":  ("delivery",   GOOD_D + "\n",      GOOD_S,               False),
    "digest_short":             ("delivery",   GOOD_D[:-2],        GOOD_S,               False),
    "digest_no_0x":             ("delivery",   GOOD_D[2:],         GOOD_S,               False),
    "digest_nonhex":            ("delivery",   GOOD_D[:-1] + "z",  GOOD_S,               False),
}

TS_PROBE = '''
import {{ anchorPreimageV2 }} from "./src/anchorPreimage.ts";
try {{
  const b = anchorPreimageV2({tier}, {digest}, {signer});
  console.log("OK " + Buffer.from(b).toString("hex"));
}} catch (e) {{ console.log("REJECT"); }}
'''

rows = []
for name, (tier, digest, signer, should_accept) in cases.items():
    try:
        b = py_emit(tier, digest, signer)
        py_ok, py_hex = True, b.hex()
    except Exception:
        py_ok, py_hex = False, ""

    proc = subprocess.run(
        ["node", "--import", "tsx", "-e", TS_PROBE.format(
            tier=json.dumps(tier), digest=json.dumps(digest), signer=json.dumps(signer))],
        capture_output=True, text=True,
    )
    out = proc.stdout.strip()
    ts_ok = out.startswith("OK ")
    ts_hex = out[3:] if ts_ok else ""

    agree = py_ok == ts_ok
    # On an accepted case the two must have written the SAME bytes, not merely both accepted.
    bytes_match = (not py_ok) or (py_hex == ts_hex)
    correct = py_ok == should_accept and ts_ok == should_accept
    note = f"{len(py_hex) // 2}B" if py_ok else "rejected"
    rows.append((name, should_accept, py_ok, ts_ok, agree, bytes_match, correct, note))

bad = [r for r in rows if not (r[4] and r[5] and r[6])]
for n, exp, p, t, a, bm, c, note in rows:
    flag = "ok " if (a and bm and c) else "BAD"
    extra = "" if bm else "  <-- BYTES DIFFER"
    print(f"{flag} {n:24s} expect_accept={str(exp):5s} py={str(p):5s} ts={str(t):5s} {note}{extra}")
print(f"\n{len(rows) - len(bad)}/{len(rows)} v2 cases: both impls agree, bytes match, AND are correct")
sys.exit(1 if bad else 0)
