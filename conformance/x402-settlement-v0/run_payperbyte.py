#!/usr/bin/env python3
"""Run the `payperbyte` rail against the UNMODIFIED upstream checker for the
x402 settlement-receipt binding extension (x402-foundation/x402 PR #2666).

Upstream pin — by content, not by ref: vaaraio/vaara tag v1.1.1 resolves to
commit 719827ce35544ee7d702c1402613d28d0e5a2552 (root tree c25f5fca, vectors
subtree 0907322, checker git blob 0669786027). The vendored copy of
tests/vectors/x402_settlement_v0/_check_independent.py is byte-identical; this
runner REFUSES to run if it drifts from the sha256 pin below.

The upstream verdict functions are rail-generic (only upstream main() hardcodes
its two rails), so the only inputs we supply are the rail name, our fixtures,
and our published test key. On top of the 7 upstream verdicts this runner adds
two rail-specific joins per step, both recomputable from committed bytes (the
upstream checker deliberately does NOT dereference backLink — a section-5
non-goal — which is why the backLink join lives here):

  backlink_resolves_delivery_capture   backLink.attestationDigest == sha256 over
                                       the committed capture file bytes
                                       (fixtures/live-receipt.json)
  scope_resolves_payload_hash          settlement.scope carries EXACTLY the
                                       delivery attestation's keccak256
                                       payloadHash from that committed capture

WHAT GREEN MEANS — and does not mean (extension section 5, normative): the
record recomputes and the binding resolves. Green is NOT an outcome claim, NOT
an issuer-honesty claim, NOT an independent conduct finding, and NOT proof of
existence at a time. The keccak256/EIP-712 verification of the capture itself
(exact wire bytes, frozen 421614 domain, signer recovery) is the native leg —
a separate command: `npm run vector` (TS) / `python3 conformance/run_vector.py`
(Python) at the package root. Provenance/tamper-evidence only, never data
correctness.

Run:  .venv/bin/python conformance/x402-settlement-v0/run_payperbyte.py
Deps: pip install rfc8785 cryptography
Exit 0 iff every verdict matches expected.json and both extra joins hold.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CHECKER = HERE / "_check_independent.py"
CAPTURE = REPO / "fixtures" / "live-receipt.json"
RAIL = "payperbyte"
CHECKER_SHA256 = "c6af0937632b83c8563c7197eddfa40a5838d78a238bcbe00f097061d3c3a07d"


def main() -> int:
    got_sha = hashlib.sha256(CHECKER.read_bytes()).hexdigest()
    if got_sha != CHECKER_SHA256:
        print("[FAIL] vendored checker drifted from the upstream pin")
        print(f"       expected {CHECKER_SHA256}")
        print(f"       got      {got_sha}")
        return 1
    print(f"[OK] checker is upstream's, byte-identical (sha256 {CHECKER_SHA256[:16]}…)")

    spec = importlib.util.spec_from_file_location("upstream_checker", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    expected = json.loads((HERE / "expected.json").read_text())
    got = {RAIL: mod._rail_verdicts(RAIL)}

    ok = got == expected
    for step in ("step0", "step1"):
        for k, v in got[RAIL][step].items():
            print(f"[{'OK' if v else 'FAIL'}] {RAIL}.{step}.{k}: {v}")
    lv = got[RAIL]["lifecycle_distinguishes_terminal"]
    print(f"[{'OK' if lv else 'FAIL'}] {RAIL}.lifecycle_distinguishes_terminal: {lv}")

    # Rail-specific joins — recomputed from committed bytes, no trust in prose.
    capture_raw = CAPTURE.read_bytes()
    capture_digest = "sha256:" + hashlib.sha256(capture_raw).hexdigest()
    payload_hash = json.loads(capture_raw)["attestation"]["payloadHash"]
    want_scope = f"byte:payload/keccak256:{payload_hash[2:]}"
    extra_ok = True
    for step in ("step0", "step1"):
        receipt = json.loads((HERE / RAIL / step / "receipt.json").read_text())
        settlement = json.loads((HERE / RAIL / step / "settlement.json").read_text())
        bl = receipt["backLink"]["attestationDigest"] == capture_digest
        sc = settlement["scope"] == want_scope
        extra_ok = extra_ok and bl and sc
        print(f"[{'OK' if bl else 'FAIL'}] {RAIL}.{step}.backlink_resolves_delivery_capture: {bl}")
        print(f"[{'OK' if sc else 'FAIL'}] {RAIL}.{step}.scope_resolves_payload_hash: {sc}")

    ok = ok and extra_ok
    print(f"\n{'all verdicts matched expected' if ok else 'MISMATCH vs expected'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
