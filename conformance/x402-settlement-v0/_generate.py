#!/usr/bin/env python3
"""Generate the `payperbyte` rail fixtures for the x402 settlement-receipt binding
extension (x402-foundation/x402 PR #2666), in the exact fixture format of the
pinned upstream suite vaaraio/vaara tests/vectors/x402_settlement_v0.

WHAT THIS RAIL BINDS
  The DATA-RESPONSE leg of the #2650 three-leg diligence trail: an x402 payment
  settled on Base mainnet, joined by content address to the delivery attestation
  over the exact response bytes (X-BYTE-Attestation, EIP-712/keccak256 — the
  native leg lives in this package's src/verify.ts + conformance/vector.json).

  Everything derives from ONE committed artifact: fixtures/live-receipt.json —
  a real $0.10 x402 call (self-screen of our own Safe, no third-party data):

    settlement.txDigest   <- the executed tx id in the capture's PAYMENT-RESPONSE
                             header (never a pre-execution intent id — spec 3.4)
    settlement fields     <- cross-checked against the on-chain USDC Transfer log
                             (Base block 49025821: payer -> payTo, 100000 atomic)
    scope                 <- "byte:payload/keccak256:<delivery payloadHash hex>",
                             the content address of the exact delivered bytes
    backLink.attestationDigest <- sha256 over the committed capture FILE bytes
    timestampMs           <- the `answer.ts` field INSIDE the signed payload
                             (bound by both attestation tiers, not a free claim)

DELIBERATE DIFFERENCES FROM THE UPSTREAM CORPUS (exhaustive):
  1. The ES256 keypair is a PUBLISHED test key (keys/es256_private.TEST-ONLY.pem
     is committed on purpose): the rail is re-mintable by anyone, so the fixtures
     never have to be taken on faith. The key signs nothing but these fixtures —
     it is NOT a PayPerByte production key. The production signatures are the
     EIP-712 ones inside the committed capture, verified by the native leg.
  2. No riskScore/thresholds in decisionDerived: the offline verdict here is
     deterministic (hashes and signatures either verify or they do not), so the
     receipt asserts no score.

Two-hash discipline (matches this package's README): the scope string carries
keccak256 INTERNALLY (the receipt's own integrity hash, bare hex); the two joins
the upstream checker recomputes (actionRef, evidenceRef.digest) are sha256 over
JCS bytes. The backLink join (sha256 over the committed capture file bytes) is
resolved by run_payperbyte.py's added rail-specific verdicts — the upstream
checker treats backLink as issuer-populated and does not dereference it (a
section-5 non-goal). Nothing rail-specific enters the upstream math.

Run:  .venv/bin/python conformance/x402-settlement-v0/_generate.py
Deps: pip install rfc8785 cryptography
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CAPTURE = REPO / "fixtures" / "live-receipt.json"
KEYS = HERE / "keys"
RAIL = "payperbyte"
SCHEMA = "x402.settlement.base/v0"

# Live-verified constants (eth_getTransactionReceipt on the capture's settlement
# tx, Base mainnet block 49025821): USDC token contract + amount + decimals.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
AMOUNT_ATOMIC = "100000"  # $0.10 at 6 decimals — matches the on-chain Transfer
DECIMALS = 6
VERIFIED_BY = "facilitator://api.cdp.coinbase.com/platform/v2/x402"


def _jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def _sha256_hex(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _load_or_mint_keys():
    priv_path = KEYS / "es256_private.TEST-ONLY.pem"
    pub_path = KEYS / "es256_public.pem"
    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        KEYS.mkdir(parents=True, exist_ok=True)
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_path.write_bytes(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return priv


def _sign_raw_rs(priv, payload: bytes) -> str:
    """ES256 over payload, returned as raw r||s = 128 lowercase hex (not DER)."""
    try:
        der = priv.sign(payload, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    except TypeError:  # older cryptography without deterministic_signing
        der = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def main() -> None:
    raw = CAPTURE.read_bytes()
    cap = json.loads(raw)

    # The executed settlement id comes from the PAYMENT-RESPONSE header the
    # facilitator returned (spec 3.4: executed id, never an intent/command id).
    pr = json.loads(base64.b64decode(cap["headers"]["payment-response"]))
    assert pr["success"] is True
    tx_digest = pr["transaction"]
    payer = pr["payer"]
    network = pr["network"]
    assert tx_digest == cap["settle"]["transaction"]
    assert network == "eip155:8453"

    delivery = cap["attestation"]
    payload_hash = delivery["payloadHash"]  # keccak256 over the exact wire bytes
    pay_to = cap["request"]["body"]["address"]

    # timestampMs: the `answer.ts` inside the SIGNED payload — a time assertion
    # that is hash-bound by both attestation tiers, not a free-floating claim.
    answer_ts = json.loads(cap["body"])["answer"]["ts"]
    timestamp_ms = int(answer_ts) * 1000
    instant = datetime.fromtimestamp(int(answer_ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    capture_digest = _sha256_hex(raw)
    agent_id = f"agent:ppb-client/{payer}"
    scope = f"byte:payload/keccak256:{payload_hash[2:]}"

    settlement_obj = {
        "amount": AMOUNT_ATOMIC,
        "assertedFrom": "net-balance-change-to-payTo",
        "asset": USDC_BASE,
        "decimals": DECIMALS,
        "network": network,
        "payTo": pay_to,
        "rail": "base",
        "scheme": "exact",
        "txDigest": tx_digest,
        "verifiedBy": VERIFIED_BY,
    }

    priv = _load_or_mint_keys()

    reasons = {
        0: (
            "delivery tier verified offline: keccak256(exact wire bytes) == "
            "payloadHash and EIP-712 recovery under the frozen BYTE Library/421614 "
            "domain == the named attester; provenance tier pending"
        ),
        1: (
            "both tiers verified offline: delivery (whole-body bytes, gateway "
            "attester) and provenance (answer-slice bytes, provider key); "
            "verdict terminal"
        ),
    }

    for seq in (0, 1):
        tuple6 = {
            "agentId": agent_id,
            "actionType": "x402.data.purchase",
            "scope": scope,
            "timestampMs": timestamp_ms,
            "seq": seq,
            "terminal": seq == 1,
        }
        action_ref = _sha256_hex(_jcs(tuple6))
        settlement = dict(tuple6)
        settlement["actionRef"] = action_ref
        settlement["schema"] = SCHEMA
        settlement["settlement"] = settlement_obj

        receipt = {
            "version": 1,
            "alg": "ES256",
            "backLink": {
                "attestationDigest": capture_digest,
                "attestationNonce": f"x402-payperbyte-{seq}",
            },
            "decisionDerived": {
                "decidedAt": instant,
                "decision": "allow",
                "evidenceRef": {
                    "canonicalization": "JCS",
                    "digest": _sha256_hex(_jcs(settlement)),
                    "ref": f"x402:action_ref/{action_ref}",
                    "schema": SCHEMA,
                },
                "policyId": "policy:foreseal-delivery-verify/1",
                "reason": reasons[seq],
            },
            "issuerAsserted": {
                "alg": "ES256",
                "iat": instant,
                "iss": "issuer://foreseal-offline-verifier",
                "nonce": f"d-payperbyte-{seq}",
                "secretVersion": "v1",
                "sub": agent_id,
            },
        }
        blocks = ("version", "alg", "backLink", "decisionDerived", "issuerAsserted")
        receipt["signature"] = _sign_raw_rs(priv, _jcs({k: receipt[k] for k in blocks}))

        _write(HERE / RAIL / f"step{seq}" / "settlement.json", settlement)
        _write(HERE / RAIL / f"step{seq}" / "receipt.json", receipt)
        print(f"[generate] step{seq}: actionRef {action_ref}")

    expected = {
        RAIL: {
            "lifecycle_distinguishes_terminal": True,
            "step0": {
                "action_ref_recomputes": True,
                "receipt_signature_ok": True,
                "settlement_binding_resolves": True,
            },
            "step1": {
                "action_ref_recomputes": True,
                "receipt_signature_ok": True,
                "settlement_binding_resolves": True,
            },
        }
    }
    _write(HERE / "expected.json", expected)

    checker_sha = hashlib.sha256((HERE / "_check_independent.py").read_bytes()).hexdigest()
    (HERE / "CHECKER.sha256").write_text(
        f"{checker_sha}  conformance/x402-settlement-v0/_check_independent.py\n"
    )
    print(f"[generate] backLink.attestationDigest {capture_digest}")
    print(f"[generate] checker sha256 {checker_sha}")


if __name__ == "__main__":
    main()
