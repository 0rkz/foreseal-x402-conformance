#!/usr/bin/env python3
"""run_vector.py — Python cross-impl consumer of conformance/vector.json.

An INDEPENDENT implementation (eth_account + eth_utils.keccak + hashlib.sha256, no shared code with
the TS side) that re-verifies every case and asserts the verdict matches the vector's `expect` block
field-for-field. If TS and Python agree on the genuine receipt and disagree on none of the adversarial
ones, the receipt is byte-reproducible by a third party — the whole point of the vector.

    python3 conformance/run_vector.py        # exit 0 = all cases match, 1 = mismatch

Deps: eth-account>=0.13, eth-utils. Provenance/tamper-evidence only; never asserts data correctness.
"""
import hashlib
import json
import sys
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

HERE = Path(__file__).resolve().parent
VEC = json.loads((HERE / "vector.json").read_text())

FROZEN = VEC["meta"]["attestation_domain"]

PAYLOAD_ATTESTATION_TYPES = {
    "PayloadAttestation": [
        {"name": "publisher", "type": "address"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "payloadLength", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ]
}

FIELDS = ["verified", "hashMatch", "lengthMatch", "domainOk", "recovered",
          "publisherMatch", "attesterMatch", "expired", "eip712Digest", "anchorInput"]


# ---- byte-exact top-level slice — faithful port of canonical.ts extractTopLevelValue -------------
_WS = set(" \t\n\r")


def _scan_string(raw, i):
    if raw[i] != '"':
        return -1
    i += 1
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        else:
            i += 1
    return -1


def _scan_value(raw, i):
    n = len(raw)
    c = raw[i]
    if c == '"':
        return _scan_string(raw, i)
    if c == "{" or c == "[":
        depth = 0
        in_str = False
        while i < n:
            ch = raw[i]
            if in_str:
                if ch == "\\":
                    i += 1
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{" or ch == "[":
                depth += 1
            elif ch == "}" or ch == "]":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return -1
    j = i
    while j < n and raw[j] not in _WS and raw[j] not in ",}]":
        j += 1
    return -1 if j == i else j


def extract_top_level_value(raw, target_key):
    n = len(raw)
    i = 0
    while i < n and raw[i] in _WS:
        i += 1
    if i >= n or raw[i] != "{":
        return None
    i += 1
    while True:
        while i < n and raw[i] in _WS:
            i += 1
        if i >= n or raw[i] == "}":
            return None
        if raw[i] != '"':
            return None
        ks = i
        i = _scan_string(raw, i)
        if i < 0:
            return None
        try:
            key = json.loads(raw[ks:i])
        except Exception:
            return None
        while i < n and raw[i] in _WS:
            i += 1
        if i >= n or raw[i] != ":":
            return None
        i += 1
        while i < n and raw[i] in _WS:
            i += 1
        vs = i
        i = _scan_value(raw, i)
        if i < 0:
            return None
        if key == target_key:
            return raw[vs:i]
        while i < n and raw[i] in _WS:
            i += 1
        if i < n and raw[i] == ",":
            i += 1
            continue
        return None


# ---- EIP-712 -------------------------------------------------------------------------------------
def _signer_of(att):
    return (att.get("publisher") or att.get("signer") or "").lower()


def _domain_ok(d):
    return bool(d) and d.get("name") == FROZEN["name"] and d.get("version") == FROZEN["version"] \
        and int(d.get("chainId")) == int(FROZEN["chainId"]) \
        and (d.get("verifyingContract") or "").lower() == FROZEN["verifyingContract"].lower()


def _digest_and_recover(att, domain):
    """Return (eip712_digest_hex, recovered_addr_lower or None) for `att` verified under `domain`."""
    msg = {
        "publisher": _signer_of(att),
        "payloadHash": att["payloadHash"],
        "payloadLength": int(att["payloadLength"]),
        "deadline": int(att["deadline"]),
    }
    try:
        signable = encode_typed_data(
            domain_data={
                "name": domain["name"],
                "version": domain["version"],
                "chainId": int(domain["chainId"]),
                "verifyingContract": domain["verifyingContract"],
            },
            message_types=PAYLOAD_ATTESTATION_TYPES,
            message_data=msg,
        )
        # EIP-712 final digest = keccak(0x19 ‖ version(0x01) ‖ domainSeparator ‖ hashStruct(message))
        digest = keccak(b"\x19" + signable.version + signable.header + signable.body)
        recovered = Account.recover_message(signable, signature=att["signature"]).lower()
        return "0x" + digest.hex(), recovered
    except Exception:
        return None, None


def _anchor_input(digest_hex, signature_hex):
    if digest_hex is None:
        return None
    h = hashlib.sha256()
    h.update(bytes.fromhex(digest_hex[2:]))
    h.update(bytes.fromhex(signature_hex[2:]))
    return "0x" + h.hexdigest()


def verify(case):
    att = case["header"]
    domain = case.get("verify_domain") or FROZEN
    tier = case["tier"]
    if tier == "delivery":
        payload = case["body"].encode("utf-8")
    else:
        sl = extract_top_level_value(case["body"], "answer")
        payload = sl.encode("utf-8") if sl is not None else None

    hash_match = payload is not None and ("0x" + keccak(payload).hex()).lower() == att["payloadHash"].lower()
    length_match = payload is not None and len(payload) == int(att["payloadLength"])
    domain_ok = _domain_ok(att["domain"])
    now = case.get("now_seconds")
    expired = (now is not None) and (int(now) > int(att["deadline"]))

    digest_hex, recovered = _digest_and_recover(att, domain)
    anchor = _anchor_input(digest_hex, att["signature"])

    publisher_match = recovered is not None and recovered == _signer_of(att)
    pin = case.get("expected_publisher")
    attester_match = None if pin is None else (recovered is not None and recovered == pin.lower())

    verified = bool(hash_match and length_match and domain_ok and publisher_match
                    and attester_match is not False and not expired)

    return {
        "verified": verified,
        "hashMatch": bool(hash_match),
        "lengthMatch": bool(length_match),
        "domainOk": bool(domain_ok),
        "recovered": recovered,
        "publisherMatch": bool(publisher_match),
        "attesterMatch": attester_match,
        "expired": bool(expired),
        "eip712Digest": digest_hex,
        "anchorInput": anchor,
    }


def _eq(a, b):
    if a is None or b is None:
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b


def main():
    fails = 0
    n = 0
    for c in VEC["cases"]:
        n += 1
        got = verify(c)
        exp = c["expect"]
        mism = [f"{f}: got {got[f]!r} != expect {exp[f]!r}" for f in FIELDS if not _eq(got[f], exp[f])]
        if not c["name"].startswith("genuine") and got["verified"]:
            mism.append(f"SECURITY: adversarial case '{c['name']}' VERIFIED but must be rejected")
        if not mism:
            print(f"PASS  [{c['tier']}] {c['name']}  (verified={got['verified']})")
        else:
            fails += 1
            print(f"FAIL  [{c['tier']}] {c['name']}")
            for m in mism:
                print(f"        {m}")
    print(f"\nPY VECTOR {'PASS' if fails == 0 else 'FAIL'} — {n - fails}/{n} cases match")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
