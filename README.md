# foreseal-eip712-anchored-receipt

An **offline** verifier and a **cross-language conformance vector** for a live PayPerByte EIP-712
`PayloadAttestation` receipt — the "our leg" of an *EIP-712 receipt as an anchored record*. It proves
provenance over the exact signed bytes and emits `anchor_input`, the single value handed to an
external existence-anchor (the "referee" leg — not built here).

*By BYTEDev Inc — PayPerByte (x402 pay-per-call data) / ForeSeal (verification).* Built from a real
`$0.10` x402 call that self-screens our own Safe (no third-party data).

---

## What it proves (zero network)

Given the exact wire bytes + the attestation, the verifier asserts three things:

1. **`keccak256(exact wire bytes) == payloadHash`** (and `payloadLength == byte length`). The bytes are
   hashed exactly as they came off the wire — never re-serialized (`JSON.stringify` would not reproduce
   the feed's Python `ensure_ascii` `\uXXXX` escapes and would yield the wrong hash).
2. **EIP-712 recovery under the FROZEN domain == the named publisher.** The signer is *recovered in
   script*, never asserted from a hardcoded address.
3. **`anchor_input = SHA-256(eip712_digest ‖ signature)`** — the hand-off to the anchor leg.

## Load-bearing disclosures (read these — they are what a reviewer re-checks)

- **TWO hashes, never conflated.** The receipt's `payloadHash` is **keccak256**. `anchor_input` is
  **SHA-256**. keccak is the receipt's own integrity hash; SHA-256 is only the anchor hand-off.
- **TWO receipts per response (both keccak256, different byte ranges).** A live x402 response carries
  two `PayloadAttestation`s under the *same* frozen domain:
  - **Delivery tier** — the `X-BYTE-Attestation` **header**, signed by the PayPerByte attester; its
    signed payload is the **entire response body**.
  - **Provenance tier** — an attestation **embedded in the body**, signed by the data provider; its
    signed payload is the **`answer` value**, sliced byte-exact via `extractTopLevelValue`
    (insertion-order compact JSON, `ensure_ascii=True`).

  (Empirically: for the captured receipt, `keccak256(whole 2682-byte body) == header.payloadHash`, and
  `keccak256(2095-byte answer slice) == embedded.payloadHash`. Both verify here.)
- **Domain split.** The EIP-712 attestation domain is **Arbitrum Sepolia `421614`** — a *frozen signing
  namespace* (pre-audit), **not** a settlement rail. The USDC payment rail is **Base mainnet `8453`**.
  Different chains, deliberately; do not conflate the signing domain with the pay rail.
- **Identity vs consistency.** Recovery proves the receipt is *internally consistent* — the signature
  recovers to the address the attestation itself names (and matches a pin only when the caller supplies
  one out-of-band). The binding of those recovered addresses to the labels "PayPerByte attester" /
  "data provider" is **out-of-band**; this artifact does not prove it. (Also in the travelling file as
  `disclosure.identity`.)
- **Scope: provenance / tamper-evidence ONLY.** This proves *which key signed these exact bytes* (and,
  once anchored, *that they existed before time T*). It says **nothing** about whether the data is
  correct. A correctness leg ("recompute-and-match") is a separate primitive, out of scope here.
- **The anchor leg is NOT ours and NOT built here.** This side computes `anchor_input` and stops.
  Nothing here asserts a settled Bitcoin timestamp or an inclusion proof — that is the anchor leg's job.

## Freshness vs provenance

The receipt carries a short freshness `deadline` (~minutes). Freshness governs whether it is safe to
**act on the verdict live**; it does **not** bound provenance. An archived/captured receipt is normally
past its deadline — anchoring is precisely what makes its provenance durable past the live window. The
CLI reports "PROVENANCE HOLDS" + the `anchor_input` even when the live deadline has passed, and flags
the expiry separately.

**The vector pins time, and says so in the file itself.** A conformance vector cannot depend on
wall-clock time, so every case carries an explicit `now_seconds`, and the genuine cases are evaluated
at `deadline - 1`. **In real time this receipt's deadline has passed.** So `"verified": true` in
`conformance/vector.json` means *"these bytes verify when evaluated inside their freshness window"* —
**not** *"this receipt is live right now."* This is stated in the travelling file too, as
`disclosure.freshness`, so the JSON cannot be read standalone and mistaken for a currently-valid
receipt. Run `npm run verify` at real wall-clock and it correctly prints `expired: true` alongside
`PROVENANCE HOLDS`.

## Run it

```bash
npm install

# 1) verify the bundled live receipt offline, print anchor_input:
npm run verify                      # or: npm run verify -- path/to/capture.json

# 2) the conformance vector — 2 genuine + 7 adversarial (all must reject), in BOTH languages:
npm run vector                      # TypeScript (viem)
pip install eth_account             # (in a venv, per the note below) — for the Python leg
npm run vector:py                   # Python  (eth_account) — same vector.json, cross-impl parity
npm run typecheck
```

The vector (`conformance/vector.json`) is produced from the genuine receipt by running the real
verifier (`npm run vector:generate`); each adversarial case is a single, transparent mutation:

**Both tiers carry their own adversarial coverage** — a positive case alone proves nothing about a
verifier, so the `answer`-slice tier is attacked independently of the header tier:

| case | tier | mutation | rejected because |
|---|---|---|---|
| `genuine` | delivery | none | — (verifies) |
| `tampered_body` | delivery | flip the verdict in the body (same length) | `keccak256 != payloadHash` |
| `wrong_attester` | delivery | pin a different expected attester | recovers to the real signer, not the pin |
| `expired` | delivery | evaluate at `now > deadline` | freshness deadline passed |
| `forked_domain` | delivery | verify under chainId `1` instead of `421614` | signature recovers to a stranger — domain is load-bearing |
| `genuine_provenance` | provenance | none (embedded tier) | — (verifies via the `answer` slice) |
| `tampered_provenance` | provenance | same verdict flip — it lands at byte ~182, **inside** the 2095-byte slice | `keccak256(slice) != embedded payloadHash` |
| `wrong_provider` | provenance | pin a different expected provider | recovers to the real embedded signer, not the pin |
| `expired_provenance` | provenance | evaluate at `now >` the **embedded** deadline | freshness deadline passed |

## `#2666` conformance rail — `payperbyte` (the data-response leg)

`conformance/x402-settlement-v0/` commits a **`payperbyte` rail in the exact fixture format of the
x402 settlement-receipt binding extension** (x402-foundation/x402 PR #2666), checked by the
**unmodified upstream checker** (`_check_independent.py`), vendored byte-identical and sha256-pinned
in `CHECKER.sha256` (the runner refuses to run on drift). Do not run the vendored checker directly —
its own `main()` hardcodes the upstream rails and will traceback here; use `run_payperbyte.py`, which
imports its rail-generic verdict functions.

**Upstream pin — by content, not by ref:** vaaraio/vaara tag `v1.1.1` → commit
`719827ce35544ee7d702c1402613d28d0e5a2552`, root tree `c25f5fca`, checker file sha256
`c6af0937632b83c8563c7197eddfa40a5838d78a238bcbe00f097061d3c3a07d`. The upstream suite reproduces at
that tree: exit 0, 14/14 verdicts.

Everything derives from the committed capture plus the public chain its `txDigest` names:

- **Exact-scheme settlement (§3.4):** `txDigest` is the *executed* tx id from the capture's
  `PAYMENT-RESPONSE` header — Base mainnet, independently checkable via
  `eth_getTransactionReceipt` (block 49025821, `100000` atomic USDC to `payTo`).
  `assertedFrom: net-balance-change-to-payTo`, atomic amount + explicit `decimals`, amount excluded
  from the join tuple.
- **`scope` = `byte:payload/keccak256:<delivery payloadHash>`** — the content address of the exact
  delivered bytes. Two-hash discipline: keccak256 rides *inside* the opaque scope string; the two
  joins the upstream checker recomputes (`actionRef`, `evidenceRef.digest`) are sha256 over JCS bytes.
- **`backLink.attestationDigest`** = sha256 over the committed capture **file bytes** — the artifact
  the backLink names IS in the tree. Per §5's non-goals the upstream checker does **not** dereference
  `backLink`; that join is resolved by `run_payperbyte.py`'s added rail-specific verdicts.
- **`timestampMs`** = the `answer.ts` field *inside the signed payload* — hash-bound by both tiers.

```bash
python3 -m venv .venv && . .venv/bin/activate     # Debian/Ubuntu/Homebrew pythons are PEP-668 managed:
pip install rfc8785 cryptography                  # a bare `pip install` errors out there
python3 conformance/x402-settlement-v0/run_payperbyte.py   # 7 upstream verdicts + 4 rail joins
```

Two deliberate differences from the upstream corpus: (1) the ES256 keypair is a **published test key**
(`keys/es256_private.TEST-ONLY.pem`, committed on purpose) so the rail is re-mintable by anyone — it
signs nothing but these fixtures and is **not** a PayPerByte production key; (2) no
`riskScore`/thresholds — the offline verdict is deterministic, so the receipt asserts none.

Per §5's normative presentation rules: green means the record recomputes and the binding resolves —
not an outcome claim, not issuer honesty, not an independent conduct finding, not existence-at-a-time.

## Files — this is the complete manifest; nothing else ships

```
src/verify.ts          byte-exact two-tier verifier + eip712Digest + anchorInput
src/canonical.ts       extractTopLevelValue — vendored verbatim from @foreseal/screen-before-you-pay
src/cli.ts             offline CLI over a capture file
src/run-vector.ts      TS conformance runner
conformance/vector.json          the 9 cases + the disclosure block (incl. disclosure.freshness)
conformance/generate_vector.ts   producer (the real verifier is the oracle)
conformance/run_vector.py        Python cross-impl runner
conformance/x402-settlement-v0/  the #2666 payperbyte rail:
    _check_independent.py        upstream checker, vendored byte-identical (sha256-pinned)
    CHECKER.sha256               the pin the runner enforces
    _generate.py                 fixture producer (re-mintable, idempotent)
    run_payperbyte.py            rail runner (7 upstream verdicts + 4 rail joins)
    expected.json                the rail's expected verdicts
    keys/                        published TEST-ONLY ES256 keypair
    payperbyte/step{0,1}/{settlement,receipt}.json
fixtures/live-receipt.json       the real captured receipt (self-screen of our own Safe)
package.json / tsconfig.json     build + scripts
```

**There is no `.ots` file in this package, and there never was one.** The anchor leg is not ours and
is not built here — `anchor_input` is the *input* an external existence-anchor tool consumes, and
computing it is where our side stops. If you are looking for a Bitcoin/OpenTimestamps proof, it does
not exist on this side of the hand-off. (The captured receipt ships as `fixtures/live-receipt.json`;
there is no top-level `receipt.json`.)
