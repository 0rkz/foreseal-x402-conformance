#!/usr/bin/env python3
"""Cross-impl NEGATIVE tests for the superseded foreseal-receipt-anchor/v1 shape.

The happy path was never going to reveal a divergence — both emitters were always going to agree
on a well-formed receipt. What matters for an interop format is that two independent
implementations agree on REJECTION, because a preimage one side emits and the other refuses is a
preimage someone will hand to `ots stamp`.

This caught a real one (2026-07-26): the Python validator used floor division for the length check
and `^...$` for the hex pattern, so it accepted an odd nibble count AND a trailing newline — the
latter emitting a FIVE-line preimage, violating the format outright. TypeScript rejected both.

    python3 conformance/test_anchor_preimage_negative.py   # exit 0 iff both agree AND are correct
"""
import subprocess, sys, json, tempfile, os
GOOD_D="0x2a34c5db45d5cb816e1b5efee2fa6a28a013712469291b5a91a35f6f22406629"
GOOD_S="0xb91e16f00b42677572e24d77742287e99e0c2c926219ea6b4f75023464303cdd49e510a4250fe3563f01c11f651d09f76fb4574abb9ee6bb2a029b9c9b5c41e41c"
cases={
 "ok_genuine":(GOOD_D,GOOD_S,True),
 "digest_odd_nibble":(GOOD_D+"a",GOOD_S,False),
 "digest_trailing_newline":(GOOD_D+"\n",GOOD_S,False),
 "digest_short":(GOOD_D[:-2],GOOD_S,False),
 "digest_no_0x":(GOOD_D[2:],GOOD_S,False),
 "sig_odd_nibble":(GOOD_D,GOOD_S+"a",False),
 "sig_trailing_newline":(GOOD_D,GOOD_S+"\n",False),
 "sig_short":(GOOD_D,GOOD_S[:-2],False),
 "digest_uppercase":(GOOD_D.upper(),GOOD_S,True),
 "digest_nonhex":(GOOD_D[:-1]+"z",GOOD_S,False),
}
sys.path.insert(0,'conformance')
from anchor_preimage import anchor_preimage as py_emit
rows=[]
for name,(d,s,should_accept) in cases.items():
    try:
        b=py_emit(d,s,"BYTE Library",421614); py_ok=True; py_note=f"{len(b)}B/{b.count(10)}LF"
    except Exception: py_ok=False; py_note="rejected"
    ts=subprocess.run(["node","--import","tsx","-e",f'''
import {{anchorPreimage}} from "./src/anchorPreimage.ts";
try {{ const b=anchorPreimage({json.dumps(d)}, {json.dumps(s)}, {{name:"BYTE Library",chainId:421614}}); console.log("OK",b.length); }}
catch(e){{ console.log("REJECT"); }}'''],capture_output=True,text=True)
    ts_ok = ts.stdout.strip().startswith("OK")
    agree = py_ok==ts_ok
    correct = py_ok==should_accept and ts_ok==should_accept
    rows.append((name,should_accept,py_ok,ts_ok,agree,correct,py_note))
bad=[r for r in rows if not (r[4] and r[5])]
for n,exp,p,t,a,c,note in rows:
    print(f"{'ok ' if a and c else 'BAD'} {n:24s} expect_accept={str(exp):5s} py={str(p):5s} ts={str(t):5s} {note}")
print(f"\n{len(rows)-len(bad)}/{len(rows)} cases: both impls agree AND are correct")
sys.exit(1 if bad else 0)
