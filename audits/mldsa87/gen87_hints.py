"""HintBitUnpack probes for ML-DSA-87 records, judged by the evaluator's reference (mldsa87.py).

Signs with dilithium-py, then rewrites only the hint field (the last OMEGA + K bytes):
- swaps of two positions inside a row (the hint set is unchanged, so only the order check rejects);
- a repeated position, a count above OMEGA, a falling count, a nonzero padding byte;
- the untouched signature as a control.

Usage: venv/bin/python -I gen87_hints.py REFERENCE_DIR OUT_JSON OUT_CAIRO [SIGNATURES]
"""
import json
import random
import sys

sys.path.insert(0, sys.argv[1])
import mldsa87 as ref  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_87  # noqa: E402

OMEGA, K = ref.OMEGA, ref.K
HINT_AT = ref.SIG_BYTES - (OMEGA + K)
rng = random.Random(87)
count = int(sys.argv[4]) if len(sys.argv) > 4 else 6

vectors = []


def add(name, msg, pk, sig):
    v = ref.verify_felts(msg, ref.pack_felts(pk), ref.pack_felts(sig))
    vectors.append({"name": name, "message": msg, "public_key": ref.pack_felts(pk),
                    "signature": ref.pack_felts(sig), "expect": v.valid, "reason": v.reason})


def rows(sig):
    y = sig[HINT_AT:]
    out, start = [], 0
    for i in range(K):
        end = y[OMEGA + i]
        out.append((start, end))
        start = end
    return y, out


made = 0
while made < count:
    pk, sk = ML_DSA_87.keygen()
    msg = rng.randrange(ref.FELT_PRIME)
    sig = ML_DSA_87.sign(sk, ref.message_bytes(msg))
    y, rr = rows(sig)
    if sum(1 for a, b in rr if b - a >= 3) < 2:
        continue
    made += 1
    add(f"valid_{made}", msg, pk, sig)
    for i, (a, b) in enumerate(rr):
        if b - a < 2:
            continue
        ys = bytearray(y)
        # swap two neighbours at the start, the middle and the end of the row
        for j in sorted({a, (a + b) // 2 - 1 if (a + b) // 2 - 1 >= a else a, b - 2}):
            t = bytearray(y)
            t[j], t[j + 1] = t[j + 1], t[j]
            add(f"swap_{made}_row{i}_at{j - a}_{t[j]}_{t[j + 1]}", msg, pk, sig[:HINT_AT] + bytes(t))
        # swap the row's first and last positions (far apart, usually different blocks)
        t = bytearray(y)
        t[a], t[b - 1] = t[b - 1], t[a]
        add(f"swapends_{made}_row{i}_{t[a]}_{t[b - 1]}", msg, pk, sig[:HINT_AT] + bytes(t))
        # repeat a position
        t = bytearray(y)
        t[a + 1] = t[a]
        add(f"repeat_{made}_row{i}", msg, pk, sig[:HINT_AT] + bytes(t))
    # a falling count, a count above OMEGA, a nonzero padding byte
    t = bytearray(y)
    nz = [i for i in range(1, K) if t[OMEGA + i] > t[OMEGA + i - 1]]
    if nz:
        i = nz[0]
        t[OMEGA + i - 1], t[OMEGA + i] = t[OMEGA + i], t[OMEGA + i - 1]
        add(f"countfall_{made}", msg, pk, sig[:HINT_AT] + bytes(t))
    t = bytearray(y); t[OMEGA + K - 1] = OMEGA + 1
    add(f"countover_{made}", msg, pk, sig[:HINT_AT] + bytes(t))
    if y[OMEGA + K - 1] < OMEGA:
        t = bytearray(y); t[OMEGA - 1] = 1
        add(f"padding_{made}", msg, pk, sig[:HINT_AT] + bytes(t))

json.dump(vectors, open(sys.argv[2], "w"))
by = {}
for v in vectors:
    by[(v["name"].split("_")[0], v["reason"])] = by.get((v["name"].split("_")[0], v["reason"]), 0) + 1
print(len(vectors), "vectors", by)

lines = ["use pqbench_ml_dsa_87::cache;", "",
         "fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {",
         "    let mut stored: Array<felt252> = array![];",
         "    let mut index = 0;",
         "    while index != cache::PARTS {",
         "        match cache::part(public_key, index) {",
         "            Some(felts) => stored.append_span(felts.span()),",
         "            None => { return false; },",
         "        }",
         "        index += 1;",
         "    }",
         "    cache::verify_cached(message_hash, stored.span(), signature)",
         "}", ""]
for n, v in enumerate(vectors):
    want = "true" if v["expect"] else "false"
    lines += [f"// {v['name']}: reference {v['reason']}",
              f"#[test]\nfn h{n:03d}_{v['name']}() {{",
              f"    let pk = array![{', '.join(hex(x) for x in v['public_key'])}];",
              f"    let sig = array![{', '.join(hex(x) for x in v['signature'])}];",
              f"    assert!(verify({hex(v['message'])}, pk.span(), sig.span()) == {want});",
              "}\n"]
open(sys.argv[3], "w").write("\n".join(lines))
