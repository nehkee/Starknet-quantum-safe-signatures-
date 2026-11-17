"""Costly-rejection probe for the Falcon-1024 record fk_29560355.

Builds, from the evaluator's reference (falcon1024.py):
- valid 17-block inputs with ordinary norms (the comparison line);
- inputs that walk every cold path of the record before failing the hint check:
  a narrow first s1 felt (vslow/slow7), two hq3 lanes whose packed square over-counts
  (rare() and exact_norm), an exact norm under the bound, and one public-key NTT
  coordinate off by one (the hint equation fails at that coordinate only).

Usage: python3 -I gen1024.py REFERENCE_DIR NORM_EMU_DIR OUT_JSON OUT_CAIRO
"""
import hashlib
import json
import random
import sys

sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import falcon1024 as ref  # noqa: E402
from norm_emu import hq_lane_value, sg_value, P, B1, B3  # noqa: E402
from mismatch_min import lanes  # noqa: E402

Q, N, BOUND = ref.Q, ref.N, ref.SIG_BOUND
RARE_CAP = 84_200_968
OFJ = 23945242826726411699303254272397162485873418786832384
ZL_MASK = 40564819206122749227211451006975
N70 = 1180591620717411303423
rng = random.Random(1024_2026)


def raw_point(message, salt):
    shake = hashlib.shake_256(salt + message.to_bytes(32, "little"))
    stream = shake.digest(ref.WORDS_PER_BLOCK * 2 * 24)
    out, used = [], 0
    while len(out) < N:
        w = (stream[2 * used] << 8) | stream[2 * used + 1]
        used += 1
        if w < ref.ACCEPT_BELOW:
            out.append(w)
    return out, -(-used // ref.WORDS_PER_BLOCK)


def groups():
    """(kind, indices) in the record's packing order: per felt, low half 9 then high half."""
    out = []
    for j in range(57):
        halves = [(18 * j, 9), (18 * j + 9, 9 if j < 56 else 7)]
        for start, cnt in halves:
            idx = list(range(start, start + cnt))
            if cnt == 9:
                out += [("s3", idx[0:3]), ("s3", idx[3:6]), ("s3", idx[6:9]),
                        ("h3", idx[0:3]), ("h3", idx[3:6]), ("h3", idx[6:9])]
            else:  # digits7: sg3, sg3, hq3, hq3, hq2(p6 - d6, s6)
                out += [("s3", idx[0:3]), ("s3", idx[3:6]), ("h3", idx[0:3]), ("h3", idx[3:6]),
                        ("h2s", [idx[6]])]
    return out


GROUPS = groups()


def packed_norm(praw, hint, s1):
    cy = OFJ
    for kind, idx in GROUPS:
        if kind == "s3":
            v = sg_value([s1[i] for i in idx])
        elif kind == "h3":
            v = hq_lane_value([praw[i] - hint[i] for i in idx])
        else:
            i = idx[0]
            v = hq_lane_value([praw[i] - hint[i], s1[i]])  # second lane holds s6 in [0, q)
        cy = (cy + v * v) % P
    jh, jl = cy >> 128, cy & ((1 << 128) - 1)
    assert jh
    return (jl & ZL_MASK) % N70 + jh // 2**82


def exact_norm(point, hint, s1):
    return sum(ref.centered((p - h) % Q) ** 2 + ref.centered(s) ** 2 for p, h, s in zip(point, hint, s1))


def seventeen_block_message():
    while True:
        msg = rng.randrange(ref.FELT_PRIME)
        sa, sb = rng.getrandbits(160), rng.getrandbits(160)
        praw, blocks = raw_point(msg, ref.salt_bytes(sa, sb))
        if blocks == 17:
            return msg, sa, sb, praw


def lanes_overcount(praw, idx, cs):
    """Packed minus exact square sum of one hq3 group, for centered s0 values cs."""
    diffs = []
    for i, c in zip(idx, cs):
        h = (praw[i] - c) % Q
        diffs.append(praw[i] - h)
    got = lanes(hq_lane_value(diffs), 3)
    return sum(g * g for g in got) - sum(ref.centered(d % Q) ** 2 for d in diffs)


def find_overcount_group(praw, idx, tries=200000):
    best = None
    for _ in range(tries):
        cs = [rng.randint(-40, 40) for _ in range(3)]
        cs[rng.randrange(3)] = rng.choice([-1, 1]) * rng.randint(5834, 6144)
        oc = lanes_overcount(praw, idx, cs)
        if oc > 0 and (best is None or oc < best[0]):
            best = (oc, cs)
            if oc < 7_500_000:
                break
    return best


def build(msg, sa, sb, praw, s1c, s0c, key_tamper=None):
    s1 = [x % Q for x in s1c]
    hint = [(p - c) % Q for p, c in zip(praw, s0c)]
    s1n = ref.ntt(s1)
    assert all(s1n), "s1 NTT not invertible"
    hn = ref.ntt(hint)
    h_ntt = [hn[i] * pow(s1n[i], Q - 2, Q) % Q for i in range(N)]
    if key_tamper is not None:
        h_ntt[key_tamper] = (h_ntt[key_tamper] + 1) % Q
    return {"message": msg, "public_key": ref.pack_1024(h_ntt),
            "signature": ref.pack_1024(s1) + [sa, sb] + ref.pack_1024(hint)}, hint, s1


vectors = []


def add(name, vec, **extra):
    verdict = ref.verify(vec["message"], vec["public_key"], vec["signature"])
    vectors.append(dict(vec, name=name, expect=verdict.valid, reason=verdict.reason,
                        blocks=verdict.blocks, norm=verdict.norm, **extra))


# Valid comparison inputs: 17 blocks, falcon.py-like norms (s1, s0 ~ N(0, 165^2)).
for k in range(2):
    msg, sa, sb, praw = seventeen_block_message()
    while True:
        s1c = [int(rng.gauss(0, 165)) for _ in range(N)]
        s0c = [int(rng.gauss(0, 165)) for _ in range(N)]
        try:
            vec, _, _ = build(msg, sa, sb, praw, s1c, s0c)
            break
        except AssertionError:
            continue
    add(f"valid17_{k}", vec)

# Attack inputs.
for k in range(1):
    msg, sa, sb, praw = seventeen_block_message()
    s0c = [0] * N
    over = 0
    for idx in ([0, 1, 2],):
        oc, cs = find_overcount_group(praw, idx)
        for i, c in zip(idx, cs):
            s0c[i] = c
        over += oc
    while True:
        s1c = [int(rng.gauss(0, 120)) for _ in range(N)]
        for i in range(9, 18):          # first s1 felt narrow: its high half is zero
            s1c[i] = 0
        used = sum(c * c for c in s1c) + sum(c * c for c in s0c)
        rem = BOUND - used
        free = [i for i in range(N) if s0c[i] == 0 and i not in (0, 1, 2, 18, 19, 20)]
        rng.shuffle(free)
        for i in free:                  # fill s0 so the exact norm is exactly the bound
            if rem <= 0:
                break
            c = min(3000, int(rem ** 0.5))
            s0c[i] = c if rng.random() < 0.5 else -c
            rem -= c * c
        assert rem == 0
        try:
            vec, hint, s1 = build(msg, sa, sb, praw, s1c, s0c)
            break
        except AssertionError:
            s0c = [c if i in (0, 1, 2, 18, 19, 20) else 0 for i, c in enumerate(s0c)]
    point = [p % Q for p in praw]
    ex = exact_norm(point, hint, s1)
    pk = packed_norm(praw, hint, s1)
    print(f"attack {k}: exact {ex}, packed {pk}, over-count {pk - ex} (lanes predicted {over}),"
          f" rare() window {BOUND} < packed <= {RARE_CAP}: {BOUND < pk <= RARE_CAP}")
    add(f"walk_valid_{k}", vec, exact=ex, packed=pk)  # every cold path, then accepted
    for j in sorted({c for f in range(57) for c in (18 * f, min(18 * f + 17, 1023))} | {510, 511, 512, 513, 1022, 1023}):
        tv, _, _ = build(msg, sa, sb, praw, s1c, s0c, key_tamper=j)
        add(f"walk_reject_{k}_key{j}", tv, exact=ex, packed=pk)

# Sanity: the emulated packed norm equals the exact norm on the ordinary valid inputs.
for v in vectors:
    if v["name"].startswith("valid17"):
        s1 = ref.unpack_1024(v["signature"][0:57])
        hint = ref.unpack_1024(v["signature"][59:116])
        praw, _ = raw_point(v["message"], ref.salt_bytes(v["signature"][57], v["signature"][58]))
        assert packed_norm(praw, hint, s1) == v["norm"], "emulation drift"

json.dump(vectors, open(sys.argv[3], "w"))
for v in vectors:
    print(v["name"], v["reason"], "blocks", v["blocks"], "norm", v["norm"])

lines = ["use pqbench_falcon_1024::Falcon1024Verifier;", "use pqbench_interface::PqSignatureVerifier;", ""]
for i, v in enumerate(vectors):
    pk = ", ".join(hex(x) for x in v["public_key"])
    sig = ", ".join(hex(x) for x in v["signature"])
    want = "true" if v["expect"] else "false"
    lines += [f"// {v['name']}: reference {v['reason']}, blocks {v['blocks']}",
              f"#[test]\nfn v{i:02d}_{v['name']}() {{",
              f"    let pk: Array<felt252> = array![{pk}];",
              f"    let sig: Array<felt252> = array![{sig}];",
              f"    assert!(Falcon1024Verifier::verify({hex(v['message'])}, pk.span(), sig.span()) == {want});",
              "}\n"]
open(sys.argv[4], "w").write("\n".join(lines))
