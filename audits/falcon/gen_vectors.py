"""Craft Falcon-512 inputs for the record, judged by the evaluator's reference verifier.

A valid input needs no Falcon secret key: the public key is part of the input. Pick s1 with an
invertible NTT and a small s0, set hint = point - s0 and h_ntt = NTT(hint) / NTT(s1). Then
s1 * h = hint and the norm is exactly ||s0||^2 + ||s1||^2, so it can be placed at the bound.

Usage: python3 -I gen_vectors.py REFERENCE_DIR OUT_JSON OUT_CAIRO
"""
import json
import random
import sys

sys.path.insert(0, sys.argv[1])
import falcon512 as ref  # noqa: E402

Q, N, BOUND = ref.Q, ref.N, ref.SIG_BOUND
rng = random.Random(20261117)


def inv(x):
    return pow(x, Q - 2, Q)


def build(message, salt_a, salt_b, s1, s0):
    point, _ = ref.hash_to_point(message, ref.salt_bytes(salt_a, salt_b))
    hint = [(p - s) % Q for p, s in zip(point, s0)]
    s1 = [x % Q for x in s1]
    s1n = ref.ntt(s1)
    if any(v == 0 for v in s1n):
        return None
    hn = ref.ntt(hint)
    h_ntt = [hn[i] * inv(s1n[i]) % Q for i in range(N)]
    pk = ref.pack_512(h_ntt)
    sig = ref.pack_512(s1) + [salt_a, salt_b] + ref.pack_512(hint)
    return {"message": message, "public_key": pk, "signature": sig}


def fill_to(total, rng, cap=6144, start=None):
    """Signed coefficients (list of 512) whose squares sum to exactly `total`."""
    out = [0] * N if start is None else list(start)
    rem = total - sum(x * x for x in out)
    idx = [i for i in range(N) if out[i] == 0]
    rng.shuffle(idx)
    for i in idx:
        if rem <= 0:
            break
        c = min(cap, int(rem ** 0.5))
        # leave something representable by the rest
        out[i] = c if rng.random() < 0.5 else -c
        rem -= c * c
    assert rem == 0, rem
    return out


def rand_small(scale, density=1.0):
    return [rng.randint(-scale, scale) if rng.random() < density else 0 for _ in range(N)]


vectors = []


def add(name, vec):
    if vec is None:
        return
    verdict = ref.verify(vec["message"], vec["public_key"], vec["signature"])
    vec = dict(vec, name=name, expect=verdict.valid, reason=verdict.reason, norm=verdict.norm)
    vectors.append(vec)


def salt():
    return rng.getrandbits(160), rng.getrandbits(160)


# 1. Norm exactly at the bound and one over, several shapes.
for shape in range(6):
    for delta in (0, 1):
        for _ in range(20):
            msg = rng.randrange(ref.FELT_PRIME)
            sa, sb = salt()
            if shape == 0:      # mass in s0
                s1 = [1] + [0] * (N - 1)
                s0 = fill_to(BOUND + delta - 1, rng)
            elif shape == 1:    # mass in s1
                s0 = [0] * N
                s1 = fill_to(BOUND + delta, rng, start=rand_small(3))
            elif shape == 2:    # big single coefficients (|c| near 5833)
                s0 = [0] * N
                s0[rng.randrange(N)] = 5833 * rng.choice([-1, 1])
                s1 = [1] + [0] * (N - 1)
                s0 = fill_to(BOUND + delta - 1, rng, start=s0)
            elif shape == 3:    # balanced
                s1 = fill_to(BOUND // 2, rng, cap=400, start=rand_small(2, 0.2))
                s0 = fill_to(BOUND + delta - BOUND // 2, rng, cap=400, start=rand_small(2, 0.2))
            elif shape == 4:    # many mid coefficients, both signs
                s1 = rand_small(150, 0.3)
                s0 = fill_to(BOUND + delta - sum(x * x for x in s1), rng, cap=400, start=rand_small(150, 0.3))
            else:               # max magnitude lanes in s1 at 6144
                s1 = [0] * N
                s1[0] = 1
                s0 = [0] * N
                s0 = fill_to(BOUND + delta - 1, rng, cap=5800)
            v = build(msg, sa, sb, s1, s0)
            if v is not None:
                add(f"bound_shape{shape}_{'over' if delta else 'at'}", v)
                break

# 2. Valid inputs, then tamper with the hint, key, s1 so only the hint equation catches it.
for k in range(8):
    msg = rng.randrange(ref.FELT_PRIME)
    sa, sb = salt()
    s1 = rand_small(100)
    s0 = rand_small(100)
    v = build(msg, sa, sb, s1, s0)
    if v is None:
        continue
    add(f"valid_{k}", v)
    hint = ref.unpack_512(v["signature"][31:60])
    s1u = ref.unpack_512(v["signature"][0:29])
    h = ref.unpack_512(v["public_key"])
    i = rng.randrange(N)
    for d in (1, Q - 1, 6144):
        t = list(hint); t[i] = (t[i] + d) % Q
        add(f"tamper_hint_{k}_{d}", dict(v, signature=v["signature"][:31] + ref.pack_512(t)))
        t = list(h); t[i] = (t[i] + d) % Q
        add(f"tamper_key_{k}_{d}", dict(v, public_key=ref.pack_512(t)))
        t = list(s1u); t[i] = (t[i] + d) % Q
        add(f"tamper_s1_{k}_{d}", dict(v, signature=ref.pack_512(t) + v["signature"][29:]))
    # hint shifted by a constant in the NTT domain: the pointwise check sees every coordinate
    hn = ref.ntt(hint)
    hn2 = [(x + 1) % Q for x in hn]
    add(f"tamper_hint_ntt_shift_{k}", dict(v, signature=v["signature"][:31] + ref.pack_512(ref.intt(hn2))))

# 3. Extreme coefficient values in key and hint (0 and q-1 everywhere) with consistent equations.
for k, fill in enumerate((0, Q - 1, 1, 6144, 6145)):
    msg = rng.randrange(ref.FELT_PRIME)
    sa, sb = salt()
    point, _ = ref.hash_to_point(msg, ref.salt_bytes(sa, sb))
    # choose hint = all `fill`; s0 = point - hint (huge norm -> reject, but exercises the hint path)
    s1 = [1] + [0] * (N - 1)
    s0 = [(p - fill) % Q for p in point]
    add(f"extreme_hint_{fill}", build(msg, sa, sb, s1, s0))
    # key all `fill` with s1 = hint * h^-1 impossible when fill = 0; instead set h = fill, hint = s1*h
    if fill:
        h_ntt = [fill] * N
        s1v = rand_small(50)
        s1n = ref.ntt([x % Q for x in s1v])
        hint = ref.intt([a * fill % Q for a in s1n])
        add(f"extreme_key_{fill}", {"message": msg, "public_key": ref.pack_512(h_ntt),
                                     "signature": ref.pack_512([x % Q for x in s1v]) + [sa, sb] + ref.pack_512(hint)})

json.dump(vectors, open(sys.argv[2], "w"))
counts = {}
for v in vectors:
    counts[v["expect"]] = counts.get(v["expect"], 0) + 1
print(len(vectors), "vectors", counts)

# Emit an snforge test per vector.
lines = ["use pqbench_falcon_512::Falcon512ShakeVerifier;", "use pqbench_interface::PqSignatureVerifier;", ""]
for i, v in enumerate(vectors):
    pk = ", ".join(hex(x) for x in v["public_key"])
    sig = ", ".join(hex(x) for x in v["signature"])
    want = "true" if v["expect"] else "false"
    lines.append(f"// {v['name']}: reference {v['reason']} norm {v['norm']}")
    lines.append(f"#[test]\nfn v{i:03d}_{v['name']}() {{")
    lines.append(f"    let pk: Array<felt252> = array![{pk}];")
    lines.append(f"    let sig: Array<felt252> = array![{sig}];")
    lines.append(f"    assert!(Falcon512ShakeVerifier::verify({hex(v['message'])}, pk.span(), sig.span()) == {want});")
    lines.append("}\n")
open(sys.argv[3], "w").write("\n".join(lines))
