"""Python emulation of the record fj_135df3c8's packed norm (packing.cairo: hq3, hq2, sg3, bg2,
and the final extraction in `et`), checked against the reference's centered norm."""
import random
import sys

P = 2**251 + 17 * 2**192 + 1
Q = 12289
B1, B3 = 2**35, 2**105

# hq3 / hq2 constants
C_HQ = 747731312448222481849872718967621633
Y_OFF = 249230249209671726169674930035103744
K_HQ = 3576095008238276593254811797070732988878109843115171765732780120446085365761
HPM3 = 297747071055821155530704983081937272832
# sg3 / bg2 constants
N4BIAS2 = 70334384441343
N4MASK2 = 281474976718848
N4BIAS3 = 83036184917349938715710381149390847
N4MASK3 = 332306998946228968226233240046804992
N4QINV = 1808809682566871010753239355074989267886550786960801817186256343979052236802
# final extraction
FINAL_BIAS = 23945242826726411699303254272397162485873418786832384
ZL_MASK = 40564819206122749227211451006975
N70 = 1180591620717411303423
BOUND_CONST = 0x81d509bffffffffffffffffffff
U128 = 2**128


def hq_lane_value(diffs):
    """v before squaring, for 2 or 3 lanes of (msg - hint) differences."""
    abc = sum(d * s for d, s in zip(diffs, (1, B1, B3)))
    x = abc + C_HQ
    w = x * 85
    assert 0 <= w < U128, ("w out of u128", diffs)
    f = w & HPM3
    y = x - Y_OFF
    return (y - f * K_HQ) % P


def hq(ms, ts):
    v = hq_lane_value([m - t for m, t in zip(ms, ts)])
    return v * v % P


def sg_value(ds):
    if len(ds) == 3:
        p = ds[0] + ds[1] * B1 + ds[2] * B3
        t = p + N4BIAS3
        flags = t & N4MASK3
    else:
        p = ds[0] + ds[1] * B1
        t = p + N4BIAS2
        flags = t & N4MASK2
    assert t < U128
    return (p - flags * N4QINV) % P


def sg(ds):
    v = sg_value(ds)
    return v * v % P


def record_accepts_norm(point_raw, hint, s1):
    """Return (accepts, cy) for the record's norm check. point_raw: raw candidates < 5q."""
    cy = 0
    for i in range(0, 510, 3):
        cy += sg(s1[i:i + 3]) + hq(point_raw[i:i + 3], hint[i:i + 3])
    cy += sg(s1[510:512]) + hq(point_raw[510:512], hint[510:512])
    cy %= P
    z = (cy + FINAL_BIAS) % P
    zh, zl = z >> 128, z & (U128 - 1)
    if zh == 0:
        return False, cy
    z02 = (zl & ZL_MASK) % N70
    n = (BOUND_CONST - zh - z02 * 2**82) % P
    return n < U128, cy


def centered(x):
    x %= Q
    return x if x <= (Q - 1) // 2 else x - Q


def ref_norm(point_raw, hint, s1):
    return sum(centered(p - h) ** 2 + centered(s) ** 2 for p, h, s in zip(point_raw, hint, s1))


def lane_check():
    """Each packed lane must hold the centered residue of its difference."""
    bad = 0
    others = [0, -12288, 61444, 6144, -6144, 30000]
    for pos in range(3):
        for d in range(-12288, 61445):
            for o in others:
                diffs = [o, o, o]
                diffs[pos] = d
                v = hq_lane_value(diffs)
                expect = sum(centered(x) * s for x, s in zip(diffs, (1, B1, B3))) % P
                if v != expect:
                    bad += 1
                    if bad < 10:
                        print("hq3 lane mismatch", pos, diffs)
    for d in range(-12288, 61445):
        for o in others:
            for pos in range(2):
                diffs = [o, o]
                diffs[pos] = d
                v = hq_lane_value(diffs)
                expect = sum(centered(x) * s for x, s in zip(diffs, (1, B1))) % P
                if v != expect:
                    bad += 1
                    if bad < 20:
                        print("hq2 lane mismatch", pos, diffs)
    for a in range(Q):
        for o in (0, 6144, 6145, 12288):
            for pos in range(3):
                ds = [o, o, o]
                ds[pos] = a
                if sg_value(ds) != sum(centered(x) * s for x, s in zip(ds, (1, B1, B3))) % P:
                    bad += 1
                    if bad < 30:
                        print("sg3 mismatch", ds)
            for pos in range(2):
                ds = [o, o]
                ds[pos] = a
                if sg_value(ds) != sum(centered(x) * s for x, s in zip(ds, (1, B1))) % P:
                    bad += 1
                    if bad < 40:
                        print("sg2 mismatch", ds)
    print("lane mismatches:", bad)
    return bad


def random_lane_check(n=2_000_000, seed=1):
    rng = random.Random(seed)
    bad = 0
    for _ in range(n):
        diffs = [rng.randint(-12288, 61444) for _ in range(3)]
        if hq_lane_value(diffs) != sum(centered(x) * s for x, s in zip(diffs, (1, B1, B3))) % P:
            bad += 1
            if bad < 10:
                print("random hq3 mismatch", diffs)
    print("random hq3 mismatches:", bad)
    return bad


def boundary_check(trials=3000, seed=2):
    """Norm vectors around the bound, including heavy, sign-structured ones."""
    rng = random.Random(seed)
    disagreements = 0
    bound = 34_034_726
    for t in range(trials):
        mode = t % 6
        # Random raw candidates < 5q and hints < q, then pick s1 so the total lands near the bound.
        hint = [rng.randrange(Q) for _ in range(512)]
        if mode == 0:  # small s0, everything near zero
            s0 = [rng.randint(-200, 200) for _ in range(512)]
        elif mode == 1:  # large uniform s0
            s0 = [rng.randint(-6144, 6144) for _ in range(512)]
        elif mode == 2:  # all max magnitude, same sign
            s0 = [6144] * 512
        elif mode == 3:  # alternating max magnitudes
            s0 = [6144 if i % 2 else -6144 for i in range(512)]
        elif mode == 4:  # sparse spikes
            s0 = [0] * 512
            for i in rng.sample(range(512), 30):
                s0[i] = rng.choice([-6144, 6144, -6000, 5999])
        else:
            s0 = [rng.choice([-1, 1]) * rng.randint(0, 260) for _ in range(512)]
        point = []
        for h, s in zip(hint, s0):
            r = (h + s) % Q
            # any raw candidate r + kq < 5q, k in 0..4
            kmax = (61444 - r) // Q
            point.append(r + Q * rng.randint(0, kmax))
        base = sum(centered(p - h) ** 2 for p, h in zip(point, hint))
        # choose s1 to bring the total near the bound when possible, else random
        s1 = [0] * 512
        target = bound + rng.choice([-2, -1, 0, 1, 2, 3, 1000, -1000])
        remaining = target - base
        i = 0
        while remaining > 0 and i < 512:
            c = min(6144, int(remaining ** 0.5))
            s1[i] = c if rng.random() < 0.5 else -c
            remaining -= c * c
            i += 1
        if mode in (2, 3):  # heavy everywhere, far above the bound
            s1 = [rng.choice([6144, -6144, 6143, -6143]) for _ in range(512)]
        s1 = [x % Q for x in s1]
        rn = ref_norm(point, hint, s1)
        acc, _ = record_accepts_norm(point, hint, s1)
        if acc != (rn <= bound):
            disagreements += 1
            if disagreements < 10:
                print("DISAGREE mode", mode, "ref norm", rn, "record accepts", acc)
    print("boundary disagreements:", disagreements, "of", trials)
    return disagreements


if __name__ == "__main__":
    which = sys.argv[1:] or ["lane", "random", "boundary"]
    if "lane" in which:
        lane_check()
    if "random" in which:
        random_lane_check()
    if "boundary" in which:
        boundary_check()
