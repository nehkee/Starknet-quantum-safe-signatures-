import sys, random
sys.path.insert(0, sys.argv[1])
from norm_emu import hq_lane_value, centered, P, B1, B3, Q
BOUND = 34_034_726

def lanes(v, k):
    # decode signed 35/70-bit lanes of v (as a signed integer near 0)
    if v > P // 2: v -= P
    out = []
    for width in ([35, 70, None] if k == 3 else [35, None]):
        if width is None:
            out.append(v); break
        mod = 1 << width
        l = v % mod
        if l >= mod // 2: l -= mod
        out.append(l); v = (v - l) >> width
    return out

def run(k, n, seed):
    rng = random.Random(seed)
    worst = None; cnt = 0
    for _ in range(n):
        diffs = [rng.randint(-12288, 61444) for _ in range(k)]
        true = [centered(x) for x in diffs]
        got = lanes(hq_lane_value(diffs), k)
        if [g*g for g in got] != [t*t for t in true]:
            cnt += 1
            tn = sum(t*t for t in true)
            if worst is None or tn < worst[0]:
                worst = (tn, diffs, true, got)
    print(k, "lane squares mismatched:", cnt, "of", n, "| smallest true triple norm among them:", worst and worst[0], worst)

if __name__=="__main__": run(3, 1_000_000, 5)
if __name__=="__main__": run(2, 1_000_000, 6)
