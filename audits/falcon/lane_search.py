import sys
sys.path.insert(0, sys.argv[1])
from norm_emu import hq_lane_value, centered
from mismatch_min import lanes
import itertools
LIM = 5833
def scan(k, ds, others):
    worst = None
    for pos in range(k):
        for o in itertools.product(others, repeat=k-1):
            for d in ds:
                diffs = list(o); diffs.insert(pos, d)
                true = [centered(x) for x in diffs]
                got = lanes(hq_lane_value(diffs), k)
                for t, g in zip(true, got):
                    if t*t != g*g and abs(t) <= LIM:
                        print("BAD", k, diffs, true, got); return True
    return False
full = range(-12288, 61445)
oth_small = [-12288, -6145, -6144, 0, 6144, 6145, 12288, 18433, 30722, 43011, 55300, 61444]
band = [d for d in full if 5000 <= abs(centered(d)) <= LIM]
oth_big = sorted(set(oth_small + list(range(-12288, 61445, 1500))))
mode = sys.argv[2]
if mode == "a":
    print("stage a k=3", scan(3, full, oth_small[:6] + oth_small[9:]))
    print("stage a k=2", scan(2, full, oth_small))
else:
    print(len(band), len(oth_big))
    print("stage b k=2", scan(2, band, oth_big)); print("stage b k=3", scan(3, band, oth_big))
