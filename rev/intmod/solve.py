#!/usr/bin/env python3
# IntMod solver: program (decoded VM instructions) was dumped with hook4.so -> trace4.txt
import struct
from analyze import parse, apply, rol, M
P = 0xfff1
rows = parse("trace4.txt")
mix = [ins for _, ins, _ in rows if ins[0] <= 4]
chk = [ins for _, ins, _ in rows if ins[0] in (5, 6)]
# pair op5 (hash into slot) with the following op6 (compare slot)
eqs, pend = [], {}
for op, a, b, slot, k, imm in chk:
    if op == 5: pend[slot] = (imm & 0xffffffff, imm >> 32)
    else:
        base, sub = pend.pop(slot)
        eqs.append((base % P, (imm + sub) % P))   # sum byte[j]*base^j == imm+sub (mod P)
print(len(mix), "mix ops,", len(eqs), "equations")
# Gaussian elimination mod P
n = 40
A = [[pow(b, j, P) for j in range(n)] + [h] for b, h in eqs]
for c in range(n):
    piv = next(r for r in range(c, len(A)) if A[r][c])
    A[c], A[piv] = A[piv], A[c]
    inv = pow(A[c][c], -1, P); A[c] = [x * inv % P for x in A[c]]
    for r in range(len(A)):
        if r != c and A[r][c]:
            f = A[r][c]; A[r] = [(x - f * y) % P for x, y in zip(A[r], A[c])]
F = bytes(A[i][n] for i in range(n))
assert all(A[i][n] < 256 for i in range(n))
st = list(struct.unpack("<5Q", F))
# invert mixing
def inv(st, ins):
    op, a, b, c, k, imm = ins; st = list(st)
    if op == 0: st[a] = (st[a] - rol(st[b], k)) & M
    elif op == 1: st[a] ^= rol(st[b], k)
    elif op == 2: st[a] = (st[a] * pow(imm, -1, 1 << 64)) & M
    elif op == 3: st[a] = rol(st[a], 64 - (k & 63))
    elif op == 4: st[a], st[b] = st[b], st[a]
    return st
for ins in reversed(mix): st = inv(st, ins)
raw = struct.pack("<5Q", *st)
print(raw)
flag = raw[:33].decode()
assert raw[33:] == b"\x07" * 7
print(flag)
open("flag.txt", "w").write(flag + "\n")
