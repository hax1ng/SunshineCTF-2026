# Code Breaker

**Category:** Pwn &nbsp;|&nbsp; **Points:** 474 &nbsp;|&nbsp; **Solves:** 147 &nbsp;|&nbsp; **Flag:** `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`

## Challenge description

> CodeBreaker: enterprise-grade encrypted key-value storage. All traffic is encrypted with
> our proprietary cipher. Your data has never been safer.
>
> `nc chal.sunshinectf.games 26005` &nbsp;·&nbsp; files: `code_breaker`, `libc.so.6`, `ld-linux-x86-64.so.2`

## Initial analysis

- **Binary:** x86-64 PIE, stripped. Partial RELRO, canary, NX, FORTIFY, **and Intel CET
  (SHSTK + IBT)**. glibc 2.39.
- No plaintext menu strings — **all traffic is enciphered** with a custom stream cipher
  (the "proprietary cipher"), so you have to implement the cipher before you can even talk
  to it.
- It's an encrypted key-value store with 16 slots. Each slot (16 bytes) at `0x41c0`:
  `{ptr, len:2, refcount:2, pad}`. A global function pointer at `0x40c0` is initialised to
  an `endbr64; ret` no-op.

## The cipher (fully reproducible client-side)

```
ks(ctr, i) = SBOX[(ctr + i + key[i & 15]) & 0xff]
ct[i] = pt[i] ^ ks(ctr, i)
```

A 256-byte SBOX at `0x2040`, two counters (`0x42c0` our-encrypt, `0x42c4` our-decrypt)
each advancing by message length, and a 2-byte big-endian length prefix per frame. The
SBOX is extracted straight from the ELF `.rodata` to avoid transcription errors.

### Handshake (owning the channel)

1. Server → client **plaintext** `[01][R:16]` (R from `/dev/urandom`) → **we learn R.**
2. Client → server plaintext `[02][C:16..]` → C is ours.
3. Key derivation over `M = R‖C` (32 bytes), 4 rounds of
   `key[j] = rol3(SBOX[key[j] ^ M[(j+8t)&31]] ^ M[3t+j])`.
4. Client → server **encrypted** `[03][MAC:16]`, `MAC[a] = key[(a+5)&15] ^ SBOX[key[a]]`.

Because R is leaked and C is ours, we derive the exact `key`, pass the MAC, and from then
on encrypt/decrypt the channel ourselves.

## Core concept — refcounted UAF → tcache poison

Commands include STORE, GET, UPDATE, DELETE, **LINK**, EXEC, INFO. The bug:

- `LINK [dst][src]` aliases two slots onto one heap chunk and bumps `src.refcount` to 2.
- `DELETE` does `free(ptr); refcount--;` but **only nulls the pointers when refcount hits
  0.** So deleting a linked chunk frees it while both slots keep pointing at it → **UAF**.

UAF + `GET`/`UPDATE` is arbitrary read/write on a freed tcache chunk → **tcache poisoning**
(glibc 2.39 safe-linking). `INFO` leaks `0xf2` bytes of `.bss` from `0x40c0`, the first 8
of which are the function pointer → **PIE base**.

## Exploitation (see [`solve.py`](./solve.py))

1. Handshake → derive `key`, own the channel.
2. `INFO` → funcptr leak → `pie_base = funcptr - 0x1390`;
   `system@plt = pie+0x1150`, target funcptr = `pie+0x40c0`.
3. **Heap leak:** STORE k0 (`0x18`) → α; `LINK k2←k0` (α.rc=2); `DELETE k0` (freed, ptrs
   retained; `α->next = α>>12`); `GET k0` → leaks `α>>12` (the safe-link key).
4. **Poison:** reclaim α so its key differs from the tcache key; STORE/DELETE a second
   chunk β; `DELETE k0` → `tcache = [α→β]`, slots k1/k2 still alias α; `UPDATE k1` with
   `p64((α>>12) ^ target)` → `α->next = target` (= `0x40c0`).
5. STORE k4 (pops α), STORE k5 = `p64(system@plt)` (pops `0x40c0`) → **funcptr = system@plt**.
6. `EXEC "/bin/sh\0"` → the program calls `funcptr("/bin/sh")` = `system("/bin/sh")`.

### Why it beats CET

No return address or ROP is corrupted. We overwrite a **data function pointer** that the
program itself calls through an indirect `call` to an `endbr64`-prefixed target
(`system@plt.sec`). Shadow stack and IBT are both satisfied — CET never trips.

## Flag retrieval

```
$ python3 solve.py          # chal.sunshinectf.games:26005
...
uid=1337(code_breaker) ...
$ cat flag.txt
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
```

## Key takeaways

- When the protocol is encrypted, reproduce the cipher first; a leaked nonce + an
  attacker-chosen value usually means you can derive the key and fully own the channel.
- Refcounted free logic that only nulls pointers at refcount 0 is a classic UAF source.
- **Intel CET doesn't stop data-pointer hijacks.** Overwriting a function pointer that
  resolves to an `endbr64` target (like `system@plt.sec`) satisfies IBT and leaves the
  shadow stack untouched — no ROP required.
