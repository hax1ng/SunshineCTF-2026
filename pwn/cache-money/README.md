# Cache Money

**Category:** Pwn &nbsp;|&nbsp; **Points:** 466 &nbsp;|&nbsp; **Solves:** 166 &nbsp;|&nbsp; **Flag:** `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}`

## Challenge description

> The arcade's credit manager tracks every wallet in the house. The books haven't been
> audited in years, so help yourself.
>
> `nc chal.sunshinectf.games 26004` &nbsp;·&nbsp; files: `cache_money`, `libc.so.6`, `ld-linux-x86-64.so.2`

## Initial analysis

- **Binary:** x86-64, **No PIE** (base `0x400000`), Partial RELRO (GOT writable), stack
  canary, NX, FORTIFY. libc 2.39 (Ubuntu 24.04).
- A "wallet manager" menu. Wallets are an array of 16 pointers at `0x4040c0`. Each wallet
  is `calloc(0x30)`:

  ```
  +0x00 name[16]     +0x10 balance (u64)   +0x18 ledger ptr
  +0x20 size (u64)   +0x28 active flag
  ```

- Handlers: `1` Open, `2` Deposit, `3` Withdraw, `4` **Transfer**, `5` Close, `6` List.
  - **Deposit** `read(0, ledger, size)` — exact size, no overflow.
  - **Withdraw** `write(1, ledger, size)` — dumps the *full* `size` bytes (so it leaks
    the contents of a freed chunk).
  - **Close** frees the ledger and the struct, zeroes the slot, but does **not** null
    `struct.ledger`.

## Core concept — Use-After-Free via `Transfer`

The `Transfer` handler is the bug. It frees the source's ledger, then copies the
(now dangling) pointer into an **active** destination without nulling it:

```c
free(src->ledger);
dst->ledger = src->ledger;   // dangling: dst points at a freed chunk, dst stays active
dst->size   = src->size;
src->ledger = 0; src->size = 0; src->active = 0;
```

That single mistake gives both halves of a UAF:

- **Withdraw(dst)** reads the freed chunk → heap and libc leaks (tcache `fd` under
  safe-linking, unsorted-bin `fd`/`bk`).
- **Deposit(dst)** writes into the freed chunk → **tcache poisoning** (overwrite the `fd`).

Because the binary is **No PIE + Partial RELRO**, the `.bss` wallet array (`0x4040c0`) and
`free@GOT` (`0x404000`) are at fixed, known addresses — perfect targets for the poison,
with no ASLR calibration needed on the low bits.

## Exploitation (see [`solve.py`](./solve.py))

1. **libc leak.** Open nine `0x100`-class wallets; Close seven (fills `tcache[0x110]`);
   `Transfer(7→8)` frees the 8th ledger into the **unsorted bin** while wallet 8 keeps the
   dangling pointer; `Withdraw(8)` dumps a `main_arena` pointer →
   `libc_base = fd - 0x203b20`.
2. **Heap leak (defeat safe-linking).** Open A, B, X, Y of size `0x80` (`tcache[0x90]`).
   `Transfer(B→Y)` frees B (`B.fd = B>>12`); `Withdraw(Y)` leaks `B>>12`, i.e. the heap
   page key used by glibc 2.39 safe-linking.
3. **Tcache poison.** `Transfer(A→X)` frees A (tcache head = A). `Deposit(X)` overwrites
   `A.fd` with `0x4040c0 ^ (B>>12)` (A and B share a page, so `A>>12 == B>>12`).
4. **Overlap the wallet array.** Open C (returns A), then Open W → `malloc` hands back
   `0x4040c0`, the `.bss` wallet-pointer array itself. (Open's `memset(array, 0, 0x80)` is
   harmless.)
5. **Forge wallets.** `Deposit(W)` rewrites the array with two fake wallet structs built
   in `.bss`: one whose ledger = `free@GOT` (`0x404000`), one whose ledger points at a
   `"/bin/sh"` string in `.bss`.
6. **Overwrite `free@GOT`.** `Deposit(0)` writes `system` into `free@GOT`.
7. **Pop a shell.** `Close(1)` → `free(fake.ledger)` becomes `system("/bin/sh")`.

## Flag retrieval

```
$ python3 solve.py          # against chal.sunshinectf.games:26004
...
uid=1337(cache_money) ...
$ cat flag.txt
sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
```

## Key takeaways

- A dangling pointer copied to a still-active object (and not nulled) is a full UAF:
  read → leaks, write → tcache poisoning.
- glibc 2.39 **safe-linking** only mangles `fd` with `addr >> 12`. Leak any freed chunk's
  `fd` on the same page and you recover the key — "safe linking won't save your tcache."
- No PIE + Partial RELRO makes `.bss` globals and the GOT fixed targets, so overlapping a
  controllable allocation onto the program's own pointer table trivialises the final write.
