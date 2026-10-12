# Safe House

**Category:** Pwn &nbsp;|&nbsp; **Points:** 476 &nbsp;|&nbsp; **Solves:** 142 &nbsp;|&nbsp; **Flag:** `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}`

## Challenge description

> The safe house processes reports and files notes for the field. Get past the front desk
> and into the vault.
>
> `nc chal.sunshinectf.games 26007` &nbsp;·&nbsp; file: `service`

## Initial analysis

`service` forks into two processes:

- The **parent** handles our text commands (`PING`, `NOTE`, `RELAY`, `SUBMIT`, …). It's
  sandboxed and never hands us the flag directly.
- The **child** manages records. It loads `flag.txt` into a protected *system* record and
  talks to the parent over a socketpair on fd 3. Its own output goes to `/dev/null`, so
  the only way to see a reply is to make it travel back through the parent.

Messages on that socket are XOR-masked with a per-process 4-byte key. The parent normally
builds those messages for us — and the normal `RELAY` sends a *zero-length* request, so we
can't just ask for a record by number. The binary is **not PIE**, so code/gadget
addresses are fixed.

## Core concept — two bugs chained

**Bug 1 — stack overflow in `SUBMIT`.** `SUBMIT <size>` reads `<size>` bytes into a
**64-byte** stack buffer without bounding it. The saved return address is **72 bytes** in,
giving us ROP. Since there's no PIE, we build chains from the binary's own functions.

**Bug 2 — negative record index in the child.** For a fetch (protocol op 3) the child
reads a **signed 32-bit** index and rejects anything `> 15`, but never checks for
**negatives**. Records are `0x40c` bytes; the first public record is at `0x4060b0` and the
first *system* record (the flag) at `0x405080`:

```
0x4060b0 - 4 × 0x40c = 0x405080
```

So **public record `-4` is the first system record.** The four bytes for `-4` are
`fc ff ff ff`. We just need to get a forged fetch for index `-4` past the front desk.

## Exploitation (see [`solve.py`](./solve.py))

1. **Leak the XOR key.** The socket key lives at `0x405060` in the parent. A ROP chain
   calls the program's "print a string" helper on a 1-byte note `X` (which sets the
   `write` length to 1), then `write(1, 0x405060+i, 1)` four times to leak the key byte by
   byte (there's no handy `pop rdx` gadget).
2. **Build the forged request.** The plaintext we want is 8 bytes —
   `03 00 04 00  fc ff ff ff` (fetch header + index `-4`) — masked with the key in
   big-endian order:

   ```python
   plain  = b'\x03\x00\x04\x00' + struct.pack('<i', -4)
   mask   = key[::-1]                      # leaked little-endian → big-endian
   packet = bytes(b ^ mask[i % 4] for i, b in enumerate(plain))
   ```
3. **Smuggle it to fd 3.** The masked bytes are staged in public `NOTE` entries and
   `write()`-n to fd 3 via ROP, sent across four `SUBMIT` rounds (3+1 header, 3+1 index).
   Notes can't hold a leading space or newline, so those bytes are sourced from `X ` or a
   newline already in `.rodata`.
4. **Keep the menu alive.** After a hijacked return the stack is misaligned for the
   command loop (`NOTE` expects a pointer at `[rsp+8]`). The script pivots to a **fake
   stack** staged in notes 6/7 and uses the gadget at `0x4014bd` to reload the loop's
   string pointers, so we can bounce between ROP stages and the menu.
5. **Collect the reply.** Once the child processes the forged fetch, a normal `RELAY 1`
   makes the parent read the queued flag reply and print it (with a short pause so the
   child finishes writing first).

## Flag retrieval

```
$ python3 solve.py --remote        # chal.sunshinectf.games:26007
...
sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```

## Key takeaways

- **Signed vs. unsigned index checks.** Validating only the upper bound of a *signed*
  index lets negative values walk backwards into adjacent, more-privileged records —
  "negative handles open secret doors."
- Chain a classic stack overflow (control flow) with a logic bug (the real primitive).
- When a child speaks only over an internal socket, you don't need its stdout — forge its
  input and let the trusted parent relay the answer back.
- No PIE turns fixed `.bss`/`.rodata` addresses into reliable gadget and data sources.
