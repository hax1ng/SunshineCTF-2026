# Homemaker

**Category:** Pwn &nbsp;|&nbsp; **Points:** 468 &nbsp;|&nbsp; **Solves:** 163 &nbsp;|&nbsp; **Flag:** `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`

## Challenge description

> **A SERVANT IN EVERY HOME, BY 1975!** APEX ATOMIC HOUSEHOLD INDUSTRIES, INC IS PROUD TO
> ANNOUNCE THE MODEL 7 "HOMEMAKER" DOMESTIC AUTOMATON. POWERED THROUGH USE OF PUNCH CARDS,
> THE MODEL 7 IS EQUIPPED WITH THOUSANDS OF BYTES OF MEMORY! THE FUTURE IS HERE, NOW!
>
> `nc sunshinectf.games 26008` &nbsp;·&nbsp; file: `homemaker`

## Initial analysis

`homemaker` is a stripped 64-bit PIE binary. It prints the retro advertisement and asks
for a "service key card" — but it wants a **binary packet**, not text:

```
ESC [ | 2-byte big-endian payload length | payload | 1-byte CRC | ESC \
```

The first payload byte is a command number:

| Command | Meaning |
|---|---|
| `1` | Unlock with a 4-byte service key |
| `2` | Copy data into the robot's stack buffer |
| `3` | Send the stack buffer back |
| `4` | Finish and return from `main` |

The unlock key is compared against `0x1337c35f`. The CRC is a simple byte-wise calc with
polynomial `0x2f` — integrity, not security. Protections include a stack canary and PIE.

## Core concept — an off-by-one that rewrites a length field

After unlocking, the buffer capacity is set to `0x100` (256). Command `2` checks the
requested size against capacity — so far so safe. But the copy loop is off by one:

```c
count = packet_length - 1;      // minus the command byte
if (count > capacity) reject();
for (i = 0; i <= count; i++)    // BUG: should be i < count
    buffer[i] = packet_data[i];
```

`i <= count` copies **257 bytes when 256 were approved**. The 257th byte is the packet's
**CRC byte**, which lands exactly on the low byte of the `capacity` field living right
after the 256-byte buffer. Send 256 data bytes whose CRC is `0xff` and capacity changes
from `0x0100` to `0x01ff` (511). We control the CRC by tweaking one data byte (255 `A`s +
`0x49` makes CRC = `0xff`).

Now the "send buffer back" command (`3`) returns **511 bytes**, dumping 255 bytes *past*
the buffer — including the **stack canary** and a **saved return address**:

```
0x100 capacity (now 0x01ff)   0x108 canary
0x110 saved rbp               0x118 return addr (always PIE+0x1a9f)
```

`PIE_base = leaked_ret - 0x1a9f`. We now have the canary and the module base.

## Exploitation (see [`remote.py`](./remote.py) / [`exploit.py`](./exploit.py))

With capacity = 511, a second command `2` overflows far past the original buffer. We
preserve the leaked canary and overwrite the return address with a short **ROP chain built
entirely from the binary itself** — so it's libc-independent:

```
ret               PIE + 0x1288     (stack alignment)
pop rdi; ret      PIE + 0x12aa
"/bin/sh" addr    PIE + 0x4875     (lives in the input-packet buffer)
system@plt        PIE + 0x10c0
```

Command `4` returns from `main`, execution follows the chain into `system("/bin/sh")`, and
the shell keeps reading from the same socket. We send `cat /ctf/flag.txt` after the final
packet.

```bash
python3 remote.py 'cat /ctf/flag.txt'
```

## Flag retrieval

```
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```

## Key takeaways

- A single `<=` vs `<` off-by-one overwrote a length/capacity field, escalating a one-byte
  overflow into an info leak and then a full overflow.
- Leaking the canary **and** a return address from the same dump defeats both the stack
  canary and PIE in one step.
- A CRC validates integrity, not authenticity — it can't stop a logic bug, and you can
  freely choose CRC bytes to land a chosen value.
- Prefer a ROP chain made only of the target binary's own gadgets to stay independent of
  the remote libc version.
