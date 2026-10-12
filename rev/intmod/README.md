# IntMod

**Category:** Reversing &nbsp;|&nbsp; **Points:** 468 &nbsp;|&nbsp; **Solves:** 162 &nbsp;|&nbsp; **Flag:** `sun{I_L0v3_Int3rrupts&SelfMod!!!}`

## Challenge description

> "IntMod?? Do you mean integer modulus??" "No. I do not mean that." "Then what, pretell,
> could it mean?" "Just put the agent on the ghidra dawg"
>
> Author: Bradley Fernandez &nbsp;·&nbsp; Flag format: `sun{flag_content}`

One stripped, non-PIE x86-64 ELF: `intmod`.

## Initial analysis

- `strings`: `Correct`, `Nope`, `validator failed: %s`, error names like `integrity error`.
- Imports: `sigaction`, `sigaltstack`, `mmap`, `munmap`, `sysconf` — a huge hint for a
  **signal-driven VM with runtime-generated code**.
- `main` reads one line, requires **exactly 33 bytes**, builds a 40-byte state
  (input + seven `0x07` padding bytes = five u64 registers), runs a validator, and prints
  `Correct` if an error accumulator ends at 0.

The name decodes to **Int**errupts + self-**Mod**ifying code.

## Core concept

The checker is a tiny VM that executes on **CPU traps**. `int3`, `ud2`, and
divide-by-zero fire signal handlers, and those handlers decrypt and run "sealed" VM
instructions directly on the real CPU registers (`r8`–`r15`) by editing the
`ucontext->uc_mcontext.gregs` saved state, with help from JIT'd stub pages.

The executor at `0x400ae0` supports:

| op | effect |
|----|--------|
| 0 | `r[a] += rol(r[b], k)` |
| 1 | `r[a] ^= rol(r[b], k)` |
| 2 | `r[a] *= imm` (odd constant → invertible mod 2⁶⁴) |
| 3 | `r[a] = rol(r[a], k)` |
| 4 | swap `r[a]`, `r[b]` |
| 5 | `slot = (Σ byte[j]·base^j − c) mod 65521` over the 40 state bytes |
| 6 | `err |= slot ^ target` |

It resists static analysis because:

- The VM registers **are** real CPU registers; the SIGTRAP/SIGILL/SIGFPE handlers mutate
  them through `ucontext`.
- Each instruction is sealed with TEA plus a splitmix-style MAC and only decoded inside
  the handler.
- `ud2` jumps into an mmap'd JIT page that builds ops out of micro-traps (e.g. `a + x`
  computed as `a - ~x - 1`). Some instructions are native-only decoys.
- gdb is useless: ptrace clashes with the program's own SIGTRAP handling.

The important realisation: **every mixing op is invertible**, and the final check is
40 linear equations in 40 unknown bytes modulo the prime 65521 (the Adler-32 prime). So
if we can recover the *decoded op list*, we never have to break the crypto — we solve the
state algebraically and run the mixing backwards.

## Solving process

Don't reverse the instruction encryption — **hook the decoder's output.** Using
`LD_PRELOAD` interposition (see the `hook*.c` files):

1. **Hook the executor** ([`hook.c`](./hook.c)): patch `0x400ae0` with
   `movabs rax, hook; jmp rax` and log each op. Registers changed *between* logged ops →
   revealed a second (trap-driven) execution path.
2. **Hook the signals** ([`hook2.c`](./hook2.c)): override `sigaction`, wrap the handler,
   and log `rip` + registers before/after every trap. This exposed the int3/ud2/div0
   sites and the JIT page.
3. **Hook instruction fetch** ([`hook4.c`](./hook4.c)): `FUN_004025a0` wraps the unsealer
   at `0x4020e0`. We replace it, call the real unsealer, and log the decoded instruction
   plus the live register state from the handler's `ucontext`. That yields the full
   logical program (identical for any input).
4. **Validate** ([`analyze.py`](./analyze.py)): replaying each decoded op reproduces the
   next logged state exactly. 13 never-fetched indices leave registers unchanged → decoys.
5. **Solve** ([`solve.py`](./solve.py)): pair each op5 with its op6 to get
   `Σ F[j]·b^j ≡ target + c (mod 65521)`, Gauss-eliminate over GF(65521) for the final
   state `F` (every value comes out < 256 — a good sign), then undo the 90 mixing ops in
   reverse (subtract, xor, multiply by the modular inverse mod 2⁶⁴, rotate right, swap).

Ghidra did the static lift headlessly via
[`ghidra_scripts/IntmodDecomp.java`](./ghidra_scripts/IntmodDecomp.java) when Binary
Ninja's MCP timed out.

## Flag retrieval

```
$ python3 solve.py
90 mix ops, 40 equations
b'sun{I_L0v3_Int3rrupts&SelfMod!!!}\x07\x07\x07\x07\x07\x07\x07'
sun{I_L0v3_Int3rrupts&SelfMod!!!}

$ ./intmod < flag.txt
Correct
```

The recovered padding is exactly seven `0x07` bytes — independent confirmation that the
inversion is correct.

## Key takeaways

- Signal/trap-based VMs keep their state in `ucontext` registers. Wrapping the handler
  with `LD_PRELOAD` `sigaction` interposition beats gdb (whose ptrace fights the program).
- **Don't reverse the instruction crypto — hook the decoder output.** Log the plaintext
  ops as they're executed.
- Replay-and-compare against logged states cheaply confirms recovered semantics and spots
  decoys / hidden ops.
- A polynomial hash check mod a prime over N bytes with N distinct bases is a Vandermonde
  linear system → unique, exactly solvable.

See [`learnings.md`](./learnings.md) for condensed technique notes captured during the solve.
