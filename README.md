# SunshineCTF 2026

Solutions, exploits, and writeups for **SunshineCTF 2026**.

- **Event:** [SunshineCTF 2026](https://2026.sunshinectf.org/)
- **Dates:** Sat 26 Sep 2026 09:00 CDT → Mon 28 Sep 2026 09:00 CDT
- **Author:** hax1ng
- **Placement:** 🥇 **1st place**
- **Flag format:** `sun{...}`
- **Solved:** 11 challenges across Forensics, Misc, Pwn, Rev, and Web

Each challenge has its own directory with a full writeup (`README.md`) and the final solve
scripts / exploits / relevant challenge files.

## Challenges

### Pwn

| Challenge | Points | Solves | Writeup |
|---|---:|---:|---|
| Cache Money | 466 | 166 | [writeup](./pwn/cache-money/README.md) |
| Code Breaker | 474 | 147 | [writeup](./pwn/code-breaker/README.md) |
| Homemaker | 468 | 163 | [writeup](./pwn/homemaker/README.md) |
| Print Print Revolution | 459 | 183 | [writeup](./pwn/print-print-revolution/README.md) |
| Safe House | 476 | 142 | [writeup](./pwn/safe-house/README.md) |
| Total Recall | 431 | 237 | [writeup](./pwn/total-recall/README.md) |

### Web

| Challenge | Points | Solves | Writeup |
|---|---:|---:|---|
| Planetary Probe | 474 | 147 | [writeup](./web/planetary-probe/README.md) |
| SiteCheck | 474 | 147 | [writeup](./web/sitecheck/README.md) |

### Reversing

| Challenge | Points | Solves | Writeup |
|---|---:|---:|---|
| IntMod | 468 | 162 | [writeup](./rev/intmod/README.md) |

### Forensics

| Challenge | Points | Solves | Writeup |
|---|---:|---:|---|
| my eyes burn | 312 | 389 | [writeup](./forensics/my-eyes-burn/README.md) |

### Misc

| Challenge | Points | Solves | Writeup |
|---|---:|---:|---|
| VecNet | 482 | 124 | [writeup](./misc/vecnet/README.md) |

> Points and solve counts are as captured from the CTFd platform (dynamic scoring, so
> point values decay as more teams solve).

## Notable solves

- **IntMod** (rev) — a checker VM that runs on **CPU traps**: `int3`/`ud2`/divide-by-zero
  handlers decrypt and execute "sealed" instructions directly on the real CPU registers
  via `ucontext`. Solved by `LD_PRELOAD`-hooking the instruction decoder to dump the
  logical program, then solving the final check as a Vandermonde linear system mod 65521.
- **VecNet** (misc) — an AI-flavoured chain ending in **embedding inversion**: recover an
  "embedding-only" password hint from a vector DB and reverse it back to text with
  `vec2text`, then crack a short password to decrypt the flag. Embeddings are not one-way.
- **Code Breaker** (pwn) — a refcounted use-after-free → tcache poison that pops a shell
  **under Intel CET (SHSTK + IBT)** by overwriting a data function pointer that resolves
  to an `endbr64` target — no ROP, no shadow-stack violation.
- **Total Recall** (pwn) — ~100 bytes of static, NX, no-libc code solved with **SROP**,
  abusing `read()`'s return value to set `rax = 15` for `rt_sigreturn`.

## Repository layout

```
.
├── forensics/   # my eyes burn
├── misc/        # VecNet
├── pwn/         # cache-money, code-breaker, homemaker,
│                #   print-print-revolution, safe-house, total-recall
├── rev/         # IntMod
└── web/         # planetary-probe, sitecheck
```

## Notes

- Challenge binaries are included for reproduction; bundled `libc.so.6` /
  `ld-linux-x86-64.so.2` blobs are **not** committed (standard glibc 2.39 / Ubuntu 24.04 —
  the required versions are noted in each pwn writeup).
- Exploit scripts target the live event endpoints (`*.sunshinectf.games`), which are
  offline after the competition.
