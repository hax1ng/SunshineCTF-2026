## New Learning: Trace signal-handler VMs with LD_PRELOAD sigaction interposition
**Skill:** `ctf-rev`
**Technique:** When a binary implements a VM via int3/ud2/div0 traps + SIGTRAP/SIGILL/SIGFPE handlers (gdb kills it with SIGTRAP),
interpose `sigaction` in an LD_PRELOAD lib, wrap the handler, and log `uc_mcontext.gregs` (VM regs often live in real CPU regs).
For non-PIE binaries, also hot-patch small internal functions (fetch/decode) at load time with `movabs rax, hook; jmp rax` and call
the original callee by absolute address to dump decoded instructions + live state.
**Context:** SunshineCTF 2026 re/IntMod — sealed instructions, JIT stub pages, decoy no-op instructions.
**Example:**
```c
int sigaction(int s,const struct sigaction*a,struct sigaction*o){ static int(*r)(int,const struct sigaction*,struct sigaction*);
  if(!r) r=dlsym(RTLD_NEXT,"sigaction");
  if(a&&(a->sa_flags&SA_SIGINFO)&&(s==4||s==5||s==8)){struct sigaction b=*a; real_h=a->sa_sigaction; b.sa_sigaction=wrap; return r(s,&b,o);}
  return r(s,a,o);}
```

## New Learning: Polynomial-hash checks mod p = Vandermonde system
**Skill:** `ctf-rev`
**Technique:** N checks of the form Σ byte[j]·b_i^j ≡ t_i (mod p) over N bytes with distinct bases -> solve linearly mod p (unique).
**Context:** IntMod: 40 Adler-prime (65521) hashes over the 40-byte final state.
