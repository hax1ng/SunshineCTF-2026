#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
static int fd = -1;
static inline uint64_t rol(uint64_t x, unsigned k){ k&=63; return k? (x<<k)|(x>>(64-k)) : x; }
typedef void (*f_ser)(uint64_t*, uint8_t*);
typedef uint32_t (*f_hash)(uint8_t*, long, uint32_t);
typedef uint32_t (*f_sub)(uint32_t, uint32_t);
uint64_t hook_exec(uint64_t *st, uint8_t *ins){
  uint32_t op = *(uint32_t*)ins; uint8_t a=ins[4], b=ins[5], c=ins[6], k=ins[7]; uint64_t imm = *(uint64_t*)(ins+8);
  char buf[512]; int n = snprintf(buf, sizeof buf, "op=%u a=%u b=%u slot=%u k=%u imm=%#llx |", op,a,b,c,k,(unsigned long long)imm);
  for (int i=0;i<10;i++) n += snprintf(buf+n, sizeof buf - n, " %016llx", (unsigned long long)st[i]);
  buf[n++]='\n'; write(fd, buf, n);
  switch(op){
  case 0: st[a] += rol(st[b], k); break;
  case 1: st[a] ^= rol(st[b], k); break;
  case 2: st[a] *= imm; break;
  case 3: st[a] = rol(st[a], k); break;
  case 4: { uint64_t t = st[a]; st[a] = st[b]; st[b] = t; } break;
  case 5: { uint8_t tmp[48]; ((f_ser)0x401060)(st, tmp); uint32_t h = ((f_hash)0x400fa0)(tmp, 0x28, (uint32_t)imm);
            uint32_t r = ((f_sub)0x400e40)(h, (uint32_t)(imm>>32)); st[8] = r; st[5+c] = r;
            n = snprintf(buf, sizeof buf, "   hash=%u r=%u\n", h, r); write(fd, buf, n); } break;
  case 6: st[9] |= st[5+c] ^ imm; break;
  case 7: break;
  default: return 0;
  }
  return 0;
}
__attribute__((constructor)) static void init(void){
  const char *p = getenv("TRACE_OUT"); fd = open(p?p:"trace.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
  uint8_t *t = (uint8_t*)0x400ae0; mprotect((void*)0x400000, 0x6000, PROT_READ|PROT_WRITE|PROT_EXEC);
  t[0]=0x48; t[1]=0xb8; uint64_t a=(uint64_t)hook_exec; memcpy(t+2,&a,8); t[10]=0xff; t[11]=0xe0;
  mprotect((void*)0x400000, 0x6000, PROT_READ|PROT_EXEC);
}
