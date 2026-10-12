#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
static int fd=-1;
typedef uint64_t (*f_open)(uint64_t, uint32_t*, uint32_t*);
uint64_t hook_fetch(long *prog, uint32_t *key, uint32_t *out){
  if (!key || !out || !prog) return 1;
  if ((uint64_t)*key >= (uint64_t)prog[1]) return 2;
  uint32_t idx = *key;
  uint64_t r = ((f_open)0x4020e0)((uint64_t)idx*0x40 + prog[0], key, out);
  char buf[256]; int n = snprintf(buf,sizeof buf,"idx=%u ret=%llu op=%u a=%u b=%u slot=%u k=%u imm=%#llx extra=%u %u %u %#llx\n",
     idx,(unsigned long long)r,out[0],((uint8_t*)out)[4],((uint8_t*)out)[5],((uint8_t*)out)[6],((uint8_t*)out)[7],
     (unsigned long long)*(uint64_t*)(out+2), out[4], out[5], out[6], (unsigned long long)*(uint64_t*)(out+8));
  write(fd,buf,n); return r;
}
__attribute__((constructor)) static void init(void){
  const char *p=getenv("TRACE_OUT"); fd=open(p?p:"trace3.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  uint8_t *t=(uint8_t*)0x4025a0; mprotect((void*)0x400000,0x5000,PROT_READ|PROT_WRITE|PROT_EXEC);
  t[0]=0x48;t[1]=0xb8; uint64_t a=(uint64_t)hook_fetch; memcpy(t+2,&a,8); t[10]=0xff;t[11]=0xe0;
  mprotect((void*)0x400000,0x5000,PROT_READ|PROT_EXEC);
}
