#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ucontext.h>
static int fd=-1; static void (*real_h)(int, siginfo_t*, void*); static ucontext_t *cur_uc;
static int idxs[] = {REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15,REG_RDI,REG_RSI};
static void wrap(int sig, siginfo_t *si, void *ctx){ ucontext_t *save=cur_uc; cur_uc=ctx; real_h(sig,si,ctx); cur_uc=save; }
int sigaction(int sig, const struct sigaction *act, struct sigaction *old){
  static int (*real)(int,const struct sigaction*,struct sigaction*);
  if(!real) real=dlsym(RTLD_NEXT,"sigaction");
  if (act && (act->sa_flags & SA_SIGINFO) && (sig==4||sig==5||sig==8)){
    struct sigaction a=*act; real_h=act->sa_sigaction; a.sa_sigaction=wrap; return real(sig,&a,old);}
  return real(sig,act,old);
}
typedef uint64_t (*f_open)(uint64_t, uint32_t*, uint32_t*);
uint64_t hook_fetch(long *prog, uint32_t *key, uint32_t *out){
  if (!key || !out || !prog) return 1;
  if ((uint64_t)*key >= (uint64_t)prog[1]) return 2;
  uint32_t idx=*key;
  uint64_t r=((f_open)0x4020e0)((uint64_t)idx*0x40+prog[0],key,out);
  char buf[512]; int n=snprintf(buf,sizeof buf,"%u %u %u %u %u %u %#llx |",idx,out[0],((uint8_t*)out)[4],((uint8_t*)out)[5],((uint8_t*)out)[6],((uint8_t*)out)[7],(unsigned long long)*(uint64_t*)(out+2));
  if (cur_uc) for(int i=0;i<10;i++) n+=snprintf(buf+n,sizeof buf-n," %llx",(unsigned long long)cur_uc->uc_mcontext.gregs[idxs[i]]);
  buf[n++]='\n'; write(fd,buf,n); return r;
}
__attribute__((constructor)) static void init(void){
  const char *p=getenv("TRACE_OUT"); fd=open(p?p:"trace4.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  uint8_t *t=(uint8_t*)0x4025a0; mprotect((void*)0x400000,0x5000,PROT_READ|PROT_WRITE|PROT_EXEC);
  t[0]=0x48;t[1]=0xb8; uint64_t a=(uint64_t)hook_fetch; memcpy(t+2,&a,8); t[10]=0xff;t[11]=0xe0;
  mprotect((void*)0x400000,0x5000,PROT_READ|PROT_EXEC);
}
