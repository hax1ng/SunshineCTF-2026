#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ucontext.h>
static int fd=-1; static void (*real_h)(int, siginfo_t*, void*); static int dumped=0;
static void logst(const char *tag, int sig, ucontext_t *uc){
  greg_t *g = uc->uc_mcontext.gregs; char buf[512];
  int n = snprintf(buf,sizeof buf,"%s sig=%d rip=%llx |", tag, sig, (unsigned long long)g[REG_RIP]);
  int idx[] = {REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15,REG_RDI,REG_RSI};
  for (int i=0;i<10;i++) n+=snprintf(buf+n,sizeof buf-n," %016llx",(unsigned long long)g[idx[i]]);
  buf[n++]='\n'; write(fd,buf,n);
}
static void wrap(int sig, siginfo_t *si, void *ctx){
  ucontext_t *uc = ctx;
  if (!dumped){ dumped=1; uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP]; uintptr_t base = rip & ~0xfffUL;
    char nm[64]; snprintf(nm,sizeof nm,"code_%lx.bin",base); int f=open(nm,O_WRONLY|O_CREAT|O_TRUNC,0644);
    write(f,(void*)base,0x2000); close(f);
    int m=open("/proc/self/maps",O_RDONLY); int mo=open("maps.txt",O_WRONLY|O_CREAT|O_TRUNC,0644); char b[4096]; ssize_t r; while((r=read(m,b,sizeof b))>0) write(mo,b,r); close(m); close(mo);}
  logst("PRE ",sig,uc); real_h(sig,si,ctx); logst("POST",sig,uc);
}
int sigaction(int sig, const struct sigaction *act, struct sigaction *old){
  static int (*real)(int,const struct sigaction*,struct sigaction*);
  if(!real) real=dlsym(RTLD_NEXT,"sigaction");
  if (fd<0){ const char*p=getenv("TRACE_OUT"); fd=open(p?p:"trace2.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);}
  if (act && (act->sa_flags & SA_SIGINFO) && (sig==4||sig==5||sig==8)){
    struct sigaction a = *act; real_h = act->sa_sigaction; a.sa_sigaction = wrap; return real(sig,&a,old);
  }
  return real(sig,act,old);
}
