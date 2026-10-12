import sys
M=(1<<64)-1
def rol(x,k): k&=63; return ((x<<k)|(x>>(64-k)))&M if k else x
def apply(st,ins):
    op,a,b,c,k,imm=ins; st=list(st)
    if op==0: st[a]=(st[a]+rol(st[b],k))&M
    elif op==1: st[a]^=rol(st[b],k)
    elif op==2: st[a]=(st[a]*imm)&M
    elif op==3: st[a]=rol(st[a],k)
    elif op==4: st[a],st[b]=st[b],st[a]
    return st
def parse(fn):
    rows=[]
    for ln in open(fn):
        l,r=ln.split('|'); f=l.split(); regs=[int(x,16) for x in r.split()]
        rows.append((int(f[0]),(int(f[1]),int(f[2]),int(f[3]),int(f[4]),int(f[5]),int(f[6],16)),regs[:5]))
    return rows
def ident(S,T):
    c=[]
    for a in range(5):
        for b in range(5):
            for k in range(64):
                for op in (0,1):
                    if a!=b and apply(S,(op,a,b,0,k,0))==T: c.append((op,a,b,0,k,0))
        for k in range(64):
            if apply(S,(3,a,0,0,k,0))==T: c.append((3,a,0,0,k,0))
        if S[a]&1 and all(S[i]==T[i] for i in range(5) if i!=a):
            imm=(T[a]*pow(S[a],-1,1<<64))&M; c.append((2,a,0,0,0,imm))
        for b in range(a+1,5):
            if apply(S,(4,a,b,0,0,0))==T: c.append((4,a,b,0,0,0))
    return c
if __name__=='__main__':
  rows=parse(sys.argv[1])
  for (i,insi,Si),(j,insj,Sj) in zip(rows,rows[1:]):
      if insi[0]>4: break
      S=apply(Si,insi)
      if j==i+1:
          if S!=Sj: print("MISMATCH at",i)
      else:
          print(f"gap {i}->{j}: missing {list(range(i+1,j))}; changed regs", [r for r in range(5) if S[r]!=Sj[r]], "cands:", ident(S,Sj)[:6] if j==i+2 else "multi")
