import gdb, struct
gdb.execute("set pagination off")
gdb.execute("handle SIGTRAP nostop noprint pass")
gdb.execute("handle SIGILL nostop noprint pass")
gdb.execute("handle SIGFPE nostop noprint pass")
gdb.execute("handle SIGSEGV nostop noprint pass")
out = open("trace.txt","w")
class BP(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        rdi = int(gdb.parse_and_eval("$rdi")); rsi = int(gdb.parse_and_eval("$rsi"))
        st = struct.unpack("<10Q", bytes(inf.read_memory(rdi, 0x50)))
        ins = bytes(inf.read_memory(rsi, 16))
        op = struct.unpack("<I", ins[:4])[0]
        a,b,c,d = ins[4],ins[5],ins[6],ins[7]; imm = struct.unpack("<Q", ins[8:])[0]
        out.write("op=%d a=%d b=%d slot=%d k=%d imm=%#x | %s\n" % (op,a,b,c,d,imm," ".join("%016x"%x for x in st)))
        return False
BP("*0x400ae0")
gdb.execute("run < input.txt")
out.close()
