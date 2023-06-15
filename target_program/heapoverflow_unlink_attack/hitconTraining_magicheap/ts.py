from pwn import *
import sys
context.log_level = "debug"
context.terminal =  ["gnome-terminal","-x","sh","-c"]
io = process("./magicheap")
gdb.attach(io)
io.interactive()
io.close()
