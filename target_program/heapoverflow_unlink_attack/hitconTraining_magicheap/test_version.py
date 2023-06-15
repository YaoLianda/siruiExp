from pwn import *

p = process("./magicheap", env={"LD_PRELOAD": "./libc-2.23.so"})
#p = process("./magicheap")
print(p.libs())

