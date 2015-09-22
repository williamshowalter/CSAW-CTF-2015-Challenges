#!/usr/bin/env python
"""
Author: William Showalter
CSAW Team: MSU-CTF
"""
import sys
import re
from pwn import *

USERNAME = "blankwall"
PASSWORD = "UJD737\x00"

#server_address = '54.173.98.115'
PORT = 12012
server_address = 'localhost'	

if __name__ == "__main__":
	sock = remote(server_address, PORT, timeout=None)

	reply = sock.recv()
	print reply

	command = "USER " + USERNAME
	sock.sendline(command)
	reply = sock.recv()
	print command +"\n" + reply
	sock.recv()

	command = "PASS " + PASSWORD
	sock.sendline(command)
	reply = sock.recv()
	print command +"\n" + reply

	sock.sendline("PASV")
	reply = sock.recv()
	pasvPort = int(re.findall("(\d+)",reply)[0])

	sock2 = remote(server_address, pasvPort, timeout=None)

	sock.sendline("LIST")
	reply = sock2.recv()
	sock2.close()
	print reply

	sock.sendline("PASV")
	reply = sock.recv()
	pasvPort = int(re.findall("(\d+)",reply)[0])

	sock.sendline("RDF")
	reply = sock.recv()
	print "RE3 FLAG: %s" % (reply)

	sock2 = remote(server_address, pasvPort, timeout=1)
	sock.sendline("RETR flag.txt")
	print sock.recv()
	reply = sock2.recv()
	print "EXP300 flag.txt reply %s" % reply

	sock2.close()

	sock.close()