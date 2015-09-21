#!/usr/bin/env python
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

	reply = sock.recv(100)
	print reply

	command = "USER " + USERNAME
	sock.sendline(command)
	reply = sock.recv(100)
	print command +"\n" + reply
	sock.recv(100)

	command = "PASS " + PASSWORD
	sock.sendline(command)
	reply = sock.recv(100)
	print command +"\n" + reply

	sock.sendline("PASV")
	reply = sock.recv(100)
	pasvPort = int(re.findall("(\d+)",reply)[0])

	sock2 = remote(server_address, pasvPort, timeout=None)

	sock.sendline("LIST")
	reply = sock2.recv(1024)
	sock2.close()
	print reply

	sock.sendline("PASV")
	reply = sock.recv(100)
	pasvPort = int(re.findall("(\d+)",reply)[0])

	sock2 = remote(server_address, pasvPort, timeout=1)
	sock.sendline("RETR flag.txt")
	print sock.recv(100)
	reply = sock2.recv(1024)
	print "RETR flag.txt reply %s" % reply

	sock2.close()
	sock.sendline("RDF")
	reply = sock.recv(100)
	print "RE3 FLAG: %s" % (reply)

	sock.close()