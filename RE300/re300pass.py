#!/usr/bin/env python
"""
Author: William Showalter
CSAW Team: MSU-CTF
"""
import sys

re3Seed = 0xd386d209
guessString = ""

def nextCharacter(passConstant,passstr):
	# If more than one character away from done
	if passConstant > (0x1505)*33:
		for p in range(48,123):
			if (passConstant-p)%33 == 0:
				attempt = nextCharacter((passConstant-p)/33, passstr+chr(p))
				if attempt != 0:
					return attempt
		return 0
	# Found correct value, reverse string
	elif passConstant == 0x1505:
		return passstr[::-1]
	# Should never recurse when less than 0x1505
	elif passConstant < 0x1505:
		print "BUG"
		return 0
	# Attempt to find last character
	else:
		for p in range(48,123):
			if (passConstant-p)%33 == 0x1505:
				return passstr+chr(p)
		return 0

def findPassword(seed):
	flag = False
	# Increment value of seed high-bits and rerun the backtrack on a new string.
	while (not flag):
		password = nextCharacter(seed,guessString)
		if seed > 0xFFFFFFFFFFFFFFFF:
			print "FAILED  %s" % (hex(seed%0xFFFFFFFF))
			break
		if password !=0:
			print "SUCCESS %s %s" % (hex(seed%0xFFFFFFFF), password)
			flag = True
		else:
			seed = seed + 0xFFFFFFFF+1
			print "FAILED  %s" % (hex(seed%0xFFFFFFFF))

def verifyPassword(password):
	i = 0x1505
	for p in password:
		i = i*33 + ord(p)
	if (i&0xFFFFFFFF) == re3Seed:
		print "SUCCESS %s %s" % (password,hex(i&0xFFFFFFFF))
	else:
		print "FAILED %s %s" % (password,hex(i&0xFFFFFFFF))
		
if __name__ == "__main__":
	if len(sys.argv) > 1:
		verifyPassword(sys.argv[1])
	else:
		findPassword(re3Seed)
