#!/usr/bin/python2
# -*- coding: utf-8 -*-

from colors import red, green

def parseName(file):
	outputFile = "ParsedNames.txt"
	# Read all of the names line by line
	with open(file) as f:
		print green("[+] Parsing names and outputting to %s" % outputFile)
		names = [line.rstrip('\n').split(" ") for line in f]
		output = open(outputFile,"w")
		for name in names:
			output.write(str(name).replace("]","").replace("[","").replace("'","") + '\n')
		output.close()
		f.close()
