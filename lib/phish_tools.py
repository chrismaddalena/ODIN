#!/usr/bin/python2
# -*- coding: utf-8 -*-

import random
from colors import red, green

# Ingest a list of names and email addresses to output a comma delimited version
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

# Ingest a list of names/emails and return a randomized version
def randomList(listA):
	print green("[+] Creating a random list of targets...")
	listB = []
	for i in range(len(listA)):
		element = random.choice(listA)
		listA.remove(element)
		listB.append(element)
	return listB
