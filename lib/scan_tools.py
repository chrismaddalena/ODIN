#!/usr/bin/python2
# -*- coding: utf-8 -*-

import sys
import socket
import nmap
from colors import red, green

# Run nmap scans - it accepts the type of scan from pentestMenu()
def runNMAP(type):
	scanType = type
	infile = raw_input("Name of IP file: ")
	outfile = raw_input("Name for output: ")
	scanner = nmap.PortScanner()

	with open(infile, 'r') as ips:
		for ip in ips:
			# Different scan types for nmap
			if scanType == 1:
				print green("[+] Running full port scan with nmap - this will take a while")
				scanner.scan(hosts=ip,ports="0-65535",arguments="-sS -sV -T4")
			if scanType == 2:
				print green("[+] Running default port scan with nmap - take a break")
				scanner.scan(hosts=ip,arguments="-sS -sV -T4")
			print green("[+] Equiviliant command if nmap was run manually:")
			print red(scanner.command_line())
			for host in scanner.all_hosts():
				print('Host: %s (%s)' % (host, scanner[host].hostname()))
				print('State: %s' % scanner[host].state())
				for proto in scanner[host].all_protocols():
					print('----------')
					print('Protocol: %s' % proto)

					lport = scanner[host][proto].keys()
					lport.sort()
					for port in lport:
						print ('Port: %s\tstate: %s' % (port, scanner[host][proto][port]['state']))
						banner = retBanner(host,port)
						try:
							print ('Banner: %s' % banner.rstrip('\n'))
						except:
							pass

	print green("[+] Creating %s to hold results" % outfile)
	with open(outfile,'w') as results:
		results.write(scanner.csv())

# Perform banner grabbing for discovered open ports
def retBanner(ip, port):
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner
	except:
		return
