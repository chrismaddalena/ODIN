#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import sys
import socket
import nmap
import time
from zapv2 import ZAPv2
from pprint import pprint
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
				print('\nHost: %s (%s)' % (host, scanner[host].hostname()))
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

def runMasscan(type):
	scanType = type
	infile = raw_input("Name of IP file: ")
	outfile = raw_input("Name for output: ")

	with open(infile,'r') as ips:
		for ip in ips:
			if scanType == 1:
				print green("[+] Running full port scan with masscan")
				command = "masscan -p0-65535 --rate 50000 --banners %s -oX %s" % (ip.rstrip(),outfile)
				os.system(command)
			if scanType == 2:
				print green("""This option requires a configuration file for masscan. Provide yours if you have one. If you don't, go back.
If you've never setup one, you can dump a configuration using this command:""")
				print red("masscan -p80,8000-8100 10.0.0.0/8 --echo > xxx.conf")
				conf = raw_input("Name of Masscan conf file: ")
				print green("[+] Running masscan with %s" % conf)
				command = "masscan -p0-65535 --rate 50000 --banners %s -oX %s" % (ip.rstrip(),outfile)
				os.system(command)
 
