#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import socket
import nmap
import OpenSSL
import ssl
import time
from colors import *


# NMAP scans - it accepts the type of scan from pentestMenu()
def runNMAP(ip, ports, args, report):
	scanner = nmap.PortScanner()
	temp = []

	try:
		scanner.scan(hosts=ip, ports=ports, arguments=args)
		print(green("[+] Scan completed using - {}").format(scanner.command_line()))
	except Exception as e:
		print(red("[!] The nmap scan failed!"))
		print(red("[!] Error: {}").format(e))

	for host in scanner.all_hosts():
		print('\nHost: %s (%s)' % (host, scanner[host].hostname()))
		print('State: %s' % scanner[host].state())

		for proto in scanner[host].all_protocols():
			print('----------')
			print('Protocol: %s' % proto)
			lport = sorted(scanner[host][proto])
			#lport = scanner[host][proto].keys()
			#lport.sort()
			for port in lport:
				print('Port: %s\tstate: %s' % (port, scanner[host][proto][port]['state']))
				print('Name: %s' % (scanner[host][proto][port]['name']))
				print('Product: %s' % (scanner[host][proto][port]['product']))
				print('Version: %s' % (scanner[host][proto][port]['version']))
				banner = retBanner(host,port)
				try:
					print('Banner: %s\n' % banner.rstrip('\n'))
				except:
					print('Banner: Unknown\n')
				# Check if port is a known web port, then add IP to target list for Eye Witness
				try:
					with open("setup/web_ports.txt","r") as file:
						for line in file:
							if str(line.rstrip()) == str(port):
								temp.append("%s:%s" % (host.rstrip(), port))
				except:
					pass

	web = "EyeWitness_Targets.txt"
	with open(web, 'a'	) as webports:
		for i in temp:
			webports.write("{}\n".format(i))

	print(green("[+] Scan complete for {} and moving to next item...".format(ip)))
	report.write(scanner.csv())


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


# Check SSL on provided port
def checkSSL(a):
	"""Get SSL Cert CN"""
	# Return None because we can't navigate to a CIDR for ssl
	if "/" in a:
		print(red("[!] Viper cannot get certicate information for a CIDR. Supply a single IP and port."))
		return None
	else:
		try:
			ip, port = a.split(":")
		except:
			ip = a
			port = 443
		next
	try:
		print(yellow("Target: {}".format(ip)))
		print(yellow("Port: {}".format(port)))
		# Connect over port port
		cert = ssl.get_server_certificate((ip, port))
	except Exception as e:
		# If it can't connect, then return nothing/fail
		print(yellow("[!] Could not connect or no certificate was found."))
		print(yellow("Error: {}".format(e)))
		return None
	try:
		# Use openssl to pull cert information
		c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		subj = c.get_subject()
		comp = subj.get_components()
		for i in comp:
			print(yellow("{}: {}".format(i[0].decode('ascii'), i[1].decode('ascii'))))
	except Exception as e:
		# if openssl fails to get information, return nothing/fail
		print(red("[!] Viper failed to get the certfication information!"))
		print(red("[!] Error: {}".format(e)))
