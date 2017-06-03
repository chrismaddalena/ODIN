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


def run_nmap(ip, ports, args, report):
	"""Run an nmap scan using supplied arguments to output a CSV file with results
	and tab-delimited terminal results
	"""
	scanner = nmap.PortScanner()
	temp = []

	try:
		scanner.scan(hosts=ip, ports=ports, arguments=args)
		print(green("[+] Scan completed using - {}").format(scanner.command_line()))
	except Exception as e:
		print(red("[!] The nmap scan failed!"))
		print(red("[!] Error: {}").format(e))

	for host in scanner.all_hosts():
		if scanner[host].hostname() == "":
			print('\nHost: {} - No Hostname'.format(host))
		else:
			hostname = scanner[host].hostname()
			print('\nHost: {} - {}'.format(host, hostname))

		print('State: %s' % scanner[host].state())
		print('----------')

		for proto in scanner[host].all_protocols():
			lport = sorted(scanner[host][proto])
			for port in lport:
				state = scanner[host][proto][port]['state']
				name = scanner[host][proto][port]['name']
				product = scanner[host][proto][port]['product']
				version = scanner[host][proto][port]['version']
				banner = retBanner(host, port)
				socket_info = "{} {} \t {} \t {} \t {} \t {} {}".format(host, hostname, port, proto, product, version, banner)
				print(socket_info)
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

	report.write(scanner.csv())


def retBanner(ip, port):
	"""Small helper function to grab the banner for an open service
	"""
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner.decode('ascii')
	except:
		return


def checkSSL(target):
	"""Get SSL certificate information
	"""
	# Return None because we can't navigate to a CIDR for SSL certificates
	if "/" in target:
		print(red("[!] Viper cannot get certicate information for a CIDR. Supply a single IP or domain and port."))
		return None
	else:
		try:
			ip, port = target.split(":")
		except:
			ip = target
			port = 443
		next
	try:
		print(yellow("Target:\t\t{}".format(ip)))
		print(yellow("Port:\t\t{}".format(port)))
		cert = ssl.get_server_certificate((ip, port))
	except Exception as e:
		# If it can't connect, then return nothing/fail
		print(yellow("[!] Could not connect or no certificate was found."))
		print(yellow("Error: {}".format(e)))
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ssl_sock = ssl.wrap_socket(s)
		ssl_sock.connect((ip, port))
		peerName = ssl_sock.getpeername()
		print(yellow("Peer Name:\t{}:{}".format(peerName[0], peerName[1])))
		print(yellow("Ciphers:"))
		for c in ssl_sock.cipher():
			print(yellow("\t\t{}".format(c)))
		print(yellow("Version:\t{}".format(ssl_sock.version())))
	except Exception as e:
		print(red("[!] Viper failed to make an SSL wrapped socket!"))
		print(red("[!] Error: {}".format(e)))
	try:
		# Use OpenSSL to collect certificate information
		c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		subj = c.get_subject()
		comp = subj.get_components()
		print(yellow("\nCertificate Details:"))
		for i in comp:
			print(yellow("{}\t\t{}".format(i[0].decode('ascii'), i[1].decode('ascii'))))
	except Exception as e:
		# If OpenSSL fails to get information, return nothing/fail
		print(red("[!] Viper failed to get the certfication information!"))
		print(red("[!] Error: {}".format(e)))
