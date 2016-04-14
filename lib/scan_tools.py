#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import socket
import nmap
import time
import OpenSSL
import ssl
import shodan
from colors import red, green

# Try to get the user's Shodan API key
try:
	shodan_key_file = open('auth/shodankey.txt', 'r')
	shodan_key_line = shodan_key_file.readlines()
	SHODAN_API_KEY = shodan_key_line[1].rstrip()
	api = shodan.Shodan(SHODAN_API_KEY)
	shodan_key_file.close()
except:
	sho_api = None

# Find what Shodan knows about your list of IPs
def shodanIPSearch(infile):
	print green("[+] Checking Shodan")
	api = shodan.Shodan(SHODAN_API_KEY)
	# Use API key to search Shodan for each IP
	with open(infile, 'r') as list:
		for ip in list:
			print green("[+] Performing Shodan search for %s" % ip)
			try:
				host = api.host(ip)
				print """
					IP: %s
					Organization: %s
					OS: %s
				""" % (host['ip_str'], host.get('org', 'n/a'), host.get('os','n/a'))

				for item in host['data']:
					print """
						Port: %s
						Banner: %s
					""" % (item['port'], item['data'])

			except shodan.APIError, e:
				print red("[!] Error: %s\n" % e)

# Run nmap scans - it accepts the type of scan from pentestMenu()
def runNMAP(type):
	scanType = type
	infile = raw_input("Name of IP file: ")
	outfile = raw_input("Name for output: ")
	scanner = nmap.PortScanner()
	temp = []

	if scanType == 1:
		print green("[+] Running full port scan with nmap - this will take a while")
	if scanType == 2:
		print green("[+] Running default port scan with nmap - take a break")

	with open(infile, 'r') as ips:
		for ip in ips:
			# Different scan types for nmap
			if scanType == 1:
				scanner.scan(hosts=ip,ports="0-65535",arguments="-sS -T4")
			if scanType == 2:
				scanner.scan(hosts=ip,ports="80,8080,443",arguments="-sS -T4 --open")
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
							print ('Banner: Unknown')
						# Check if port is a known web port, add IP to target list for Eye Witness
						try:
							with open("Web_Hosts.txt","w") as output:
								with open("setup/web_ports.txt","r") as file:
									for line in file:
										if str(line.rstrip()) == str(port):
											temp.append("%s:%s" % (host.rstrip(), port))
								output.write('\n'.join(temp))
						except:
							pass

	print green("[+] Creating %s to hold results" % outfile)
	with open(outfile,'w') as results:
		results.write(scanner.csv())

def webNMAP():
		infile = raw_input("Name of IP file: ")
		scanner = nmap.PortScanner()

		with open(infile, 'r') as ips:
			for ip in ips:
				print green("[+] Scanning for web ports listed in /setup/web_ports.txt")
				with open('setup/web_ports.txt','r') as ports:
					for port in ports:
						print "[+] Scanning for port %s" % port
						scanner.scan(hosts=ip,ports=port,arguments="-sS -sV -T4 --open")
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

def checkSSL(a):
	"""Get SSL Cert CN"""
	# Return None because we can't navigate to a CIDR for ssl.
	if "/" in a:
		print red("[!] Viper can't get certicate information for a CIDR! Supply a hostname or single IP.")
		return None
	else:
		next
	try:
		# Connect over port 443.
		cert = ssl.get_server_certificate((a, 443))
	except Exception, e:
		# If it can't connect, return nothing/fail
		return None
	try:
		# use openssl to pull cert information
		c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		subj = c.get_subject()
		comp = subj.get_components()
		print comp
		for i in comp:
			if 'CN' in i:
				print i[1]
			elif 'CN' not in i:
				continue
			else:
				return None
	except Exception,e:
		# if openssl fails to get information, return nothing/fail
		print red("[!] Viper failed to get te certfication information!")
		print red("[!] Error: %s" % e)
