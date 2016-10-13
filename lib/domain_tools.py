#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import requests
from xml.etree import ElementTree  as eT
import time
from colors import *
import socket

# Try to get the user's Shodan API key
try:
	shodan_key_file = open('auth/shodankey.txt', 'r')
	shodan_key_line = shodan_key_file.readlines()
	SHODAN_API_KEY = shodan_key_line[1].rstrip()
	shoAPI = shodan.Shodan(SHODAN_API_KEY)
	shodan_key_file.close()
except:
	shoAPI = None

# Try to get the user's URLVoid API key
try:
	urlvoid_key_file = open('auth/urlvoidkey.txt', 'r')
	urlvoid_key_line = urlvoid_key_file.readlines()
	URLVOID_API_KEY = urlvoid_key_line[1].rstrip()
	urlvoid_key_file.close()
except:
	URLVOID_API_KEY = None

my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'} # Google-friendly user-agent
sleep = 10 # Sleep time for Google

def collectDomainInfo(client,domain):
	print(green("Viper will now attempt to gather information from DNS records and other sources."))

	f = "reports/{}/Domain_Report.txt".format(client)

	with open(f, 'w') as report:
		# Create the Domain Report
		try:
			report.write("### Domain Report for {} ###\n".format(domain))
		except Exception  as e:
			print(red("[!] Failed to create new report file!"))
			print(red("[!] Error: {}".format(e)))

		# Run whois
		try:
			print(green("[+] Running whois"))
			report.write("\n---WHOIS Results---\n")
			who = whois.whois(domain)
			report.write("Registrant: {}\n".format(who.name))
			report.write("Organization: {}\n".format(who.org))
			for email in who.emails:
			   report.write("Email: {}\n".format(email))
			report.write("Address: {}, {}{}, {}, {}\n".format(who.address,who.city,who.zipcode,who.state,who.country))
			for server in who.name_servers:
				report.write("DNS: {}\n".format(server))
			report.write("DNSSEC: {}\n".format(who.dnssec))
			report.write("Status: {}\n".format(who.status))
		except Exception  as e:
			report.write("The whois lookup failed!\n")
			print(red("[!] Failed to collect whois information!"))
			print(red("[!] Error: {}".format(e)))

		# Run RDAP lookup
		# Special thanks to GRC_Ninja for reccomending this!
		try:
			print(green("[+] Running RDAP lookup"))
			report.write("\n---RDAP LOOKUP Results---\n")
			domainIP = socket.gethostbyname(domain)
			rdapwho = IPWhois(domainIP)
			results = rdapwho.lookup_rdap(depth=1)
			asn = results['asn']
			report.write("ASN: {}\n".format(asn))
			asn_country_code = results['asn_country_code']
			report.write("ASN Country Code: {}\n".format(asn_country_code))
			network_cidr = results['network']['cidr']
			report.write("Network CIDR: {}\n\n".format(network_cidr))

			for object_key, object_dict in results['objects'].items():
				handle = str(object_key)
				if results['objects'] is not None:
					for item in results['objects']:
						name = results['objects'][item]['contact']['name']
						if name is not None:
							report.write("Name: {}\n".format(name))

						title = results['objects'][item]['contact']['title']
						if title is not None:
							report.write("Title: {}\n".format(title))

						role = results['objects'][item]['contact']['role']
						if role is not None:
							report.write("Role: {}\n".format(role))

						email = results['objects'][item]['contact']['email']
						if email is not None:
							report.write("Email: {}\n".format(email[0]['value']))

						phone = results['objects'][item]['contact']['phone']
						if phone is not None:
							report.write("Phone: {}\n".format(phone[0]['value']))

						address = results['objects'][item]['contact']['address']
						if address is not None:
							report.write("Address: {}\n\n".format(address[0]['value']))
		except Exception  as e:
			report.write("The RDAP lookup failed!")
			print(red("[!] The RDAP lookup failed!"))
			print(red("[!] Error: {}".format(e)))

		# Check reputation with URLVoid
		try:
			if URLVOID_API_KEY is not None:
				print(green("[+] Checking reputation with URLVoid"))
				report.write("\n---URLVOID Results---\n")
				url = "http://api.urlvoid.com/api1000/{}/host/{}".format(URLVOID_API_KEY,domain)
				response = requests.get(url)
				tree = ET.fromstring(response.content)

				for child in tree:
					maliciousCheck = child.tag
					if maliciousCheck == "detections":
						detected = 1
					else:
						detected = 0

				if detected == 1:
					print(red("[+] URLVoid found malicious activity reported for this domain!"))
				else:
					print(green("[+] URLVoid found no malicious activity reported for this domain."))

				repData = tree[0]
				ipData = repData[11]

				report.write("Host: {}\n".format(ET.tostring(repData[0], method='text').rstrip()))
				report.write("Domain Age: {}\n".format(ET.tostring(repData[3], method='text').rstrip()))
				report.write("Google Rank: {}\n".format(ET.tostring(repData[4], method='text').rstrip()))
				report.write("Alexa Rank: {}\n".format(ET.tostring(repData[5], method='text').rstrip()))

				report.write("Address: {}\n".format(ET.tostring(ipData[0], method='text').rstrip()))
				report.write("Hostname: {}\n".format(ET.tostring(ipData[1], method='text').rstrip()))
				report.write("ASN: {}\n".format(ET.tostring(ipData[2], method='text').rstrip()))
				report.write("ASName: {}\n".format(ET.tostring(ipData[3], method='text').rstrip()))
				report.write("Country: {}\n".format(ET.tostring(ipData[5], method='text').rstrip()))
				report.write("Region: {}\n".format(ET.tostring(ipData[6], method='text').rstrip()))
				report.write("City: {}\n\n".format(ET.tostring(ipData[7], method='text').rstrip()))
			else:
				report.write("No URLVoid API key, so skipping test.")
				print(green("[-] No URLVoid API key, so skipping this test."))
				pass
		except Exception  as e:
			report.write("Could not load URLVoid for reputation check!")
			print(red("[!] Could not load URLVoid for reputation check!"))
			print(red("[!] Error: {}".format(e)))

def dnsRecon(client,domain):
	f = "reports/{}/DNS_Report.txt".format(client)

	with open(f, 'w') as report:
		# Run dnsrecon for several different lookups
		print(green("[+] Running dnsrecon"))
		report.write("\n---DNSRECON Results---\n")
		# Standard lookup for records
		try:
			cmd = "dnsrecon -d {} -t std | cut -b 5-".format(domain)
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print(red("[!] Execution of dnsrecon -t std failed!"))
			report.write("Execution of dnsrecon -t stdfailed!\n")
		# Google for sub-domains
		try:
			cmd = "dnsrecon -d {} -t goo | cut -b 5-".format(domain)
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print(red("[!] Execution of dnsrecon -t goo failed!"))
			report.write("Execution of dnsrecon -t goo failed!\n")
		# Zone Transfers
		try:
			cmd = "dnsrecon -d {} -t axfr | cut -b 5-".format(domain)
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print(red("[!] Execution of dnsrecon -t axfr failed!"))
			report.write("Execution of dnsrecon -t axfr failed!\n")
		# Brute force sub-domains
		try:
			cmd = "dnsrecon -d {} -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f | cut -b 5-".format(domain)
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print(red("[!] Execution of dnsrecon -t brt failed!"))
			report.write("Execution of dnsrecon -t brt failed!\n")

		# Run firece
		print(green("[+] Running fierce"))
		report.write("\n---FIERCE Results---\n")
		# The wordlist location is the default location for fierce's hosts.txt on Kali 2
		try:
			cmd = "fierce -dns {} -wordlist /usr/share/fierce/hosts.txt | head -n -2".format(domain)
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print(red("[!] Execution of fierce failed!"))
			report.write("Execution of fierce failed!\n")

def shodanLookUp(client,domain):
	f = "reports/{}/Shodan_Report.txt".format(client)

	with open(f, 'w') as report:
		# Perform Shodan searches
		print(green("[+] Checking Shodan"))
		if shoAPI is None:
			print(red("[!] No Shodan API key, so skipping Shodan searches"))
		else:
			report.write("\n---SHODAN Results---\n")
			# Use API key to search Shodan for client name and client domain
			print(green("[+] Performing Shodan search for {}".format(client)))
			try:
				clientResults = shoAPI.search(client)
			except shodan.APIError as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
			print(green("[+] Performing Shodan search for {}".format(domain)))
			try:
				domainResults = shoAPI.search(domain)
			except shodan.APIError as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
			try:
				report.write("Client name results found: {}\n".format(clientResults['total']))
				# Pull the most interesting information from search results
				for result in clientResults['matches']:
						report.write("IP: {}\n".format(result['ip_str']))
						for name in result['hostnames']:
							report.write("Hostname: {}\n".format(name))
						report.write("OS: {}\n".format(result['os']))
						report.write("Port: {}\n".format(result['port']))
						report.write("Data: {}\n".format(result['data']))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))

			try:
				report.write("Domain results found: {}\n".format(domainResults['total']))
				for result in domainResults['matches']:
						report.write("IP: {}\n".format(result['ip_str']))
						for name in result['hostnames']:
							report.write("Hostname: {}\n".format(name))
						report.write("OS: {}\n".format(result['os']))
						report.write("Port: {}\n".format(result['port']))
						report.write("Data: {}\n".format(result['data']))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
			report.write("Error: {}\n".format(e))

def googleFu(client,domain):
	f = "reports/{}/Gooogle_Report.txt".format(client)

	with open(f, 'w') as report:
		# Search for different login/logon/admin/administrator pages
		report.write("\n--- GOOGLE HACKING LOGIN Results ---\n")
		print(green("[+] Beginning Google queries..."))
		print(yellow("[-] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, try again later or use a VPN/proxy."))
		print(green("[+] Checking Google for login pages"))
		try:
			# Login Logon Admin and administrator
			# Edit setup/google_strings.txt to customize your search terms
			for start in range(0,10):
				with open('setup/google_strings.txt') as googles:
					url = "https://www.google.com/search?q=site:{}+".format(domain)
					terms = googles.readlines()
					totalTerms = len(terms)
					for i in range (totalTerms-1):
						url = url + "intitle:{}+OR+".format(terms[i].rstrip())
					url = url + "intitle:{}&start={}".format(terms[totalTerms-1].rstrip(), str(start*10))

				r = requests.get(url, headers = my_headers)
				status = r.status_code
				soup = BeautifulSoup(r.text)

				for cite in soup.findAll('cite'):
					try:
						report.write("{}\n".format(cite.text))
					except:
						if not status == 200:
							report.write("Viper did not receive a 200 OK! You can double check by using this search query:\n")
							report.write("Query: {}".format(url))
							break
						else:
							continue

				# Take a break to avoid Google blocking our IP
				time.sleep(sleep)
		except Exception  as e:
			print ("Error: {}".format(e))
			print(red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again later."))
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: {}\n".format(url))

		report.write("\n--- GOOGLE HACKING INDEX OF Results ---\n")
		print(green("[+] Checking Google for pages offering file indexes"))
		try:
			# Look for "index of"
			for start in range(0,10):
				url = "https://www.google.com/search?q=site:{}+intitle:index.of&start=".format(domain + str(start*10))

				r = requests.get(url, headers = my_headers)
				status = r.status_code
				soup = BeautifulSoup(r.text)

				for cite in soup.findAll('cite'):
					try:
						report.write("{}\n".format(cite.text))
					except:
						if not status == 200:
							report.write("Viper did not receive a 200 OK! You can double check by using this search query:\n")
							report.write("Query: {}".format(url))
							break
						else:
							continue

				# Take a break to avoid Google blocking our IP
				time.sleep(sleep)
		except Exception  as e:
			print ("Error: {}".format(e))
			print(red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again."))
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: {}\n".format(url))
