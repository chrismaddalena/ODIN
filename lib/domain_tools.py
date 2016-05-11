#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import whois
from BeautifulSoup import BeautifulSoup
import requests
from xml.etree import ElementTree as ET
import time
from colors import *

# Try to get the user's Shodan API key
try:
	shodan_key_file = open('auth/shodankey.txt', 'r')
	shodan_key_line = shodan_key_file.readlines()
	SHODAN_API_KEY = shodan_key_line[1].rstrip()
	api = shodan.Shodan(SHODAN_API_KEY)
	shodan_key_file.close()
except:
	sho_api = None

# Try to get the user's URLVoid API key
try:
	urlvoid_key_file = open('auth/urlvoidkey.txt', 'r')
	urlvoid_key_line = urlvoid_key_file.readlines()
	URLVOID_API_KEY = urlvoid_key_line[1].rstrip()
	urlvoid_key_file.close()
except:
	URLVOID_API_KEY = None

# Number of commands
total = 7 # Tests
def collect(client,domain):
	print green("Viper will now attempt to gather information from DNS records and other sources.")

	client = client
	domain = domain
	my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'} # Google-friendly user-agent
	sleep = 10

	# Create directory for client reports and report
	if not os.path.exists("reports/%s" % client):
		try:
			os.makedirs("reports/%s" % client)
		except Exception as e:
			print red("[!] Could not create reports directory! Terminating and returning...")
			print red("[!] Error: %s" % e)
			return

	file = "reports/%s/Domain_Report.txt" % client

	with open(file, 'w') as report:
		# Create the Domain Report
		try:
			report.write("### Domain Report for %s ###\n" % domain)
			print green("[+] Running whois (1/%s)" % total)
			# Run whois
			report.write("\n---WHOIS Results---\n")
			who = whois.whois(domain)
			report.write("Registrant: %s\n" % who.name)
			report.write("Organization: %s\n" % who.org)
			for email in who.emails:
			   report.write("Email: %s\n" % email)
			report.write("Address: %s, %s %s, %s, %s\n" % (who.address,who.city,who.zipcode,who.state,who.country))
			for server in who.name_servers:
				report.write("DNS: %s\n" % server)
			report.write("DNSSEC: %s\n" % who.dnssec)
			report.write("Status: %s\n" % who.status)
		except Exception as e:
			print red("[!] Failed to collect whois information.")
			print red("[!] Error: %s" % e)

		# Check reputation with URLVoid
		try:
			if URLVOID_API_KEY is not None:
				print green("[+] Checking reputation with URLVoid (2/%s)" % total)
				report.write("\n---URLVOID Results---\n")
				url = "http://api.urlvoid.com/api1000/%s/host/%s" % (URLVOID_API_KEY,domain)
				response = requests.get(url)
				tree = ET.fromstring(response.content)

				for child in tree:
					maliciousCheck = child.tag
					if maliciousCheck == "detections":
						detected = 1
					else:
						detected = 0

				if detected == 1:
					print red("[+] URLVoid found malicious activity reported for this domain!")
				else:
					print green("[+] URLVoid found no malicious activity reported for this domain.")

				repData = tree[0]
				ipData = repData[11]

				report.write("Host: %s\n" % ET.tostring(repData[0], method='text'))
				report.write("Domain Age: %s\n" % ET.tostring(repData[3], method='text'))
				report.write("Google Rank: %s\n" % ET.tostring(repData[4], method='text'))
				report.write("Alexa Rank: %s\n" % ET.tostring(repData[5], method='text'))

				report.write("Address: %s\n" % ET.tostring(ipData[0], method='text'))
				report.write("Hostname: %s\n" % ET.tostring(ipData[1], method='text'))
				report.write("ASN: %s\n" % ET.tostring(ipData[2], method='text'))
				report.write("ASName: %s\n" % ET.tostring(ipData[3], method='text'))
				report.write("Country: %s\n" % ET.tostring(ipData[5], method='text'))
				report.write("Region: %s\n" % ET.tostring(ipData[6], method='text'))
				report.write("City: %s\n" % ET.tostring(ipData[7], method='text'))
			else:
				print green("[-] No URLVoid API key, so skipping this test.")
				pass
		except:
			print red("[!] Could not load URLVoid for reputation check!")

		# Run dnsrecon for several different lookups
		print green("[+] Running dnsrecon (3/%s)" % total)
		report.write("\n---DNSRECON Results---\n")
		# Standard lookup for records
		try:
			cmd = "dnsrecon -d %s -t std | cut -b 5-" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t std failed!")
			report.write("Execution of dnsrecon -t stdfailed!\n")
		# Google for sub-domains
		try:
			cmd = "dnsrecon -d %s -t goo | cut -b 5-" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t goo failed!")
			report.write("Execution of dnsrecon -t goo failed!\n")
		# Zone Transfers
		try:
			cmd = "dnsrecon -d %s -t axfr | cut -b 5-" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t axfr failed!")
			report.write("Execution of dnsrecon -t axfr failed!\n")
		# Brute for ce sub-domains
		try:
			cmd = "dnsrecon -d %s -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f | cut -b 5-" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t brt failed!")
			report.write("Execution of dnsrecon -t brt failed!\n")

		# Run firece
		print green("[+] Running fierce (4/%s)" % total)
		report.write("\n---FIERCE Results---\n")
		# The wordlist location is the default location for fierce's hosts.txt on Kali 2
		try:
			cmd = "fierce -dns %s -wordlist /usr/share/fierce/hosts.txt | head -n -2" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of fierce failed!")
			report.write("Execution of fierce failed!\n")

		# Perform Shodan searches
		print green("[+] Checking Shodan (5/%s)" % total)
		api = shodan.Shodan(SHODAN_API_KEY)
		report.write("\n---SHODAN Results---\n")
		# Use API key to search Shodan for client name and client domain
		print green("[+] Performing Shodan search for %s" % client)
		try:
			clientResults = api.search(client)
		except shodan.APIError, e:
			print red("[!] Error: %s" % e)
			report.write("Error: %s\n" % e)
		print green("[+] Performing Shodan search for %s" % domain)
		try:
			domainResults = api.search(domain)
		except shodan.APIError, e:
			print red("[!] Error: %s" % e)
			report.write("Error: %s\n" % e)
		report.write("Client name results found: %s\n" % clientResults['total'])
		try:
			# Pull the most interesting information from search results
			for result in clientResults['matches']:
					report.write("IP: %s\n" % result['ip_str'])
					for name in result['hostnames']:
						report.write("Hostname: %s\n" % name)
					report.write("OS: %s\n" % result['os'])
					report.write("Port: %s\n" % result['port'])
					report.write("Data: %s\n" % result['data'])
		except Exception, e:
			print red("[!] Error: %s" % e)
			report.write("Error: %s\n" % e)

		report.write("Domain results found: %s\n" % domainResults['total'])
		try:
			for result in domainResults['matches']:
					report.write("IP: %s\n" % result['ip_str'])
					for name in result['hostnames']:
						report.write("Hostname: %s\n" % name)
					report.write("OS: %s\n" % result['os'])
					report.write("Port: %s\n" % result['port'])
					report.write("Data: %s\n" % result['data'])
		except Exception, e:
			print red("[!] Error: %s" % e)
			report.write("Error: %s\n" % e)

		# Search for different login/logon/admin/administrator pages
		report.write("\n--- GOOGLE HACKING LOGIN Results ---\n")
		print green("[+] Beginning Google queries...")
		print yellow("[-] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, try again later or use a VPN/proxy.")
		print green("[+] Checking Google for login pages (6/%s)" % total)
		try:
			# Login Logon Admin and administrator
			# Edit setup/google_strings.txt to customize your search terms
			for start in range(0,10):
				with open('setup/google_strings.txt') as googles:
					url = "https://www.google.com/search?q=site:%s+" % domain
					terms = googles.readlines()
					totalTerms = len(terms)
					for i in range (totalTerms-1):
						url = url + "intitle:%s+OR+" % terms[i].rstrip()
					url = url + "intitle:%s&start=%s" % (terms[totalTerms-1].rstrip(), str(start*10))

				r = requests.get(url, headers = my_headers)
				status = r.status_code
				soup = BeautifulSoup(r.text)

				for cite in soup.findAll('cite'):
					try:
						report.write("%s\n" % cite.text)
					except:
						if not status == 200:
							report.write("Viper did not receive a 200 OK! You can double check by using this search query:\n")
							report.write("Query: %s" % url)
							break
						else:
							continue

				# Take a break to avoid Google blocking our IP
				time.sleep(sleep)
		except Exception as e:
			print ("Error: %s" % e)
			print red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again later.")
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: %s \n" % url)

		report.write("\n--- GOOGLE HACKING INDEX OF Results ---\n")
		print green("[+] Checking Google for pages offering file indexes (7/%s)" % total)
		try:
			# Look for "index of"
			for start in range(0,10):
				url = "https://www.google.com/search?q=site:%s+intitle:index.of&start=" % domain + str(start*10)

				r = requests.get(url, headers = my_headers)
				status = r.status_code
				soup = BeautifulSoup(r.text)

				for cite in soup.findAll('cite'):
					try:
						report.write("%s\n" % cite.text)
					except:
						if not status == 200:
							report.write("Viper did not receive a 200 OK! You can double check by using this search query:\n")
							report.write("Query: %s" % url)
							break
						else:
							continue

				# Take a break to avoid Google blocking our IP
				time.sleep(sleep)
		except Exception as e:
			print ("Error: %s" % e)
			print red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again.")
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: %s \n" % url)

	report.close()
