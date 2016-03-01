#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import whois
from BeautifulSoup import BeautifulSoup
import urllib2
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

# Number of commands
total = 7 # Tests
def collect(client,domain):
	print green("""Viper will now attempt to gather information from DNS records and other sources.""")

	client = client
	domain = domain
	browser = urllib2.build_opener()
	browser.addheaders = [('User-agent', 'Mozilla/5.0')] # Google-friendly user-agent
	# Create directory for client reports and report
	if not os.path.exists("reports/%s" % client):
		try:
			os.makedirs("reports/%s" % client)
		except Exception as e:
			print red("[!] Could not create reports directory! Terminating and returning...")
			print red("[!] Error: %s" % e)
			return

	file = 'reports/%s/Domain_Report.txt' % client

	with open(file, 'w') as report:
		# Create the Domain Report
		try:
			report.write("### Domain Report for %s ###\n" % (domain))
			print green("[+] Running whois (1/%s)" % total)
			# Run whois
			report.write("\n---WHOIS Results---\n")
			who = whois.whois(domain)
			report.write("Registrant: %s\n" % who.name)
			report.write("Organization: %s\n" % (who.org))
			for email in who.emails:
			   report.write("Email: %s\n" % email)
			report.write("Address: %s, %s %s, %s, %s\n" % (who.address,who.city,who.zipcode,who.state,who.country))
			for server in who.name_servers:
				report.write("DNS: %s\n" % server)
			report.write("DNSSEC: %s\n" % (who.dnssec))
			report.write("Status: %s\n" % (who.status))
		except Exception as e:
			print red("[!] Failed to collect whois information.")
			print red("[!] Error: %s" % e)

		# Run urlcrazy
		print green("[+] Running urlcrazy (2/%s)" % total)
		report.write("\n---URLCRAZY Results---\n")
		try:
			cmd = "urlcrazy %s -f csv" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of urlcrazy failed!")
			report.write("Execution of urlcrazy failed!\n")

		# Run dnsrecon for several different lookups
		print green("[+] Running dnsrecon (3/%s)" % total)
		report.write("\n---DNSRECON Results---\n")
		# Standard lookup for records
		try:
			cmd = "dnsrecon -d %s -t std" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t std failed!")
			report.write("Execution of dnsrecon -t stdfailed!\n")
		# Google for sub-domains
		try:
			cmd = "dnsrecon -d %s -t goo" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t goo failed!")
			report.write("Execution of dnsrecon -t goo failed!\n")
		# Zone Transfers
		try:
			cmd = "dnsrecon -d %s -t axfr" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of dnsrecon -t axfr failed!")
			report.write("Execution of dnsrecon -t axfr failed!\n")
		# Sub-domains
		try:
			cmd = "dnsrecon -d %s -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f" % domain
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
			cmd = "fierce -dns %s -wordlist /usr/share/fierce/hosts.txt" % domain
			result = subprocess.check_output(cmd,shell=True)
			report.write(result)
		except:
			print red("[!] Execution of fierce failed!")
			report.write("Execution of fierce failed!\n")

		# Perform Shodan searches
		print green("[+] Checking Shodan (5/%s)" % total)
		api = shodan.Shodan(SHODAN_API_KEY)
		report.write("\n---SHODAN Results---\n")
		try:
			# Use API key to search Shodan for client name and client domain
			clientResults = api.search(client)
			domainResults = api.search(domain)

			report.write("Client name results found: %s\n" % clientResults['total'])
			# Pull the most interesting information from search results
			for result in clientResults['matches']:
					report.write("IP: %s\n" % result['ip_str'])
					report.write("Hostname: %s\n" % result['hostnames'])
					report.write("OS: %s\n" % result['os'])
					report.write("Port: %s\n" % result['port'])
					report.write("Data: %s\n" % result['data'])
			report.write("Domain results found: %s\n" % domainResults['total'])
			for result in domainResults['matches']:
					report.write("IP: %s\n" % result['ip_str'])
					report.write("Hostname: %s\n" % result['hostnames'])
					report.write("OS: %s\n" % result['os'])
					report.write("Port: %s\n" % result['port'])
					report.write("Data: %s\n" % result['data'])
		except shodan.APIError, e:
				print 'Error: %s' % e

		# Search for different login/logon/admin/administrator pages
		report.write("\n--- GOOGLE HACKING LOGIN Results ---\n")
		print green("[+] Checking Google for login pages (6/%s)" % total)
		print red("[!] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, just try again or use a VPN.")
		try:
			# Login Logon Admin and administrator
			# Add '+OR+intitle:YOUR_TERM' to add more options to search for
			for start in range(0,10):
				url = "https://www.google.com/search?q=site:%s+intitle:login+OR+intitle:logon+OR+intitle:admin+OR+intitle:administrator&start=" % domain + str(start*10)
				page = browser.open(url)
				soup = BeautifulSoup(page)

				for cite in soup.findAll('cite'):
					report.write("%s\n" % cite.text)
		except:
			print red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again.")
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: %s \n" % url)

		report.write("\n--- GOOGLE HACKING INDEX OF Results ---\n")
		print green("[+] Checking Google for pages offering file indexes (7/%s)" % total)
		print red("[!] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, just try again or use a VPN.")
		try:
			# Look for "index of"
			for start in range(0,10):
				url = "https://www.google.com/search?q=site:%s+intitle:index.of&start=" % domain + str(start*10)
				page = browser.open(url)
				soup = BeautifulSoup(page)

				for cite in soup.findAll('cite'):
					report.write("%s\n" % cite.text)
		except:
			print red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again.")
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: %s \n" % url)

	report.close()
