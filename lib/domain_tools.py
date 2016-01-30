#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
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
total = 6 # Tests
def collect(client,domain):
    print green("""Viper will now attempt to gather information from DNS records and other sources.""")

    client = client
    domain = domain
    browser = urllib2.build_opener()
    browser.addheaders = [('User-agent', 'Mozilla/5.0')] # Google-friendly user-agent
	# Create drectory for client reports and report
    if not os.path.exists("reports/%s" % client):
		try:
			os.mkdir("reports/%s" % client)
		except:
			print red("[!] Could not create reports directory!")

    file = 'reports/%s/Domain_Report.txt' % client

    with open(file, 'w') as report:
        # Create the Domain Report
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

        # Run urlcrazy
    	print green("[+] Running urlcrazy (2/%s)" % total)
    	report.write("\n---URLCRAZY Results---\n")
    	os.system('urlcrazy %s >> reports/%s/Domain_Report.txt' % (domain,domain))

        # Run dnsrecon for several different lookups
    	print green("[+] Running dnsrecon (3/%s)" % total)
    	report.write("\n---DNSRECON Results---\n")
    	# Standard lookup for records
    	os.system('dnsrecon -d %s -t std >> reports/%s/Domain_Report.txt' % (domain,domain))
    	# Google for sub-domains
    	os.system('dnsrecon -d %s -t goo >> reports/%s/Domain_Report.txt' % (domain,domain))
    	# Zone Transfers
    	os.system('dnsrecon -d %s -t axfr >> reports/%s/Domain_Report.txt' % (domain,domain))
    	# Sub-domains
    	os.system('dnsrecon -d %s -t brt -D /pentest/intelligence-gathering/dnsrecon/namelist.txt --iw -f >> reports/%s/Domain_Report.txt' % (domain,domain))

        # Run firece
    	print green("[+] Running fierce (4/%s)" % total)
    	report.write("\n---FIERCE Results---\n")
    	os.system('fierce -dns %s -wordlist /pentest/intelligence-gathering/fierce/hosts.txt -suppress>> reports/%s/Domain_Report.txt' % (domain,client))

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
    			pass

    	# Search for different login/logon/admin/administrator pages
    	report.write("\n--- GOOGLE HACKING LOGIN Results ---\n")
        print green("[+] Checking Google for login pages (6/%s)" % total)
    	# Login
    	for start in range(0,10):
    		url = "https://www.google.com/search?q=site:%s+intitle:login&start=" % domain + str(start*10)
    		page = browser.open(url)
    		soup = BeautifulSoup(page)

    		for cite in soup.findAll('cite'):
    			report.write("%s\n" % cite.text)
    	# Logon
    	for start in range(0,10):
    		url = "https://www.google.com/search?q=site:%s+intitle:logon&start=" % domain + str(start*10)
    		page = browser.open(url)
    		soup = BeautifulSoup(page)

    		for cite in soup.findAll('cite'):
    			report.write("%s\n" % cite.text)
    	# Admin
    	for start in range(0,10):
    		url = "https://www.google.com/search?q=site:%s+intitle:admin&start=" % domain + str(start*10)
    		page = browser.open(url)
    		soup = BeautifulSoup(page)

    		for cite in soup.findAll('cite'):
    			report.write("%s\n" % cite.text)
    	# Administrator
    	for start in range(0,10):
    		url = "https://www.google.com/search?q=site:%s+intitle:administrator&start=" % domain + str(start*10)
    		page = browser.open(url)
    		soup = BeautifulSoup(page)

    		for cite in soup.findAll('cite'):
    			report.write("%s\n" % cite.text)

    report.close()
