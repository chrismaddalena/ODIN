#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import shodan
import whois

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
total = 5 # Tests

def collect(client,domain):
	print """Viper will now attempt to gather information from DNS records and other sources.
	"""
    
	client = client
	domain = domain
	# Create drectory for client reports
	if not os.path.exists("reports/%s" % client):
		try:
			os.mkdir("reports/%s" % client)
		except:
			print "[!] Could not create reports directory!"

    # Create the Domain Report
	os.system('echo "### Domain Report for %s ###\n" >> reports/%s/Domain_Report.txt' % (domain,client))
	print "[+] Running whois (1/%s)" % total
    # Run whois
	os.system('echo "\n---WHOIS Results---\n" >> reports/%s/Domain_Report.txt' % client)
	who = whois.whois(domain)
	os.system('echo "Registrant: %s" >> reports/%s/Domain_Report.txt' % (who.name,client))
	os.system('echo "Organization: %s" >> reports/%s/Domain_Report.txt' % (who.org,client))
	os.system('echo "Emails: %s" >> reports/%s/Domain_Report.txt' % (who.emails,client))
	os.system('echo "Address: %s, %s %s, %s, %s" >> reports/%s/Domain_Report.txt' % (who.address,who.city,who.zipcode,who.state,who.country,client))
	os.system('echo "DNS: %s" >> reports/%s/Domain_Report.txt' % (who.name_servers,client))
	os.system('echo "DNSSEC: %s" >> reports/%s/Domain_Report.txt' % (who.dnssec,client))
	os.system('echo "Status: %s" >> reports/%s/Domain_Report.txt' % (who.status,client))

    # Run urlcrazy
	print "[+] Running urlcrazy (2/%s)" % total
	os.system('echo "\n---URLCRAZY Results---\n" >> reports/%s/Domain_Report.txt' % client)
	os.system('urlcrazy %s >> reports/%s/Domain_Report.txt' % (domain,domain))

    # Run dnsrecon for several different lookups
	print "[+] Running dnsrecon (3/%s)" % total
	os.system('echo "\n---DNSRECON Results---\n" >> reports/%s/Domain_Report.txt' % client)
	# Standard lookup for records
	os.system('dnsrecon -d %s -t std >> reports/%s/Domain_Report.txt' % (domain,domain))
	# Google for sub-domains
	os.system('dnsrecon -d %s -t goo >> reports/%s/Domain_Report.txt' % (domain,domain))
	# Zone Transfers
	os.system('dnsrecon -d %s -t axfr >> reports/%s/Domain_Report.txt' % (domain,domain))
	# Sub-domains
	os.system('dnsrecon -d %s -t brt -D /pentest/intelligence-gathering/dnsrecon/namelist.txt --iw -f >> reports/%s/Domain_Report.txt' % (domain,domain))

    # Run firece
	print "[+] Running fierce (4/%s)" % total
	os.system('echo "\n---FIERCE Results---\n" >> reports/%s/Domain_Report.txt' % client)
	os.system('fierce -dns %s -wordlist /pentest/intelligence-gathering/fierce/hosts.txt -suppress>> reports/%s/Domain_Report.txt' % (domain,client))

    # Perform Shodan searches
	print "[+] Checking Shodan (5/%s)" % total
	api = shodan.Shodan(SHODAN_API_KEY)
	os.system('echo "\n---SHODAN Results---\n" >> reports/%s/Domain_Report.txt' % client)
	try:
		# Use API key to search Shodan for client name and client domain
		clientResults = api.search(client)
		domainResults = api.search(domain)

		os.system('echo "Client name results found: %s" >> reports/%s/Domain_Report.txt' % (clientResults['total'],client))
        # Pull the most interesting information from search results
		for result in clientResults['matches']:
				os.system('echo "IP: %s" >> reports/%s/Domain_Report.txt' % (result['ip_str'],client))
				os.system('echo "Hostname: %s" >> reports/%s/Domain_Report.txt' % (result['hostnames'],client))
				os.system('echo "OS: %s" >> reports/%s/Domain_Report.txt' % (result['os'],client))
				os.system('echo "Port: %s" >> reports/%s/Domain_Report.txt' % (result['port'],client))
				os.system('echo "Data: %s" >> reports/%s/Domain_Report.txt' % (result['data'],client))
		os.system('echo "Domain results found: %s" >> reports/%s/Domain_Report.txt' % (domainResults['total'],client))
		for result in domainResults['matches']:
				os.system('echo "IP: %s" >> reports/%s/Domain_Report.txt' % (result['ip_str'],client))
				os.system('echo "Hostname: %s" >> reports/%s/Domain_Report.txt' % (result['hostnames'],client))
				os.system('echo "OS: %s" >> reports/%s/Domain_Report.txt' % (result['os'],client))
				os.system('echo "Port: %s" >> reports/%s/Domain_Report.txt' % (result['port'],client))
				os.system('echo "Data: %s \n" >> reports/%s/Domain_Report.txt' % (result['data'],client))
	except shodan.APIError, e:
			print 'Error: %s' % e
			pass
