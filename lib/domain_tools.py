#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import censys.certificates
from cymon import Cymon
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import requests
from xml.etree import ElementTree  as eT
import time
from colors import *
import socket
from IPy import IP
import socket
from netaddr import *

my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'} # Google-friendly user-agent
sleep = 10 # Sleep time for Google

# Try to get the user's Shodan API key
try:
	shodan_key_file = open('auth/shodankey.txt', 'r')
	shodan_key_line = shodan_key_file.readlines()
	SHODAN_API_KEY = shodan_key_line[1].rstrip()
	shoAPI = shodan.Shodan(SHODAN_API_KEY)
	shodan_key_file.close()
except:
	shoAPI = None

# Try to get the user's Cymon API key
try:
	cymon_key_file = open('auth/cymonkey.txt', 'r')
	cymon_key_line = cymon_key_file.readlines()
	CYMON_API_KEY = cymon_key_line[1].rstrip()
	cyAPI = Cymon(CYMON_API_KEY)
	cymon_key_file.close()
except:
	cyAPI = None

# Try to get the user's URLVoid API key
try:
	urlvoid_key_file = open('auth/urlvoidkey.txt', 'r')
	urlvoid_key_line = urlvoid_key_file.readlines()
	URLVOID_API_KEY = urlvoid_key_line[1].rstrip()
	urlvoid_key_file.close()
except:
	URLVOID_API_KEY = None

# Try to get the user's Full Contact API key
try:
	contact_key_file = open('auth/fullcontactkey.txt', 'r')
	contact_key_line = contact_key_file.readlines()
	CONTACT_API_KEY = contact_key_line[1].rstrip()
	contact_key_file.close()
except:
	CONTACT_API_KEY = None

# Try to get the user's Censys API key
try:
	censys_key_file = open('auth/censyskey.txt', 'r')
	censys_key_line = censys_key_file.readlines()
	CENSYS_API_ID = censys_key_line[1].rstrip()
	CENSYS_API_SECRET = censys_key_line[2].rstrip()
	cenCertAPI = censys.certificates.CensysCertificates(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
	cenAddAPI = censys.ipv4.CensysIPv4(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
	censys_key_file.close()
except:
	cenCertAPI = None
	cenAddAPI = None


# Check if string is an IP address or not - will assume it is a domain otherwise
def isip(str):
	try:
		IP(str)
	except ValueError:
		return False
	return True


def fullContactDomain(domain, report):
	if CONTACT_API_KEY is None:
		print(red("[!] No Full Contact API key, so skipping these searches."))
	else:
		base_url = 'https://api.fullcontact.com/v2/company/lookup.json'
		payload = {'domain':domain, 'apiKey':CONTACT_API_KEY}
		resp = requests.get(base_url, params=payload)

		if resp.status_code == 200:
			print(resp.text.encode('ascii', 'ignore'))


def getDNSRecord(domain, recordType):
	answer = dns.resolver.query(domain, recordType)
	return answer


def genScope(scope_file):
	"""Parse scope to expand IP ranges"""
	scope = []
	try:
		with open(scope_file, 'r') as preparse:
			for i in preparse:
				# Check if there is a -
				# Ex: 192.168.1.1-50 becomes 192.168.1.1,192.168.1.50
				i = i.rstrip()
				if "-" in i:
					print(green("[+] {} is a range - expanding...".format(i.rstrip())))
					i = i.rstrip()
					a = i.split("-")
					startrange = a[0]
					b = a[0]
					dotSplit = b.split(".")
					j = "."
					# Join the values using a "." so it makes a valid IP
					combine = dotSplit[0], dotSplit[1], dotSplit[2], a[1]
					endrange = j.join(combine)
					# Calculate the IP range
					ip_list = list(iter_iprange(startrange, endrange))
					# Iterate through the range and remove ip_ist
					for i in ip_list:
						a = str(i)
						# Append the IPs
						scope.append(a)
				# Check if range has _
				# Ex: 192.168.1.2_192.168.1.155
				elif "_" in i:
					print(green("[+] {} is a range - expanding...".format(i.rstrip())))
					i = i.rstrip()
					a = i.split("_")
					startrange = a[0]
					endrange = a[1]
					ip_list = list(iter_iprange(startrange, endrange))
					for i in ip_list:
						a = str(i)
						# Append the IPs to the array
						scope.append(a)
				elif "/" in i:
					print(green("[+] {} is a CIDR - converting...".format(i.rstrip())))
					i = i.rstrip()
					ip_list = list(IPNetwork(i))
					for e in sorted(ip_list):
						st = str(e)
						scope.append(st)
				else:
					scope.append(i.rstrip())
	except Exception as e:
		print(red("[!] Parsing of scope file failed!"))
		print(red("[!] Error: {}".format(e)))

	return scope


def collectDomainInfo(domain, report, verbose):
	# Run whois
	try:
		report.write("\n---Info for {}---\n".format(domain))
		# If entry is a domain, then run whois and try to get the IP address
		# Note: IP may return different results because domain may resolve to a load balancer, DDoS service, etc.
		if not isip(domain):
			print(green("[+] {} is (probably) not an IP address, so treating it as a domain name. Running whois and looking up IP for RDAP.".format(domain)))
			# Collect DNS records using PyDNS
			print(green("[+] Collecting DNS records for {}".format(domain)))
			report.write("DNS Records\n")
			report.write("MX Records:\n")
			try:
				mx_records = getDNSRecord(domain, "MX")
				for i in mx_records:
					report.write(i + "\n")
			except:
				report.write("No MX records found\n")
			report.write("NS Records:\n")

			try:
				ns_records = getDNSRecord(domain, "NS")
				for i in ns_records:
					report.write(i + "\n")
			except:
				report.write("No NS records found... what?\n")

			report.write("SOA Records:\n")
			try:
				soa_records = getDNSRecord(domain, "SOA")
				for i in soa_records:
					report.write(i + "\n")
			except:
				report.write("No SOA records found\n")

			report.write("TXT Records:\n")
			try:
				txt_records = getDNSRecord(domain, "TXT")
				for i in txt_records:
					report.write(i + "\n")
			except:
				report.write("No TXT records found\n")

			report.write("A Records:\n")
			try:
				a_records = getDNSRecord(domain, "A")
				for i in a_records:
					report.write(i + "\n")
			except:
				report.write("No MX records found\n")

			print(green("[+] Running whois for {}".format(domain)))
			who = whois.whois(domain)
			report.write("Domain Name: {}\n".format(who.domain_name))
			try:
				for name in who.registrant_name:
					report.write("Registrant: {}\n".format(name))
			except:
				pass # No registrant names, so we pass - can happen when IP points to a subdomain like server.domain.com
			report.write("Organization: {}\n".format(who.org))
			if verbose:
				for email in who.emails:
					report.write("Email: {}\n".format(email))
				report.write("Address: {}, {}{}, {}, {}\n".format(who.address,who.city,who.zipcode,who.state,who.country))
				for server in who.name_servers:
					report.write("DNS: {}\n".format(server))
				report.write("DNSSEC: {}\n".format(who.dnssec))
				report.write("Status: {}\n".format(who.status))
			domain = socket.gethostbyname(domain)
			report.write("Domain IP (see RDAP below): {}\n\n".format(domain))
			print(green("[+] IP is {} - using this for RDAP.".format(domain)))

		who = whois.whois(domain)
		report.write("Domain Name: {}\n".format(who.domain_name))
		try:
			for name in who.registrant_name:
				report.write("Registrant: {}\n".format(name))
		except:
			pass # No registrant names, so we pass - can happen when IP points to a subdomain like server.domain.com
		report.write("Organization: {}\n".format(who.org))
		if verbose:
			for email in who.emails:
				report.write("Email: {}\n".format(email))
			report.write("Address: {}, {}{}, {}, {}\n".format(who.address,who.city,who.zipcode,who.state,who.country))
			for server in who.name_servers:
				report.write("DNS: {}\n".format(server))
			report.write("DNSSEC: {}\n".format(who.dnssec))
			report.write("Status: {}\n".format(who.status))
	except Exception  as e:
		report.write("The whois lookup failed for {}!\n\n".format(domain))
		print(red("[!] Failed to collect whois information for {}!").format(domain))
		print(red("[!] Error: {}".format(e)))

	# Run RDAP lookup
	# Special thanks to GRC_Ninja for reccomending this!
	try:
		print(green("[+] Running RDAP lookup for {}".format(domain)))
		rdapwho = IPWhois(domain)
		results = rdapwho.lookup_rdap(depth=1)
		asn = results['asn']
		report.write("ASN: {}\n".format(asn))
		asn_country_code = results['asn_country_code']
		report.write("ASN Country Code: {}\n".format(asn_country_code))
		network_cidr = results['network']['cidr']
		report.write("Network CIDR: {}\n\n".format(network_cidr))
		if verbose:
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
		report.write("The RDAP lookup failed for {}!\n\n".format(domain))
		print(red("[!] Failed to collect RDAP information for {}!").format(domain))
		print(red("[!] Error: {}".format(e)))

	shodanSearch(domain, report)
	censysSearch(domain, report)
	

def urlVoidLookup(domain, report):
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
	except Exception as e:
		report.write("Could not load URLVoid for reputation check!")
		print(red("[!] Could not load URLVoid for reputation check!"))
		print(red("[!] Error: {}".format(e)))


def dnsRecon(target, client, brute):
	f = "reports/{}/DNS_Report - {}.txt".format(client,target)
	with open(f, 'w') as report:
		report.write("### DNS Report for {} ###\n\n".format(target))
		# Run dnsrecon for several different lookups
		print(green("[+] Running dnsrecon for {}".format(target)))
		# Standard lookup for records
		try:
			cmd = "dnsrecon -d {} -t std | cut -b 5-".format(target)
			result = subprocess.check_output(cmd, shell=True)
			report.write("\n---DNSRecon -t std Results---\n")
			report.write(result.decode())
		except:
			print(red("[!] Execution of dnsrecon -t std failed!"))
			report.write("Execution of dnsrecon -t stdfailed!\n")
		# Google for sub-domains
		try:
			cmd = "dnsrecon -d {} -t goo | cut -b 5-".format(target)
			result = subprocess.check_output(cmd, shell=True)
			report.write("\n---DNSRecon -t goo Results---\n")
			report.write(result.decode())
		except:
			print(red("[!] Execution of dnsrecon -t goo failed!"))
			report.write("Execution of dnsrecon -t goo failed!\n")
		# Zone Transfers
		try:
			cmd = "dnsrecon -d {} -t axfr | cut -b 5-".format(target)
			result = subprocess.check_output(cmd, shell=True)
			report.write("\n---DNSRecon -t axfr Results---\n")
			report.write(result.decode())
		except:
			print(red("[!] Execution of dnsrecon -t axfr failed!"))
			report.write("Execution of dnsrecon -t axfr failed!\n")

		if brute:
			print(green("[+] Brute forcing was selected, so starting those tests. This will take a while -- you brought this on yourself."))
			# Brute force sub-domains
			try:
				cmd = "dnsrecon -d {} -t brt -D /usr/share/dnsrecon/namelist.txt --iw -f | cut -b 5-".format(target)
				result = subprocess.check_output(cmd, shell=True)
				report.write("\n---DNSRecon -t brt Results---\n")
				report.write(result.decode())
			except:
				print(red("[!] Execution of dnsrecon -t brt failed!"))
				report.write("Execution of dnsrecon -t brt failed!\n")
			# Run Firece
			print(green("[+] Running fierce for {}".format(target)))
			# The wordlist location is the default location for fierce's hosts.txt on Kali 2
			try:
				cmd = "fierce -dns {} -wordlist /usr/share/fierce/hosts.txt | head -n -2".format(target)
				result = subprocess.check_output(cmd, shell=True)
				report.write("---Fierce DNS Results---\n")
				report.write(result.decode())
			except:
				print(red("[!] Execution of Fierce failed!"))
				report.write("Execution of Fierce failed!\n")
		else:
			print(green("[+] Brute forcing was not selected, so skipping test."))


def shodanSearch(target, report):
	# Perform Shodan searches
	if shoAPI is None:
		pass
	else:
		if not isip(target):
			try:
				print(green("[+] Performing Shodan search for {}".format(target)))
				targetResults = shoAPI.search(target)
			except shodan.APIError as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
			try:
				report.write("Shodan results found for {}: {}\n".format(target,targetResults['total']))
				for result in targetResults['matches']:
						report.write("IP: {}\n".format(result['ip_str']))
						for name in result['hostnames']:
							report.write("Hostname: {}\n".format(name))
						report.write("OS: {}\n".format(result['os']))
						report.write("Port: {}\n".format(result['port']))
						report.write("Data: {}\n".format(result['data']))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
		else:
			print(green("[+] Performing Shodan lookup for {}".format(target)))
			try:
				host = shoAPI.host(target)
				report.write("IP: {}\n".format(host['ip_str']))
				report.write("Organization: {}\n".format(host.get('org', 'n/a')))
				report.write("OS: {}\n".format(host.get('os', 'n/a')))
				for item in host['data']:
					report.write("Port: {}\n".format(item['port']))
					report.write("Banner: {}\n".format(item['data']))
			except shodan.APIError as e:
				print(red("[!] Error: %s" % e))
				report.write("[!] Error: %s" % e)


def censysSearch(target, report):
	if cenCertAPI is None:
		pass
	else:
		print(green("[+] Performing Censys search for {}".format(target)))
		if not isip(target):
			report.write("Censys certificate results for {}\n".format(target))
			try:
				fields = ["parsed.subject_dn", "parsed.issuer_dn"]
				for cert in cenCertAPI.search(target, fields=fields):
					report.write(cert["parsed.subject_dn"] + "\n")
					report.write(cert["parsed.issuer_dn"] + "\n")
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
		else:
			report.write("Censys IPv4 results for {}\n".format(target))
			try:
				for i in cenAddAPI.search(target):
					for prot in i["protocols"]:
						report.write(prot + "\n")
			except Exception as e:
				print(red("[!] Error: %s" % e))
				report.write("[!] Error: %s" % e)


def googleFu(client, target):
	f = "reports/{}/Gooogle_Report - {}.txt".format(client,target)

	with open(f, 'w') as report:
		# Search for different login/logon/admin/administrator pages
		report.write("\n### GOOGLE HACKING Report for {} ###\n".format(target))
		report.write("---GOOGLE LOGIN PAGE Results---\n")
		print(green("[+] Beginning Google queries..."))
		print(yellow("[-] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, try again later or use a VPN/proxy."))
		print(green("[+] Checking Google for login pages"))
		try:
			# Login Logon Admin and administrator
			# Edit setup/google_strings.txt to customize your search terms
			for start in range(0,10):
				with open('setup/google_strings.txt') as googles:
					url = "https://www.google.com/search?q=site:{}+".format(target)
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

		report.write("\n--- GOOGLE INDEX OF PAGE Results ---\n")
		print(green("[+] Checking Google for pages offering file indexes"))
		try:
			# Look for "index of"
			for start in range(0,10):
				url = "https://www.google.com/search?q=site:{}+intitle:index.of&start=".format(target + str(start*10))

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


# Cymon - Provides URLs associated with an IP
def searchCymon(target, report):
	print(green("[+] Checking Cymon for domains associated with the provided list of IPs"))
	try:
		# Search for domains tied to the IP
		data = cyAPI.ip_domains(target)
		results = data['results']
		report.write("\n--- The following data is for IP: {}---\n".format(target))
		report.write("DOMAIN search results:\n")
		for result in results:
			report.write("\nURL: %s\n" % result['name'])
			report.write("Created: %s\n" % result['created'])
			report.write("Updated: %s\n" % result['updated'])
		# Search for security events for the IP
		data = cyAPI.ip_events(target)
		results = data['results']
		report.write("\nEVENT results:\n")
		for result in results:
			report.write("\nTitle: %s\n" % result['title'])
			report.write("Description: %s\n" % result['description'])
			report.write("Created: %s\n" % result['created'])
			report.write("Updated: %s\n" % result['updated'])
			report.write("Details: %s\n" % result['details_url'])
		print(green("[+] Cymon search completed!"))
	except:
		print(red("[!] Could not load Cymon.io! Check your connection to Cymon."))
