#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import censys.certificates
import censys.ipv4
from cymon import Cymon
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import requests
from xml.etree import ElementTree  as ET
import time
from colors import *
import socket
from IPy import IP
import socket
from netaddr import *
import dns.resolver
import csv

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


def isip(str):
	"""Check if string is an IP address or not - will assume it is a domain otherwise.
	"""
	try:
		IP(str)
	except ValueError:
		return False
	return True


def fullContactDomain(domain, report):
	"""Use Full Contact API to collect social media info -- API key required
	"""
	if CONTACT_API_KEY is None:
		print(red("[!] No Full Contact API key, so skipping these searches."))
	else:
		base_url = 'https://api.fullcontact.com/v2/company/lookup.json'
		payload = {'domain':domain, 'apiKey':CONTACT_API_KEY}
		resp = requests.get(base_url, params=payload)

		if resp.status_code == 200:
			print(resp.text.encode('ascii', 'ignore'))


def getDNSRecord(domain, recordType):
	"""Simple function to get the target domain;s DNS records
	"""
	answer = dns.resolver.query(domain, recordType)
	return answer


def genScope(scope_file):
	"""Parse scope to expand IP ranges
	"""
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


def runWhois(domain):
	"""Perform a whois lookup for the provided target
	"""
	try:
		who = whois.whois(domain)
		results = {}
		results['domain_name'] = who.domain_name
		results['registrar'] = who.registrar
		results['expiration_date'] = who.expiration_date
		results['registrant'] = who.name
		results['org'] = who.org
		results['admin_email'] = who.emails[0]
		results['tech_email'] = who.emails[1]
		results['address'] = "{}, {}{}, {}, {}\n".format(who.address, who.city, who.zipcode, who.state, who.country)
		results['dnssec'] = who.dnssec

		return results
	except Exception as e:
		print(red("[!] Failed to collect domain information for {}!").format(domain))
		print(red("[!] Error: {}".format(e)))


def runRDAP(domain_ip):
	"""Perform an RDAP lookup for an IP address
	From IPWhois: IPWhois.lookup_rdap() is now the recommended lookup method.
	RDAP provides a far better data structure than legacy whois and REST lookups
	(previous implementation). RDAP queries allow for parsing of contact information
	and details for users, organizations, and groups. RDAP also provides more
	detailed network information.
	"""
	try:
		rdapwho = IPWhois(domain_ip)
		results = rdapwho.lookup_rdap(depth=1)

		return results
	except Exception as e:
		print(red("[!] Failed to collect RDAP information for {}!").format(domain_ip))
		print(red("[!] Error: {}".format(e)))


def goCrazy(client, target):
	"""Run urlcrazy to locate typosquatted domains related to the targte domain
	"""
	f = "reports/{}/Typosquatting_Report - {}.txt".format(client, target)
	outfile = "reports/{}/crazy_temp.csv".format(client)
	finalCSV = "reports/{}/{}_urlcrazy.csv".format(client, target)
	domains = []
	a_records = []
	mx_records = []
	squatted = {}
	print(green("[+] Running urlcrazy for {}".format(target)))
	with open(f, 'w') as report:
		try:
			report.write("### URLCRAZY Typosquatting Report for {} ###\n\n".format(target))
			cmd = "urlcrazy -f csv -o {} {}".format(outfile, target)
			with open(os.devnull, "w") as devnull:
				subprocess.call(cmd, stdout=devnull, shell=True)
			with open(outfile, 'r') as results:
				reader = csv.DictReader(row.replace('\0', '') for row in results)
				for row in reader:
					if len(row) != 0:
						if row['CC-A'] != "?":
							domains.append(row['Typo'])
							a_records.append(row['DNS-A'])
							mx_records.append(row['DNS-MX'])

			squatted = zip(domains, a_records, mx_records)

			report.write("Domain\t\t\tDNS-A\t\tDNS-MX\n")
			for d in squatted:
				report.write("{}\t{}\t{}\n".format(d[0], d[1], d[2]))

			os.rename(outfile, finalCSV)
		except Exception as e:
			print(red("[!] Execution of urlcrazy failed!"))
			print(red("[!] Error: {}".format(e)))
			report.write("Execution of urlcrazy failed!\n")
			report.write("[!] Error: {}".format(e))


def collectDomainInfo(domain, report, verbose):
	"""Collect various domain information (whois, DNS, RDAP) for the target domain.
	"""
	domain_name = domain
	domain_ip = socket.gethostbyname(domain)
	try:
		report.write("\n---Info for {}---\n".format(domain))
		# If entry is a domain, then run whois and try to get the IP address
		# Note: IP may return different results because domain may resolve to a load balancer, DDoS service, etc.
		if not isip(domain):
			print(green("[+] {} is (probably) not an IP address, so treating it as a domain name. Running whois and using associated IP address for RDAP.".format(domain)))
			# Collect DNS records using PyDNS
			print(green("[+] Collecting DNS records for {}".format(domain)))
			report.write("DNS Records for {}\n".format(domain))
			report.write("MX Records:\n")
			try:
				mx_records = getDNSRecord(domain, "MX")
				for i in mx_records:
					report.write("{}\n".format(i))
			except:
				report.write("No MX records found\n")

			report.write("\nNS Records:\n")
			try:
				ns_records = getDNSRecord(domain, "NS")
				for i in ns_records:
					report.write("{}\n".format(i))
			except:
				report.write("No NS records found... what?\n")

			report.write("\nSOA Records:\n")
			try:
				soa_records = getDNSRecord(domain, "SOA")
				for i in soa_records:
					report.write("{}\n".format(i))
			except:
				report.write("No SOA records found\n")

			report.write("\nTXT Records:\n")
			try:
				txt_records = getDNSRecord(domain, "TXT")
				for i in txt_records:
					report.write("{}\n".format(i))
			except:
				report.write("No TXT records found\n")

			report.write("\nA Records:\n")
			try:
				a_records = getDNSRecord(domain, "A")
				for i in a_records:
					report.write("{}\n".format(i))
			except:
				report.write("No MX records found\n")

			# Run whois lookup
			print(green("[+] Running whois for {}".format(domain)))
			results = runWhois(domain)

			# Log whois results to domain report
			report.write("\nDomain Name:\t{}\n".format(results['domain_name'][0].lower()))
			report.write("Registrar:\t{}\n".format(results['registrar']))
			report.write("Expiration:\t{}\n".format(results['expiration_date'][0]))
			report.write("Organization:\t{}\n".format(results['org']))
			report.write("Registrant:\t{}\n".format(results['registrant']))
			report.write("Admin Contact:\t{}\n".format(results['admin_email']))
			report.write("Tech Contact:\t{}\n".format(results['tech_email']))
			report.write("Address:\t{}\n".format(results['address'].rstrip()))
			report.write("DNSSEC:\t\t{}\n\n".format(results['dnssec']))

			# Output some useful domain information for immediate review
			print(yellow("\nDomain \t Registrar \t Expiration"))
			print(yellow("{} \t {} \t {}\n".format(results['domain_name'][0].lower(), results['registrar'], results['expiration_date'][0])))

			print(yellow("Domain \t Admin Contact \t Tech Contact"))
			print(yellow("{} \t {} \t {}\n".format(results['domain_name'][0].lower(), results['admin_email'], results['tech_email'])))

			report.write("Domain IP (see RDAP below): {}\n\n".format(domain_ip))
			print(green("[+] IP is {} - using this for RDAP.".format(domain_ip)))
	except Exception as e:
		report.write("Failed to collect domain information for {}!\n\n".format(domain))

	# Run RDAP lookup
	# Special thanks to GRC_Ninja for recommending this!
	try:
		print(green("[+] Running RDAP lookup for {}".format(domain)))
		results = runRDAP(domain_ip)

		# Output some useful domain information for immediate review
		print(yellow("\nNet Range \t Organization \t Source"))
		print(yellow("{} \t {} \t {}\n".format(results['network']['cidr'], results['network']['name'], results['asn_registry'])))

		report.write("RDAP information from {}\n".format(results['asn_registry']))
		organization = results['network']['name']
		report.write("Organization:\t{}\n".format(organization))
		network_cidr = results['network']['cidr']
		report.write("Network CIDR:\t{}\n".format(network_cidr))
		asn = results['asn']
		report.write("ASN:\t\t{}\n".format(asn))
		asn_country_code = results['asn_country_code']
		report.write("ASN Country:\t{}\n".format(asn_country_code))
		# Verbose mode is optional to allow users to NOT
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
		else:
				report.write("\nEnumeration of contact information was skipped because Verbose mode was not enabled.\n\n")
	except Exception  as e:
		report.write("The RDAP lookup failed for {}!\n\n".format(domain_ip))

	shodanSearch(domain_name, report)
	censysSearch(domain_name, report)
	# If the name and IP are the same, then we have an IP and don't want to search twice
	if domain_name == domain_ip:
		print(green("[!] Skipping, check worked"))
	else:
		shodanSearch(domain_ip, report)
		censysSearch(domain_ip, report)


def urlVoidLookup(domain, report):
	"""Collect reputation data from URLVoid for target domain -- API key required
	"""
	if not isip(domain):
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

				report.write("Host: {}\n".format(ET.tostring(repData[0], method='text').rstrip().decode('ascii')))
				report.write("Domain Age: {}\n".format(ET.tostring(repData[3], method='text').rstrip().decode('ascii')))
				report.write("Google Rank: {}\n".format(ET.tostring(repData[4], method='text').rstrip().decode('ascii')))
				report.write("Alexa Rank: {}\n".format(ET.tostring(repData[5], method='text').rstrip().decode('ascii')))

				report.write("Address: {}\n".format(ET.tostring(ipData[0], method='text').rstrip().decode('ascii')))
				report.write("Hostname: {}\n".format(ET.tostring(ipData[1], method='text').rstrip().decode('ascii')))
				report.write("ASN: {}\n".format(ET.tostring(ipData[2], method='text').rstrip().decode('ascii')))
				report.write("ASName: {}\n".format(ET.tostring(ipData[3], method='text').rstrip().decode('ascii')))
				report.write("Country: {}\n".format(ET.tostring(ipData[5], method='text').rstrip().decode('ascii')))
				report.write("Region: {}\n".format(ET.tostring(ipData[6], method='text').rstrip().decode('ascii')))
				report.write("City: {}\n\n".format(ET.tostring(ipData[7], method='text').rstrip().decode('ascii')))
			else:
				report.write("No URLVoid API key, so skipping test.")
				print(green("[-] No URLVoid API key, so skipping this test."))
				pass
		except Exception as e:
			report.write("Could not load URLVoid for reputation check!")
			print(red("[!] Could not load URLVoid for reputation check!"))
			print(red("[!] Error: {}".format(e)))
	else:
		print(red("[!] Target is not a domain, so skipping URLVoid queries."))


def searchCymon(target, report):
	"""Get reputation data for target from Cymon.io -- API key required
	"""
	print(green("[+] Checking Cymon for domains associated with the provided list of IPs."))
	try:
		if isip(target):
			# Search for IP and domains tied to the IP
			data = cyAPI.ip_domains(target)
			results = data['results']
			report.write("\n--- The following data is for IP: {}---\n".format(target))
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
		else:
			# Search for domains and IP addresses tied to the domain
			results = cyAPI.domain_lookup(target)
			report.write("\n--- The following data is for domain: {}---\n".format(target))
			report.write("\nURL: %s\n" % results['name'])
			report.write("Created: %s\n" % results['created'])
			report.write("Updated: %s\n" % results['updated'])
			for source in results['sources']:
				report.write("Source: {}\n".format(source))
			for ip in results['ips']:
				report.write("IP: {}\n".format(ip))

		print(green("[+] Cymon search completed!"))
	except:
		print(red("[!] Cymon.io returned a 404 indicating no results."))


def dnsRecon(target, client, brute):
	"""Additional DNS information collection using DNSRecon
	"""
	f = "reports/{}/DNS_Report - {}.txt".format(client, target)
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
			report.write("Execution of dnsrecon -t std failed!\n")
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
	"""Collect information Shodan has for target IP or domain name -- API key required
	"""
	if shoAPI is None:
		pass
	else:
		if not isip(target):
			print(green("[+] Performing Shodan search for {}".format(target)))
			try:
				targetResults = shoAPI.search(target)
			except shodan.APIError as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
			try:
				report.write("Shodan results found for {}: {}\n\n".format(target, targetResults['total']))
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
			except shodan.APIError as e:
				print(red("[!] Error: {}".format(e)))
				report.write("[!] Error: {}".format(e))
			try:
				report.write("Shodan results found for {}:\n\n".format(target))
				report.write("IP: {}\n".format(host['ip_str']))
				report.write("Organization: {}\n".format(host.get('org', 'n/a')))
				report.write("OS: {}\n".format(host.get('os', 'n/a')))
				for item in host['data']:
					report.write("Port: {}\n".format(item['port']))
					report.write("Banner: {}\n".format(item['data']))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))


def censysSearch(target, report):
	"""Collect information Censys has for target IP or domain name -- API key required
	"""
	if cenCertAPI is None:
		pass
	else:
		print(green("[+] Performing Censys search for {}".format(target)))
		if not isip(target):
			report.write("Censys certificate results for {}:\n\n".format(target))
			try:
				fields = ["parsed.subject_dn", "parsed.issuer_dn"]
				for cert in cenCertAPI.search(target, fields=fields):
					report.write("{}\n".format(cert["parsed.subject_dn"]))
					report.write("{}\n\n".format(cert["parsed.issuer_dn"]))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("Error: {}\n".format(e))
		else:
			report.write("\nCensys IPv4 results for {}:\n\n".format(target))
			try:
				for i in cenAddAPI.search(target):
					for prot in i["protocols"]:
						report.write("{}\n".format(prot))
			except Exception as e:
				print(red("[!] Error: {}".format(e)))
				report.write("[!] Error: {}".format(e))


def googleFu(client, target):
	"""Use Google to find pages with login forms and "index of" pages
	"""
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
