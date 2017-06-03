#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
import censys.certificates
import censys.ipv4
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import requests
from xml.etree import ElementTree  as ET
import time
from colors import *
import socket
from IPy import IP
from netaddr import *
import dns.resolver
import csv
from lib import helpers


class Domain_Check(object):
	"""A class containing the tools for performing OSINT against IP addresses
	and domain names.
	"""
	# Google-friendly user-agent
	my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'}
	# Sleep time for Google
	sleep = 10
	# Cymon.io API endpoint
	cymon_api = "https://cymon.io/api/nexus/v1"

	def __init__(self):
		"""Everything that should be intiiated with a new Domain_Check object goes here."""
		try:
			# Try to get the user's Shodan API key
			SHODAN_API_KEY = helpers.config_section_map("Shodan")["api_key"]
			self.shoAPI = shodan.Shodan(SHODAN_API_KEY)
		except Exception as e:
			self.shoAPI = None
			print(yellow("[!] Did not find a Shodan API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			# Try to get the user's Cymon API key
			self.CYMON_API_KEY = helpers.config_section_map("Cymon")["api_key"]
		except Exception as e:
			print(yellow("[!] Did not find a Cymon API key, so proceeding without API auth."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			# Try to get the user's URLVoid API key
			self.URLVOID_API_KEY = helpers.config_section_map("URLVoid")["api_key"]
		except Exception as e:
			self.URLVOID_API_KEY = None
			print(yellow("[!] Did not find a URLVoid API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			# Try to get the user's Full Contact API key
			self.CONTACT_API_KEY = helpers.config_section_map("Full Contact")["api_key"]
		except Exception as e:
			self.CONTACT_API_KEY = None
			print(yellow("[!] Did not find a Full Contact API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			# Try to get the user's Censys API key
			CENSYS_API_ID = helpers.config_section_map("Censys")["api_id"]
			CENSYS_API_SECRET = helpers.config_section_map("Censys")["api_secret"]
			self.cenCertAPI = censys.certificates.CensysCertificates(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
			self.cenAddAPI = censys.ipv4.CensysIPv4(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
		except Exception as e:
			self.cenCertAPI = None
			self.cenAddAPI = None
			print(yellow("[!] Did not find a Censys API ID/secret."))
			print(yellow("L.. Details: {}".format(e)))

	def is_ip(self, str):
		"""Checks if the provided string is an IP address or not. If the check
		fails, it will be assumed the string is a domain in most cases.

		IPy is used to determine if a string is a valid IP address. A True or
		False is returned.
		"""
		try:
			IP(str)
		except ValueError:
			return False
		return True

	def full_contact_domain(self, domain, report):
		"""Uses the Full Contact API to collect social media info.

		An API key is required.

		This has not been implemented, mostly because their sales team hounded
		me with some bizarre emails and pitches after I got my key.
		"""
		if self.CONTACT_API_KEY is None:
			print(red("[!] No Full Contact API key, so skipping these searches."))
		else:
			base_url = 'https://api.fullcontact.com/v2/company/lookup.json'
			payload = {'domain':domain, 'apiKey':self.CONTACT_API_KEY}
			resp = requests.get(base_url, params=payload)

			if resp.status_code == 200:
				print(resp.text.encode('ascii', 'ignore'))

	def get_dns_record(self, domain, record_type):
		"""Simple function to get the specified DNS record for the target domain."""
		answer = dns.resolver.query(domain, record_type)
		return answer

	def run_whois(self, domain):
		"""Perform a whois lookup for the provided target domain. The whois
		results are returned as a dictionary.
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
			print(red("L.. Details: {}".format(e)))

	def run_rdap(self, ip_address):
		"""Perform an RDAP lookup for an IP address. An RDAP lookup object is
		returned.

		From IPWhois: IPWhois.lookup_rdap() is now the recommended lookup method.
		RDAP provides a far better data structure than legacy whois and REST lookups
		(previous implementation). RDAP queries allow for parsing of contact information
		and details for users, organizations, and groups. RDAP also provides more
		detailed network information.
		"""
		try:
			rdapwho = IPWhois(ip_address)
			results = rdapwho.lookup_rdap(depth=1)
			return results
		except Exception as e:
			print(red("[!] Failed to collect RDAP information for {}!").format(ip_address))
			print(red("L.. Details: {}".format(e)))

	def run_urlcrazy(self, client, target, cymon_api=cymon_api):
		"""Run urlcrazy to locate typosquatted domains related to the target domain.
		The full output is saved to a csv file and then domains with A-records
		are analyzed to see if they may be in use for malicious purposes.
		The domain names and IP addresses are checked against Cymon.io's threat
		feeds. If a result is found (200 OK), then the domain or IP has been
		reported to be part of some sort of malicious activity relatively recently.

		A Cymon API key is recommended, but not required.
		"""
		f = "reports/{}/Typosquatting_Report - {}.csv".format(client, target)
		outfile = "reports/{}/crazy_temp.csv".format(client)
		final_csv = "reports/{}/{}_urlcrazy.csv".format(client, target)
		domains = []
		a_records = []
		mx_records = []
		squatted = {}
		print(green("[+] Running urlcrazy for {}".format(target)))
		with open(f, 'w') as report:
			csv_writer = csv.writer(report, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
			try:
				cmd = "urlcrazy -f csv -o '{}' {}".format(outfile, target)
				with open(os.devnull, "w") as devnull:
					subprocess.check_call(cmd, stdout=devnull, shell=True)
				with open(outfile, 'r') as results:
					reader = csv.DictReader(row.replace('\0', '') for row in results)
					for row in reader:
						if len(row) != 0:
							if row['CC-A'] != "?":
								domains.append(row['Typo'])
								a_records.append(row['DNS-A'])
								mx_records.append(row['DNS-MX'])

				squatted = zip(domains, a_records, mx_records)

				csv_writer.writerow(["Domain", "DNS-A", "DNS-MX", "Malicious?"])

				session = requests.Session()
				session.headers = {'content-type': 'application/json', 'accept': 'application/json'}

				if self.CYMON_API_KEY != None:
					session.headers.update({'Authorization': 'Token {0}'.format(self.CYMON_API_KEY)})

				# Search for domains and IP addresses tied to the domain name
				for d in squatted:
					try:
						r = session.get(cymon_api + "/domain/" + d[0])
						# results = json.loads(r.text)

						if r.status_code == 200:
							malicious_domain = 1
						else:
							malicious_domain = 0
					except Exception as e:
						malicious_domain = 0
						print(red("[!] There was an error checking {} with Cymon.io!".format(d[0])))

					# Search for domains and IP addresses tied to the A-record IP
					try:
						r = session.get(cymon_api + "/ip/" + d[1])
						# results = json.loads(r.text)

						if r.status_code == 200:
							malicious_ip = 1
						else:
							malicious_ip = 0
					except Exception as e:
						malicious_ip = 0
						print(red("[!] There was an error checking {} with Cymon.io!".format(d[1])))

					if malicious_domain == 1:
						cymon_result = "Yes"
						print(yellow("[*] {} was flagged as malicious, so consider looking into this.".format(d[0])))
					elif malicious_ip == 1:
						cymon_result = "Yes"
						print(yellow("[*] {} was flagged as malicious, so consider looking into this.".format(d[1])))
					else:
						cymon_result = "No"

					csv_writer.writerow([d[0], d[1], d[2], cymon_result])

				os.rename(outfile, final_csv)
				print(green("[+] The full urlcrazy results are in {}.".format(final_csv)))
				print(green("L.. The typosquatting report has been saved as {}.".format(f)))
			except Exception as e:
				print(red("[!] Execution of urlcrazy failed!"))
				print(red("L.. Details: {}".format(e)))
				csv_writer.writerow(["Execution of urlcrazy failed!"])
				csv_writer.writerow(["L.. Details: {}".format(e)])

	def collect_domain_info(self, domain, report, verbose):
		"""Collect various domain information (whois, DNS, RDAP) for the target
		domain. This executes several other functions for Shodan and Censys
		lookups.
		"""
		try:
			domain_name = domain
			domain_ip = socket.gethostbyname(domain)
			report.write("\n---Info for {}---\n".format(domain))
			# If entry is a domain, then run whois and try to get the IP address
			# Note: IP may return different results because domain may resolve to a load balancer, DDoS service, etc.
			if not self.is_ip(domain):
				print(green("[+] {} is not a valid IP, so it is (probably) a domain name. Running whois and using associated IP address for RDAP.".format(domain)))
				# Collect DNS records using PyDNS
				print(green("[+] Collecting DNS records for {}".format(domain)))
				report.write("DNS Records for {}\n".format(domain))
				report.write("MX Records:\n")
				try:
					mx_records = self.get_dns_record(domain, "MX")
					for i in mx_records:
						report.write("{}\n".format(i))
				except:
					report.write("No MX records found\n")

				report.write("\nNS Records:\n")
				try:
					ns_records = self.get_dns_record(domain, "NS")
					for i in ns_records:
						report.write("{}\n".format(i))
				except:
					report.write("No NS records found... what?\n")

				report.write("\nSOA Records:\n")
				try:
					soa_records = self.get_dns_record(domain, "SOA")
					for i in soa_records:
						report.write("{}\n".format(i))
				except:
					report.write("No SOA records found\n")

				report.write("\nTXT Records:\n")
				try:
					txt_records = self.get_dns_record(domain, "TXT")
					for i in txt_records:
						report.write("{}\n".format(i))
				except:
					report.write("No TXT records found\n")

				report.write("\nA Records:\n")
				try:
					a_records = self.get_dns_record(domain, "A")
					for i in a_records:
						report.write("{}\n".format(i))
				except:
					report.write("No MX records found\n")

				# Run whois lookup
				print(green("[+] Running whois for {}".format(domain)))
				results = self.run_whois(domain)

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
			results = self.run_rdap(domain_ip)

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

		self.run_shodan_search(domain_name, report)
		self.run_censys_search(domain_name, report, verbose)
		# If the name and IP are the same, then we have an IP and don't want to search twice
		if domain_name == domain_ip:
			print(green("[!] Skipping, check worked"))
		else:
			self.run_shodan_search(domain_ip, report)
			self.run_censys_search(domain_ip, report, verbose)

	def run_urlvoid_lookup(self, domain, report):
		"""Collect reputation data from URLVoid for target domain.

		A free API key is required.
		"""
		if not self.is_ip(domain):
			try:
				if self.URLVOID_API_KEY is not None:
					print(green("[+] Checking reputation with URLVoid"))
					report.write("\n---URLVOID Results---\n")
					url = "http://api.urlvoid.com/api1000/{}/host/{}".format(URLVOID_API_KEY,domain)
					response = requests.get(url)
					tree = ET.fromstring(response.content)

					for child in tree:
						malicious_check = child.tag
						if malicious_check == "detections":
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
				print(red("L.. Details: {}".format(e)))
		else:
			print(red("[!] Target is not a domain, so skipping URLVoid queries."))

	def search_cymon(self, target, report):
		"""Get reputation data for target from Cymon.io.

		An API key is not required, but is reocmmended.
		"""
		print(green("[+] Checking Cymon for domains associated with the provided list of IPs."))
		try:
			if self.is_ip(target):
				# Search for IP and domains tied to the IP
				data = self.cyAPI.ip_domains(target)
				results = data['results']
				report.write("\n--- The following data is for IP: {}---\n".format(target))
				for result in results:
					report.write("\nURL: %s\n" % result['name'])
					report.write("Created: %s\n" % result['created'])
					report.write("Updated: %s\n" % result['updated'])
				# Search for security events for the IP
				data = self.cyAPI.ip_events(target)
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
				results = self.cyAPI.domain_lookup(target)
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

	def run_shodan_search(self, target, report):
		"""Collect information Shodan has for target IP or domain name.

		An API key is required.
		"""
		if self.shoAPI is None:
			pass
		else:
			# If the target is an IP, use 'host' lookup, else use 'search'
			if not self.is_ip(target):
				print(green("[+] Performing Shodan search for {}".format(target)))
				try:
					targetResults = self.shoAPI.search(target)
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
					host = self.shoAPI.host(target)
				except shodan.APIError as e:
					print(red("[!] Error: {}".format(e)))
					report.write("[!] Error: {}".format(e))
				try:
					report.write("Shodan results found for {}:\n\n".format(target))
					report.write("IP: {}\n".format(host['ip_str']))
					report.write("OS: {}\n".format(host.get('os', 'n/a')))
					report.write("Organization: {}\n".format(host.get('org', 'n/a')))
					report.write("OS: {}\n".format(host.get('os', 'n/a')))
					# Collect the banners
					for item in host['data']:
						report.write("Port: {}\n".format(item['port']))
						report.write("Banner: {}\n".format(item['data']))
					# Check for any vulns Shodan knows about
					for item in host["vulns"]:
						CVE = item.replace("!", "")
						report.write("Vulns: {}\n".format(CVE))
						exploits = self.shoAPI.exploits.search(CVE)
						for item in exploits["matches"]:
							if item.get("cve")[0] == CVE:
								report.write("L.. {}\n".format(item.get("description")))
				except Exception as e:
					print(red("[!] Error: {}".format(e)))
					report.write("Error: {}\n".format(e))

	def run_censys_search(self, target, report, verbose):
		"""Collect information Censys has for target IP or domain name.

		A free API key is required.
		"""
		if self.cenCertAPI is None:
			pass
		else:
			print(green("[+] Performing Censys search for {}".format(target)))
			# Censys can return a LOT of certificate chain info, so it's collected
			# only when verbose mode is enabled
			if not self.is_ip(target) and verbose:
				print(yellow("[*] Verbose mode enabled, so returning certificate data from Censys."))
				report.write("Censys certificate results for {}:\n\n".format(target))
				try:
					fields = ["parsed.subject_dn", "parsed.issuer_dn"]
					for cert in self.cenCertAPI.search(target, fields=fields):
						report.write("{}\n".format(cert["parsed.subject_dn"]))
						report.write("{}\n\n".format(cert["parsed.issuer_dn"]))
				except Exception as e:
					print(red("[!] Error: {}".format(e)))
					report.write("Error: {}\n".format(e))
			else:
				report.write("\nCensys IPv4 results for {}:\n\n".format(target))
				try:
					for i in self.cenAddAPI.search(target):
						for prot in i["protocols"]:
							report.write("{}\n".format(prot))
				except Exception as e:
					print(red("[!] Error: {}".format(e)))
					report.write("[!] Error: {}".format(e))

	def run_dnsrecon(self, target, client, brute):
		"""Run additional DNS information collection using DNSRecon."""
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

	def generate_scope(self, scope_file):
		"""Parse scope to expand IP ranges."""
		scope = []
		try:
			with open(scope_file, 'r') as preparse:
				for i in preparse:
					# Check if there is a hyphen
					# Ex: 192.168.1.1-50 will become 192.168.1.1,192.168.1.50
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
					# Check if range has an underscore
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

	def search_google(self, client, target):
		"""Use Google to find pages with login forms and 'index of' pages."""
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
