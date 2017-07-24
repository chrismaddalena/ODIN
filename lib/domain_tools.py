#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import shodan
from cymon import Cymon
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
	# Sleep time for Google and Shodan
	sleep = 10
	# Cymon.io API endpoint
	cymon_api = "https://cymon.io/api/nexus/v1"

	def __init__(self):
		"""Everything that should be initiated with a new object goes here."""
		# Collect the API keys from the config file
		try:
			SHODAN_API_KEY = helpers.config_section_map("Shodan")["api_key"]
			self.shoAPI = shodan.Shodan(SHODAN_API_KEY)
		except Exception as e:
			self.shoAPI = None
			print(yellow("[!] Did not find a Shodan API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			self.CYMON_API_KEY = helpers.config_section_map("Cymon")["api_key"]
			self.cyAPI = Cymon(self.CYMON_API_KEY)
		except Exception as e:
			self.cyAPI = Cymon()
			print(yellow("[!] Did not find a Cymon API key, so proceeding without API auth."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			self.URLVOID_API_KEY = helpers.config_section_map("URLVoid")["api_key"]
		except Exception as e:
			self.URLVOID_API_KEY = None
			print(yellow("[!] Did not find a URLVoid API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
			self.CONTACT_API_KEY = helpers.config_section_map("Full Contact")["api_key"]
		except Exception as e:
			self.CONTACT_API_KEY = None
			print(yellow("[!] Did not find a Full Contact API key."))
			print(yellow("L.. Details: {}".format(e)))

		try:
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
		"""Checks if the provided string is an IP address or not. If
		the check fails, it will be assumed the string is a domain
		in most cases.

		IPy is used to determine if a string is a valid IP address. A True or
		False is returned.
		"""
		try:
			IP(str)
		except ValueError:
			return False
		return True

	def generate_scope(self, scope_file):
		"""Parse scope to expand IP ranges."""
		scope = []
		try:
			with open(scope_file, "r") as preparse:
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
						# Iterate through the range and remove ip_list
						for i in ip_list:
							a = str(i)
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
			print(red("L.. Details: {}".format(e)))

		return scope

	def full_contact_domain(self, domain):
		"""Uses the Full Contact API to collect social media info. This returns
		the FullContact JSON response.

		An API key is required.

		This has not been implemented, mostly because their sales
		team hounded me with some bizarre emails and pitches after
		I got my key.
		"""
		if self.CONTACT_API_KEY is None:
			print(red("[!] No Full Contact API key, so skipping these searches."))
		else:
			base_url = "https://api.fullcontact.com/v2/company/lookup.json"
			payload = {'domain':domain, 'apiKey':self.CONTACT_API_KEY}
			resp = requests.get(base_url, params=payload)

			if resp.status_code == 200:
				return resp.text.encode('ascii', 'ignore')

	def get_dns_record(self, domain, record_type):
		"""Simple function to get the specified DNS record for the
		target domain.
		"""
		answer = dns.resolver.query(domain, record_type)
		return answer

	def run_whois(self, domain):
		"""Perform a whois lookup for the provided target domain.
		The whois results are returned as a dictionary.

		This can fail, usually if the domain is registered through
		a registrar outside of North America.
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
			print(red("[!] The whois lookup for {} failed!").format(domain))
			print(red("L.. Details: {}".format(e)))

	def run_rdap(self, ip_address):
		"""Perform an RDAP lookup for an IP address. An RDAP lookup
		object is returned.

		From IPWhois: IPWhois.lookup_rdap() is now the recommended
		lookup method. RDAP provides a far better data structure than
		legacy whois and REST lookups (previous implementation).
		RDAP queries allow for parsing of contact information and
		details for users, organizations, and groups. RDAP also
		provides more detailed network information.
		"""
		try:
			rdapwho = IPWhois(ip_address)
			results = rdapwho.lookup_rdap(depth=1)

			return results
		except Exception as e:
			print(red("[!] Failed to collect RDAP information for {}!").format(ip_address))
			print(red("L.. Details: {}".format(e)))

	def run_urlcrazy(self, client, target, cymon_api=cymon_api):
		"""Run urlcrazy to locate typosquatted domains related to
		the target domain. The full output is saved to a csv file
		and then domains with A-records are analyzed to see if they
		may be in use for malicious purposes. The domain names and
		IP addresses are checked against Cymon.io's threat feeds.
		If a result is found (200 OK), then the domain or IP has
		been reported to be part of some sort of malicious
		activity relatively recently.

		The function returns a list of domains, A-records, MX-records,
		and the results from Cymon.

		A Cymon API key is recommended, but not required.
		"""
		# Check to see if urlcrazy is available
		try:
			subprocess.call("urlcrazy")
			urlcrazy_present = True
		except OSError as e:
			if e.errno == os.errno.ENOENT:
				# The urlcrazy command was not found
				print(yellow("[!] A test call to urlcrazy failed, so skipping urlcrazy run."))
				print(yellow("L.. Details: {}".format(e)))
				urlcrazy_present = False
			else:
				# Something else went wrong while trying to run urlcrazy
				print(yellow("[!] A test call to urlcrazy failed, so skipping urlcrazy run."))
				print(yellow("L.. Details: {}".format(e)))
				urlcrazy_present = False
			return urlcrazy_present

		if urlcrazy_present:
			outfile = "reports/{}/crazy_temp.csv".format(client)
			final_csv = "reports/{}/{}_urlcrazy.csv".format(client, target)
			domains = []
			a_records = []
			mx_records = []
			squatted = {}
			print(green("[+] Running urlcrazy for {}".format(target)))
			try:
				cmd = "urlcrazy -f csv -o '{}' {}".format(outfile, target)
				with open(os.devnull, "w") as devnull:
					subprocess.check_call(cmd, stdout=devnull, shell=True)
				with open(outfile, "r") as results:
					reader = csv.DictReader(row.replace("\0", "") for row in results)
					for row in reader:
						if len(row) != 0:
							if row['CC-A'] != "?":
								domains.append(row['Typo'])
								a_records.append(row['DNS-A'])
								mx_records.append(row['DNS-MX'])

				squatted = zip(domains, a_records, mx_records)

				session = requests.Session()
				session.headers = {'content-type': 'application/json', 'accept': 'application/json'}
				# Add the Cymon API, if available, to the headers
				if self.CYMON_API_KEY != None:
					session.headers.update({'Authorization': 'Token {0}'.format(self.CYMON_API_KEY)})

				# Search for domains and IP addresses tied to the domain name
				urlcrazy_results = []
				for domain in squatted:
					try:
						r = session.get(cymon_api + "/domain/" + domain[0])
						# results = json.loads(r.text)

						if r.status_code == 200:
							malicious_domain = 1
						else:
							malicious_domain = 0
					except Exception as e:
						malicious_domain = 0
						print(red("[!] There was an error checking {} with Cymon.io!".format(domain[0])))

					# Search for domains and IP addresses tied to the A-record IP
					try:
						r = session.get(cymon_api + "/ip/" + domain[1])
						# results = json.loads(r.text)

						if r.status_code == 200:
							malicious_ip = 1
						else:
							malicious_ip = 0
					except Exception as e:
						malicious_ip = 0
						print(red("[!] There was an error checking {} with Cymon.io!".format(domain[1])))

					if malicious_domain == 1:
						cymon_result = "Yes"
						print(yellow("[*] {} was flagged as malicious, so consider looking into this.".format(domain[0])))
					elif malicious_ip == 1:
						cymon_result = "Yes"
						print(yellow("[*] {} was flagged as malicious, so consider looking into this.".format(domain[1])))
					else:
						cymon_result = "No"

					temp = {}
					temp['domain'] = domain[0]
					temp['a-records'] = domain[1]
					temp['mx-records'] = domain[2]
					temp['malicious'] = cymon_result
					urlcrazy_results.append(temp)

				os.rename(outfile, final_csv)
				print(green("[+] The full urlcrazy results are in {}.".format(final_csv)))
				return urlcrazy_results

			except Exception as e:
				print(red("[!] Execution of urlcrazy failed!"))
				print(red("L.. Details: {}".format(e)))
		else:
			print(yellow("[*] Skipped urlcrazy check."))

	def run_shodan_search(self, target):
		"""Collect information Shodan has for target domain name. This uses
		the Shodan search instead of host lookup and returns the target results
		dictionary from Shodan.

		A Shodan API key is required.
		"""
		if self.shoAPI is None:
			pass
		else:
			print(green("[+] Performing Shodan domain search for {}".format(target)))
			try:
				target_results = self.shoAPI.search(target)
				return target_results
			except shodan.APIError as e:
				print(red("[!] Error fetching Shodan info for {}".format(target)))
				print(red("L.. Details: {}".format(e)))

	def run_shodan_lookup(self, target):
		"""Collect information Shodan has for target IP address. This uses
		the Shodan host lookup instead of search and returns the target results
		dictionary from Shodan.

		A Shodan API key is required.
		"""
		# dns_resolve = "https://api.shodan.io/dns/resolve?hostnames=" + target + "&key=" + SHODAN_API_KEY
	    # resolved = requests.get(dnsResolve)
	    # target_ip = resolved.json()[target]

		if self.shoAPI is None:
			pass
		else:
			print(green("[+] Performing Shodan IP lookup for {}".format(target)))
			try:
				target_results = self.shoAPI.host(target)
				return target_results
			except shodan.APIError as e:
				print(red("[!] Error fetching Shodan info for {}".format(target)))
				print(red("L.. Details: {}".format(e)))

	def run_shodan_exploit_search(self, CVE):
		"""Function to lookup CVEs through Shodan and return the results."""
		exploits = self.shoAPI.exploits.search(CVE)
		return exploits

	def search_cymon_ip(self, target):
		"""Get reputation data from Cymon.io for target IP address. This returns
		two dictionaries for domains and security events.

		An API key is not required, but is recommended.
		"""
		print(green("[+] Checking Cymon for domains associated with the provided IP address."))
		try:
			# Search for IP and domains tied to the IP
			data = self.cyAPI.ip_domains(target)
			domains_results = data['results']
			# Search for security events for the IP
			data = self.cyAPI.ip_events(target)
			ip_results = data['results']
			print(green("[+] Cymon search completed!"))
			return domains_results, ip_results
		except:
			print(red("[!] Cymon.io returned a 404 indicating no results."))

	def search_cymon_domain(self, target):
		"""Get reputation data from Cymon.io for target domain. This returns a
		dictionary for the IP addresses tied to the domain.

		An API key is not required, but is recommended.
		"""
		print(green("[+] Checking Cymon for domains associated with the provided IP address."))
		try:
			# Search for domains and IP addresses tied to the domain
			results = self.cyAPI.domain_lookup(target)
			print(green("[+] Cymon search completed!"))
			return results
		except:
			print(red("[!] Cymon.io returned a 404 indicating no results."))

	def run_censys_search_cert(self, target):
		"""Collect certificate information from Censys for the target domain
		name. This returns a dictionary of certificate information. Censys can
		return a LOT of certificate chain info, so be warned.

		This function uses these fields: parsed.subject_dn and parsed.issuer_dn

		A free API key is required.
		"""
		if self.cenCertAPI is None:
			pass
		else:
			print(green("[+] Performing Censys certificate search for {}".format(target)))
			try:
				fields = ["parsed.subject_dn", "parsed.issuer_dn"]
				certs = self.cenCertAPI.search(target, fields=fields)
				return certs
			except Exception as e:
				print(red("[!] Error collecting Censys certificate data for {}.".format(target)))
				print(red("L.. Details: {}".format(e)))

	def run_censys_search_address(self, target):
		"""Collect open port/protocol information from Censys for the target
		IP address. This returns a dictionary of protocol information.

		A free API key is required.
		"""
		if self.cenAddAPI is None:
			pass
		else:
			print(green("[+] Performing Censys open port search for {}".format(target)))
			try:
				data = self.cenAddAPI.search(target)
				return data
			except Exception as e:
				print(red("[!] Error collecting Censys data for {}.".format(target)))
				print(red("L.. Details: {}".format(e)))

	def run_urlvoid_lookup(self, domain):
		"""Collect reputation data from URLVoid for the target domain. This
		returns an ElementTree object.

		A free API key is required.
		"""
		if not self.is_ip(domain):
			try:
				if self.URLVOID_API_KEY is not None:
					print(green("[+] Checking reputation for {} with URLVoid".format(domain)))
					url = "http://api.urlvoid.com/api1000/{}/host/{}".format(self.URLVOID_API_KEY,domain)
					response = requests.get(url)
					tree = ET.fromstring(response.content)
					return tree
				else:
					print(green("[-] No URLVoid API key, so skipping this test."))
					pass
			except Exception as e:
				print(red("[!] Could not load URLVoid for reputation check!"))
				print(red("L.. Details: {}".format(e)))
		else:
			print(red("[!] Target is not a domain, so skipping URLVoid queries."))

	def run_dns_bruteforce(self, domain):
		"""Uses subbrute library to bruteforce the domain's subdomains and returns
		a list of results.
		"""

		# TODO UNDER CONSTRUCTION

		# subdomains = subbrute.run(domain)

		return subdomains

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
