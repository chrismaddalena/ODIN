#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
- - - - - - - CODENAME - - - - - - -
 :::  === ::: :::====  :::===== :::====
 :::  === ::: :::  === :::      :::  ===
 ===  === === =======  ======   =======
  ======  === ===      ===      === ===
	==    === ===      ======== ===  ===

Developer: Chris Maddalena
"""

import sys
import os
from colors import *
from lib import *
import click

# Create drectory for client reports and report
def setupReports(client):
	if not os.path.exists("reports/{}".format(client)):
		try:
			os.makedirs("reports/{}".format(client))
		except:
			print(red("[!] Could not create reports directory!"))

class AliasedGroup(click.Group):
	"""Allows commands to be called by their first unique character"""

	def get_command(self, ctx, cmd_name):
		"""
		Allows commands to be called by thier first unique character
		:param ctx: Context information from click
		:param cmd_name: Calling command name
		:return:
		"""

		rv = click.Group.get_command(self, ctx, cmd_name)
		if rv is not None:
			return rv
		matches = [x for x in self.list_commands(ctx)
					if x.startswith(cmd_name)]
		if not matches:
			return None
		elif len(matches) == 1:
			return click.Group.get_command(self, ctx, matches[0])
		ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
def viper():
	"""
	Welcome to Viper! To use Viper, select a module you wish to run. Functions are split into modules for flexibility.\n
	Run MODULE --help for more information on a speicifc module.\n
	Warning: Some functions will require running Viper with sudo (e.g. nmap SYN scans)!
	"""
	# Everything starts here
	pass


@viper.command(name='osint', short_help='The full OSINT suite of tools will be run (domain, people, Shodan).')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for Shodan.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)
@click.option('-sF', '--scope-file', type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-s', '--scoped-ips', help='Scoped IP addresses. Can be used instead of a scoping file.', multiple=True)
@click.option('--dns/--no-dns', default=False, help='Set option if you do or do not want to brute force DNS. Defaults to no DNS.')
@click.option('--google/--no-google', default=False, help='Set option if you do or do not want to Google for index pages and admin pages for the domain. Defaults to no Google.')
@click.option('--files/--no-files', default=False, help='Set option if you do or do not want to Google for files on the domain. Defaults to no Google.')
@click.pass_context

def osint(self,client,domain,dns,google,files,scope_file,scoped_ips):
	"""
	The Shadow-Viper intelligence gathering toolkit:\n
	This module runs all OSINT modules together. Viper uses TheHarvester to locate email addresses and social media profiles.
	Profiles are cross-referenced with HaveIBeenPwned, Twitter's API, and LinkedIn.\n
	Viper uses various tools and APIs are used to collect domain/IP information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: Twitter, URLVoid, Cymon, and Shodan
	"""

	asciis.printArt()
	print(green("[+] OSINT Module Selected: Viper will run all recon modules."))
	setupReports(client)
	f = "reports/{}/Domain_Report.txt".format(client)
	report = open(f, 'w')

	email_tools.harvest(client,domain)

	try:
		report.write("### Domain Report for {} ###\n".format(client))
	except Exception  as e:
		print(red("[!] Failed to create new report file!"))
		print(red("[!] Error: {}".format(e)))

	if scope_file:
		scope = domain_tools.genScope(scope_file)
		for i in scope:
			domain_tools.collectDomainInfo(i,report)
			domain_tools.shodanLookUp(i,report)
	else:
		domain_tools.collectDomainInfo(domain,report)
		domain_tools.shodanSearch(domain,report)

	if dns is True:
		print(green("[+] DNS recon was selected: Viper will brute force DNS with Fierce and DNSRecon."))
		if scope_file:
			for ip in scope:
				if not domain_tools.isip(ip):
					domain_tools.dnsRecon(ip,client)
		else:
			domain_tools.dnsRecon(domain,client)
	else:
		print(yellow("[+] DNS recon was NOT selected: Viper skipped DNS brute forcing."))

	if files is True:
		print(green("[+] File discovery was selected: Viper will perform Google searches to find files for the provided domain."))
		file_discovery.discover(client,domain)
	else:
		print(yellow("[+] File discovery was NOT selected: Viper skipped Googling for files."))

	if google is True:
		print(green("[+] Google discovery was selected: Viper will perform Google searches to find admin and index pages."))
		domain_tools.googleFu(client,domain)
	else:
		print(yellow("[+] Google discovery was NOT selected: Viper skipped Googling for admin and index pages."))

	report.close()


@viper.command(name='people',
	short_help='Only email addresses and social media profile recon (email, Twitter, and LinkedIn). Provide an email @domain.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for naming reports.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)

def people(client,domain):
	"""
	This module uses TheHarvester to locate email addresses and social media profiles. Profiles are cross-referenced with
	HaveIBeenPwned, Twitter's API, and LinkedIn.\n
	A Twitter app key is necessary for the Twitter API integration.
	"""

	asciis.printArt()
	print(green("[+] People Module Selected: Viper will run only modules for email addresses and social media."))
	setupReports(client)

	email_tools.harvest(client,domain)


@viper.command(name='domain', short_help='Only domain-related recon will be performed (DNS, Shodan, rep data). Provide a list of IPs and domains.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for Shodan.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)
@click.option('-sF', '--scope-file', type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-s', '--scoped-ips', help='Scoped IP addresses. Can be used instead of a scoping file.', multiple=True)
@click.option('--dns/--no-dns', default=False, help='Set option if you do or do not want to brute force DNS. Defaults to no DNS.')
@click.option('--google/--no-google', default=False, help='Set option if you do or do not want to Google for index pages and admin pages for the domain. Defaults to no Google.')
@click.option('--files/--no-files', default=False, help='Set option if you do or do not want to Google for files on the domain. Defaults to no Google.')

def domain(self,client,domain,dns,google,files,scope_file,scoped_ips):
	"""
	This module uses various tools and APIs to collect information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: URLVoid, Cymon, and Shodan
	"""

	asciis.printArt()
	print(green("[+] Domain Module Selected: Viper will run only domain and IP-related modules."))
	setupReports(client)
	f = "reports/{}/Domain_Report.txt".format(client)
	report = open(f, 'w')

	try:
		report.write("### Domain Report for {} ###\n".format(client))
	except Exception  as e:
		print(red("[!] Failed to create new report file!"))
		print(red("[!] Error: {}".format(e)))

	if scope_file:
		scope = domain_tools.genScope(scope_file)
		for i in scope:
			domain_tools.collectDomainInfo(i,report)
			domain_tools.shodanLookUp(i,report)
	else:
		domain_tools.collectDomainInfo(domain,report)
		domain_tools.shodanSearch(domain,report)

	if dns is True:
		print(green("[+] DNS recon was selected: Viper will brute force DNS with Fierce and DNSRecon."))
		if scope_file:
			for ip in scope:
				if not domain_tools.isip(ip):
					domain_tools.dnsRecon(ip,client)
		else:
			domain_tools.dnsRecon(domain,client)
	else:
		print(yellow("[+] DNS recon was NOT selected: Viper skipped DNS brute forcing."))

	if files is True:
		print(green("[+] File discovery was selected: Viper will perform Google searches to find files for the provided domain."))
		file_discovery.discover(client,domain)
	else:
		print(yellow("[+] File discovery was NOT selected: Viper skipped Googling for files."))

	if google is True:
		print(green("[+] Google discovery was selected: Viper will perform Google searches to find admin and index pages."))
		domain_tools.googleFu(client,domain)
	else:
		print(yellow("[+] Google discovery was NOT selected: Viper skipped Googling for admin and index pages."))

	report.close()


@viper.command(name='shodan', short_help='Look-up IPs and domains on Shodan using the Shodan API and your API key.')
@click.option('-sF', '--scope-file', help='Name fo the file with your IP addresses.', type = click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-s', '--scope-ips', help='Scoped IP addresses. Can be used instead of a scoping file.', multiple=True)
@click.option('-o', '--output', default='Shodan_Report.txt', help='Name of the output file for the information.')

def shodan(scope_file,scope_ips,output):
	"""
	The Range-Viper network data toolkit:\n
	Look-up information on IP addresses using Shodan's API and your API key.\n
	You must have a Shodan API key!
	"""

	report = open(output, 'w')

	asciis.printArt()
	print(green("[+] Shodan Module Selected: Viper will check Shodan for the provided domains and IPs."))
	if scope_ips == () and scope_file is None:
		print(red("[!] No targets provided! Use -s or -sF"))
	if scope_file:
		scope = domain_tools.genScope(scope_file)
		for i in scope:
			report.write("---SHODAN RESULTS for {}---\n".format(i))
			domain_tools.shodanSearch(i,report)

	if scope_ips:
		for ip in scope_ips:
			report.write("---SHODAN RESULTS for {}---\n".format(ip))
			domain_tools.shodanSearch(ip,report)

	report.close()


@viper.command(name='scan', short_help='Scan IPs and domains using nmap or MassScan - This is noisy!')
@click.option('-iF', '--infile', help='Name fo the file with your IP addresses.',type = click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-oF', '--outfile', help='Name of the output file for the results.')

def scan():
	"""
	Viper has shortcuts for many of the popular scanners. Select a scanner, provide a text file with IPs, and Viper will take care of the rest.
	You can run full nmap SYN scans, the same with common scripts, or Masscan with full ports.
	For custom Masscan scans, edit Viper's masscan.config file.\n
	SYN scans require sudo! Start Viper with sudo if you want to use them.
	"""

	asciis.printArt()
	setupReports(client)

	# 1. Full port nmap SYN scan (-sSV -T4 -p-)
	scanType = 1
	scan_tools.runNMAP(scanType)

	# 2. Default 1000 port nmap SYN scan (-sSV -T4)
	scanType = 2
	scan_tools.runNMAP(scanType)

	# 3. Full port masscan (-p0-65535)
	scanType = 1
	scan_tools.runMasscan(1)

	# 4. Masscan with conf file (-c)
	scanType = 2
	scan_tools.runMasscan(2)

@viper.command(name='verify', short_help='Verify an external pen test scope. This returns a csv file with SSL cert, whois, and other data for verification.')
@click.option('-iF', '--infile', type = click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-oF', '--outfile', help='Scoped IP addresses. Can be used instead of a scoping file.')
@click.option('-c', '--cidr', default=False, help='Set to True to not run DNS checks (faster).')

def verify(infile, outfile, cidr):
	"""
	This module will use reverse DNS, ARIN, and SSL certificate information to try to verify testing scope.
	"""
	print(green("""
Viper will attempt to verify ownership of the provided IP addresses (single or CIDR ranges) using various tools: ARIN, whois, DNS, and SSL cert informaiton.
Please provide a list of IPs in a text file and Viper will output a CSV of results.
	"""))
	# initialize our array for IP address storage
	ips = []
	# initialize our dict for info storage
	out = {}

	try:
		if CIDR == "y":
			breakrange = True
		else:
			breakrange = False
		verify.infile(infile, ips, breakrange)
		verify.who(ips, out)
		verify.outfile(out, outfile)
	except Exception as e:
		print(red("[!] Verification failed!"))
		print(red("[!] Error: %s" % e))

@viper.command(name='knowing', short_help='Saturday Morning Cartoons are a thing I miss.')

def knowing():
	print(red("G.") + "I." + blue(" Jooooe!"))


if __name__ == "__main__":
	viper()



		#The Pit-Viper penetration testing toolkit
		#Some of these scans require running Viper with sudo!
		#nmap stuff

		#SSLLabs
		#target = raw_input("Enter full target URL for scan (e.g. www.google.com): ")
		#ssllabsscanner.getResults(target,testType)
		#target = raw_input("Enter full target URL for scan (e.g. www.google.com): ")
		#ssllabsscanner.getResults(target,testType)
		# host = raw_input("Enter IP or hostname to check: ")
		# scan_tools.checkSSL(host)

		#Ninja-Viper reporting toolkit
		# 			print(green("""
		# Viper can join multiple .nessus files into one report.
		#
		# 	1. Place your files into the same directory.
		# 	2. Provide the directory and the first .nessus file.
		# 	3. Provide name for the final .nessus file and report title.
		# 			""")
		#
		# 			dir = raw_input("Directory with Nessus files: ")
		# 			#first = raw_input("First Nessus file: ")
		# 			output = raw_input("Name for final Nessus file: ")
		# 			name = raw_input("Name for final report: ")
		# 			joinessus.joiner(dir,output,name)


		#The Swamp-Viper phishing toolkit:
		# file = raw_input("Enter name of file with the names: ")
		# phish_tools.parseName(file)

		# # Randomize the list of targets
		# elif option == "2":
		# 	file = raw_input("Enter the location of file of targets: ")
		# 	output = raw_input("Enter a name for the output file (txt): ")
		# 	try:
		# 		print(green ("[+] Attempting to read %s" % file))
		# 		with open (file, 'r') as file:
		# 			names = file.readlines()
		# 		with open(output, "w") as file:
		# 			temp = []
		# 			temp = phish_tools.randomList(names)
		# 			file.write(''.join(str(i) for i in temp))
		# 		print(green("[+] Successfully created a random list of targets written to %s" % output))
		# 		phishingMenu()
		# 	except Exception as e:
		# 		print(red("[!] Failed to open the file!"))
		# 		print(red("[!] Error: %s" % e))
		# 		phishingMenu()
