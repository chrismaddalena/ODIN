#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 :::====     :::====     :::    :::= ===
 :::  ===    :::  ===    :::    :::=====
 ===  ===    ===  ===    ===    ========
 ===  ===    ===  ===    ===    === ====
  ======  :: =======  :: === :: ===  === ::

Developer:   Chris Maddalena
Description: Observation, Detection, and Investigation of Networks
			 O.D.I.N. is an evolution of Codename:Viper. As with any project that
			 uses a codename, it must eventually get a real name and evolve.
			 O.D.I.N. was designed to assist with OSINT automation for penetration
			 testing clients and their networks, both the types with IP address
			 and social. Provide a client's name, IPs, and domain(s) to gather
			 information from sources like whois, DNS, and Shodan.

			 O.D.I.N. is made possible through the help, input, and work provided by others.
			 Ninjasl0th - Creator of the original scope verification script and all around cool dude!
			 GRC_Ninja - For providing great feedback regarding HTTP requests and RDAP.
			 My teammates who use my code, graciously provide feedback, and are so patient with bugs.

			 And to these folks who have maintained and offered some of the tools used by O.D.I.N.:

			 Laramies - Creator of the awesome TheHarvester (https://github.com/laramies/theHarvester).
			 TrullJ - For making the slick SSL Labs Scanner module (https://github.com/TrullJ/ssllabs).
			 Altjx - Creator of the original Python version of FOCA, pyfoca.py (https://github.com/altjx/ipwn/blob/master/pyfoca.py).
"""

import os
from colors import *	# Enable pretty colors in the terminal
from lib import *		# Import the custom ODIN modules
import click			# Command Line Interface Creation Kit
import time				# Just for determining the current time


# Create a directory for the client reports
def setup_reports(client):
	if not os.path.exists("reports/{}".format(client)):
		try:
			os.makedirs("reports/{}".format(client))
		except:
			print(red("[!] Could not create reports directory!"))


# Setup a class for CLICK
class AliasedGroup(click.Group):
	"""Allows commands to be called by their first unique character."""

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
def odin():
	"""
	:::====     :::====     :::    :::= ===\n
	:::  ===    :::  ===    :::    :::=====\n
	===  ===    ===  ===    ===    ========\n
	===  ===    ===  ===    ===    === ====\n
	 ======  :: =======  :: === :: ===  === ::\n
	Welcome to O.D.I.N.! To use O.D.I.N., select a module you wish to run. Functions are split into modules for flexibility.\n
	Run 'odin.py <MODULE> --help' for more information on a specific module.\n
	"""
	# Everything starts here
	pass


# The OSINT module -- hit it with everything
@odin.command(name='osint', short_help='The full OSINT suite of tools will be run (domain, people, Shodan).')
@click.option('-c', '--client', help='The target client, such as "ABC Company," to use for report titles.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, resolve_path=True), help='A text file containing your in-scope IP addresses and domain names. List each one on a new line.')
@click.option('--dns', is_flag=True, help='Use this flag if you want to run DNSRecon and Fierce.')
@click.option('--google', is_flag=True, help='Use this flag if you want to Google for index pages and admin pages for the domain.')
@click.option('--files', is_flag=True, help='Use this flag if you want to Google for files on the domain.')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output for more domain information. Warning: this can be more than you might need.')
@click.option('-b', '--brute', is_flag=True, help='With brute enabled with --dns, O.D.I.N. will use DNSRecon/Fierce to brute force DNS.')
@click.pass_context

def osint(self, client, domain, dns, google, files, scope_file, verbose, brute):
	"""
	The full O.D.I.N. toolkit:\n
	This module runs all OSINT modules together. O.D.I.N. uses TheHarvester to locate email addresses and social media profiles.
	Profiles are cross-referenced with HaveIBeenPwned, Twitter's API, and LinkedIn.\n
	O.D.I.N. uses various tools and APIs to collect domain/IP information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: Twitter, URLVoid, Cymon, and Shodan.
	"""
	asciis.print_art()
	setup_reports(client)
	print(green("[+] OSINT Module Selected: O.D.I.N. will run all recon modules."))

	f = "reports/{}/Domain_Report.txt".format(client)
	report = open(f, 'w')

	# csv_writer = csv.writer(report, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

	email_tools.harvest(client, domain)
	domain_tools.run_urlcrazy(client, domain)

	try:
		report.write("### Domain Report for {} ###\n".format(client))
	except Exception  as e:
		print(red("[!] Failed to create new report file!"))
		print(red("L.. Details: {}".format(e)))

	if scope_file:
		scope = domain_tools.generate_scope(scope_file)
		# Just in case you forget the domain in your scope file, it's added here
		scope.append(domain)
		for i in scope:
			domain_tools.collect_domain_info(i, report, verbose)
	else:
		domain_tools.collect_domain_info(domain, report, verbose)

	if dns:
		print(green("[+] DNS recon was enabled: O.D.I.N. will perform DNS enumeration with Fierce and DNSRecon."))
		if scope_file:
			for ip in scope:
				if not domain_tools.isip(ip):
					domain_tools.run_dnsrecon(ip, client, brute)
		else:
			domain_tools.run_dnsrecon(domain, client, brute)
	else:
		print(yellow("[+] DNS recon was not enabled: DNS enumeration was skipped."))

	if files:
		print(green("[+] File discovery was enabled: O.D.I.N. will perform Google searches to find files for the provided domain."))
		file_discovery.discover(client, domain)
	else:
		print(yellow("[+] File discovery was not enabled: O.D.I.N. skipped Googling for files."))

	if google:
		print(green("[+] Google discovery was enabled: O.D.I.N. will perform Google searches to find admin and index pages."))
		domain_tools.googleFu(client, domain)
	else:
		print(yellow("[+] Google discovery was not enabled: O.D.I.N. skipped Googling for admin and index pages."))

	report.close()


# The PEOPLE module -- Primarily TheHarvester with some Twitter and LinkedIn sprinkled in
@odin.command(name='people',
	short_help='Only email addresses and social media profile recon (email, Twitter, and LinkedIn). Provide an email @domain.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for naming reports.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)

def people(client,domain):
	"""
	The People module:
	Uses TheHarvester to locate email addresses and social media profiles. Profiles are cross-referenced with
	HaveIBeenPwned, Twitter's API, and LinkedIn.\n
	A Twitter app key is necessary for the Twitter API integration.
	"""
	asciis.print_art()
	print(green("[+] People Module Selected: O.D.I.N. will run only modules for email addresses and social media."))
	setup_reports(client)

	email_tools.harvest(client, domain)


# The DOMAIN module -- Forget social and focus on IPs and domain names
@odin.command(name='domain', short_help='Only domain-related recon will be performed (DNS, Shodan, rep data). Provide a list of IPs and domains.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for report titles.', required=True)
@click.option('-d', '--domain', help='The email domain, such as example.com. Do not include @.', required=True)
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('--dns', is_flag=True, help='Set option if you do or do not want to brute force DNS. Defaults to no DNS.')
@click.option('--google', is_flag=True, help='Set option if you do or do not want to Google for index pages and admin pages for the domain. Defaults to no Google.')
@click.option('--files', is_flag=True, help='Set option if you do or do not want to Google for files on the domain. Defaults to no Google.')
@click.option('-v', '--verbose', is_flag=True, help='With verbose enabled, more domain information is collected.')
@click.option('-b', '--brute', is_flag=True, help='With brute enabled, O.D.I.N. will use DNSRecon/Fierce to brute force DNS.')

def domain(client, domain, dns, google, files, scope_file, verbose, brute):
	"""
	The Domain module uses various tools and APIs to collect information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: URLVoid, Cymon, and Shodan
	"""
	asciis.print_art()
	setup_reports(client)
	print(green("[+] Domain Module Selected: O.D.I.N. will run only domain and IP-related modules."))

	f = "reports/{}/Domain_Report.csv".format(client)
	report = open(f, 'w')

	domain_checker = domain_tools.Domain_Check()
	#domain_checker.run_urlcrazy(client, domain)

	try:
		report.write("### Domain Report for {} ###\n".format(client))
	except Exception  as e:
		print(red("[!] Failed to create new report file!"))
		print(red("L.. Details: {}".format(e)))

	if scope_file:
		scope = domain_tools.generate_scope(scope_file)
		# Just in case you forget the domain in your scope file, it's added here
		scope.append(domain)
		for i in scope:
			domain_checker.collect_domain_info(i, report, verbose)
	else:
		domain_checker.collect_domain_info(domain, report, verbose)

	if dns:
		print(green("[+] DNS recon was selected: O.D.I.N. will brute force DNS with Fierce and DNSRecon."))
		if scope_file:
			for ip in scope:
				if not domain_checker.isip(ip):
					domain_checker.run_dnsrecon(ip, client, brute)
		else:
			domain_checker.run_dnsrecon(domain, client, brute)
	else:
		print(yellow("[+] DNS recon was NOT selected: O.D.I.N. skipped DNS brute forcing."))

	if files:
		print(green("[+] File discovery was selected: O.D.I.N. will perform Google searches to find files for the provided domain."))
		file_discovery.discover(client, domain)
	else:
		print(yellow("[+] File discovery was NOT selected: O.D.I.N. skipped Googling for files."))

	if google:
		print(green("[+] Google discovery was selected: O.D.I.N. will perform Google searches to find admin and index pages."))
		domain_checker.googleFu(client, domain)
	else:
		print(yellow("[+] Google discovery was NOT selected: O.D.I.N. skipped Googling for admin and index pages."))

	report.close()


# The SHODAN module -- Perform Shodan searches only
@odin.command(name='shodan', short_help='Look-up IPs and domains on Shodan using the Shodan API and your API key.')
@click.option('-sf', '--scope-file', help='Name fo the file with your IP addresses.', type = click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-s', '--scope-ips', help='Provide individual IP addresses. Multiple IPs can be provided and this can be used instead of a scoping file. (Ex: -s IP -s IP -s IP)', multiple=True)
@click.option('-o', '--output', default='Shodan_Report.txt', help='Name of the output file for the information.')

def shodan(scope_file, scope_ips, output):
	"""
	The Shodan module:\n
	Look-up information on IP addresses using Shodan's API and your API key.\n
	You must have a Shodan API key!
	"""
	report = open(output, 'w')

	asciis.print_art()
	print(green("[+] Shodan Module Selected: O.D.I.N. will check Shodan for the provided domains and IPs."))
	if scope_ips == () and scope_file is None:
		print(red("[!] No targets provided! Use -s or -sf"))
	try:
		report.write("---SHODAN Results as of {}---\n\n".format(time.strftime("%m/%d/%Y")))
		if scope_file:
			scope = domain_tools.genScope(scope_file)
			for i in scope:
				report.write("---Shodan shows this for {}---\n".format(i))
				domain_tools.run_shodan_search(i, report)

		if scope_ips:
			for i in scope_ips:
				report.write("---Shodan shows this for {}---\n".format(i))
				domain_tools.run_shodan_search(i, report)
		print(green("[+] The Shodan search has completed!"))
	except Exception as e:
		print(red("[!] The Shodan search could not be completed!"))
		print(red("L.. Details: {}").format(e))

	report.close()


# The VERIFY module -- No OSINT, just a way to check a scope list of IPs and domain names
@odin.command(name='verify', short_help='Verify an external pen test scope. This returns a csv file with SSL cert, whois, and other data for verification.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used for report titles.', required=True)
@click.option('-sf', '--scope-file', help='Name fo the file with your IP addresses.', type = click.Path(exists=True, readable=True, resolve_path=True), required=True)
#@click.option('-s', '--scope-ips', help='Scoped IP addresses. Can be used instead of a scoping file.', multiple=True)
@click.option('-o', '--output', default='Verification.csv', help='Output file (CSV) for the findings.')
@click.option('--cidr', is_flag=True, help='Use if the scoped IPs include any CIDRs.')

def verify(scope_file, output, cidr, client):
	"""
	The Verify module:
	Uses reverse DNS, ARIN, and SSL certificate information to try to verify testing scope.
	"""
	asciis.print_art()
	print(green("[+] Scope Verification Module Selected: O.D.I.N. will attempt to verify who owns the provided IP addresses."))
	setup_reports(client)
	report = "reports/{}/{}".format(client, output)

	# initialize our array for IP address storage
	ips = []
	# initialize our dict for info storage
	out = {}

	try:
		verification.infile(scope_file, ips, cidr)
		verification.who(ips, out)
		verification.outfile(out, report)
	except Exception as e:
		print(red("[!] Verification failed!"))
		print(red("L.. Details: {}".format(e)))


# The REP module -- Check a target's reputation against Cymon and URLVoid records
@odin.command(name='rep', short_help='Check reputation of provided IP or domain.')
@click.option('-t', '--target', help='The target IP address or domain.', required=True)
@click.option('-o', '--output', default='Reputation_Report.txt', help='Name of the output file for the search results.')

def rep(target, output):
	"""
	The Rep module:
	Can be used to quickly collect reputation data for the provided IP address. O.D.I.N. will query URLVoid and eSentire's Cymon.\n
	API keys for URLVoid and Cymon are required!
	"""
	report = open(output, 'w')

	asciis.print_art()
	print(green("[+] Reputation Module Selected: O.D.I.N. will reputation data for the provided IP address or domain name."))
	domain_tools.search_cymon(target, report)
	domain_tools.run_urlvoid_lookup(target, report)


# TODO: CHOPPING BLOCK
# The SSL module -- Run SSLLabs' scanner against the target domain
@odin.command(name='ssl', short_help='Check SSL cert for provided IP or domain.')
@click.option('-t', '--target', help='IP address with the certificate. Include the port if it is not 443, e.g. IP:8080', required=True)
@click.option('--labs', is_flag=True, help='Query Qualys SSL Labs in addition to pulling the certificate.')

def ssl(target, labs):
	"""
	This module can be used to quickly pull an SSL certificate's information for easy reference.
	It can also be used to run an SSLLabs scan on the target (coming soon).
	"""
	asciis.print_art()
	print(green("[+] SSL Module Selected: O.D.I.N. will pull SSL certificate information for the provided IP and port."))
	scan_tools.checkSSL(target)
	if labs:
		ssllabsscanner.get_results(target, 1)


# The SCAN module -- Run an nmap scan with some additional processing
@odin.command(name='scan', short_help='Scan IPs and domains using nmap or MassScan - This is noisy!')
@click.option('-sf', '--scope-file', help='Name fo the file with your IP addresses.', type = click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-s', '--scope-ips', help='Scoped IP addresses. Can be used instead of a scoping file.', multiple=True)
@click.option('-o', '--output', default='Scan_Report.csv', help='Name of the CSV output file for the scan results.')
@click.option('-p','--ports', help='The ports to be included in your scan, e.g. 80 or 0-65535', required=True)
@click.option('-a','--args', help='The scan arguments for the selected scanner (e.g. "-sSV -T4 --open"). Do not use -oA for nmap.', required=True)

def scan(ports, args, scope_file, scope_ips, output):
	"""
	The Pit-Viper penetration testing toolkit:\n
	O.D.I.N. can run nmap scans for you. Provide your scope and arguments and O.D.I.N. will take care of the rest.
	O.D.I.N. will flag web ports and output a text file that can be used with tools like EyeWitness for screenshots.
	You can edit the web ports O.D.I.N. looks for by editing ~/Web_Ports.txt.\n
	SYN scans require sudo! Start O.D.I.N. with sudo if you plan to run a SYN scan.
	"""
	report = open(output, 'w')

	asciis.print_art()
	print(green("[+] Scan Module Selected: O.D.I.N. will run your scan against the provided domains and IPs."))
	if scope_ips == () and scope_file is None:
		print(red("[!] No targets provided! Use -s or -sf"))

	if scope_file:
		with open(scope_file, 'r') as scope:
			for i in scope:
				print(green("[+] Running nmap againts {}".format(i.rstrip())))
				scan_tools.run_nmap(i.rstrip(), ports, args, report)

	if scope_ips:
		for ip in scope_ips:
			print(green("[+] Running nmap againts {}".format(ip)))
			scan_tools.run_nmap(ip, ports, args, report)

	report.close()
# TODO: END OF CHOPPING BLOCK


if __name__ == "__main__":
	odin()
