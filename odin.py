#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 :::====     :::====     :::    :::= ===
 :::  ===    :::  ===    :::    :::=====
 ===  ===    ===  ===    ===    ========
 ===  ===    ===  ===    ===    === ====
  ======  :: =======  :: === :: ===  === ::

Developer:   Chris "cmaddy" Maddalena
Description: Observation, Detection, and Investigation of Networks
			 O.D.I.N. is an evolution of Codename:Viper. As with any project that
			 uses a codename, it must eventually get a real name and evolve.
			 O.D.I.N. was designed to assist with OSINT automation for penetration
			 testing clients and their networks, both the types with IP address
			 and social. Provide a client's name, IPs, and domain(s) to gather
			 information from sources like whois, DNS, and Shodan.

			 O.D.I.N. is made possible through the help, input, and work provided
			 by others. Therefore, this project is entirely open source and
			 available to all to use/modify.
"""

from colors import *
from lib import *
import click
import os
import xlsxwriter


# Create a directory for the client reports
def setup_reports(client):
	if not os.path.exists("reports/{}".format(client)):
		try:
			os.makedirs("reports/{}".format(client))
		except:
			print(red("[!] Could not create the reports directory!"))


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
		ctx.fail("Too many matches: %s" % ", ".join(sorted(matches)))

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
def odin():
	"""
	Welcome to O.D.I.N.! To use O.D.I.N., select a module you wish to run. Functions are split into modules for flexibility.\n
	Run 'odin.py <MODULE> --help' for more information on a specific module.\n
	"""
	# Everything starts here
	pass


# The OSINT module -- hit it with everything
@odin.command(name='osint', short_help="The full OSINT suite of tools will be run (domain, people, Shodan).")
@click.option('-c', '--client', help="The target client, such as ABC Company, to use for report titles.", required=True)
@click.option('-d', '--domain', help="The target's domain, such as example.com.", required=True)
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, resolve_path=True), help="A text file containing your in-scope IP addresses and domain names. List each one on a new line.")
@click.option('--dns', is_flag=True, help="Set this option if you want ODIN to perform DNS brute forcing on the scope file's domains.")
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files under the provided domain (-d) and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
@click.option('-x', '--delete', is_flag=True, help="Set this option if you want the downloaded files with --file to be deleted after analysis.")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output for more (maybe way too much) domain contact info, Censys certificate information, and additional status messages.")
@click.pass_context
def osint(self, client, domain, dns, files, scope_file, verbose):
	"""
	The full O.D.I.N. toolkit:\n
	This module runs all OSINT modules together. O.D.I.N. uses TheHarvester to locate email addresses and social media profiles.
	Profiles are cross-referenced with HaveIBeenPwned, Twitter's API, and LinkedIn.\n
	O.D.I.N. uses various tools and APIs to collect domain/IP information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: Twitter, Censys, Shodan, and Cymon.
	"""
	asciis.print_art()

	print(green("[+] OSINT Module Selected: O.D.I.N. will run all recon modules."))
	setup_reports(client)
	output_report = "reports/{}/OSINT_Report.xlsx".format(client)

	scope, ip_list, domains_list = reporter.prepare_scope(scope_file, domain)
	with xlsxwriter.Workbook(output_report) as workbook:
		reporter.create_domain_report(workbook, scope, ip_list, domains_list, dns)
		reporter.create_urlcrazy_worksheet(workbook, client, domain)
		reporter.create_shodan_worksheet(workbook, ip_list, domains_list)
		reporter.create_censys_worksheet(workbook, scope, verbose)
		reporter.create_people_worksheet(workbook, domain)
		if files:
			reporter.create_foca_worksheet(workbook, domain, ext, delete, verbose)


# The DOMAIN module -- Forget social and focus on IPs and domain names
@odin.command(name='domain', short_help="Only domain-related recon will be performed (RDAP, DNS, Shodan). Provide a list of IPs and domains.")
@click.option('-c', '--client', help="The target client, such as ABC Company. This will be used for report titles.", required=True)
@click.option('-d', '--domain', help="The target's domain, such as example.com.", required=True)
@click.option('-sf', '--scope-file', help="A list of IP address/ranges and domains.", type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('--dns', is_flag=True, help="Set this option if you want ODIN to perform DNS brute forcing on the scope file's domains.")
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files under the provided domain (-d) and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
@click.option('-x', '--delete', is_flag=True, help="Set this option if you want the downloaded files with --file to be deleted after analysis.")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output for more (maybe way too much) domain contact info, Censys certificate information, and additional status messages.")
def domain(client, domain, dns, files, ext, delete, scope_file, verbose):
	"""
	The Domain module uses various tools and APIs to collect information on the provided IP addresses and/or domains.\n
	Several API keys are required for all of the look-ups: Censys, Shodan, and Cymon.
	"""
	asciis.print_art()

	print(green("[+] Domain Module Selected: O.D.I.N. will run only domain and IP-related modules."))
	setup_reports(client)
	output_report = "reports/{}/Domain_Report.xlsx".format(client)

	scope, ip_list, domains_list = reporter.prepare_scope(scope_file, domain)
	with xlsxwriter.Workbook(output_report) as workbook:
		reporter.create_domain_report(workbook, scope, ip_list, domains_list, dns)
		reporter.create_urlcrazy_worksheet(workbook, client, domain)
		reporter.create_shodan_worksheet(workbook, ip_list, domains_list)
		reporter.create_censys_worksheet(workbook, scope, verbose)
		if files:
			reporter.create_foca_worksheet(workbook, domain, ext, delete, verbose)


# The PEOPLE module -- Primarily TheHarvester with some Twitter and LinkedIn sprinkled in
@odin.command(name='people',
	short_help="Only email addresses and social media profile recon (email, Twitter, and LinkedIn). Provide an email @domain.")
@click.option('-c', '--client', help="The target client, such as ABC Company. This will be used for naming reports.", required=True)
@click.option('-d', '--domain', help="The email domain, such as example.com. Do not include @.", required=True)
def people(client,domain):
	"""
	Uses TheHarvester is used to locate email addresses and social media profiles. Profiles are cross-referenced with
	HaveIBeenPwned, Twitter's API, and LinkedIn to try to find security breaches, pastes, and social media accounts.\n
	A Twitter app key is necessary for the Twitter API integration.
	"""
	asciis.print_art()

	print(green("[+] People Module Selected: O.D.I.N. will run only modules for email addresses and social media."))
	setup_reports(client)
	output_report = "reports/{}/People_Report.xlsx".format(client)

	with xlsxwriter.Workbook(output_report) as workbook:
		reporter.create_people_worksheet(workbook, domain)


# The SHODAN module -- Perform Shodan searches only
@odin.command(name='shodan', short_help="Look-up IPs and domains on Shodan using the Shodan API and your API key.")
@click.option('-sf', '--scope-file', help="Name fo the file with your IP addresses.", type = click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('-o', '--output', default="Shodan_Report.xlsx", help="Name of the output xlsx file for the information. Default is Shodan_Report.xlsx.")
def shodan(scope_file, output):
	"""
	The Shodan module:\n
	Look-up information on IP addresses using Shodan's API and your API key.\n
	You must have a Shodan API key!
	"""
	asciis.print_art()

	print(green("[+] Shodan Module Selected: O.D.I.N. will check Shodan for the provided domains and IPs."))
	output_report = output

	scope, ip_list, domains_list = reporter.prepare_scope(scope_file)

	with xlsxwriter.Workbook(output_report) as workbook:
		reporter.create_shodan_worksheet(workbook, ip_list, domains_list)


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
	Uses reverse DNS, ARIN, and SSL certificate information to help you verify a testing scope.
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


# # The REP module -- Check a target's reputation against Cymon and URLVoid records
# @odin.command(name='rep', short_help='Check reputation of provided IP or domain.')
# @click.option('-t', '--target', help='The target IP address or domain.', required=True)
# @click.option('-o', '--output', default='Reputation_Report.txt', help='Name of the output file for the search results.')
# def rep(target, output):
# 	"""
# 	The Rep module:
# 	Can be used to quickly collect reputation data for the provided IP address. O.D.I.N. will query RDAP, Shodan, URLVoid, and eSentire's Cymon.\n
# 	API keys for Shodan, URLVoid, and Cymon are required!
# 	"""
# 	report = open(output, 'w')
# 	domain_checker = domain_tools.Domain_Check()
#
# 	asciis.print_art()
# 	print(green("[+] Reputation Module Selected: O.D.I.N. will reputation data for the provided IP address or domain name."))
# 	domain_checker.search_cymon(target, report)
# 	domain_checker.run_urlvoid_lookup(target, report)
#
#
# # The SSL module -- Run SSLLabs' scanner against the target domain
# @odin.command(name='ssl', short_help='Check SSL cert for provided IP or domain.')
# @click.option('-t', '--target', help='IP address with the certificate. Include the port if it is not 443, e.g. IP:8080', required=True)
# @click.option('--labs', is_flag=True, help='Query Qualys SSL Labs in addition to pulling the certificate.')
# def ssl(target, labs):
# 	"""
# 	This module can be used to quickly pull an SSL certificate's information for easy reference.
# 	It can also be used to run an SSLLabs scan on the target (coming soon).
# 	"""
# 	asciis.print_art()
# 	print(green("[+] SSL Module Selected: O.D.I.N. will pull SSL certificate information for the provided IP and port."))
# 	scan_tools.checkSSL(target)
# 	if labs:
# 		ssllabsscanner.get_results(target, 1)


if __name__ == "__main__":
	odin()
