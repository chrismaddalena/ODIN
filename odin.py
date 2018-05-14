#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 :::====   :::====   :::  :::= ===
 :::  ===  :::  ===  :::  :::=====
 ===  ===  ===  ===  ===  ========
 ===  ===  ===  ===  ===  === ====
  ======   =======   ===  ===  ===

Developer:   Chris "cmaddy" Maddalena
Version:     1.7 "Muninn"
Description: Observation, Detection, and Investigation of Networks
             ODIN was designed to assist with OSINT automation for penetration testing clients and
             their networks, both the types with IP address and social. Provide a client's name,
             IPs, and domain(s) to gather information from sources like whois, DNS, Shodan, and
             much more.

             ODIN is made possible through the help, input, and work provided by others. Therefore,
             this project is entirely open source and available to all to use/modify.
"""

import os
import multiprocess
import click
from colors import red, green, yellow
from lib import reporter, asciis, verification


def setup_reports(client):
    """Function to create a reports directory for the target client."""
    if not os.path.exists("reports/{}".format(client)):
        try:
            os.makedirs("reports/{}".format(client))
        except OSError as error:
            print(red("[!] Could not create the reports directory!"))
            print(red("L.. Details: {}".format(error)))


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
        command = click.Group.get_command(self, ctx, cmd_name)
        if command is not None:
            return command
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail("Too many matches: %s" % ", ".join(sorted(matches)))

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)

# Note: The following function descriptors will look weird and some will contain \n.
# This is necessary for CLICK. These are displayed with the -h help info and need to be written
# just like we want them to be displayed in the user's terminal.
def odin():
    """
Welcome to O.D.I.N.! To use O.D.I.N., select a module you wish to run. Functions are split into
modules for flexibility.\n
Run 'odin.py <MODULE> --help' for more information on a specific
module.
    """
    # Everything starts here
    pass


# The OSINT module -- hit it with everything
@odin.command(name='osint', short_help="The full OSINT suite of tools will be run (domain, people\
, and Shodan).")
@click.option('-c', '--client', help="The target client, such as ABC Company, to use for report \
titles.", required=True)
@click.option('-d', '--domain', help="The target's domain, such as example.com.", required=True)
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, \
              resolve_path=True), help="A text file containing your in-scope IP addresses and \
domain names. List each one on a new line.", required=True)
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files \
under the provided domain (-d) and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. \
Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
@click.option('-x', '--delete', is_flag=True, help="Set this option \
if you want the downloaded files with --file to be deleted after analysis.")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output for more (maybe way \
too much) domain contact info.")
@click.option('-w', '--aws', help="A list of AWS S3 bucket names to validate.",  \
              type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-wf', '--aws-fixes', help="A list of strings to be added to the start and end of \
AWS S3 bucket names.", type=click.Path(exists=True, readable=True, resolve_path=True))
@click.pass_context

def osint(self, client, domain, files, ext, delete, scope_file, aws, aws_fixes, verbose):
    """
The full O.D.I.N. toolkit:\n
This module runs all OSINT modules together. O.D.I.N. uses TheHarvester and Hunter.io
to locate email addresses and social media profiles. Profiles are then cross-referenced with
HaveIBeenPwned, Twitter's API, and search engines to collect additional information.\n
O.D.I.N. uses various tools and APIs to collect domain/IP information on the provided IP
addresses and/or domains.\n
Several API keys are required for all of the look-ups: Twitter, Censys, Shodan, EmailHunter,
and Cymon.
    """
    asciis.print_art()
    print(green("[+] OSINT Module Selected: O.D.I.N. will run all recon modules."))

    if verbose:
        print(yellow("[*] Verbose output Enabled -- Enumeration of RDAP contact information \
is enabled, so you may get a lot of it if scope includes a large cloud provider."))
    else:
        print(yellow("[*] Verbose output Disabled -- Enumeration of contact information \
will be skipped."))

    # Perform prep work for reporting
    setup_reports(client)
    output_report = "reports/{}/OSINT_DB.db".format(client)

    if __name__ == "__main__":
        report = reporter.Reporter(output_report)
        scope, ip_list, domains_list = report.prepare_scope(scope_file, domain)

        # Create empty job queue
        jobs = []
        company_info = multiprocess.Process(name="Company Info Report",
                                            target=report.create_company_info_table,
                                            args=(domain,))
        jobs.append(company_info)
        employee_report = multiprocess.Process(name="Employee Report",
                                               target=report.create_people_table,
                                               args=(domain, client))
        jobs.append(employee_report)
        domain_report = multiprocess.Process(name="Domains Report",
                                             target=report.create_domain_report_table,
                                             args=(scope, ip_list, domains_list, verbose))
        jobs.append(domain_report)
        urlcrazy_report = multiprocess.Process(name="Domain Squatting Report",
                                               target=report.create_urlcrazy_table,
                                               args=(client, domain))
        jobs.append(urlcrazy_report)
        shodan_report = multiprocess.Process(name="Shodan Report",
                                            target=report.create_shodan_table,
                                            args=(ip_list, domains_list))
        jobs.append(shodan_report)
        cloud_report = multiprocess.Process(name="Cloud Report",
                                            target=report.create_cloud_table,
                                            args=(client, domain, aws, aws_fixes))
        jobs.append(cloud_report)
        if files:
            files_report = multiprocess.Process(name="File Metadata Report",
                                                target=report.create_foca_table,
                                                args=(domain, ext, delete, verbose))
            jobs.append(files_report)

        for job in jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in jobs:
            job.join()

        report.close_out_reporting()
        print(green("[+] Job's done! Your results are in {}.".format(output_report)))


# The DOMAINS module -- Forget social and focus on IPs and domain names
@odin.command(name='domains', short_help="Only domain-related recon will be performed (RDAP, DNS, \
and Shodan). Provide a list of IPs and domains.")
@click.option('-c', '--client', help="The target client, such as ABC Company. This will be used \
for report titles.", required=True)
@click.option('-d', '--domain', help="The target's domain, such as example.com.", required=True)
@click.option('-sf', '--scope-file', help="A list of IP address/ranges and domains.", \
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files \
under the provided domain (-d) and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. \
Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
@click.option('-x', '--delete', is_flag=True, help="Set this option if you want the downloaded \
files with --file to be deleted after analysis.")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output for more (maybe way \
too much) domain contact info.")
@click.option('-w', '--aws', help="A list of AWS S3 bucket names to validate.", \
              type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-wf', '--aws-fixes', help="A list of strings to be added to the start and end of \
AWS S3 bucket names.", type=click.Path(exists=True, readable=True, resolve_path=True))
@click.pass_context

def domains(self, client, domain, files, ext, delete, scope_file, aws, aws_fixes, verbose):
    """
The Domain module uses various tools and APIs to collect information on the provided IP addresses
and/or domains.\n
Several API keys are required for all of the look-ups: Censys, FullContact, Shodan, URLVoid, and
Cymon.
    """
    asciis.print_art()
    print(green("[+] Domain Module Selected: O.D.I.N. will run only domain and IP-related \
modules."))
    if verbose:
        print(yellow("[*] Verbose output Enabled -- Enumeration of RDAP contact information \
is enabled, so you may get a lot of it if scope includes a large cloud provider."))
    else:
        print(yellow("[*] Verbose output Disabled -- Enumeration of contact information \
will be skipped."))

    # Perform prep work for reporting
    setup_reports(client)
    output_report = "reports/{}/OSINT_DB.db".format(client)

    if __name__ == "__main__":
        report = reporter.Reporter(output_report)
        scope, ip_list, domains_list = report.prepare_scope(scope_file, domain)

        # Create empty job queue
        jobs = []
        workbook = "boo"
        company_info = multiprocess.Process(name="Company Info Report",
                                            target=report.create_company_info_table,
                                            args=(domain,))
        jobs.append(company_info)
        domain_report = multiprocess.Process(name="Domains Report",
                                             target=report.create_domain_report_table,
                                             args=(scope, ip_list, domains_list, verbose))
        jobs.append(domain_report)
        urlcrazy_report = multiprocess.Process(name="Domain Squatting Report",
                                               target=report.create_urlcrazy_table,
                                               args=(workbook, client, domain))
        jobs.append(urlcrazy_report)
        shodan_report = multiprocess.Process(name="Shodan Report",
                                             target=report.create_shodan_table,
                                             args=(workbook, ip_list, domains_list))
        jobs.append(shodan_report)
        cloud_report = multiprocess.Process(name="Cloud Report",
                                            target=report.create_cloud_table,
                                            args=(client, domain, aws, aws_fixes))
        jobs.append(cloud_report)
        if files:
            files_report = multiprocess.Process(name="File Metadata Report",
                                                target=report.create_foca_table,
                                                args=(workbook, domain, ext, delete, verbose))
            jobs.append(files_report)

        for job in jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in jobs:
            job.join()

        report.close_out_reporting()
        print(green("[+] Job's done! Your results are in {}.".format(output_report)))


# The PEOPLE module -- Primarily email hunting with some Twitter and LinkedIn sprinkled in
@odin.command(name='people',
              short_help="Only email addresses and social media profile recon (email, Twitter, and \
LinkedIn). Provide an email @domain.")
@click.option('-c', '--client', help="The target client, such as ABC Company. This will be used \
for naming reports.", required=True)
@click.option('-d', '--domain', help="The email domain, such as example.com. Do not include \
@.", required=True)
@click.pass_context

def people(self, client, domain):
    """
Uses TheHarvester and EmailHunter to locate email addresses and social media profiles. Profiles
are cross-referenced with HaveIBeenPwned, Twitter's API, and search engines to try to find security
breaches, pastes, and social media accounts.\n
Several API keys are required for all of the look-ups: EmailHunter and Twitter.
    """
    asciis.print_art()
    print(green("[+] People Module Selected: O.D.I.N. will run only modules for email addresses \
and social media."))

    # Perform prep work for reporting
    setup_reports(client)
    output_report = "reports/{}/OSINT_DB.db".format(client)

    if __name__ == "__main__":
        report = reporter.Reporter(output_report)

        # Create empty job queue
        jobs = []
        company_info = multiprocess.Process(name="Company Info Report",
                                            target=report.create_company_info_table,
                                            args=(domain,))
        jobs.append(company_info)
        employee_report = multiprocess.Process(name="Employee Report",
                                               target=report.create_people_table,
                                               args=(domain, client))
        jobs.append(employee_report)

        for job in jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in jobs:
            job.join()

        report.close_out_reporting()
        print(green("[+] Job's done! Your results are in {}.".format(output_report)))


# The SHODAN module -- Mostly a Shodan CLI
@odin.command(name='shodan', short_help="Look-up IPs and domains on Shodan using the Shodan API \
and your API key.")
@click.option('-sf', '--scope-file', help="Name of the file with your IP addresses.", 
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('-o', '--output', default="Shodan_DB.db", help="Name of the output DB file for the \
results. Default is Shodan_DB.db.")
@click.pass_context

def shodan(self, scope_file, output):
    """
The Shodan module:\n
Look-up information on the target IP address(es) using Shodan's API.\n
A Shodan API key is required.
    """
    asciis.print_art()
    print(green("[+] Shodan Module Selected: O.D.I.N. will check Shodan for the provided domains \
and IPs."))

    if __name__ == "__main__":
        report = reporter.Reporter(output)
        scope, ip_list, domains_list = report.prepare_scope(scope_file)

        # Create empty job queue
        jobs = []
        shodan_report = multiprocess.Process(name="Shodan Report",
                                            target=report.create_shodan_table,
                                            args=(ip_list, domains_list))
        jobs.append(shodan_report)

        for job in jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in jobs:
            job.join()

        report.close_out_reporting()
        print(green("[+] Job's done! Your results are in {}.".format(output)))

# The VERIFY module -- No OSINT, just a way to check a ownership of a list of IPs
@odin.command(name='verify', short_help='Verify an external pen test scope. This returns a csv \
file with SSL cert, whois, and other data for verification.')
@click.option('-c', '--client', help='The target client, such as ABC Company. This will be used \
for report titles.', required=True)
@click.option('-sf', '--scope-file', help='Name fo the file with your IP addresses.', \
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
# @click.option('-s', '--scope-ips', help='Scoped IP addresses. Can be used instead of a scoping \
# file.', multiple=True)
@click.option('-o', '--output', default='Verification.csv', help='Output file (CSV) for the \
findings.')
@click.option('--cidr', is_flag=True, help='Use if the scoped IPs include any CIDRs.')
@click.pass_context

def verify(self, scope_file, output, cidr, client):
    """
The Verify module:
Uses reverse DNS, ARIN, and SSL certificate information to help you verify a testing scope.
Sometimes clients provide a bad IP address or two and you may not realize it.\n

This is only for verifying IP addresses. Domains may not have public ownership information
available. Compare the IP ownership information from ARIN and any certificate information that
is found to what you know about your client.

Acceptable IP addresses/ranges include:\n
* x.x.x.x-y (ex: 8.8.8.8-10)\n
* x.x.x.x_x.x.x.y (ex: 8.8.8.8_8.8.8.10\n
* x.x.x.x/yz (ex: 8.8.8.0/24)\n
* x.x.x.x (ex: 8.8.8.8)\n

    """
    asciis.print_art()

    print(green("[+] Scope Verification Module Selected: O.D.I.N. will attempt to verify who owns \
the provided IP addresses."))

    setup_reports(client)
    report = "reports/{}/{}".format(client, output)

    ip_list = []
    out = {}

    try:
        verification.prepare_scope(scope_file, ip_list, cidr)
        verification.perform_whois(ip_list, out)
        verification.print_output(out, report)
    except Exception as error:
        print(red("[!] Verification failed!"))
        print(red("L.. Details: {}".format(error)))

    print(green("[+] Job's done! Your identity report is in {}.".format(report)))


# TODO: HERE THERE BE DRAGONS
# Everything below here is under construction and a little bit janky ¯\_(ツ)_/¯

# The SSL module -- Run SSLLabs' scanner against the target domain
# @odin.command(name='ssl', short_help='Check SSL cert for provided IP or domain.')
# @click.option('-t', '--target', help='IP address with the certificate. \
# Include the port if it is not 443, e.g. IP:8080', required=True)
# @click.option('--labs', is_flag=True, help='Query Qualys SSL Labs in \
# addition to pulling the certificate.')
# @click.option('--cache', is_flag=True, help='Try to get cached scan data from \
# a completed SSL Labs scan, if available.')
# def ssl(target, labs, cache):
#     """
#     This module can be used to quickly pull an SSL certificate's information for easy reference.
#     It can also be used to run an SSLLabs scan on the target (coming soon).
#     """
#     asciis.print_art()
#     print(green("[+] SSL Module Selected: O.D.I.N. will pull SSL certificate \
# information for the provided IP and port."))
    
#     ssl_checker.check_ssl(target)
#     if labs:
#         if cache:
#             print(green("[+] Checking SSL Labs' cache data for this host."))
#             ssl_checker.get_results(target, 2)
#         else:
#             print(green("[+] SSL Labs scanning was enabled, so requesting \
# information from Qualys."))
#             ssl_checker.get_results(target, 1)


# The REP module -- Check a target's reputation against Cymon and URLVoid records
# @odin.command(name='rep', short_help='Check reputation of provided IP or domain.')
# @click.option('-t', '--target', help='The target IP address or domain.', required=True)
# def rep(target):
#     """
#     The Rep module:
#     Can be used to quickly collect reputation data for the provided \
# IP address. O.D.I.N. will query eSentire's Cymon.io and threat feeds.\n
#     An API key for Cymon is recommended.
#     """
#     asciis.print_art()

#     print(green("[+] Reputation Module Selected: O.D.I.N. will collect reputation \
# data for the provided IP address or domain name."))

#     report = reporter.Reporter()
#     report.create_cymon_worksheet(target)


if __name__ == "__main__":
    odin()
