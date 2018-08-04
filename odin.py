#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 :::====   :::====   :::  :::= ===
 :::  ===  :::  ===  :::  :::=====
 ===  ===  ===  ===  ===  ========
 ===  ===  ===  ===  ===  === ====
  ======   =======   ===  ===  ===

Developer:   Chris "cmaddy" Maddalena
Version:     1.9.1 "Muninn"
Description: Observation, Detection, and Investigation of Networks
             ODIN was designed to assist with OSINT automation for penetration testing clients and
             their networks, both the types with IP address and social. Provide a client's name and
             some domains to gather information from sources like RDAP, DNS, Shodan, and
             so much more.

             ODIN is made possible through the help, input, and work provided by others. Therefore,
             this project is entirely open source and available to all to use/modify.
"""

import os
from multiprocess import Process, Manager
import click
from colors import red, green, yellow
from lib import reporter, asciis, verification, htmlreporter, grapher


def setup_reports(client):
    """Function to create a reports directory structure for the target organization."""
    if not os.path.exists("reports/{}".format(client)):
        try:
            os.makedirs("reports/{}".format(client))
            os.makedirs("reports/{}/screenshots".format(client))
            os.makedirs("reports/{}/file_downloads".format(client))
            os.makedirs("reports/{}/html_report".format(client))
        except OSError as error:
            print(red("[!] Could not create the reports directory!"))
            print(red("L.. Details: {}".format(error)))


# Setup a class for CLICK
class AliasedGroup(click.Group):
    """Allows commands to be called by their first unique character."""

    def get_command(self, ctx, cmd_name):
        """
        Allows commands to be called by their first unique character
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

# That's right, we support -h and --help! Not using -h for an argument like 'host'! ;D
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)

# Note: The following function descriptors will look weird and some will contain '\n' in spots.
# This is necessary for CLICK. These are displayed with the help info and need to be written
# just like we want them to be displayed in the user's terminal. Whitespace really matters.
def odin():
    """
Welcome to ODIN! To use ODIN, select a module you wish to run. Functions are split into modules
to support a few different use cases.\n
Run 'odin.py <MODULE> --help' for more information on a specific module.
    """
    # Everything starts here
    pass


# The OSINT module -- This is the primary module that does all the stuff
# Basic, required arguments
@odin.command(name='osint', short_help="The full OSINT suite of tools will be run (see README).")
@click.option('-o', '--organization', help="The target client, such as `ABC Company`, to use for \
report titles and some keyword searches.", required=True)
@click.option('-d', '--domain', help="The target's primary domain, such as example.com. Use \
whatever the target uses for email and their main website. Add more domains to your scope file.",
              required=True)
# Optional arguments
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, \
              resolve_path=True), help="A text file containing additional IP addresses and \
domain names you want to include. List each one on a new line.", required=False)
# File searching arguments
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files \
under the provided domain (-d), download files, and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. \
Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
@click.option('-x', '--delete', is_flag=True, help="Set this option if you want the downloaded \
files with --file to be deleted after analysis.")
# Cloud-related arguments
@click.option('-w', '--aws', help="A list of AWS S3 bucket names to validate.",  \
              type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-wf', '--aws-fixes', help="A list of strings to be added to the start and end of \
AWS S3 bucket names.", type=click.Path(exists=True, readable=True, resolve_path=True))
# Reporting-related arguments
@click.option('--html', is_flag=True, help="Create an HTML report at the end for easy browsing.")
@click.option('--graph', is_flag=True, help="Create a Neo4j graph database from the completed \
SQLite3 database.")
@click.option('--nuke', is_flag=True, help="Clear the Neo4j project before converting the \
database. This is used with --graph.")
@click.option('--screenshots', is_flag=True, help="Attempt to take screenshots of discovered \
web services.")
# Pass the above arguments on to your osint function
@click.pass_context

def osint(self, organization, domain, files, ext, delete, scope_file, aws, aws_fixes, html,
          screenshots, graph, nuke):
    """
The OSINT toolkit:\n
This is ODIN's primary module. ODIN will take the tagret organization, domain, and other data
provided and hunt for information. On the human side, ODIN looks for employee names,
email addresses, and social media profiles. Names and emails are cross-referenced with
HaveIBeenPwned, Twitter's API, and search engines to collect additional information.

ODIN also uses various tools and APIs to collect information on the provided IP addresses
and domain names, including things like DNS and IP address history.

View the README for the full detailsand lists of API keys!

Note: If providing a scope file, acceptable IP addresses/ranges include:

    * Single Address:      8.8.8.8

    * Basic CIDR:          8.8.8.0/24

    * Nmap-friendly Range: 8.8.8.8-10

    * Underscores? OK:     8.8.8.8_8.8.8.10
    """
    click.clear()
    asciis.print_art()
    print(green("[+] OSINT Module Selected: ODIN will run all recon modules."))

    verbose = None

    if verbose:
        print(yellow("[*] Verbose output Enabled -- Enumeration of RDAP contact information \
is enabled, so you may get a lot of it if scope includes a large cloud provider."))

    # Perform prep work for reporting
    setup_reports(organization)
    report_path = "reports/{}/".format(organization)
    output_report = report_path + "OSINT_DB.db"

    if __name__ == "__main__":
        # Create manager server to handle variables shared between jobs
        manager = Manager()
        ip_list = manager.list()
        domain_list = manager.list()
        # Create reporter object and generate final list, the scope from scope file
        report = reporter.Reporter(report_path, output_report)
        report.create_tables()
        scope, ip_list, domain_list = report.prepare_scope(ip_list, domain_list, scope_file, domain)

        # Create some jobs and put Python to work!
        # Job queue 1 is for the initial phase
        jobs = []
        # Job queue 2 is used for jobs using data from job queue 1
        more_jobs = []
        # Job queue 3 is used for jobs that take a while and use the progress bar, i.e. AWS enum
        even_more_jobs = []
        company_info = Process(name="Company Info Collector",
                               target=report.create_company_info_table,
                               args=(domain,))
        jobs.append(company_info)
        employee_report = Process(name="Employee Hunter",
                                  target=report.create_people_table,
                                  args=(domain, organization))
        jobs.append(employee_report)
        domain_report = Process(name="Domain and IP Address Recon",
                                target=report.create_domain_report_table,
                                args=(organization, scope, ip_list, domain_list, verbose))
        jobs.append(domain_report)

        shodan_report = Process(name="Shodan Queries",
                                target=report.create_shodan_table,
                                args=(ip_list, domain_list))
        more_jobs.append(shodan_report)
        urlcrazy_report = Process(name="Domain Squatting Recon",
                                  target=report.create_urlcrazy_table,
                                  args=(organization, domain))
        more_jobs.append(urlcrazy_report)

        cloud_report = Process(name="Cloud Recon",
                               target=report.create_cloud_table,
                               args=(organization, domain, aws, aws_fixes))
        even_more_jobs.append(cloud_report)

        if screenshots:
            take_screenshots = Process(name="Screenshot Snapper",
                                       target=report.capture_web_snapshots,
                                       args=(report_path,))
            more_jobs.append(take_screenshots)

        if files:
            files_report = Process(name="File Hunter",
                                   target=report.create_foca_table,
                                   args=(domain, ext, delete, report_path, verbose))
            jobs.append(files_report)

        print(green("[+] Beginning initial discovery phase! This could take some time..."))
        for job in jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in jobs:
            job.join()

        print(green("[+] Initial discovery is complete! Proceeding with additional queries..."))
        for job in more_jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in more_jobs:
            job.join()

        print(green("[+] Final phase: checking the cloud and web services..."))
        for job in even_more_jobs:
            print(green("[+] Starting new process: {}".format(job.name)))
            job.start()
        for job in even_more_jobs:
            job.join()

        report.close_out_reporting()
        print(green("[+] Job's done! Your results are in {} and can be viewed and queried with \
any SQLite browser.".format(output_report)))

        if graph:
            graph_reporter = grapher.Grapher(output_report)
            print(green("[+] Loading ODIN database file {} for conversion to Neo4j").format(output_report))

            if nuke:
                confirm = input(red("\n[!] You set the --nuke option. This wipes out all nodes \
for a fresh start. Proceed? (Y\\N) "))
                if confirm == "Y" or confirm == "y":
                    graph_reporter.clear_neo4j_database()
                    print(green("[+] Database successfully wiped!\n"))
                    graph_reporter.convert()
                else:
                    print(red("[!] Then you can convert your database to a graph database later. \
Run lib/grapher.py with the appropriate options."))
            else:
                graph_reporter.convert()

        if html:
            print(green("\n[+] Creating the HTML report using {}.".format(output_report)))
            html_reporter = htmlreporter.HTMLReporter(organization, report_path + "/html_report/", output_report)
            html_reporter.generate_full_report()


# The VERIFY module -- No OSINT, just a way to check a ownership of a list of IPs
@odin.command(name='verify', short_help="This module assists with verifying ownership of a list \
of IP addresses. This returns a csv file with SSL cert, whois, and other data for verification.")
@click.option('-o', '--organization', help="The target client, such as `ABC Company`, to use for \
report titles and some keyword searches.", required=True)
@click.option('-sf', '--scope-file', help="Name of the file with your IP addresses.", \
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('-r', '--report', default="Verification.csv", help="Output file (CSV) for the \
findings.")
@click.option('--cidr', is_flag=True, help="Use if the scoped IPs include any CIDRs.")
# Pass the above arguments on to your verify function
@click.pass_context

def verify(self, scope_file, output, cidr, client):
    """
HERE THERE BE DRAGONS : This code needs updating, so it might be janky.

The Verify module:
Uses reverse DNS, ARIN, and SSL/TLS certificate information to help you verify ownership of a
list of IP addresses.

This is only for verifying IP addresses. Domains may not have public ownership information
available. Compare the IP ownership information from ARIN and certificate information to what
you know about the presumed owner to determine ownership.

Acceptable IP addresses/ranges include:

    * Single Address:      8.8.8.8

    * Basic CIDR:          8.8.8.0/24

    * Nmap-friendly Range: 8.8.8.8-10

    * Underscores? OK:     8.8.8.8_8.8.8.10
    """
    asciis.print_art()
    print(green("[+] Scope Verification Module Selected: ODIN will attempt to verify who owns \
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

if __name__ == "__main__":
    odin()
