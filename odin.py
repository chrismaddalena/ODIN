#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 :::====   :::====   :::  :::= ===
 :::  ===  :::  ===  :::  :::=====
 ===  ===  ===  ===  ===  ========
 ===  ===  ===  ===  ===  === ====
  ======   =======   ===  ===  ===

Developer:   Chris "cmaddy" Maddalena
Version:     2.0.0 "Huginn"
Description: Observation, Detection, and Investigation of Networks
             ODIN was designed to assist with OSINT automation for penetration testing clients and
             their networks, both the types with IP address and social. Provide a client's name and
             some domains to gather information from sources like RDAP, DNS, Shodan, and
             so much more.

             ODIN is made possible through the help, input, and work provided by others. Therefore,
             this project is entirely open source and available to all to use/modify.
"""

import os

import click
from multiprocess import Process, Manager

from lib import reporter, asciis, verification, htmlreporter, grapher, helpers


VERSION = "2.0.0"
CODENAME = "HUGINN"


def setup_reports(client):
    """Function to create a reports directory structure for the target organization."""
    if not os.path.exists("reports/{}".format(client)):
        try:
            os.makedirs("reports/{}".format(client))
            os.makedirs("reports/{}/screenshots".format(client))
            os.makedirs("reports/{}/file_downloads".format(client))
            os.makedirs("reports/{}/html_report".format(client))
        except OSError as error:
            click.secho("[!] Could not create the reports directory!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")


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
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=200)

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
@click.option('-o', '--organization', help='The target client, such as "ABC Company," to use for \
report titles and searches for domains and cloud storage buckets.', required=True)
@click.option('-d', '--domain', help="The target's primary domain, such as example.com. Use \
whatever the target uses for email and their main website. Provide additional domains in a scope \
file using --scope-file.",required=True)
# Optional arguments
@click.option('-sf', '--scope-file', type=click.Path(exists=True, readable=True, \
resolve_path=True), help="A text file containing additional domain names you want to include. IP \
addresses can also be provided, if necessary. List each one on a new line.", required=False)
@click.option('--whoxy-limit', default=10, help="The maximum number of domains discovered via \
reverse whois that ODIN will resolve and use when searching services like Censys and Shodan. \
You may get hundreds of results from reverse whois, so this is intended to save time and \
API credits. Default is 10 domains and setting it above maybe 20 or 30 is not recommended. \
It is preferable to perform a search using a tool like Vincent Yiu's DomLink and then provide \
the newly discovered domains in your scope file with --scope-file.")
@click.option('--typo', is_flag=True, help="Use urlcrazy (must be in user's PATH) to locate \
registered lookalike domains and then check those domains agaisnt URLVoid and Cymon.io to see \
if the domains or associated IP addresses have been flagged as malicious.")
# File searching arguments
@click.option('--files', is_flag=True, help="Use this option to use Google to search for files \
under the provided domain (-d), download files, and extract metadata.")
@click.option('-e', '--ext', default="all", help="File extensions to look for with --file. \
Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.")
# Cloud-related arguments
@click.option('-w', '--aws', help="A list of additional keywords to be used when searching for \
cloud sotrage buckets.",type=click.Path(exists=True, readable=True, resolve_path=True))
@click.option('-wf', '--aws-fixes', help="A list of strings to be added to the start and end of \
the cloud storage bucket names.", type=click.Path(exists=True, readable=True, resolve_path=True))
# Reporting-related arguments
@click.option('--html', is_flag=True, help="Create an HTML report at the end for easy browsing.")
@click.option('--graph', is_flag=True, help="Create a Neo4j graph database from the completed \
SQLite3 database.")
@click.option('--nuke', is_flag=True, help="Clear the Neo4j project before converting the \
database. This is only used with --graph.")
@click.option('--screenshots', is_flag=True, help="Attempt to take screenshots of discovered \
web services.")
@click.option('--unsafe', is_flag=True, help="Adding this flag will spawn the headless Chrome \
browser with the --no-sandbox command line flag. This is NOT recommended for any users who are \
NOT running ODIN on a Kali Linux VM as root. Chrome will not run as the root user on Kali \
without this option.")
# Pass the above arguments on to your osint function
@click.pass_context

def osint(self, organization, domain, files, ext, scope_file, aws, aws_fixes, html,
          screenshots, graph, nuke, whoxy_limit, typo, unsafe):
    """
The OSINT toolkit:\n
This is ODIN's primary module. ODIN will take the tagret organization, domain, and other data
provided and hunt for information. On the human side, ODIN looks for employee names,
email addresses, and social media profiles. Names and emails are cross-referenced with
HaveIBeenPwned, Twitter's API, and search engines to collect additional information.

ODIN also uses various tools and APIs to collect information on the provided IP addresses
and domain names, including things like DNS and IP address history.

View the wiki for the full details, reporting information, and lists of API keys.

Note: If providing any IP addresses in a scope file, acceptable IP addresses/ranges include:

    * Single Address:      8.8.8.8

    * Basic CIDR:          8.8.8.0/24

    * Nmap-friendly Range: 8.8.8.8-10

    * Underscores? OK:     8.8.8.8_8.8.8.10
    """
    click.clear()
    click.secho(asciis.print_art(), fg="magenta")
    click.secho("\tRelease v{}, {}".format(VERSION, CODENAME), fg="magenta")
    click.secho("[+] OSINT Module Selected: ODIN will run all recon modules.", fg="green")

    # Perform prep work for reporting
    setup_reports(organization)
    report_path = "reports/{}/".format(organization)
    output_report = report_path + "OSINT_DB.db"

    if __name__ == "__main__":
        # Create manager server to handle variables shared between jobs
        manager = Manager()
        ip_list = manager.list()
        domain_list = manager.list()
        rev_domain_list = manager.list()
        # Create reporter object and generate lists of everything, just IP addresses, and just domains
        browser = helpers.setup_headless_chrome(unsafe)
        report = reporter.Reporter(organization, report_path, output_report, browser)
        report.create_tables()
        scope, ip_list, domain_list = report.prepare_scope(ip_list, domain_list, scope_file, domain)
        # Create some jobs and put Python to work!
        # Job queue 1 is for the initial phase
        jobs = []
        # Job queue 2 is used for jobs using data from job queue 1
        more_jobs = []
        # Job queue 3 is used for jobs that take a while and use the progress bar, i.e. AWS enum
        even_more_jobs = []
        # Phase 1 jobs
        company_info = Process(name="Company Info Collector",
                               target=report.create_company_info_table,
                               args=(domain,))
        jobs.append(company_info)
        employee_report = Process(name="Employee Hunter",
                                  target=report.create_people_table,
                                  args=(domain_list, rev_domain_list, organization))
        jobs.append(employee_report)
        domain_report = Process(name="Domain and IP Hunter",
                                target=report.create_domain_report_table,
                                args=(organization, scope, ip_list, domain_list, rev_domain_list, whoxy_limit))
        jobs.append(domain_report)
        # Phase 2 jobs
        shodan_report = Process(name="Shodan Hunter",
                                target=report.create_shodan_table,
                                args=(ip_list, domain_list))
        more_jobs.append(shodan_report)
        if typo:
            urlcrazy_report = Process(name="Lookalike Domain Reviewer",
                                    target=report.create_urlcrazy_table,
                                    args=(organization, domain))
            more_jobs.append(urlcrazy_report)
        if screenshots:
            take_screenshots = Process(name="Screenshot Snapper",
                                       target=report.capture_web_snapshots,
                                       args=(report_path, browser))
            more_jobs.append(take_screenshots)
        if files:
            files_report = Process(name="File Hunter",
                                   target=report.create_foca_table,
                                   args=(domain, ext, report_path))
            more_jobs.append(files_report)
        # Phase 3 jobs
        cloud_report = Process(name="Cloud Hunter",
                               target=report.create_cloud_table,
                               args=(organization, domain, aws, aws_fixes))
        even_more_jobs.append(cloud_report)
        # Process the lists of jobs in phases, starting with phase 1
        click.secho("[+] Beginning initial discovery phase! This could take some time...", fg="green")
        for job in jobs:
            click.secho("[+] Starting new process: {}".format(job.name), fg="green")
            job.start()
        for job in jobs:
            job.join()
        # Wait for phase 1 and then begin phase 2 jobs
        click.secho("[+] Initial discovery is complete! Proceeding with additional queries...", fg="green")
        for job in more_jobs:
            click.secho("[+] Starting new process: {}".format(job.name), fg="green")
            job.start()
        for job in more_jobs:
            job.join()
        # Wait for phase 2 and then begin phase 3 jobs
        click.secho("[+] Final phase: checking the cloud and web services...", fg="green")
        for job in even_more_jobs:
            click.secho("[+] Starting new process: {}".format(job.name), fg="green")
            job.start()
        for job in even_more_jobs:
            job.join()
        # All jobs are done, so close out the SQLIte3 database connection
        report.close_out_reporting()
        click.secho("[+] Job's done! Your results are in {} and can be viewed and queried with \
any SQLite browser.".format(output_report), fg="green")
        # Perform addiitonal tasks depending on the user's command line options
        if graph:
            graph_reporter = grapher.Grapher(output_report)
            click.secho("[+] Loading ODIN database file {} for conversion to Neo4j".format(output_report), fg="green")
            if nuke:
                if click.confirm(click.style("[!] You set the --nuke option. This wipes out all nodes for a \
fresh start. Proceed?", fg="red"), default=True):
                    graph_reporter.clear_neo4j_database()
                    click.secho("[+] Database successfully wiped!\n", fg="green")
                    graph_reporter.convert()
                else:
                    click.secho("[!] You can convert your database to a graph database later. \
Run lib/grapher.py with the appropriate options.", fg="red")
            else:
                graph_reporter.convert()
        if html:
            click.secho("\n[+] Creating the HTML report using {}.".format(output_report), fg="green")
            html_reporter = htmlreporter.HTMLReporter(organization, report_path + "/html_report/", output_report)
            html_reporter.generate_full_report()


# The VERIFY module -- No OSINT, just a way to check a ownership of a list of IPs
@odin.command(name='verify', short_help="This module assists with verifying ownership of a list \
of IP addresses. This returns a csv file with SSL cert, whois, and other data for verification.")
@click.option('-o', '--organization', help='The target client, such as "ABC Company," to use for \
report titles and some keyword searches.', required=True)
@click.option('-sf', '--scope-file', help="Name of the file with your IP addresses.", \
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('-r', '--report', default="Verification.csv", help="Output file (CSV) for the \
findings.")
# Pass the above arguments on to your verify function
@click.pass_context

def verify(self, organization, scope_file, report):
    """
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
    click.secho(asciis.print_art(), fg="magenta")
    click.secho("\tRelease v{}, {}".format(VERSION, CODENAME), fg="magenta")
    click.secho("[+] Scope Verification Module Selected: ODIN will attempt to verify who owns \
the provided IP addresses.", fg="green")
    setup_reports(organization)
    report_path = "reports/{}/{}".format(organization, report)
    expanded_scope = []
    results = {}
    try:
        verification.prepare_scope(scope_file, expanded_scope)
        verification.perform_whois(expanded_scope, results)
        verification.print_output(results, report_path)
    except Exception as error:
        click.secho("[!] Verification failed!", fg="red")
        click.secho("L.. Details: {}".format(error), fg="red")
    click.secho("[+] Job's done! Your identity report is in {}.".format(report_path), fg="green")


if __name__ == "__main__":
    odin()
