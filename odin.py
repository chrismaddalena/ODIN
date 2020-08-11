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
import sys
import logging

import click

from lib import asciis, grapher, helpers, htmlreporter, reporter, verification
from multiprocess import Manager, Process


VERSION = "3.0.0"
CODENAME = "GUNGNIR"


def setup_reports(client):
    """Create a ``reports`` directory structure for the target organization."""
    if not os.path.exists("reports/{}".format(client)):
        try:
            os.makedirs("reports/{}".format(client))
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
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
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
@odin.command(
    name="osint", short_help="The full OSINT suite of tools will be run (see README)."
)
@click.option(
    "-o",
    "--organization",
    help='The target client, such as "ABC Company," to use for report titles and searches for domains and cloud storage buckets.',
    required=True,
)
@click.option(
    "-d",
    "--domain",
    help="The target's primary domain, such as example.com. Use \
whatever the target uses for email and their main website. Provide additional domains in a scope \
file using --scope-file.",
    required=True,
)
# Optional arguments
@click.option(
    "-sf",
    "--scope-file",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    help="A text file containing additional domain names you want to include. IP addresses can also be provided, if necessary. List each one on a new line.",
    required=False,
)
@click.option(
    "--whoxy-limit",
    default=10,
    help="The maximum number of domains discovered via \
reverse WHOIS that ODIN will resolve and use when searching services like Censys and Shodan. \
You may get hundreds of results from reverse WHOIS, so this is intended to save time and \
API credits. Default is 10 domains and setting it above maybe 20 or 30 is not recommended. \
It is preferable to perform a search using a tool like Vincent Yiu's DomLink and then provide \
the newly discovered domains in your scope file with --scope-file.",
)
@click.option(
    "--whoxy", is_flag=True, help="Enable WhoXY queries to discover new domain names."
)
@click.option(
    "--history",
    is_flag=True,
    help="Enable Netcraft site review look-ups to collect historical \
IP address data for all domain names. This double the number of Netcraft requests. If you have \
or expect a large list of domain names and do not need the data, consider skipping this.",
)
@click.option(
    "--typo",
    is_flag=True,
    help="Generate a list of lookalike domain names for the \
provided domain (--domain), check if they have been registered, and then check those domains \
against URLVoid and Cymon.io to see if the domains or associated IP addresses have been \
flagged as malicious.",
)
# File searching arguments
@click.option(
    "--files",
    is_flag=True,
    help="Use this option to use Google to search for files under the provided domain (--domain), download files, and extract metadata.",
)
@click.option(
    "-e",
    "--ext",
    default="all",
    help="File extensions to look for with --file. Default is 'all' or you can pick from key, pdf, doc, docx, xls, xlsx, and ppt.",
)
# Cloud-related arguments
@click.option(
    "-w",
    "--aws",
    help="A list of additional keywords to be used when searching for cloud sotrage buckets.",
    type=click.Path(exists=True, readable=True, resolve_path=True),
)
@click.option(
    "-wf",
    "--aws-fixes",
    help="A list of strings to be added to the start and end of the cloud storage bucket names.",
    type=click.Path(exists=True, readable=True, resolve_path=True),
)
# Reporting-related arguments
@click.option(
    "--html", is_flag=True, help="Create an HTML report at the end for easy browsing."
)
@click.option(
    "--graph",
    is_flag=True,
    help="Create a Neo4j graph database from the completed SQLite3 database.",
)
@click.option(
    "--nuke",
    is_flag=True,
    help="Clear the Neo4j project before converting the database. This is only used with --graph.",
)
@click.option(
    "--unsafe",
    is_flag=True,
    help="Adding this flag will spawn the headless Chrome \
browser with the --no-sandbox command line flag. This is NOT recommended for any users who are \
NOT running ODIN on a Kali Linux VM as root. Chrome will not run as the root user on Kali \
without this option.",
)
@click.option(
    "--verbose", is_flag=True, help="Set logging levels to INFO for verbose output",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Set logging levels to DEBUG for super verbose output",
)
# Pass the above arguments on to your osint function
@click.pass_context
def osint(
    self,
    organization,
    domain,
    files,
    ext,
    scope_file,
    aws,
    aws_fixes,
    html,
    graph,
    nuke,
    history,
    whoxy,
    whoxy_limit,
    typo,
    unsafe,
    verbose,
    debug,
):
    """
The OSINT toolkit:

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
    click.secho(
        "[+] OSINT Module Selected: ODIN will run all recon modules.", fg="green"
    )
    # Perform prep work for reporting
    setup_reports(organization)
    report_path = "reports/{}/".format(organization)
    output_report = report_path + "OSINT_DB.db"

    if __name__ == "__main__":
        logging_level = logging.WARNING
        if verbose:
            logging_level = logging.INFO
        if debug:
            logging_level = logging.DEBUG

        # Setup logging output based on verbose option
        logging.basicConfig(
            format="%(asctime)s %(levelname)s: %(name)s: %(message)s",
            level=logging_level,
            datefmt="%H:%M:%S",
            stream=sys.stderr,
        )

        # Create reporter object and generate lists of everything, just IP addresses, and just domains
        browser = helpers.setup_headless_chrome(unsafe)
        report = reporter.Reporter(
            organization=organization,
            domain=domain,
            scope_file=scope_file,
            report_path=report_path,
            report_name=output_report,
            webdriver=browser,
        )

        report.create_tables()

        # Phase 0 – Seed the reporter with the domain name and scope file
        scope, ip_list, domain_list = report.prepare_scope()

        # Phase 1 – Collect company information
        report.report_fullcontact()

        # Phase 2 – Begin collecting domain data
        report.report_whois(whoxy=whoxy, whoxy_limit=whoxy_limit)
        report.report_dns()

        # Phase 3 – Search for subdomains of all known domain names
        report.report_netcraft()
        report.report_dumpster()
        report.report_spyse()

        if history:
            report.report_netcraft_history()

        report.report_certificates_censys()
        report.report_certificates_crtsh()
        report.uniq_subdomains()
        report.report_subdomains()
        report.report_takeovers()

        # Phase 4 – Review resolved IP addresses with RDAP and Shodan
        report.report_rdap()
        report.report_shodan()

        # Phase 5 – Search for cloud storage
        report.report_cloud(wordlist=aws, fix_wordlist=aws_fixes)

        # All jobs are done, so close out the SQLite3 database connection
        report.close_out_reporting()

        click.secho(
            "[+] Job's done! Your results are in {} and can be viewed and queried with any SQLite browser.".format(
                output_report
            ),
            fg="green",
        )
        # Perform additional tasks depending on the user's command line options
        if graph:
            graph_reporter = grapher.Grapher(output_report)
            click.secho(
                "[+] Loading ODIN database file {} for conversion to Neo4j".format(
                    output_report
                ),
                fg="green",
            )
            if nuke:
                if click.confirm(
                    click.style(
                        "[!] You set the --nuke option. This wipes out all nodes for a fresh start. Proceed?",
                        fg="red",
                    ),
                    default=True,
                ):
                    try:
                        graph_reporter.clear_neo4j_database()
                        click.secho("[+] Database successfully wiped!\n", fg="green")
                    except Exception as error:
                        click.secho(
                            "[!] Failed to clear the database! Check the Neo4j console and your configuration and try running grapher.py again.",
                            fg="red",
                        )
                        click.secho("L.. Details: {}".format(error), fg="red")
                else:
                    click.secho(
                        "[!] You can convert your database to a graph database later. Run lib/grapher.py with the appropriate options.",
                        fg="red",
                    )
            try:
                graph_reporter.convert()
            except Exception as error:
                click.secho(
                    "[!] Failed to convert the database! Check the Neo4j console and your configuration and try running grapher.py again.",
                    fg="red",
                )
                click.secho("L.. Details: {}".format(error), fg="red")
        if html:
            click.secho(
                "[+] Creating the HTML report using {}.".format(output_report),
                fg="green",
            )
            try:
                html_reporter = htmlreporter.HTMLReporter(
                    organization, report_path + "/html_report/", output_report
                )
                html_reporter.generate_full_report()
            except Exception as error:
                click.secho("[!] Failed to create the HTML report!", fg="red")
                click.secho("L.. Details: {}".format(error), fg="red")


# The VERIFY module -- No OSINT, just a way to check a ownership of a list of IPs
@odin.command(
    name="verify",
    short_help="This module assists with verifying ownership of a list of IP addresses. This returns a csv file with SSL cert, WHOIS, and other data for verification.",
)
@click.option(
    "-o",
    "--organization",
    help='The target client, such as "ABC Company," to use for report titles and some keyword searches.',
    required=True,
)
@click.option(
    "-sf",
    "--scope-file",
    help="Name of the file with your IP addresses.",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
)
@click.option(
    "-r",
    "--report",
    default="Verification.csv",
    help="Output file (CSV) for the \
findings.",
)
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
    click.secho(
        "[+] Scope Verification Module Selected: ODIN will attempt to verify who owns the provided IP addresses.",
        fg="green",
    )
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
    click.secho(
        "[+] Job's done! Your identity report is in {}.".format(report_path), fg="green"
    )


if __name__ == "__main__":
    odin()
