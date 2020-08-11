#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module brings the other modules together for generating an SQLite3 database.
"""

import asyncio
import base64
import datetime
import logging
import os
import re
import socket
import sqlite3
from time import sleep
from xml.etree import ElementTree as ET

import click

import aiohttp
from aiohttp import ClientSession
from lib import (
    cloud_toolkit,
    dns_toolkit,
    filehunter,
    fullcontact,
    harvester,
    helpers,
    hibp,
    screenshots,
    shodan_toolkit,
    subdomain_toolkit,
    takeover_toolkit,
    typosquat,
    whois_toolkit,
)

logger = logging.getLogger(__name__)


class Reporter(object):
    """Call other modules to collect results and create a database."""

    # Shodan's rate limit is 1 request/second
    # Default of 3 is respectful – no one is in a rush
    shodan_sleep = 3

    # Have I Been Pwned's rate limit is 1500ms, but double it to be nice
    hibp_sleep = 3

    # Censys rate limits for a free account is usually 0.4 actions/second (120.0 in 5 minutes)
    # A default of 5 seconds is respectful and allows a potential second action before sleeping
    censys_sleep = 5

    scope_file = None
    scope = []
    ip_list = []
    domain_list = []
    rev_domain_list = []
    subdomains = []
    resolveable_subdomains = []

    def __init__(
        self, organization, domain, scope_file, report_path, report_name, webdriver
    ):
        """
        Everything that should be initiated with a new object goes here.

        **Parameters**

        ``organization``
            Name of the organization, used for searches and reports

        ``domain``
            Organization's primary domain name

        ``report_path``
            File path to be used for the report directory

        ``report_name``
            Name to be used for the report

        ``webdriver``
            Selenium webdriver object to be used for web request automation
        """

        self.domain = domain
        self.organization = organization
        self.scope_file = scope_file

        # Create the report database -- NOT in memory to allow for multiprocessing and archiving
        self.webdriver = webdriver
        self.report_path = report_path
        self.organization = organization

        # Initiate the new class objects
        self.full_contact = fullcontact.FullContact()
        self.whois_toolkit = whois_toolkit.Identify()
        self.dns_toolkit = dns_toolkit.DNSCollector()
        self.cert_collector = subdomain_toolkit.CertSearcher()
        self.subdomain_collector = subdomain_toolkit.SubdomainCollector(self.webdriver)
        self.takeover_analzyer = takeover_toolkit.TakeoverChecks()

        self.harvester = harvester.Harvester()
        self.cloud_hunter = cloud_toolkit.BucketHunter()
        self.lookalike_toolkit = typosquat.TypoCheck()
        self.shodan_toolkit = shodan_toolkit.ShodanTools()
        self.haveibeenpwned = hibp.HaveIBeenPwned()

        # Check if a report directory already exists for the named client
        if os.path.isfile(report_name):
            if click.confirm(
                click.style(
                    "[!] A report for this client already exists. Are you sure you want to overwrite it?",
                    fg="red",
                ),
                default=True,
            ):
                os.remove(report_name)
            else:
                click.secho("[!] Exiting...", fg="red")
                exit()
        # Connect to our database
        self.conn = sqlite3.connect(report_name)
        self.c = self.conn.cursor()

    def create_tables(self) -> None:
        """Create the SQLite3 database tables used to store the findings."""
        # Create the 'hosts' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'hosts' (
                        'id' INTEGER PRIMARY KEY,
                        'host' text,
                        'in_scope_file' text,
                        'source' text
                        );
            """
        )
        self.conn.commit()
        # Create the 'company_info' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'company_info' (
                        'company_name' text,
                        'logo' text,
                        'website' text,
                        'employee_count' text,
                        'year_founded' text,
                        'website_overview' text,
                        'corporate_keyword' text,
                        'email_address' text,
                        'phone_number' text,
                        'physical_address' text
                        )
            """
        )
        self.conn.commit()
        # Create the 'dns' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'dns' (
                        'id' INTEGER PRIMARY KEY,
                        'domain' text,
                        'subdomain' integer,
                        'ns_record' text,
                        'a_record' text,
                        'cname_record' text,
                        'mx_record' text,
                        'txt_record' text,
                        'soa_record' text,
                        'dmarc_record' text,
                        'office_365_tenant' text
                        )"""
        )
        self.conn.commit()
        # Create the 'subdomains' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'subdomains' (
                        'id' INTEGER PRIMARY KEY,
                        'domain' text,
                        'subdomain' text,
                        'domain_frontable' text,
                        'domain_takeover' text
                        )"""
        )
        self.conn.commit()
        # Create the 'certificate' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'certificates' (
                        'id' INTEGER PRIMARY KEY,
                        'host' text,
                        'subject' text,
                        'issuer' text,
                        'censys_fingerprint' text,
                        'signature_algo' text,
                        'self_signed' text,
                        'start_date' text,
                        'expiration_date' text,
                        'alternate_names' text
                        )"""
        )
        self.conn.commit()
        # Create the 'ip_history' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'ip_history' (
                        'id' INTEGER PRIMARY KEY,
                        'domain' text,
                        'netblock_owner' text,
                        'ip_address' text,
                        'last_seen' text
                        )"""
        )
        self.conn.commit()
        # Create the 'whois_data' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'whois_data' (
                        'id' INTEGER PRIMARY KEY,
                        'domain' text,
                        'registrar' text,
                        'expiration' text,
                        'organization' text,
                        'registrant' text,
                        'admin_contact' text,
                        'tech_contact' text,
                        'address' text,
                        'dns_sec' text
                        )"""
        )
        self.conn.commit()
        # Create the 'rdap_data' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'rdap_data' (
                        'id' INTEGER PRIMARY KEY,
                        'ip_address' text,
                        'rdap_source' text,
                        'organization' text,
                        'network_cidr' text,
                        'asn' text,
                        'country_code' text
                        )"""
        )
        self.conn.commit()
        # Create the 'shodan_search' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'shodan_search' (
                        'id' INTEGER PRIMARY KEY,
                        'domain' text,
                        'ip_address' text,
                        'hostname' text,
                        'os' text,
                        'port' text,
                        'banner_data' text
                        )"""
        )
        self.conn.commit()
        # Create the 'shodan_host_lookup' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'shodan_host_lookup' (
                        'id' INTEGER PRIMARY KEY,
                        'ip_address' text,
                        'os' text,
                        'organization' text,
                        'port' text,
                        'banner_data' text
                        )"""
        )
        self.conn.commit()
        # Create the 'cloud' table
        self.c.execute(
            """CREATE TABLE IF NOT EXISTS 'cloud' (
                        'name' text,
                        'bucket_uri' text,
                        'bucket_arn' text,
                        'publicly_accessible' text
                        )"""
        )
        self.conn.commit()
        # Create the 'email_address' table
        # self.c.execute(
        #     """CREATE TABLE IF NOT EXISTS 'email_addresses' (
        #                 'email_address' text,
        #                 'breaches' text,
        #                 'pastes' text
        #                 )"""
        # )
        # self.conn.commit()
        # self.conn.commit()
        # Create the 'file_metadata' table
        # self.c.execute(
        #     """CREATE TABLE IF NOT EXISTS 'file_metadata' (
        #                 'filename' text,
        #                 'creation_date' text,
        #                 'author' text,
        #                 'produced_by' text,
        #                 'modification_date' text
        #                 )"""
        # )
        # self.conn.commit()
        # Create the 'lookalike' table
        # self.c.execute(
        #     """CREATE TABLE IF NOT EXISTS 'lookalike' (
        #                 'domain' text,
        #                 'rank' text,
        #                 'a_record' text,
        #                 'mx_record' text,
        #                 'hostname' text,
        #                 'domain_age' text,
        #                 'google_rank' text,
        #                 'alexa_rank' text,
        #                 'asn' text,
        #                 'asn_name' text,
        #                 'urlvoid_hit' text,
        #                 'urlvoid_engines' text
        #                 )"""
        # )
        # self.conn.commit()

    def close_out_reporting(self) -> None:
        """List each database tables and close the database connection."""
        # Grab all table names for confirmation
        self.c.execute("SELECT NAME FROM sqlite_master WHERE TYPE = 'table'")
        written_tables = self.c.fetchall()
        for table in written_tables:
            logger.info(
                'The "{table_name}" table was created successfully.'.format(
                    table_name=table[0]
                )
            )
        # Close the connection to the database
        self.conn.close()
        logger.info("Closed connection to the database")

    def prepare_scope(self) -> list:
        """
        Split the provided scope file into IP addresses and domain names.
        """
        # Generate the scope lists from the supplied scope file, if there is one
        if self.scope_file:
            self.scope = helpers.generate_scope(self.scope_file)
            logger.info(
                "Processed the provided scope file, {sf}".format(sf=self.scope_file)
            )

        if self.domain:
            # Just in case the provided domain is not in the scope file, it's added here
            if not any(self.domain in d for d in self.scope):
                self.scope.append(self.domain)
                logger.info(
                    "Added provided domain, {domain}, to the scope".format(
                        domain=self.domain
                    )
                )
        # Create lists of IP addresses and domain names from the scope
        for item in self.scope:
            if helpers.is_ip(item):
                self.ip_list.append(item)
            elif item == "":
                pass
            else:
                self.domain_list.append(item)
        # Insert all currently known addresses and domains into the hosts table
        for target in self.scope:
            self.c.execute(
                "INSERT INTO hosts VALUES (NULL, ?, ?, ?)", (target, True, "Scope File")
            )
            self.conn.commit()
            logger.debug("Inserted {target} into the hosts table".format(target=target))
        logger.info("Updated hosts table with initial domain names and IP addresses")
        logger.info(
            "Beginning with a total list of {scope_len} made up of {domain_len} domains and {ip_len} IP addresses".format(
                scope_len=len(self.scope),
                domain_len=len(self.domain_list),
                ip_len=len(self.ip_list),
            )
        )

        return self.scope, self.ip_list, self.domain_list

    def report_fullcontact(self) -> None:
        """
        Record the company information provided by the Full Contact API.

        **Parameters**

        ``domain``
            Domain name to be used for Full Contact queries
        """
        # Try to collect the info from Full Contact
        info_json = self.full_contact.full_contact_company(self.domain)
        if info_json:
            logger.info(
                "Received data from Full Contact for {domain}".format(
                    domain=self.domain
                )
            )
            logger.debug(info_json)
            try:
                # Record the data from Full Contact
                name = info_json["name"]
                logo = info_json["logo"]
                website = info_json["website"]
                if "employees" in info_json:
                    approx_employees = info_json["employees"]
                else:
                    approx_employees = None
                if "founded" in info_json:
                    year_founded = info_json["founded"]
                else:
                    year_founded = None
                if "overview" in info_json:
                    website_overview = info_json["overview"]
                else:
                    website_overview = None
                if "keywords" in info_json:
                    corp_keywords = ", ".join(info_json["keywords"])
                else:
                    corp_keywords = None
                # The NULLS will be replaced below if the data is available
                logger.debug("Inserting Full Contact data into database")
                self.c.execute(
                    "INSERT INTO company_info VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
                    (
                        name,
                        logo,
                        website,
                        approx_employees,
                        year_founded,
                        website_overview,
                        corp_keywords,
                    ),
                )
                self.conn.commit()
                # If Full Contact returned any social media info, add columns for the service(s)
                temp = []
                for profile in info_json["details"]["profiles"]:
                    service = profile
                    logger.info(
                        "Found a {service} profile for this company".format(
                            service=service
                        )
                    )
                    profile_url = info_json["details"]["profiles"][profile]["url"]
                    # Check if we already have a column for this social media service and append if so
                    if service in temp:
                        self.c.execute(
                            "UPDATE company_info SET %s = %s || ', ' || '%s'"
                            % (service, service, profile_url)
                        )
                        self.conn.commit()
                    else:
                        self.c.execute(
                            "ALTER TABLE company_info ADD COLUMN " + service + " text"
                        )
                        self.conn.commit()
                        self.c.execute(
                            "UPDATE company_info SET '%s' = '%s'"
                            % (service, profile_url)
                        )
                        self.conn.commit()
                        temp.append(service)
                logger.debug(temp)
                # Update the table with information that is not always available
                if "emails" in info_json["details"]:
                    logger.info("Looking for email addresses for this company")
                    email_addresses = []
                    for email in info_json["details"]["emails"]:
                        email_addresses.append(email["value"])
                    self.c.execute(
                        "UPDATE company_info SET email_address = '%s'"
                        % (", ".join(email_addresses))
                    )
                    self.conn.commit()
                    logger.debug(email_addresses)
                if "phones" in info_json["details"]:
                    logger.info("Looking for phone numbers for this company")
                    phone_numbers = []
                    for number in info_json["details"]["phones"]:
                        phone_numbers.append(number["value"])
                    self.c.execute(
                        "UPDATE company_info SET phone_number = '%s'"
                        % (", ".join(phone_numbers))
                    )
                    self.conn.commit()
                if "locations" in info_json["details"]:
                    logger.info("Looking for locations for this company")
                    for address in info_json["details"]["locations"]:
                        complete = ""
                        for key, value in address.items():
                            if key == "region":
                                complete += "{}, ".format(value)
                            elif key == "country":
                                complete += "{}, ".format(value)
                            elif key == "label":
                                pass
                            else:
                                complete += "{}, ".format(value)
                    self.c.execute(
                        "UPDATE company_info SET physical_address = '%s'" % (complete)
                    )
                    self.conn.commit()
            except Exception as error:
                click.secho(
                    "[!] Full Contact returned no data for {}.".format(self.domain),
                    fg="red",
                )
                logger.debug(error)
        else:
            self.c.execute(
                "INSERT INTO company_info VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                (self.organization,),
            )
            self.conn.commit()
            logger.info("Created company_info table without any Full Contact data")
        logger.info("Completed the collection and review of the Full Contact data")

    def report_whois(self, whoxy, whoxy_limit) -> None:
        """
        Perform WHOIS queries using legacy WHOIS and the WhoXY API and record results.

        **Parameters**

        ``whoxy``
            Boolean flag to enable WhoXY reverse WHOIS look-ups

        ``whoxy_limit``
            Integer value to limit the number of reverse WHOIS look-ups
        """
        # Get whois records and lookup other domains registered to the same org
        logger.info(
            "Performing WHOIS queries for all %s domain names", len(self.domain_list)
        )
        for domain in self.domain_list:
            results = {}
            try:
                # Run whois lookup using standard whois
                results = self.whois_toolkit.query_whois(domain)
                logger.info(
                    "Executing legacy WHOIS query for {domain}".format(domain=domain)
                )
                if results:
                    logger.debug(results)
                    # Check if more than one expiration date is returned, it happens
                    if isinstance(results["expiration_date"], datetime.date):
                        expiration_date = results["expiration_date"]
                    # We have a list, so break-up list into human readable dates and times
                    else:
                        expiration_date = []
                        for date in results["expiration_date"]:
                            expiration_date.append(date.strftime("%Y-%m-%d %H:%M:%S"))
                        expiration_date = ", ".join(expiration_date)
                    registrar = results["registrar"]
                    whois_org = results["org"]
                    registrant = results["registrant"]
                    admin_email = results["admin_email"]
                    tech_email = results["tech_email"]
                    address = results["address"].rstrip()
                    if results["dnssec"] is None:
                        dnssec = None
                    elif results["dnssec"] == "unsigned":
                        dnssec = results["dnssec"]
                    else:
                        dnssec = ", ".join(results["dnssec"])
                    # Insert the results into the tableExcept
                    self.c.execute(
                        "INSERT INTO whois_data VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            domain,
                            registrar,
                            expiration_date,
                            whois_org,
                            registrant,
                            admin_email,
                            tech_email,
                            address,
                            dnssec,
                        ),
                    )
                    self.conn.commit()
                    logger.debug(
                        "Inserted WHOIS data for {domain}".format(domain=domain)
                    )
            except Exception as error:
                error_messages.append(
                    "[!] There was an error with WHOIS lookup for {}: {}".format(
                        domain, error
                    )
                )
                logger.error(
                    "Legacy WHOIS lookup failed for {domain}: ".format(domain=domain)
                )
            # If whois failed, try a WhoXY whois lookup
            # This is only done if whois failed so we can save on API credits
            if whoxy and not results:
                logger.info(
                    "Legacy WHOIS look-up failed, so ttrying WhoXY for {domain}".format(
                        domain=domain
                    )
                )
                try:
                    # Run a whois lookup using the WhoXY API
                    whoxy_results = self.whois_toolkit.query_whoxy_whois(domain)
                    if whoxy_results:
                        registrar = whoxy_results["registrar"]
                        expiration_date = whoxy_results["expiry_date"]
                        whoxy_org = whoxy_results["organization"]
                        registrant = whoxy_results["registrant"]
                        address = whoxy_results["address"]
                        admin_contact = whoxy_results["admin_contact"]
                        tech_contact = whoxy_results["tech_contact"]
                        self.c.execute(
                            "INSERT INTO whois_data VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                            (
                                domain,
                                registrar,
                                expiration_date,
                                whoxy_org,
                                registrant,
                                admin_contact,
                                tech_contact,
                                address,
                            ),
                        )
                        self.conn.commit()
                except Exception as error:
                    logger.error(
                        "There was an error running WhoXY WHOIS for {domain}".format(
                            domain=domain
                        )
                    )

            # Fetch any organization names found from whois lookups and the provided organization
            all_orgs = []
            logger.info("Getting all organizations discovered via WHOIS data")
            self.c.execute("SELECT organization FROM whois_data")
            whois_orgs = self.c.fetchall()
            for org in whois_orgs:
                if org[0]:
                    all_orgs.append(org[0])
            # Check if user-declared org name is in the list and add it if it is not
            if not self.organization in all_orgs:
                all_orgs.append(self.organization)
            logger.debug(all_orgs)
            # Loop over org names to perform reverse WhoXY WHOIS look-ups
            for org_name in all_orgs:
                if org_name == "N/A":
                    continue
                # We definitely do not want to do a reverse lookup for every domain linked to a domain
                # privacy organization, so attempt to filter those
                whois_privacy = [
                    "privacy",
                    "private",
                    "proxy",
                    "whois",
                    "guard",
                    "muumuu",
                    "dreamhost",
                    "protect",
                    "registrant",
                    "aliyun",
                    "internet",
                    "whoisguard",
                    "perfectprivacy",
                    "N/A",
                ]
                # Split-up the org name and test if any piece matches a whois privacy keyword
                if (
                    whoxy
                    and org_name is not "N/A"
                    and not any(
                        x.strip(", ").strip().lower() in whois_privacy
                        for x in org_name.split(" ")
                    )
                ):
                    logger.info(
                        "Performing WhoXY reverse domain lookup with organization name %s",
                        org_name,
                    )
                    try:
                        # Try to find other domains using the organization name from the whois record
                        (
                            reverse_whoxy_results,
                            total_results,
                        ) = self.whois_toolkit.query_whoxy_company(org_name)
                        logger.debug(reverse_whoxy_results)
                        if reverse_whoxy_results:
                            if total_results > whoxy_limit:
                                logger.info(
                                    'WhoXY returned %s reverse WHOIS results for %s (limit was %s): Review these in the "whois_data" table and consider running ODIN again with a list of domains you find interesting (using the -sf option))',
                                    total_results,
                                    org_name,
                                    whoxy_limit,
                                )
                            else:
                                logger.info(
                                    "WhoXY returned %s reverse WHOIS results for %s which is under your limit of %s",
                                    total_results,
                                    org_name,
                                    whoxy_limit,
                                )
                            # Process the results and determine if they will be used for asset discovery
                            logger.info(
                                "Processing domain names from WhoXY reverse WHOIS results"
                            )
                            for result in reverse_whoxy_results:
                                rev_domain = reverse_whoxy_results[result]["domain"]
                                registrar = reverse_whoxy_results[result]["registrar"]
                                expiration_date = reverse_whoxy_results[result][
                                    "expiry_date"
                                ]
                                org = reverse_whoxy_results[result]["organization"]
                                registrant = reverse_whoxy_results[result]["registrant"]
                                address = reverse_whoxy_results[result]["address"]
                                admin_contact = reverse_whoxy_results[result][
                                    "admin_contact"
                                ]
                                tech_contact = reverse_whoxy_results[result][
                                    "tech_contact"
                                ]
                                # Add whois data for any new domain names to the database
                                if not rev_domain in self.domain_list:
                                    self.c.execute(
                                        "INSERT INTO whois_data VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                                        (
                                            rev_domain,
                                            registrar,
                                            expiration_date,
                                            org,
                                            registrant,
                                            admin_contact,
                                            tech_contact,
                                            address,
                                        ),
                                    )
                                    self.conn.commit()
                                    # If whoxy-limit allows, add the rev domain(s) to the master list
                                    if not total_results > whoxy_limit:
                                        self.domain_list.append(rev_domain)
                                        self.rev_domain_list.append(rev_domain)
                                        self.c.execute(
                                            "INSERT INTO hosts VALUES (NULL, ?, ?, ?)",
                                            (rev_domain, False, "WhoXY"),
                                        )
                                        self.conn.commit()
                    except Exception as error:
                        logger.error(
                            "Encountered an error while running WhoXY reverse WHOIS for %s",
                            org_name,
                        )
                        logger.debug(error)
                else:
                    if whoxy:
                        logger.warning(
                            "Skipped %s because it looked like a WHOIS privacy org",
                            org_name,
                        )

    async def _prepare_async_dns(
        self, domains: list, record_types: list, o365: bool
    ) -> list:
        """
        Prepare asynchronous DNS queries for a list of domain names.

        **Parameters**

        ``domains``
            List of domain names

        ``record_types``
            List of record types represented as strings (e.g., ["A", "TXT"])

        ``o365``
            Boolean to add DNS queries to check for Office 365 tenants
        """
        tasks = []
        # For each domain, create a task for each DNS record of interest
        for domain in domains:
            for record_type in record_types:
                tasks.append(
                    self.dns_toolkit.fetch_dns_record(
                        domain=domain, record_type=record_type
                    )
                )
            if o365:
                tasks.append(self.dns_toolkit.check_office_365(domain=domain))
        # Gather all tasks for execution
        all_tasks = await asyncio.gather(*tasks)
        return all_tasks

    def _run_async_dns(self, domains: list, record_types: list, o365: bool) -> dict:
        """
        Execute asynchronous DNS queries for a list of domain names.

        ``domains``
            List of domain names

        ``record_types``
            List of record types represented as strings (e.g., ["A", "TXT"])

        ``o365``
            Boolean to add DNS queries to check for Office 365 tenants
        """
        # Setup an event loop
        event_loop = asyncio.get_event_loop()
        # Use an event loop (instead of ``asyncio.run()``) to easily get list of results
        results = event_loop.run_until_complete(
            self._prepare_async_dns(
                domains=domains, record_types=record_types, o365=o365
            )
        )
        # Result is a list of dicts – seven for each domain name
        combined = {}
        # Combine all dicts with the same domain name
        for res in results:
            for key, value in res.items():
                if key in combined:
                    combined[key].update(value)
                else:
                    combined[key] = {}
                    combined[key].update(value)
        return combined

    def report_dns(self) -> None:
        """
        Execute asynchronous DNS queries for all known domains names and record results.
        """
        record_types = ["A", "NS", "MX", "TXT", "CNAME", "SOA", "DMARC"]

        dns_records = self._run_async_dns(
            domains=self.domain_list, record_types=record_types, o365=True
        )

        for domain in self.domain_list:
            if domain in dns_records:
                a_record = dns_records[domain]["a_record"]
                mx_record = dns_records[domain]["mx_record"]
                ns_record = dns_records[domain]["ns_record"]
                txt_record = dns_records[domain]["txt_record"]
                soa_record = dns_records[domain]["soa_record"]
                cname_record = dns_records[domain]["cname_record"]
                dmarc_record = dns_records[domain]["dmarc_record"]
                o365_tenant = dns_records[domain]["o365"]["tenant_uri"]

                # Make a temporary list of A record IP addresses
                temp = []
                if isinstance(a_record, list):
                    for record in a_record:
                        temp.append(record)
                else:
                    temp.append(a_record)

                # Check if A record IP addresses are already known
                for record in temp:
                    self.c.execute(
                        "SELECT count(*) FROM hosts WHERE host=?", (record,),
                    )
                    res = self.c.fetchone()
                    if res[0] == 0:
                        logger.info(
                            "Found a new IP address: {address}".format(address=record)
                        )
                        self.c.execute(
                            "INSERT INTO 'hosts' VALUES (NULL, ?, ?, ?)",
                            (record, False, "Domain DNS"),
                        )
                        self.conn.commit()
                        # Also add new IP addressess to the master list
                        if not record in self.ip_list:
                            self.ip_list.append(record)

                # Check for lists because SQLite3 won't accept list as a field value
                if isinstance(a_record, list):
                    a_record = ", ".join(a_record)
                if isinstance(mx_record, list):
                    mx_record = ", ".join(mx_record)
                if isinstance(ns_record, list):
                    ns_record = ", ".join(ns_record)
                if isinstance(txt_record, list):
                    txt_record = ", ".join(txt_record)
                if isinstance(soa_record, list):
                    soa_record = ", ".join(soa_record)
                if isinstance(cname_record, list):
                    cname_record = ", ".join(cname_record)
                if isinstance(dmarc_record, list):
                    dmarc_record = ", ".join(dmarc_record)

                # Insert the DNS record data into the table
                is_subdomain = False
                self.c.execute(
                    "INSERT INTO 'dns' VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        domain,
                        is_subdomain,
                        ns_record,
                        a_record,
                        cname_record,
                        mx_record,
                        txt_record,
                        soa_record,
                        dmarc_record,
                        o365_tenant,
                    ),
                )
                self.conn.commit()

    def report_spyse(self) -> None:
        """
        Execute the Spyse queries to discover subdomains.
        """
        for domain in self.domain_list:
            spyse_results = []
            try:
                logger.info(
                    "Querying Spyse for subdomains of {domain}".format(domain=domain)
                )
                spyse_results = self.subdomain_collector.query_spyse(domain)
            except Exception as error:
                logger.error(
                    "There was a problem collecting results from Spyse for {domain}.".format(
                        domain=domain
                    )
                )

            # Loop over the results and append to master list
            if spyse_results:
                for subdomain in spyse_results:
                    self.subdomains.append(subdomain)
            logger.info("Subdomains so far: %s", set(self.subdomains))

    def report_dumpster(self) -> None:
        """
        Execute the DNS Dumpster queries to discover subdomains.
        """
        for domain in self.domain_list:
            dumpster_results = []
            try:
                logger.info(
                    "Querying DNS Dumpster for subdomains of {domain}".format(
                        domain=domain
                    )
                )
                dumpster_results = self.subdomain_collector.query_dns_dumpster(domain)
            except Exception as error:
                logger.error(
                    "There was a problem collecting results from DNS Dumpster for {domain}.".format(
                        domain=domain
                    )
                )

            # Check DNS Dumpster data
            if dumpster_results:
                # See if we can save the domain map from DNS Dumpster
                if dumpster_results["image_data"]:
                    with open(
                        self.report_path + domain + "_Domain_Map.png", "wb"
                    ) as fh:
                        fh.write(base64.decodebytes(dumpster_results["image_data"]))
                # Record the info from DNS Dumpster
                for result in dumpster_results["dns_records"]["host"]:
                    if result["reverse_dns"]:
                        subdomain = result["domain"]
                    else:
                        subdomain = result["domain"]
                    # Avoid adding the base domain to our subdomains list
                    if not bool(
                        re.search(
                            "^" + re.escape(domain),
                            subdomain.rstrip("HTTP:"),
                            re.IGNORECASE,
                        )
                    ):
                        # Some DNS Dumpster results will have an "HTTP:" stuck on the end
                        self.subdomains.append(subdomain.rstrip("HTTP:"))
        logger.info("Subdomains so far: %s", set(self.subdomains))

    def report_netcraft(self) -> None:
        """
        Execute the Netcraft queries to discover subdomains.
        """
        logger.info("Searching Netcraft for domains")
        for domain in self.domain_list:
            netcraft_results = []
            try:
                netcraft_results = self.subdomain_collector.query_netcraft(domain)
                logger.debug(netcraft_results)
            except Exception as error:
                logger.error(
                    "There was a problem collecting results from Netcraft for {domain}.".format(
                        domain=domain
                    )
                )

            # Check Netcraft data
            if netcraft_results:
                for key, value in netcraft_results.items():
                    # Avoid adding the base domain to our subdomains list
                    if value["site"] != domain:
                        self.subdomains.append(value["site"])
        logger.info("Subdomains so far: %s", set(self.subdomains))

    def report_netcraft_history(self) -> None:
        """
        Execute the Spyse queries to discover domain IP address history.
        """
        logger.info("Searching Netcraft for domain history records")
        for domain in self.domain_list:
            ip_history = []
            try:
                ip_history = self.subdomain_collector.query_netcraft_history(domain)
                logger.debug(ip_history)
            except:
                logger.error(
                    "Encounterd a problem collecting domain history from Netcraft for %s (timeouts are common with this request)",
                    domain,
                )

            if ip_history:
                for key, value in ip_history.items():
                    net_owner = value["netblock_owner"]
                    ip_address = value["ip_address"]
                    last_seen = value["last_seen"]
                    self.c.execute(
                        "INSERT INTO ip_history VALUES (NULL, ?, ?, ?, ?)",
                        (domain, net_owner, ip_address, last_seen),
                    )
                    self.conn.commit()

    def report_certificates_censys(self) -> None:
        """
        Execute the Censys queries to discover certificates and parse subdomains.
        """
        logger.info("Starting censys.io searches for certificates")
        for domain in self.domain_list:
            discovered_subdomains = []
            # Try to collect certificate data for the domain
            try:
                # Search for certificates catalogued by censys.io
                cert_data = self.cert_collector.query_censys_certificates(domain)
                if cert_data:
                    logger.info(
                        "Retrieved certificate data for %s from censys.io", domain
                    )
                    try:
                        for cert in cert_data:
                            issuer = cert["parsed.issuer_dn"]
                            subject = cert["parsed.subject_dn"]
                            parsed_names = cert["parsed.names"]
                            exp_date = cert["parsed.validity.end"]
                            start_date = cert["parsed.validity.start"]
                            fingerprint = cert["parsed.fingerprint_sha256"]
                            self_signed = cert["parsed.signature.self_signed"]
                            signature_algo = cert["parsed.signature_algorithm.name"]
                            cert_domain = self.cert_collector.parse_cert_subdomain(
                                subject
                            )
                            # Insert the certificate data into the ``certificates`` table
                            self.c.execute(
                                "INSERT INTO 'certificates' VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    cert_domain,
                                    subject,
                                    issuer,
                                    fingerprint,
                                    signature_algo,
                                    self_signed,
                                    start_date,
                                    exp_date,
                                    ", ".join(parsed_names),
                                ),
                            )
                            self.conn.commit()

                            # Add the collected names to the master list of subdomains
                            discovered_subdomains.append(cert_domain)
                            discovered_subdomains.extend(parsed_names)
                    except Exception as error:
                        if "400 (max_results)" in str(error):
                            logger.warning(
                                "Censys results for %s exceeded the 1,000 record limit for free API keys, so censys returned only the first 1,000",
                                domain,
                            )
                        else:
                            logger.error(
                                "Encountered an error contacting censys.io for %s",
                                domain,
                            )
                        pass
                    # Filter out unwanted domains, duplicates, and wildcards
                    discovered_subdomains = self.cert_collector.filter_subdomains(
                        domain=domain, subdomains=discovered_subdomains
                    )
                    self.subdomains.extend(discovered_subdomains)
            except:
                logger.error("Encountered an error contacting censys.io for %s", domain)
                pass

            # Sleep for Censys rate limits
            sleep(self.censys_sleep)

        logger.info("Subdomains so far: %s", set(self.subdomains))

    def report_certificates_crtsh(self) -> None:
        """
        Execute the Crt.sh queries to discover certificates and parse subdomains.
        """
        logger.info("Starting crt.sh searches for certificates")
        for domain in self.domain_list:
            discovered_subdomains = []
            try:
                # Search for certificates catalogued by crt.sh
                cert_data = self.cert_collector.query_crtsh(domain, True)
                if cert_data:
                    for cert in cert_data:
                        try:
                            exp_date = cert["not_after"]
                            name_value = cert["name_value"]
                            start_date = cert["not_before"]
                            issuer = cert["issuer_name"].replace('"', "")
                            # Try to avoid dupes by only recording this if the crt.sh ``name_value`` field is unknown
                            # Crt.sh does not have fingerprints for comparison with Censys results
                            if name_value not in self.subdomains:
                                self.c.execute(
                                    "INSERT INTO 'certificates' VALUES (NULL, ?, NULL, ?, NULL, NULL, NULL, ?, ?, ?)",
                                    (domain, issuer, start_date, exp_date, name_value,),
                                )
                                self.conn.commit()
                                discovered_subdomains.append(name_value)
                        except:
                            logger.error(
                                "Encountered an error contacting crt.sh for {domain}".format(
                                    domain=domain
                                )
                            )
                            pass
                    # Filter out unwanted domains, duplicates, and wildcards
                    discovered_subdomains = self.cert_collector.filter_subdomains(
                        domain=domain, subdomains=discovered_subdomains
                    )
                    self.subdomains.extend(discovered_subdomains)
            except:
                logger.error(
                    "Encountered an error contacting crt.sh for {domain}".format(
                        domain=domain
                    )
                )
                pass

            # Sleep between domains to be respectful
            sleep(self.censys_sleep)

        logger.info("Subdomains so far: %s", set(self.subdomains))

    def uniq_subdomains(self) -> None:
        """
        Remove duplicates from the master list of subdomains.
        """
        self.subdomains = set(self.subdomains)
        logger.debug("Unique subdomains: %s", self.subdomains)

    def report_subdomains(self) -> None:
        """
        Resolve all subdomains, perform takeover checks, and record results.
        """
        logger.info("Preparing to fetch A and CNAME records for all subdomains")

        # Only A and CNAME records to look for new IP addresses or takeover ops
        record_types = ["A", "CNAME"]

        dns_records = self._run_async_dns(
            domains=self.subdomains, record_types=record_types, o365=False
        )

        for subdomain in self.subdomains:
            logger.info("Resolving and recording %s", subdomain)
            # All subdomains should be in here even if they have no records
            if subdomain in dns_records:
                a_record = dns_records[subdomain]["a_record"]
                cname_record = dns_records[subdomain]["cname_record"]

                # Make a temporary list of A record IP addresses
                temp = []
                if isinstance(a_record, list):
                    for record in a_record:
                        temp.append(record)
                else:
                    temp.append(a_record)

                # Check if A record IP addresses are already known
                for record in temp:
                    if helpers.is_ip(record):
                        # Resolved to an IP address, so track it
                        self.resolveable_subdomains.append(subdomain)
                        # Check if the IP address is already in the database
                        self.c.execute(
                            "SELECT count(*) FROM hosts WHERE host=?", (record,),
                        )
                        res = self.c.fetchone()
                        if res[0] == 0:
                            logger.info(
                                "Found a new IP address: {address}".format(
                                    address=record
                                )
                            )
                            self.c.execute(
                                "INSERT INTO 'hosts' VALUES (NULL, ?, ?, ?)",
                                (record, False, "Subdomain DNS"),
                            )
                            self.conn.commit()
                            # Also add new IP addressess to the master list
                            if not record in self.ip_list:
                                self.ip_list.append(record)

                # Check A and CNAME records for hints of domain fronting or takeover ops
                frontable = False
                can_takeover = False
                # Check A records and then CNAME if no hits
                frontable = self.takeover_analzyer.check_domain_fronting(
                    dns_record=a_record
                )
                if frontable["result"] is False:
                    frontable = self.takeover_analzyer.check_domain_fronting(
                        dns_record=a_record
                    )
                if frontable["result"] is True:
                    frontable = "{service} ({dns_record})".format(
                        service=frontable["service"], dns_record=frontable["record"]
                    )
                else:
                    frontable = frontable["result"]

                # Check for lists because SQLite3 won't accept list as a field value
                if isinstance(a_record, list):
                    a_record = ", ".join(a_record)
                if isinstance(cname_record, list):
                    cname_record = ", ".join(cname_record)

                # Record the results for this subdomain
                domain = ".".join(subdomain.split(".")[-2:])
                self.c.execute(
                    "INSERT INTO 'subdomains' VALUES (NULL, ?, ?, ?, ?)",
                    (domain, subdomain, frontable, can_takeover),
                )
                self.conn.commit()

                # Insert the DNS record data into the table
                is_subdomain = True
                self.c.execute(
                    "INSERT INTO 'dns' VALUES (NULL, ?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, NULL)",
                    (subdomain, is_subdomain, a_record, cname_record,),
                )
                self.conn.commit()
            else:
                logger.error(
                    "This domain was not found in the DNS results: {domain}".format(
                        domain=subdomain
                    )
                )

    async def _prepare_async_takeover_analysis(self, domains: list) -> list:
        """
        Prepare asynchronous web requests for a list of subdomains.

        **Parameters**

        ``domains``
            List of domain names
        """
        # Create a task for each subdomain in the list using the same ClientSession
        async with ClientSession() as session:
            tasks = []
            for domain in domains:
                tasks.append(
                    self.takeover_analzyer.check_domain_takeover(
                        domain=domain, session=session, ssl=False
                    )
                )
            # Gather all tasks for execution
            all_tasks = await asyncio.gather(*tasks)
        return all_tasks

    def _run_async_takeover_analysis(self, domains: list) -> dict:
        """
        Execute asynchronous web requests for all resolveable subdomains to check for
        potential takeover opportunities.

        ``domains``
            List of domain names
        """
        # Setup an event loop
        event_loop = asyncio.get_event_loop()

        # Use an event loop (instead of ``asyncio.run()``) to easily get list of results
        results = event_loop.run_until_complete(
            self._prepare_async_takeover_analysis(domains=domains)
        )
        return results

    def report_takeovers(self) -> None:
        """
        Execute subdomain analysis for takeover opportunities and record the results.
        """
        logger.info(
            "Beginning takeover checks with %s resolveable subdomains",
            len(self.resolveable_subdomains),
        )
        # Remove any duplicates in the master list
        self.resolveable_subdomains = set(self.resolveable_subdomains)

        # Check if any of the resoveable subdomains are vulnerable to takeover
        results = self._run_async_takeover_analysis(domains=self.resolveable_subdomains)

        for result in results:
            for subdomain, verdict in result.items():
                if verdict["result"]:
                    # Update database with results
                    self.c.execute(
                        "UPDATE 'subdomains' SET domain_takeover=? WHERE subdomain=?",
                        (verdict["service"], subdomain),
                    )
                else:
                    logger.debug("Verdict was False for %s so no update", subdomain)

    def report_rdap(self) -> None:
        """
        Execute RDAP queries for all IP addresses and record the results.
        """
        # The RDAP lookups are only for IPs
        for target in self.ip_list:
            try:
                if helpers.is_ip(target):
                    logger.info("Performing an RDAP query for %s", target)
                    # Log RDAP lookups
                    results = None
                    results = self.whois_toolkit.query_rdap(target)
                    if results:
                        rdap_source = results["asn_registry"]
                        org = results["network"]["name"]
                        net_cidr = results["network"]["cidr"]
                        asn = results["asn"]
                        country_code = results["asn_country_code"]
                        self.c.execute(
                            "INSERT INTO rdap_data VALUES (NULL, ?, ?, ?, ?, ?, ?)",
                            (target, rdap_source, org, net_cidr, asn, country_code,),
                        )
                        self.conn.commit()
                else:
                    continue
            except Exception as error:
                logger.error("RDAP lookup failed for {target}".format(target=target))

    def report_shodan(self) -> None:
        """
        Record Shodan search results in the SQLite3 database.

        **Parameters**

        ``ip_list``
            List of IP addresses

        ``domain_list``
            List of domain names
        """
        num_of_addresses = len(self.ip_list)
        seconds = num_of_addresses * self.shodan_sleep
        minutes = round(seconds / 60, 2)
        logger.warning(
            "ODIN has %s IP addresses, so Shodan searches will require approx %s minutes with the %s second API request delay",
            num_of_addresses,
            minutes,
            self.shodan_sleep,
        )
        # Go through the domain list for Shodan searches
        for domain in self.domain_list:
            try:
                logger.info("Searching Shodan for %s", domain)
                shodan_search_results = self.shodan_toolkit.search_shodan(domain)
                if shodan_search_results["total"] > 0:
                    for result in shodan_search_results["matches"]:
                        ip_address = result["ip_str"]
                        hostnames = ", ".join(result["hostnames"])
                        operating_system = result["os"]
                        port = result["port"]
                        data = result["data"]
                        self.c.execute(
                            "INSERT INTO shodan_search VALUES (NULL, ?, ?, ?, ?, ?, ?)",
                            (
                                domain,
                                ip_address,
                                hostnames,
                                operating_system,
                                port,
                                data,
                            ),
                        )
                        self.conn.commit()
                else:
                    logger.info(
                        "Shodan did not return any results for {domain}.".format(
                            domain=domain
                        )
                    )
            except:
                logger.error(
                    "Encountered an error while retrieving Shodan results for {domain}".format(
                        domain=domain
                    )
                )

            # Take a break for Shodan's rate limits
            sleep(self.shodan_sleep)

        # Go through the IP address list for Shodan searches
        for ip in self.ip_list:
            try:
                logger.info("Searching Shodan for %s", ip)
                shodan_lookup_results = self.shodan_toolkit.query_ipaddr(ip)
                if shodan_lookup_results:
                    ip_address = shodan_lookup_results["ip_str"]
                    operating_system = shodan_lookup_results.get("os", "n/a")
                    org = shodan_lookup_results.get("org", "n/a")
                    # Collect the banners
                    for item in shodan_lookup_results["data"]:
                        port = item["port"]
                        data = item["data"].rstrip()
                        self.c.execute(
                            "INSERT INTO shodan_host_lookup VALUES (NULL, ?, ?, ?, ?, ?)",
                            (ip_address, operating_system, org, port, data),
                        )
                        self.conn.commit()
            except:
                logger.error(
                    "Encountered an error while retrieving Shodan results for %s",
                    domain,
                )
            # Take a break for Shodan's rate limits
            sleep(self.shodan_sleep)

    async def _prepare_async_cloud_search(self, wordlist: list, regions: list) -> list:
        """
        Prepare asynchronous web requests using a wordlist and list of Digital Ocean regions.

        **Parameters**

        ``domains``
            List of domain names
        """
        # Create a task for each subdomain in the list using the same ClientSession
        async with ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False)
        ) as session:
            tasks = []
            for word in wordlist:
                for region in regions:
                    tasks.append(
                        self.cloud_hunter.check_space(
                            space_name=word, region=region, session=session
                        )
                    )
            # Gather all tasks for execution
            all_tasks = await asyncio.gather(*tasks)
        return all_tasks

    def _run_async_cloud_search(self, wordlist: list, regions: list) -> dict:
        """
        Execute asynchronous web requests for

        ``domains``
            List of domain names
        """
        # Setup an event loop
        event_loop = asyncio.get_event_loop()

        # Use an event loop (instead of ``asyncio.run()``) to easily get list of results
        results = event_loop.run_until_complete(
            self._prepare_async_cloud_search(wordlist=wordlist, regions=regions)
        )
        return results

    def report_cloud(self, wordlist=None, fix_wordlist=None):
        """
        Record findings related to cloud services and storage buckets.

        **Parameters**

        ``wordlist``
            Optional file with a list of keywords

        ``fix_wordlist``
            Optional file with a list of strings used for prefixes and suffixes
        """
        # Check all Digital Oceans regions
        # https://www.digitalocean.com/docs/spaces/#regional-availability
        regions = ["NYC3", "SFO2", "AMS3", "SGP1", "FRA1"]

        # Mangle the wordlists and keywords
        mangled_wordlist = self.cloud_hunter.generate_wordlst(
            client=self.organization,
            domain=self.domain,
            wordlist=wordlist,
            fix_wordlist=fix_wordlist,
        )
        logger.info(
            "Generated list of %s potential bucket names", len(mangled_wordlist)
        )
        do_space_count = len(regions) * len(mangled_wordlist)
        logger.info(
            "Performing web requests to check %s potential Digital Ocean spaces",
            do_space_count,
        )
        # Run asynchronous web requests to check Digital Ocean
        do_results = self._run_async_cloud_search(
            wordlist=mangled_wordlist, regions=regions
        )
        logger.info("Performing awscli commands to identify S3 buckets")
        aws_results = self.cloud_hunter.enumerate_buckets(wordlist=mangled_wordlist)

        all_results = []
        for bucket in do_results:
            all_results.append(bucket)
        for bucket in aws_results:
            all_results.append(bucket)

        # Write S3 Bucket table contents
        for bucket in all_results:
            logger.debug(
                "Logging bucket %s with exist value %s",
                bucket["bucketName"],
                bucket["exists"],
            )
            if bucket["exists"]:
                logger.info(
                    "Recording bucket %s to database because it exists",
                    bucket["bucketName"],
                )
                self.c.execute(
                    "INSERT INTO 'cloud' VALUES (?, ?, ?, ?)",
                    (
                        bucket["bucketName"],
                        bucket["bucketUri"],
                        bucket["arn"],
                        bucket["public"],
                    ),
                )
                self.conn.commit()
