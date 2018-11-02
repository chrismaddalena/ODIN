#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module brings the other modules together for generating an SQLite3 database.
"""

import re
import os
import sys
import socket
import base64
import sqlite3
import datetime
from time import sleep

import click
from xml.etree import ElementTree as ET

from lib import subdomains,takeovers,whois,dns,shodantools,cloud,fullcontact,harvester,filehunter,helpers,screenshots,typosquat,hibp


class Reporter(object):
    """Class that calls upon the other modules to collect results and then format a report saved as
    a SQLite3 database for easy review and queries. These results can then be converted to a Neo4j
    graph database using the grapher.py library or an HTML report using the htmlreporter.py library.
    """
    # Set sleep time for different functions
    sleep = 10
    hibp_sleep = 3

    def __init__(self,organization,report_path,report_name,webdriver):
        """Everything that should be initiated with a new object goes here.

        Parameters:
        organization    The name of the organization, used for searches and reports
        report_path     The file path to be used for the report directory
        report_name     The name to be used for the report
        webdriver       A Selenium webdriver object to be used for web request automation
        """
        # Create the report database -- NOT in memory to allow for multiprocessing and archiving
        self.webdriver = webdriver
        self.report_path = report_path
        self.organization = organization
        # Initiate the new class objects
        self.dns_toolkit = dns.DNSCollector()
        self.whois_toolkit = whois.Identify()
        self.harvester = harvester.Harvester()
        self.cloud_hunter = cloud.BucketHunter()
        self.full_contact = fullcontact.FullContact()
        self.cert_searcher = subdomains.CertSearcher()
        self.lookalike_toolkit = typosquat.TypoCheck()
        self.shodan_toolkit = shodantools.ShodanTools()
        self.takeover_analzyer = takeovers.TakeoverChecks()
        self.haveibeenpwned = hibp.HaveIBeenPwned(self.webdriver)
        self.subdomain_hunter = subdomains.SubdomainCollector(self.webdriver)
        # Check if a report directory already exists for the named client
        if os.path.isfile(report_name):
            if click.confirm(click.style("[!] A report for this client already exists. Are you \
sure you want to overwrite it?",fg="red"),default=True):
                os.remove(report_name)
            else:
                click.secho("[!] Exiting...",fg="red")
                exit()
        # Connect to our database
        self.conn = sqlite3.connect(report_name)
        self.c = self.conn.cursor()

    def create_tables(self):
        """Create the SQLite3 database tables used to store the findings."""
       # Create the 'hosts' table
        self.c.execute('''CREATE TABLE 'hosts' (
                        'id' INTEGER PRIMARY KEY, 'host_address' text,
                        'in_scope_file' text, 'source' text
                        )''')
        # Create the 'company_info' table
        self.c.execute('''CREATE TABLE 'company_info' (
                        'company_name' text, 'logo' text, 'website' text, 'employees' text,
                        'year_founded' text, 'website_overview' text, 'corporate_keyword' text,
                        'email_address' text, 'phone_number' text, 'physical_address' text
                        )''')
        # Create the 'dns' table
        self.c.execute('''CREATE TABLE 'dns' (
                        'id' INTEGER PRIMARY KEY, 'domain' text, 'ns_record' text, 'a_record' text,
                        'mx_record' text, 'txt_record' text, 'soa_record' text, 'dmarc' text,
                        'office_365_tenant' text, 'vulnerable_cache_snooping' text
                        )''')
        # Create the 'subdomains' table
        self.c.execute('''CREATE TABLE 'subdomains' (
                        'id' INTEGER PRIMARY KEY,'domain' text, 'subdomain' text, 'ip_address' text,
                        'domain_frontable' text, 'domain_takeover' text
                        )''')
        # Create the 'certificate' table
        self.c.execute('''CREATE TABLE 'certificates' (
                        'id' INTEGER PRIMARY KEY, 'host' text, 'subject' text, 'issuer' text,
                        'censys_fingerprint' text, 'signature_algo' text, 'self_signed' text,
                        'start_date' text, 'expiration_date' text, 'alternate_names' text
                        )''')
        # Create the 'ip_history' table
        self.c.execute('''CREATE TABLE 'ip_history' (
                        'id' INTEGER PRIMARY KEY, 'domain' text, 'netblock_owner' text,
                        'ip_address' text
                        )''')
        # Create the 'whois_data' table
        self.c.execute('''CREATE TABLE 'whois_data' (
                        'id' INTEGER PRIMARY KEY, 'domain' text, 'registrar' text, 'expiration' text,
                        'organization' text, 'registrant' text, 'admin_contact' text,
                        'tech_contact' text, 'address' text, 'dns_sec' text
                        )''')
        # Create the 'rdap_data' table
        self.c.execute('''CREATE TABLE 'rdap_data' (
                        'id' INTEGER PRIMARY KEY, 'ip_address' text, 'rdap_source' text,
                        'organization' text, 'network_cidr' text, 'asn' text, 'country_code' text,
                        'robtex_related_domains' text
                        )''')
        # Create the 'shodan_search' table
        self.c.execute('''CREATE TABLE 'shodan_search' (
                        'id' INTEGER PRIMARY KEY, 'domain' text, 'ip_address' text, 'hostname' text,
                        'os' text, 'port' text, 'banner_data' text
                        )''')
        # Create the 'shodan_host_lookup' table
        self.c.execute('''CREATE TABLE 'shodan_host_lookup' (
                        'id' INTEGER PRIMARY KEY, 'ip_address' text, 'os' text, 'organization' text,
                        'port' text, 'banner_data' text
                        )''')
        # Create the 'email_address' table
        self.c.execute('''CREATE TABLE 'email_addresses' (
                        'email_address' text, 'breaches' text, 'pastes' text
                        )''')
        # Create the 'twitter' table
        self.c.execute('''CREATE TABLE 'twitter' (
                        'handle' text, 'real_name' text, 'follower_count' text, 'location' text,
                        'description' text
                        )''')
        # Create the 'employee_data' table
        self.c.execute('''CREATE TABLE 'employee_data' (
                        'name' text, 'job_title' text, 'phone_number' text,
                        'linkedin_url' text
                        )''')
        # Create the 'file_metadata' table
        self.c.execute('''CREATE TABLE 'file_metadata' (
                        'filename' text, 'creation_date' text, 'author' text, 'produced_by' text,
                        'modification_date' text
                        )''')
        # Create the 'lookalike' table
        self.c.execute('''CREATE TABLE 'lookalike' (
                        'domain' text, 'rank' text, 'a_record' text, 'mx_record' text, 'cymon_hit' text,
                        'urlvoid_ip' text, 'hostname' text, 'domain_age' text, 'google_rank' text,
                        'alexa_rank' text, 'asn' text, 'asn_name' text, 'urlvoid_hit' text,
                        'urlvoid_engines' text
                        )''')
        # Create the 'cloud' table
        self.c.execute('''CREATE TABLE 'cloud' (
                        'name' text, 'bucket_uri' text, 'bucket_arn' text, 'publicly_accessible' text
                        )''')

    def close_out_reporting(self):
        """List each database tables and close the database connection."""
        # Grab all table names for confirmation
        self.c.execute("SELECT NAME FROM sqlite_master WHERE TYPE = 'table'")
        written_tables = self.c.fetchall()
        for table in written_tables:
            click.secho("[+] The {} table was created successfully.".format(table[0]),fg="green")
        # Close the connection to the database
        self.conn.close()

    def prepare_scope(self,ip_list,domain_list,scope_file=None,domain=None):
        """Split a provided scope file into IP addresses and domain names.

        Parameters:
        ip_list         A list to be used for holding IP addresses
        domain_list     A list to be used for holding domain names
        scope_file      An optional scope file to parse
        domain          An optional domain name to be added to the final scope and domain name list
        """
        # Generate the scope lists from the supplied scope file, if there is one
        scope = []
        if scope_file:
            scope = helpers.generate_scope(scope_file)
        if domain:
            # Just in case the provided domain is not in the scope file, it's added here
            if not any(domain in d for d in scope):
                scope.append(domain)
        # Create lists of IP addresses and domain names from the scope
        for item in scope:
            if helpers.is_ip(item):
                ip_list.append(item)
            elif item == "":
                pass
            else:
                domain_list.append(item)
        # Insert all currently known addresses and domains into the hosts table
        for target in scope:
            self.c.execute("INSERT INTO hosts VALUES (NULL,?,?,?)",(target,True,"Scope File"))
            self.conn.commit()
        return scope,ip_list,domain_list

    def create_company_info_table(self,domain):
        """Record the company information provided by the Full Contact API.

        Parameters:
        domain      The domain name to be used for Full Contact queries
        """
        # Try to collect the info from Full Contact
        info_json = self.full_contact.full_contact_company(domain)
        if info_json:
            try:
                # Record the data from Full Contact
                name = info_json['name']
                logo = info_json['logo']
                website = info_json['website']
                if "employees" in info_json:
                    approx_employees = info_json['employees']
                else:
                    approx_employees = None
                if "founded" in info_json:
                    year_founded = info_json['founded']
                else:
                    year_founded = None
                if "overview" in info_json:
                    website_overview = info_json['overview']
                else:
                    website_overview = None
                if "keywords" in info_json:
                    corp_keywords = ", ".join(info_json['keywords'])
                else:
                    corp_keywords = None
                # The NULLS will be replaced below if the data is available
                self.c.execute("INSERT INTO company_info VALUES (?,?,?,?,?,?,?,NULL,NULL,NULL)",
                                (name,logo,website,approx_employees,year_founded,website_overview,
                                corp_keywords))
                self.conn.commit()
                # If Full Contact returned any social media info, add columns for the service(s)
                temp = []
                for profile in info_json['details']['profiles']:
                    service = profile
                    profile_url = info_json['details']['profiles'][profile]['url']
                    # Check if we already have a column for this social media service and append if so
                    if service in temp:
                        self.c.execute("UPDATE company_info SET %s = %s || ', ' || '%s'"  % (service,service,profile_url))
                        self.conn.commit()
                    else:
                        self.c.execute("ALTER TABLE company_info ADD COLUMN " + service + " text")
                        self.c.execute("UPDATE company_info SET '%s' = '%s'" % (service,profile_url))
                        self.conn.commit()
                        temp.append(service)
                # Update the table with information that is not always available
                if "emails" in info_json['details']:
                    email_addresses = []
                    for email in info_json['details']['emails']:
                        email_addresses.append(email['value'])
                    self.c.execute("UPDATE company_info SET email_address = '%s'" % (', '.join(email_addresses)))
                    self.conn.commit()
                if "phones" in info_json['details']:
                    phone_numbers = []
                    for number in info_json['details']['phones']:
                        phone_numbers.append(number['value'])
                    self.c.execute("UPDATE company_info SET phone_number = '%s'" % (', '.join(phone_numbers)))
                    self.conn.commit()
                if "locations" in info_json['details']:
                    for address in info_json['details']['locations']:
                        complete = ""
                        for key,value in address.items():
                            if key == "region":
                                complete += "{}, ".format(value)
                            elif key == "country":
                                complete += "{}, ".format(value)
                            elif key == "label":
                                pass
                            else:
                                complete += "{}, ".format(value)
                    self.c.execute("UPDATE company_info SET physical_address = '%s'" % (complete))
                    self.conn.commit()
            except Exception as error:
                click.secho("\n[!] Full Contact returned no data for {}.".format(domain),fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
        else:
            self.c.execute("INSERT INTO company_info VALUES (?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                            (self.organization,))

    def create_domain_report_table(self,organization,scope,ip_list,domain_list,rev_domain_list,whoxy_limit):
        """Generate a domain report consisting of information like DNS records and subdomains.

        Parameters:
        organization        The name of the target organization
        scope               The full scope list output by prepare_scope()
        ip_list             The full IP address list output by prepare_scope()
        domain_list         The full domain name list output by prepare_scope()
        rev_domain_list     A list of domain names discovered via WhoXY reverse WHOIS look-ups
        whoxy_limit         An integer to limit the number of reverse WHOIS look-ups
        """
        # Get whois records and lookup other domains registered to the same org
        for domain in domain_list:
            results = {}
            try:
                # Run whois lookup using standard whois
                results = self.whois_toolkit.run_whois(domain)
                if results:
                    # Check if more than one expiration date is returned, it happens
                    if isinstance(results['expiration_date'],datetime.date):
                        expiration_date = results['expiration_date']
                    # We have a list, so break-up list into human readable dates and times
                    else:
                        expiration_date = []
                        for date in results['expiration_date']:
                            expiration_date.append(date.strftime("%Y-%m-%d %H:%M:%S"))
                        expiration_date = ", ".join(expiration_date)
                    registrar = results['registrar']
                    whois_org = results['org']
                    registrant = results['registrant']
                    admin_email = results['admin_email']
                    tech_email = results['tech_email']
                    address = results['address'].rstrip()
                    if results['dnssec'] == "unsigned":
                        dnssec = results['dnssec']
                    else:
                        dnssec = ', '.join(results['dnssec'])
                    # Insert the results into the table
                    self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                                    (domain,registrar,expiration_date,whois_org,registrant,
                                     admin_email,tech_email,address,dnssec))
                    self.conn.commit()
            except Exception as error:
                click.secho("[!] There was an error running whois for {}!".format(domain),fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
            # If whois failed, try a WhoXY whois lookup
            # This is only done if whois failed so we can save on API credits
            if not results:
                try:
                    # Run a whois lookup using the WhoXY API
                    whoxy_results = self.whois_toolkit.run_whoxy_whois(domain)
                    if whoxy_results:
                        registrar = whoxy_results['registrar']
                        expiration_date = whoxy_results['expiry_date']
                        whoxy_org = whoxy_results['organization']
                        registrant = whoxy_results['registrant']
                        address = whoxy_results['address']
                        admin_contact = whoxy_results['admin_contact']
                        tech_contact = whoxy_results['tech_contact']
                        self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,NULL)",
                                        (domain,registrar,expiration_date,whoxy_org,registrant,
                                         admin_contact,tech_contact,address))
                except Exception as error:
                    click.secho("[!] There was an error running WhoXY whois for {}!".format(domain),fg="red")
                    click.secho("L.. Details: {}".format(error),fg="red")
        # Fetch any organization names found from whois lookups and the provided organization
        all_orgs = []
        self.c.execute("SELECT organization FROM whois_data")
        whois_orgs = self.c.fetchall()
        for org in whois_orgs:
            if org[0]:
                all_orgs.append(org[0])
        if not organization in all_orgs:
            all_orgs.append(organization)
        for org_name in all_orgs:
            # We definitely do not want to do a reverse lookup for every domain linked to a domain
            # privacy organization, so attempt to filter those
            whois_privacy = ["privacy","private","proxy","whois","guard","muumuu",\
                             "dreamhost","protect","registrant","aliyun","internet",\
                             "whoisguard","perfectprivacy"]
            # Split-up the org name and test if any piece matches a whois privacy keyword
            if not any(x.strip(",").strip().lower() in whois_privacy for x in org_name.split(" ")):
                click.secho("[+] Performing WhoXY reverse domain lookup with organization name {}."
                             .format(org_name),fg="green")
                try:
                    # Try to find other domains using the organization name from the whois record
                    reverse_whoxy_results,total_results = self.whois_toolkit.run_whoxy_company_search(org_name)
                    if reverse_whoxy_results:
                        if total_results > whoxy_limit:
                            click.secho("[*] WhoXY returned {} reverse whois results for \
{}. This is above your WhoXY limit of {}.\nAdding these to the list of domain names would mean \
ODIN would perform Shodan searches and Censys/crt.sh certificate searches for each of these \
domains. This can be very hard on API credits and may take a long time. ODIN won't use these \
domains for asset discovery this time. It is better to review these domains manually and then \
consider running ODIN again with a list of domains you find interesting (using the -sf option)."
.format(total_results,org_name,whoxy_limit),fg="yellow")
                        else:
                            click.secho("[*] WhoXY returned {} reverse whois results for \
{}. This is within your limit of {}, so ODIN will add these to the list of domains \
to resolve them, collect DNS records, and search Shodan and certificates."
.format(total_results,org_name,whoxy_limit),fg="yellow")
                        # Process the results and determine if they will be used for asset discovery
                        for result in reverse_whoxy_results:
                            rev_domain = reverse_whoxy_results[result]['domain']
                            registrar = reverse_whoxy_results[result]['registrar']
                            expiration_date = reverse_whoxy_results[result]['expiry_date']
                            org = reverse_whoxy_results[result]['organization']
                            registrant = reverse_whoxy_results[result]['registrant']
                            address = reverse_whoxy_results[result]['address']
                            admin_contact = reverse_whoxy_results[result]['admin_contact']
                            tech_contact = reverse_whoxy_results[result]['tech_contact']
                            # Add whois data for any new domain names to the database
                            if not rev_domain in domain_list:
                                self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,NULL)",
                                                (rev_domain,registrar,expiration_date,org,registrant,
                                                 admin_contact,tech_contact,address))
                                # If whoxy-limit allows, add the rev domain(s) to the master list
                                if not total_results > whoxy_limit:
                                    domain_list.append(rev_domain)
                                    rev_domain_list.append(rev_domain)
                                    self.c.execute("INSERT INTO hosts VALUES (NULL,?,?,?)",
                                                    (rev_domain,False,"WhoXY"))
                except Exception as error:
                    click.secho("[!] There was an error running WhoXY reverse whois for {}!".format(org_name),fg="red")
                    click.secho("L.. Details: {}".format(error),fg="red")
            else:
                click.secho("[*] Whois organization looks like it's a whois privacy org -- {} -- \
so this one has been skipped for WhoXY reverse lookups.".format(org_name),fg="yellow")
        # Master list of domains may include new domains now, so resume looping through domain_list
        with click.progressbar(domain_list,
                               label="[*] Collecting DNS records",
                               length=len(domain_list)) as bar:
            for domain in bar:
                vulnerable_dns_servers = []
                # Get the DNS records for each domain, starting with NS
                try:
                    temp = []
                    ns_records_list = self.dns_toolkit.get_dns_record(domain,"NS")
                    for rdata in ns_records_list.response.answer:
                        for item in rdata.items:
                            temp.append(item.to_text())
                    ns_records = ", ".join(x.strip(".") for x in temp)
                except:
                    ns_records = "None"
                # Record name server that resolve cached queries
                try:
                    for nameserver in temp:
                        result = self.dns_toolkit.check_dns_cache(nameserver.strip("."))
                        if result:
                            vulnerable_dns_servers.append(result)
                except:
                    pass
                bar.update(.125)
                # Collect each type of DNS record for the domain(s)
                try:
                    temp = []
                    a_records = self.dns_toolkit.get_dns_record(domain,"A")
                    for rdata in a_records.response.answer:
                        for item in rdata.items:
                            temp.append(item.to_text())
                            # Check if this a known IP and add new addresses to the list
                            self.c.execute("SELECT count(*) FROM hosts WHERE host_address=?",(item.to_text(),))
                            res = self.c.fetchone()
                            if res[0] == 0:
                                self.c.execute("INSERT INTO 'hosts' VALUES (NULL,?,?,?)",
                                                (item.to_text(),False,"Domain DNS"))
                                self.conn.commit()
                                # Also add A record IP addressess to the master list
                                if not item.to_text() in ip_list:
                                    ip_list.append(item.to_text())
                    a_records = ", ".join(temp)
                except:
                    a_records = "None"
                bar.update(.125)
                try:
                    mx_records = self.dns_toolkit.return_dns_record_list(domain,"MX")
                except:
                    mx_records = "None"
                bar.update(.125)
                try:
                    txt_records = self.dns_toolkit.return_dns_record_list(domain,"TXT")
                except:
                    txt_records = "None"
                bar.update(.125)
                try:
                    soa_records = self.dns_toolkit.return_dns_record_list(domain,"SOA")
                except:
                    soa_records = "None"
                bar.update(.125)
                try:
                    dmarc_record = self.dns_toolkit.return_dns_record_list("_dmarc." + domain,"TXT")
                except:
                    dmarc_record = "None"
                bar.update(.125)
                try:
                    o365_tenant = self.dns_toolkit.check_office_365(domain)
                except:
                    o365_tenant = "No"
                bar.update(.125)
                # Insert the DNS record data into the table
                self.c.execute("INSERT INTO 'dns' VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                                (domain,ns_records,a_records,mx_records,txt_records,soa_records,
                                 dmarc_record,o365_tenant,", ".join(vulnerable_dns_servers)))
                self.conn.commit()
                bar.update(.125)
        # Next phase, loop to collect the subdomain information
        # Netcraft, DNS Dumpster, findsubdomains.com, and TLS certificates are used for this
        with click.progressbar(label="[*] Collecting subdomains",
                               length=len(domain_list)) as bar:
            for domain in domain_list:
                collected_subdomains = []
                dumpster_results = []
                netcraft_results = []
                findsubdomains_results = []
                try:
                    dumpster_results = self.subdomain_hunter.check_dns_dumpster(domain)
                except:
                    click.secho("\n[!] There was a problem collecting results from DNS Dumpster for {}."
                                .format(domain),fg="red")
                try:
                    netcraft_results = self.subdomain_hunter.check_netcraft(domain)
                except Exception as error:
                    click.secho("\n[!] There was a problem collecting results from NetCraft for {}."
                                .format(domain),fg="red")
                try:
                    findsubdomains_results = self.subdomain_hunter.query_subdomainof(domain)
                except Exception as error:
                    click.secho("\n[!] There was a problem collecting results from FindSubdomains for {}."
                                .format(domain),fg="red")
                bar.update(.2)
                # Check the findsubdomains.com results
                if findsubdomains_results:
                    for subdomain in findsubdomains_results:
                        collected_subdomains.append(subdomain)
                # Check DNS Dumpster data
                if dumpster_results:
                    # See if we can save the domain map from DNS Dumpster
                    if dumpster_results['image_data']:
                        with open(self.report_path + domain + "_Domain_Map.png","wb") as fh:
                            fh.write(base64.decodebytes(dumpster_results['image_data']))
                    # Record the info from DNS Dumpster
                    for result in dumpster_results['dns_records']['host']:
                        if result['reverse_dns']:
                            subdomain = result['domain']
                            # ip = result['ip']
                            # asn = result['as']
                            # provider = result['provider']
                        else:
                            subdomain = result['domain']
                            # ip = result['ip']
                            # asn = result['as']
                            # provider = result['provider']
                        # Avoid adding the base domain to our subdomains list
                        if not bool(re.search("^" + re.escape(domain),subdomain.rstrip("HTTP:"),re.IGNORECASE)):
                            collected_subdomains.append(subdomain.rstrip("HTTP:"))
                bar.update(.2)
                # Check NetCraft data
                if netcraft_results:
                    for result in netcraft_results:
                        # Avoid adding the base domain to our subdomains list
                        if not bool(re.search("^" + re.escape(domain),result,re.IGNORECASE)):
                            collected_subdomains.append(result)
                # Try to collect certificate data for the domain
                try:
                    # Search for certificates catalogued by censys.io
                    cert_data = self.cert_searcher.search_censys_certificates(domain)
                    if cert_data:
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
                                cert_domain = self.cert_searcher.parse_cert_subdomain(subject)
                                # Insert the certificate info into the certificates table
                                self.c.execute("INSERT INTO 'certificates' VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                                                (cert_domain,subject,issuer,fingerprint,signature_algo,
                                                 self_signed,start_date,exp_date,", ".join(parsed_names)))
                                self.conn.commit()
                                # Add the collected names to the list of subdomains
                                collected_subdomains.append(cert_domain)
                                collected_subdomains.extend(parsed_names)
                        except Exception as error:
                            if "400 (max_results)" in str(error):
                                click.secho("\n[!] Too many results for a free API key, so we \
can only get the first 1,000. ODIN will also check crt.sh and other resources, so this is just \
a heads up!",fg="yellow")
                                click.secho("L.. Details: {}".format(error),fg="yellow")
                            else:
                                click.secho("L.. Details: {}".format(error),fg="red")
                            pass
                except:
                    pass
                bar.update(.2)
                try:
                    # Search for certificates catalogued by crt.sh
                    cert_data = self.cert_searcher.search_crtsh(domain,True)
                    if cert_data:
                        for cert in cert_data:
                            try:
                                exp_date = cert["not_after"]
                                name_value = cert["name_value"]
                                start_date = cert["not_before"]
                                issuer = cert["issuer_name"].replace('"','')
                                # Only record this certificate if the crt.sh name_value field is
                                # unknown. This should avoid recording duplicate certificates.
                                # Unfortunately, crt.sh does not have fingerprints for comparison
                                # with Censys results.
                                if name_value not in collected_subdomains:
                                    self.c.execute("INSERT INTO 'certificates' VALUES (NULL,?,NULL,?,NULL,NULL,NULL,?,?,?)",
                                                    (domain,issuer,start_date,exp_date,name_value))
                                    self.conn.commit()
                                    collected_subdomains.append(name_value)
                            except:
                                pass
                except:
                    pass
                bar.update(.2)
                # Filter out any uninteresting domains caught in the net and remove duplicates
                # Also removes wildcards, i.e. *.google.com
                collected_subdomains = self.cert_searcher.filter_subdomains(domain,collected_subdomains)
                unique_collected_subdomains = set(collected_subdomains)
                # Resolve the subdomains to IP addresses
                for unique_sub in unique_collected_subdomains:
                    if not bool(re.match("^" + domain,unique_sub)):
                        try:
                            ip_address = socket.gethostbyname(unique_sub)
                            # Check if this a known IP and add it to hosts if not
                            self.c.execute("SELECT count(*) FROM hosts WHERE host_address=?",(ip_address,))
                            res = self.c.fetchone()
                            if res[0] == 0:
                                self.c.execute("INSERT INTO 'hosts' VALUES (Null,?,?,?)",
                                                (ip_address,False,"Subdomain Enumeration"))
                                self.conn.commit()
                                # Also add it to our list of IP addresses
                                ip_list.append(ip_address)
                        except:
                            ip_address = "Lookup Failed"
                        # Check for any CDNs that can be used for domain fronting or takeovers
                        frontable = self.takeover_analzyer.check_domain_fronting(unique_sub)
                        can_takeover = self.takeover_analzyer.check_domain_takeover(unique_sub)
                        if can_takeover:
                            click.secho("\n[!] Potential takeover detected: %s" % unique_sub,fg="red")
                        # Record the results for this subdomain
                        self.c.execute("INSERT INTO 'subdomains' VALUES (NULL,?,?,?,?,?)",
                                        (domain,unique_sub,ip_address,frontable,can_takeover))
                        self.conn.commit()
                bar.update(.2)
                # Take a break for Censys' rate limits
                sleep(self.sleep)
        # Loop through domains to collect IP history from NetCraft
        for domain in domain_list:
            ip_history = []
            try:
                ip_history = self.subdomain_hunter.fetch_netcraft_domain_history(domain)
            except:
                click.secho("[!] There was a problem collecting domain history from NetCraft for {}."
                             .format(domain),fg="red")
            if ip_history:
                for result in ip_history:
                    net_owner = result[0]
                    ip_address = result[1]
                    self.c.execute("INSERT INTO ip_history VALUES (NULL,?,?,?)",
                                    (domain,net_owner,ip_address))
                    self.conn.commit()
        # The RDAP lookups are only for IPs, but we get the IPs for each domain name, too
        self.c.execute("SELECT host_address FROM hosts")
        collected_hosts = self.c.fetchall()
        for target in collected_hosts:
            try:
                # Slightly change output and record target if it's a domain
                target = target[0]
                if helpers.is_ip(target):
                    target_ip = target
                elif target == "":
                    pass
                else:
                    target_ip = socket.gethostbyname(target)
                # Log RDAP lookups
                results = self.whois_toolkit.run_rdap(target_ip)
                if results:
                    rdap_source = results['asn_registry']
                    org = results['network']['name']
                    net_cidr = results['network']['cidr']
                    asn = results['asn']
                    country_code = results['asn_country_code']
                    # Check Robtex for results for the current target
                    robtex = self.whois_toolkit.lookup_robtex_ip_info(target_ip)
                    if robtex:
                        results = []
                        for result in robtex['pas']:
                            results.append(result['o'])
                        robtex_results = ", ".join(results)
                    else:
                        robtex_results = "None"
                    self.c.execute("INSERT INTO rdap_data VALUES (NULL,?,?,?,?,?,?,?)",
                                   (target_ip,rdap_source,org,net_cidr,asn,country_code,
                                    robtex_results))
                    self.conn.commit()
            except socket.error as error:
                click.secho("[!] Could not resolve {}!".format(target),fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
            except Exception as error:
                click.secho("[!] The RDAP lookup failed for {}!".format(target),fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")

    def create_shodan_table(self,ip_list,domain_list):
        """Record Shodan search results in the SQLite3 database.
        
        Parameters:
        ip_list         A list of IP addresses
        domain_list     A list of domain names
        """
        num_of_addresses = len(ip_list)
        seconds = num_of_addresses * self.sleep
        minutes = round(seconds/60,2)
        click.secho("[*] ODIN has {} IP addresses, so Shodan searches part will take about {} \
minutes with the {} second API request delay."
                     .format(num_of_addresses,minutes,self.sleep),fg="yellow")
        # Go through the domain list for Shodan searches
        with click.progressbar(domain_list,
                               label="[*] Checking domains with Shodan",
                               length=len(domain_list)) as bar:
            for domain in bar:
                try:
                    shodan_search_results = self.shodan_toolkit.run_shodan_search(domain)
                    if shodan_search_results['total'] > 0:
                        for result in shodan_search_results['matches']:
                            ip_address = result['ip_str']
                            hostnames = ", ".join(result['hostnames'])
                            operating_system = result['os']
                            port = result['port']
                            data = result['data']
                            self.c.execute("INSERT INTO shodan_search VALUES (NULL,?,?,?,?,?,?)",
                                            (domain,ip_address,hostnames,operating_system,port,data))
                            self.conn.commit()
                    else:
                        click.secho("\n[*] No Shodan results for {}.".format(domain),fg="yellow")
                except:
                    pass
                # Take a break for Shodan's rate limits
                sleep(self.sleep)
        # Go through the IP address list for Shodan searches
        with click.progressbar(ip_list,
                               label="[*] Checking IPs with Shodan",
                               length=len(ip_list)) as bar:
            for ip in bar:
                try:
                    shodan_lookup_results = self.shodan_toolkit.run_shodan_lookup(ip)
                    if shodan_lookup_results:
                        ip_address = shodan_lookup_results['ip_str']
                        operating_system = shodan_lookup_results.get('os','n/a')
                        org = shodan_lookup_results.get('org','n/a')
                        # Collect the banners
                        for item in shodan_lookup_results['data']:
                            port = item['port']
                            data = item['data'].rstrip()
                            self.c.execute("INSERT INTO shodan_host_lookup VALUES (NULL,?,?,?,?,?)",
                                            (ip_address,operating_system,org,port,data))
                            self.conn.commit()
                except:
                    pass
                # Take a break for Shodan's rate limits
                sleep(self.sleep)

    def create_people_table(self,domain_list,rev_domain_list,client):
        """Record publicly available information related to individuals, including email addresses
        and social media profiles.

        Parameters:
        domain_list         A list of domain names
        rev_domain_list     A list of domains discovered via reverse WHOIS queries
        client              The name of the target organization
        """
        # Setup lists for holding results
        unique_emails = []
        unique_people = []
        unique_twitter = []
        hunter_job_titles = {}
        hunter_linkedin = {}
        hunter_phone_nums = {}
        # Search for LinkedIn profiles using the company name
        linkedin_harvester = harvester.SearchLinkedIn(client)
        harvested_linkedin = linkedin_harvester.do_search()
        # Search for social media profiles and email addresses associated with each domain
        for domain in domain_list:
            if domain not in rev_domain_list:
                # Search for emails, names, and social media handles
                harvester_emails,harvested_twitter = self.harvester.harvest_all(domain)
                hunter_harvester = harvester.SearchEmailHunter(domain)
                hunter_json = hunter_harvester.do_search()
                # Process the collected data
                temp_emails,temp_people,temp_twitter,temp_job_titles,temp_linkedin,temp_phone_nums = \
                self.harvester.process_harvested_lists(harvester_emails,harvested_twitter,hunter_json)
                unique_emails.extend(temp_emails)
                unique_people.extend(temp_people)
                unique_twitter.extend(temp_twitter)
                hunter_job_titles.update(temp_job_titles)
                hunter_linkedin.update(temp_linkedin)
                hunter_phone_nums.update(temp_phone_nums)
        # If we have emails, record them and check HaveIBeenPwned
        if unique_emails:
            unique_emails = list(set(unique_emails))
            click.secho("[+] Checking emails with HaveIBeenPwned. There is a {} second delay \
between requests.".format(self.hibp_sleep),fg="green")
            with click.progressbar(unique_emails,
                                   label="[*] Checking emails with HIBP",
                                   length=len(unique_emails)) as bar:
                for email in bar:
                    self.c.execute("INSERT INTO email_addresses VALUES (?,NULL,NULL)",(email,))
                    self.conn.commit()
                    try:
                        # Make sure we drop that @domain.com result Harvester often includes
                        if email == '@' + domain or email == " ":
                            pass
                        else:
                            # click.secho("[+] Checking {} with HIBP".format(email),fg="green")
                            pwned = self.haveibeenpwned.pwn_check(email)
                            # Give HIBP a rest for a few seconds
                            sleep(self.hibp_sleep)
                            pastes = self.haveibeenpwned.paste_check(email)
                            if pwned:
                                hits = []
                                for pwn in pwned:
                                    hits.append(pwn['Name'])
                                pwned_results = ", ".join(hits)
                            else:
                                pwned_results = "None Found"
                            if pastes:
                                temp_pastes = []
                                for paste in pastes:
                                    temp_pastes.append("Source: {} Title: {} ID: {}".format(paste['Source'],paste['Title'],paste['Id']))
                                pastes_results = ", ".join(temp_pastes)
                            else:
                                pastes_results = "None Found"
                            # Update the email address table with this additional data
                            self.c.execute("UPDATE email_addresses SET breaches=?,pastes=? WHERE email_address=?",
                                            (pwned_results,pastes_results,email))
                            self.conn.commit()
                            # Give HIBP a rest for a few seconds
                            sleep(self.hibp_sleep)
                    except Exception as error:
                        click.secho("\n[!] Error checking {} with HaveIBeenPwned's database!".format(email),fg="red")
                        click.secho("L.. Detail: {}".format(error),fg="red")
        # If we have Twitter handles, check Twitter for user data
        if unique_twitter:
            unique_twitter = list(set(unique_twitter))
            # Collect any available Twitter info for discovered handles
            with click.progressbar(unique_twitter,
                                   label="[*] Checking identified Twitter profiles",
                                   length=len(unique_twitter)) as bar:
                for handle in bar:
                    try:
                        data = self.harvester.harvest_twitter(handle)
                        if data:
                            self.c.execute("INSERT INTO twitter VALUES (?,?,?,?,?)",
                                            (data['handle'],data['real_name'],data['followers'],
                                             data['location'],data['user_description']))
                            self.conn.commit()
                    except:
                        pass
        # If we have names, check if EmailHunter returned any additional information for them
        if harvested_linkedin:
            for profile in harvested_linkedin:
                unique_people.append(profile)
                job_title = harvested_linkedin[profile]['job_title']
                profile_link = harvested_linkedin[profile]['linkedin_profile']
                self.c.execute("INSERT INTO employee_data VALUES (?,?,NULL,?)",(profile,job_title,profile_link))
                self.conn.commit()
        if unique_people:
            unique_people = list(set(unique_people))
            for person in unique_people:
                try:
                    # Insert the name into the table to start, if it is not already in there
                    if person not in harvested_linkedin:
                        self.c.execute("INSERT INTO employee_data VALUES (?,NULL,NULL,NULL)",(person,))
                        self.conn.commit()
                    # Record their job title, if we have one from Hunter
                    if person in hunter_job_titles:
                        for name,title in hunter_job_titles.items():
                            if name == person:
                                self.c.execute("UPDATE employee_data SET JobTitle = ? WHERE Name = ?",
                                                (title,person))
                                self.conn.commit()
                    # Record their phone number, if we have one from Hunter
                    if person in hunter_phone_nums:
                        for name,number in hunter_phone_nums.items():
                            if name == person:
                                self.c.execute("UPDATE employee_data SET PhoneNumber = ? WHERE Name = ?",
                                                (number,person))
                                self.conn.commit()
                    # Record their verified LinkedIn profile, if we have one from Hunter
                    if person in hunter_linkedin:
                        for name,link in hunter_linkedin.items():
                            if name == person:
                                self.c.execute("UPDATE employee_data SET LinkedIn = ? WHERE Name = ?",
                                                (link,person))
                                self.conn.commit()
                except:
                    pass

    def create_metadata_table(self,domain_name,extensions,download_dir):
        """Record the file collection results, including filenames, URLs, and file metadata.
        
        Parameters:
        domain_name     A domain name to use for searches
        extensions      The file types to search for
        download_dir    A file path to use for saving the downloaded files
        """
        # Setup Google settings -- pages to look through and timeout
        page_results = 10
        socket.setdefaulttimeout(5)
        exts = extensions.split(',')
        supported_exts = ['all','pdf','doc','docx','xls','xlsx','ppt','pptx']
        for i in exts:
            if i.lower() not in supported_exts:
                click.secho("[!] You've provided an unsupported file extension for --file.",fg="red")
                click.secho("L.. Ignoring: {}".format(i),fg="red")
                exts.remove(i)
        if "all" in exts:
            exts = supported_exts[1:]
        # Discover files, extract metadata, and record it
        click.secho("[+] Performing file discovery under {}.".format(domain_name),fg="green")
        parser = filehunter.Metaparser(domain_name,page_results,exts,download_dir,self.webdriver)
        metadata = parser.grab_meta()
        if metadata:
            # Write out the metadata for each found file
            for result in metadata:
                self.c.execute("INSERT INTO file_metadata VALUES (?,?,?,?,?)",
                               (result[0],result[1],result[2],result[3],result[4]))
                self.conn.commit()

    def create_lookalike_table(self,client,domain):
        """Record lookalike domains and the threat feed results for each domain.

        Parameters:
        client      The name of the target organization
        domain      The domain name to use for the typo-squatting checks
        """
        lookalike_results = self.lookalike_toolkit.run_domain_twister(domain)
        if lookalike_results:
            # Record each typosquatted domain
            for result in lookalike_results:
                domain = result['domain']
                rank = result['rank']
                a_records = result['a_records']
                mx_records = result['mx_records']
                malicious = result['malicious']
                self.c.execute("INSERT INTO lookalike VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                               (domain,str(rank),a_records,mx_records,malicious))
                self.conn.commit()
                # Check each domain with URLVoid for reputation data
                tree = self.lookalike_toolkit.run_urlvoid_lookup(domain)
                count = ""
                engines = ""
                if tree is not None:
                    # Check to see if urlvoid shows the domain flagged by any engines
                    try:
                        for child in tree:
                            malicious_check = child.tag
                            if malicious_check == "detections":
                                detections = tree[1]
                                engines = detections[0]
                                count = ET.tostring(detections[1],method='text').rstrip().decode('ascii')
                                temp = []
                                for engine in engines:
                                    temp.append(ET.tostring(engine,method='text').rstrip().decode('ascii'))
                                engines = ", ".join(temp)
                        rep_data = tree[0]
                        if len(rep_data) == 0:
                            pass
                        else:
                            target = ET.tostring(rep_data[0],method='text').rstrip().decode('ascii')
                            domain_age = ET.tostring(rep_data[3],method='text').rstrip().decode('ascii')
                            google_rank = ET.tostring(rep_data[4],method='text').rstrip().decode('ascii')
                            alexa_rank = ET.tostring(rep_data[5],method='text').rstrip().decode('ascii')
                            if rep_data[11]:
                                ip_data = rep_data[11]
                                ip_add = ET.tostring(ip_data[0],method='text').rstrip().decode('ascii')
                                hostnames = ET.tostring(ip_data[1],method='text').rstrip().decode('ascii')
                                asn = ET.tostring(ip_data[2],method='text').rstrip().decode('ascii')
                                asn_name = ET.tostring(ip_data[3],method='text').rstrip().decode('ascii')
                            else:
                                ip_add = None
                                hostnames = None
                                asn = None
                                asn_name = None
                            self.c.execute('''UPDATE lookalike
                                            SET 'urlvoid_ip'=?,
                                                'hostname'=?,
                                                'domain_age'=?,
                                                'google_rank'=?,
                                                'alexa_rank'=?,
                                                'asn'=?,
                                                'asn_name'=?,
                                                'urlvoid_hit'=?,
                                                'urlvoid_engines'=?
                                            WHERE domain = ?''',
                                            (ip_add,hostnames,domain_age,google_rank,alexa_rank,asn,
                                             asn_name,count,engines,target))
                            self.conn.commit()
                    except:
                        # click.secho("[!] There was an error getting the data for {}.".format(domain),fg="red")
                        pass

    def create_cloud_table(self,client,domain,wordlist=None,fix_wordlist=None):
        """Record findings related to cloud services and storage buckets.

        Parameters:
        client          The name of the target organization
        domain          The domain name to use as a seed for the generated word list
        wordlist        An optional file with a list of keywords
        fix_wordlist    An optional file with a list of strings used for prefixes and suffixes
        """
        verified_buckets = self.cloud_hunter.enumerate_buckets(client,domain,wordlist,fix_wordlist)
        if verified_buckets:
            # Write S3 Bucket table contents
            for bucket in verified_buckets:
                if bucket['exists']:
                    self.c.execute("INSERT INTO 'cloud' VALUES (?,?,?,?)",
                                   (bucket['bucketName'],bucket['bucketUri'],
                                    bucket['arn'],bucket['public']))
                    self.conn.commit()
            click.secho("[+] Cloud storage searches are complete.",fg="green")
        else:
            click.secho("[*] Nothing was returned for the cloud storage searches.",fg="yellow")

    def capture_web_snapshots(self,output_dir,webdriver):
        """Attempt to take screenshots of discovered web services.
        
        Parameters:
        output_dir      A file path for saving the screenshots
        webdriver       A Selenium webdriver object to use for taking the snapshots
        """
        camera = screenshots.Screenshotter(webdriver)
        output_dir += "screenshots/"
        # Get the list of targets from the database
        self.c.execute("SELECT host_address FROM hosts")
        target_list = self.c.fetchall()
        # Attempt a screenshot of each host using HTTP and HTTPS
        with click.progressbar(target_list,
                               label="[*] Taking screenshots",
                               length=len(target_list)) as bar:
            for target in bar:
                camera.take_screenshot(target[0],output_dir)
