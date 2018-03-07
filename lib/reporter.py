#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module brings the other modules together for generating an SQLite3 database."""

import socket
import time
import base64
import datetime
import sqlite3
from xml.etree import ElementTree  as ET
from colors import red, green, yellow
from lib import domain_tools, email_tools, pyfoca, helpers
import sys
import os


class Reporter(object):
    """A class that can be used to call upon the other modules to collect results and then format
    a report saved as a SQLite3 database for easy review and queries.
    """
    ip_addresses = []
    domains_list = []
    sleep = 10
    hibp_sleep = 3

    def __init__(self, report_name):
        """Everything that should be initiated with a new object goes here."""
        # Initiate the new class objects
        self.DC = domain_tools.DomainCheck()
        self.PC = email_tools.PeopleCheck()
        # Create the report database -- NOT in memory to allow for multiprocessing and archiving
        if os.path.isfile(report_name):
            confirm = input(red("[!] A report for this client already exists. Are you sure you want to overwrite it? (Y\\N)"))
            if confirm == "Y" or confirm == "y":
                os.remove(report_name)
            else:
                print(red("[!] Exiting..."))
                exit()
        self.conn = sqlite3.connect(report_name)
        self.c = self.conn.cursor()

    def close_out_reporting(self):
        """Function to check the new database and tables and close the connections."""
        # Grab all table names for confirmation
        self.c.execute("SELECT NAME FROM sqlite_master WHERE TYPE = 'table'")
        written_tables = self.c.fetchall()
        for table in written_tables:
            print(green("[+] {} table complete!".format(table[0])))
        # Close the connection to the database
        self.conn.close()

    def prepare_scope(self, scope_file, domain=None):
        """Function to split the user's scope file into IP addresses and domain names."""
        # Generate the scope lists from the supplied scope file, if there is one
        scope = []
        scope = self.DC.generate_scope(scope_file)

        if domain:
            # Just in case the domain is not in the scope file, it's added here
            if not any(domain in d for d in scope):
                print(yellow("[*] The provided domain, {}, was not found in your scope file, so \
it has been added to the scope for OSINT.".format(domain)))
                scope.append(domain)

        # Create lists of IP addresses and domain names from scope
        for item in scope:
            if helpers.is_ip(item):
                self.ip_addresses.append(item)
            elif item == "":
                pass
            else:
                self.domains_list.append(item)

        # Record the scope being used in the database
        self.c.execute('''CREATE TABLE 'ReportScope' ('Target' text)''')
        for target in scope:
            self.c.execute("INSERT INTO ReportScope VALUES (?)", (target,))
            self.conn.commit()

        return scope, self.ip_addresses, self.domains_list

    def create_company_info_table(self, domain):
        """Function to generate a table of company information provided via Full Contact."""
        # Try to collect the info from Full Contact
        info_json = self.PC.full_contact_company(domain)

        if info_json is not None:
            try:
                # Create the CompanyInfo table
                self.c.execute('''CREATE TABLE 'CompanyInfo'
                            ('CompanyName' text, 'Logo' text, 'Website' text, 'ApproxEmployees' text,
                            'YearFounded' text, 'WebsiteOverview' text, 'CorporateKeywords' text,
                            'EmailAddresses' text, 'PhoneNumbers' text, 'PhysicalAddresses' text
                            )''')
                # INSERT the data from Full Contact
                name = info_json['organization']['name']
                logo = info_json['logo']
                website = info_json['website']
                approx_employees = info_json['organization']['approxEmployees']
                year_founded = info_json['organization']['founded']
                website_overview = info_json['organization']['overview']
                corp_keywords= ", ".join(info_json['organization']['keywords'])
                # The NULLS will be replaced below if the data is available
                self.c.execute("INSERT INTO CompanyInfo VALUES (?,?,?,?,?,?,?,NULL,NULL,NULL)",
                                (name, logo, website, approx_employees, year_founded, website_overview,
                                corp_keywords))
                self.conn.commit()

                # If Full Contact returned any social media info, add columns for the service
                for profile in info_json['socialProfiles']:
                    service = profile['typeName']
                    profile_url = profile['url']
                    self.c.execute("ALTER TABLE CompanyInfo ADD COLUMN " + service + " text")
                    self.c.execute("UPDATE CompanyInfo SET '%s' = '%s'" % (service, profile_url))
                    self.conn.commit()
                
                # Update the table with information that is not always available
                if "emailAddresses" in info_json['organization']['contactInfo']:
                    email_addresses = []
                    for email in info_json['organization']['contactInfo']['emailAddresses']:
                        email_addresses.append(email['value'])
                    self.c.execute("UPDATE CompanyInfo SET EmailAddresses = '%s'" % (', '.join(email_addresses)))
                    self.conn.commit()
                if "phoneNumbers" in info_json['organization']['contactInfo']:
                    phone_numbers = []
                    for number in info_json['organization']['contactInfo']['phoneNumbers']:
                        phone_numbers.append(number['number'])
                    self.c.execute("UPDATE CompanyInfo SET PhoneNumbers = '%s'" % (', '.join(phone_numbers)))
                    self.conn.commit()
                if "addresses" in info_json['organization']['contactInfo']:
                    for address in info_json['organization']['contactInfo']['addresses']:
                        complete = ""
                        for key, value in address.items():
                            if key == "region":
                                complete += "{}, ".format(value['name'])
                            elif key == "country":
                                complete += "{}, ".format(value['name'])
                            elif key == "label":
                                pass
                            else:
                                complete += "{}, ".format(value)
                    self.c.execute("UPDATE CompanyInfo SET PhysicalAddresses = '%s'" % (complete))
                    self.conn.commit()
            except:
                print(red("[!] No data found for {} in Full Contact's database. This may not be \
the company's primary domain used for their website.".format(domain)))

    def create_domain_report_table(self, scope, ip_addresses, domains_list, verbose):
        """Function to generate a domain report consisting of information like DNS records and
        subdomains.
        """
        # Create the DNS table for holding the domains' DNS records
        self.c.execute('''CREATE TABLE 'DNS'
                    ('Domain' text, 'NSRecords' text, 'ARecords' text, 'MXRecords' text,
                    'TXTRecords' text, 'SOARecords' text, 'VulnerableCacheSnooping' text)''')

        # Get the DNS records for each domain
        for domain in domains_list:
            # Get the NS records
            try:
                temp = []
                ns_records_list = self.DC.get_dns_record(domain, "NS")
                for rdata in ns_records_list.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                ns_records = ", ".join(temp)
                # Record name server that resolve cached queries
                vulnerable_dns_servers = []
                for nameserver in temp:
                    result = self.DC.check_dns_cache(nameserver.strip("."))
                    if result:
                        vulnerable_dns_servers.append(result)
            except:
                ns_records = "None"
            # Get the A records
            try:
                temp = []
                a_records = self.DC.get_dns_record(domain, "A")
                for rdata in a_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                a_records = ", ".join(temp)
            except:
                a_records = "None"
            # Get the MX records
            try:
                temp = []
                mx_records = self.DC.get_dns_record(domain, "MX")
                for rdata in mx_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                mx_records = ", ".join(temp)
            except:
                mx_records = "None"
            # Get the TXT records
            try:
                temp = []
                txt_records = self.DC.get_dns_record(domain, "TXT")
                for rdata in txt_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                txt_records = ", ".join(temp)
            except:
                txt_records = "None"
            # Get the SOA records
            try:
                temp = []
                soa_records = self.DC.get_dns_record(domain, "SOA")
                for rdata in soa_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                soa_records = ", ".join(temp)
            except:
                soa_records = "None"
            # INSERT the DNS records into the table
            self.c.execute("INSERT INTO 'DNS' VALUES (?,?,?,?,?,?,?)",
                           (domain, ns_records, a_records, mx_records, txt_records, soa_records,
                            ", ".join(vulnerable_dns_servers)))
            self.conn.commit()

            sys.exit()

        # Create the Subdomains table for recording subdomain info for each domain
        self.c.execute('''CREATE TABLE 'Subdomains'
            ('Domain' text, 'Subdomain' text, 'IP' text, 'ASN' text, 'Provider' text,
            'DomainFrontable' text)''')

        # Collect the subdomain information from DNS Dumpster and NetCraft
        for domain in domains_list:
            print(green("[+] Checking DNS Dumpster and NetCraft for {}".format(domain)))
            dumpster_results = []
            netcraft_results = []
            try:
                dumpster_results = self.DC.check_dns_dumpster(domain)
            except:
                print(red("[!] There was a problem collecting results from DNS Dumpster for {}.".format(domain)))
            try:
                netcraft_results = self.DC.check_netcraft(domain)
            except:
                print(red("[!] There was a problem collecting results from NetCraft for {}.".format(domain)))
            
            if dumpster_results:
                # See if we can save the domain map from DNS Dumpster
                if dumpster_results['image_data']:
                    with open("reports/" + domain + "_Domain_Map.png", "wb") as fh:
                        fh.write(base64.decodebytes(dumpster_results['image_data']))
                # Record the info from DNS Dumpster
                for result in dumpster_results['dns_records']['host']:
                    if result['reverse_dns']:
                        # TODO: Reverse DNS
                        subdomain = result['domain']
                        ip = result['ip']
                        asn = result['as']
                        provider = result['provider']
                    else:
                        subdomain = result['domain']
                        ip = result['ip']
                        asn = result['as']
                        provider = result['provider']

                    # Check the subdomain for domain fronting possibilties
                    frontable = self.DC.check_domain_fronting(result['domain'])

                    # INSERT the subdomain info into the table
                    self.c.execute("INSERT INTO Subdomains VALUES (?,?,?,?,?,?)",
                                (domain, subdomain, ip, asn, provider, frontable))
                    self.conn.commit()

            # INSERT the subdomain info collected from NetCraft
            if netcraft_results:
                for result in netcraft_results:
                    frontable = self.DC.check_domain_fronting(result)
                    self.c.execute("INSERT INTO Subdomains VALUES (?,?,NULL,NULL,NULL,?)",
                                   (domain, result, frontable))
                    self.conn.commit()

        # Create IPHistory table for historical data collected from NetCraft
        self.c.execute('''CREATE TABLE 'IPHistory'
                    ('Domain' text, 'Netblock Owner' text, 'IP' text)''')

        for domain in domains_list:
            ip_history = []
            try:
                ip_history = self.DC.fetch_netcraft_domain_history(domain)
            except:
                print(red("[!] There was a problem collecting domain history from NetCraft for {}.".format(domain)))

            if ip_history:
                for result in ip_history:
                    net_owner = result[0]
                    ip = result[1]
                    self.c.execute("INSERT INTO IPHistory VALUES (?,?,?)",
                                   (domain, net_owner, ip))
                    self.conn.commit()

        # Create the WhoisData table
        self.c.execute('''CREATE TABLE 'WhoisData'
                    ('Domain' text, 'Registrar' text, 'Expiration' text, 'Organization' text,
                    'Registrant' text, 'AdminContact' text, 'TectContact' text, 'Address' text,
                    'DNSSec' text)''')

        # The whois lookups are only for domain names
        for domain in domains_list:
            try:
                # Run whois lookup
                print(green("[+] Running whois for {}".format(domain)))
                results = self.DC.run_whois(domain)
                # Log whois results to domain report
                if results:
                    # Check if more than one expiration date is returned
                    if isinstance(results['expiration_date'], datetime.date):
                        expiration_date = results['expiration_date']
                    # We have a list, so break-up list into human readable dates and times
                    else:
                        expiration_date = []
                        for date in results['expiration_date']:
                            expiration_date.append(date.strftime("%Y-%m-%d %H:%M:%S"))
                        expiration_date = ", ".join(expiration_date)

                    registrar = results['registrar']
                    org = results['org']
                    registrant = results['registrant']
                    admin_email = results['admin_email']
                    tech_email = results['tech_email']
                    address = results['address'].rstrip()
                    dnssec = ', '.join(results['dnssec'])

                    self.c.execute("INSERT INTO WhoisData VALUES (?,?,?,?,?,?,?,?,?)",
                                   (domain, registrar, expiration_date, org, registrant,
                                   admin_email, tech_email, address, dnssec))
                    self.conn.commit()
            except Exception as error:
                print(red("[!] There was an error running whois for {}!".format(domain)))
                print(red("L.. Details: {}".format(error)))

        # Create RDAP table
        self.c.execute('''CREATE TABLE 'RDAPData'
                    ('IP' text, 'RDAPSource' text, 'Organization' text, 'NetworkCIDRs' text,
                    'ASN' text, 'CountryCode' text, 'RobtexRelatedDomains' text)''')

        # The RDAP lookups are only for IPs, but we get the IPs for each domain name, too
        for target in scope:
            try:
                # Slightly change output and recorded target if it's a domain
                if helpers.is_ip(target):
                    target_ip = target
                    for_output = target
                    print(green("[+] Running RDAP lookup for {}".format(for_output)))
                elif target == "":
                    pass
                else:
                    target_ip = socket.gethostbyname(target)
                    for_output = "{} ({})".format(target_ip, target)
                    print(green("[+] Running RDAP lookup for {}".format(for_output)))

                # Log RDAP lookups
                results = self.DC.run_rdap(target_ip)
                if results:
                    rdap_source = results['asn_registry']
                    org = results['network']['name']
                    net_cidr = results['network']['cidr']
                    asn = results['asn']
                    country_code = results['asn_country_code']

                # TODO: Convert Verbose mode output into something easily recorded in the DB
#                 # Verbose mode is optional to allow users to NOT be overwhelmed by contact data
#                 if verbose:
#                     row += 1
#                     for object_key, object_dict in results['objects'].items():
#                         if results['objects'] is not None:
#                             for item in results['objects']:
#                                 name = results['objects'][item]['contact']['name']
#                                 if name is not None:
#                                     dom_worksheet.write(row, 1, "Contact Name:")
#                                     dom_worksheet.write(row, 2, name)
#                                     row += 1

#                                 title = results['objects'][item]['contact']['title']
#                                 if title is not None:
#                                     dom_worksheet.write(row, 1, "Contact's Title:")
#                                     dom_worksheet.write(row, 2, title)
#                                     row += 1

#                                 role = results['objects'][item]['contact']['role']
#                                 if role is not None:
#                                     dom_worksheet.write(row, 1, "Contact's Role:")
#                                     dom_worksheet.write(row, 2, role)
#                                     row += 1

#                                 email = results['objects'][item]['contact']['email']
#                                 if email is not None:
#                                     dom_worksheet.write(row, 1, "Contact's Email:")
#                                     dom_worksheet.write(row, 2, email[0]['value'])
#                                     row += 1

#                                 phone = results['objects'][item]['contact']['phone']
#                                 if phone is not None:
#                                     dom_worksheet.write(row, 1, "Contact's Phone:")
#                                     dom_worksheet.write(row, 2, phone[0]['value'])
#                                     row += 1

#                                 address = results['objects'][item]['contact']['address']
#                                 if address is not None:
#                                     dom_worksheet.write(row, 1, "Contact's Address:")
#                                     dom_worksheet.write(row, 2, address[0]['value'])
#                                     row += 1

                    # Check Robtex for results for the current target
                    robtex = self.DC.lookup_robtex_ipinfo(target_ip)
                    if robtex:
                        results = []
                        for result in robtex['pas']:
                            results.append(result['o'])
                        robtex_results = ", ".join(results)
                    else:
                        robtex_results = "None"

                    self.c.execute("INSERT INTO RDAPData VALUES (?,?,?,?,?,?,?)",
                                   (for_output, rdap_source, org, net_cidr, asn, country_code,
                                   robtex_results))
                    self.conn.commit()
            except Exception as error:
                print(red("[!] The RDAP lookup failed for {}!".format(target)))
                print(red("L.. Details: {}".format(error)))

        # Create the URLVoid table
        self.c.execute('''CREATE TABLE 'URLVoidResults'
                    ('Domain' text, 'IP' text, 'Hostname(s)' text, 'DomainAge' text,
                    'GoogleRank' text, 'AlexaRank' text, 'ASN' text, 'AsnName' text,
                    'MaliciousCount' text, 'MaliciousEngines' text)''')

        # Check each domain with URLVoid for reputation and some Alexa data
        for domain in domains_list:
            tree = self.DC.run_urlvoid_lookup(domain)
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
                            count = ET.tostring(detections[1], method='text').rstrip().decode('ascii')
                            temp = []
                            for engine in engines:
                                temp.append(ET.tostring(engine, method='text').rstrip().decode('ascii'))
                            engines = ", ".join(temp)

                            print(yellow("[*] URLVoid found malicious activity reported for \
                                        {}!".format(domain)))

                    rep_data = tree[0]
                    ip_data = rep_data[11]

                    target = ET.tostring(rep_data[0], method='text').rstrip().decode('ascii')
                    ip_add = ET.tostring(ip_data[0], method='text').rstrip().decode('ascii')
                    hostnames = ET.tostring(ip_data[1], method='text').rstrip().decode('ascii')
                    domain_age = ET.tostring(rep_data[3], method='text').rstrip().decode('ascii')
                    google_rank = ET.tostring(rep_data[4], method='text').rstrip().decode('ascii')
                    alexa_rank = ET.tostring(rep_data[5], method='text').rstrip().decode('ascii')
                    asn = ET.tostring(ip_data[2], method='text').rstrip().decode('ascii')
                    asn_name = ET.tostring(ip_data[3], method='text').rstrip().decode('ascii')

                    self.c.execute("INSERT INTO URLVoidResults VALUES (?,?,?,?,?,?,?,?,?,?)",
                                   (target, ip_add, hostnames, domain_age, google_rank,
                                   alexa_rank, asn, asn_name, count, engines))
                    self.conn.commit()
                except:
                    print(red("[!] There was an error getting the data for {}.".format(domain)))

    def create_urlcrazy_table(self, client, domain):
        """Function to add a worksheet for URLCrazy results."""
        # Check if urlcrazy is available and proceed with recording results
        urlcrazy_results = self.DC.run_urlcrazy(client, domain)
        if not urlcrazy_results:
            pass
        else:
            # Prepare for URLCrazy searches
            self.c.execute('''CREATE TABLE 'UrlcrazyResults'
                        ('Domain' text, 'A' text, 'MX' text, 'Malicious' text)''')
            # Record each typosquatted domain
            for result in urlcrazy_results:
                domain = result['domain']
                a_records = result['a-records']
                mx_records = result['mx-records']
                malicious = result['malicious']

                self.c.execute("INSERT INTO UrlcrazyResults VALUES (?,?,?,?)",
                                (domain, a_records, mx_records, malicious))
                self.conn.commit()

    def create_shodan_table(self, ip_addresses, domains_list):
        """Function to create a Shodan table with Shodan search results."""
        # Prepare for Shodan searches
        self.c.execute('''CREATE TABLE 'ShodanSearchResults'
                    ('IP' text, 'Hostname(s)' text, 'OS' text, 'Port' text, 'Data' text)''')

        for domain in domains_list:
            try:
                results = self.DC.run_shodan_search(domain)
                if results['total'] > 0:
                    for result in results['matches']:
                        ip = result['ip_str']
                        hostnames = ", ".join(result['hostnames'])
                        operating_system = result['os']
                        port = result['port']
                        data = result['data']

                        self.c.execute("INSERT INTO ShodanSearchResults VALUES (?,?,?,?,?)",
                                       (ip, hostnames, operating_system, port, data))
                        self.conn.commit()
                else:
                    print(yellow("[*] No results for {}.".format(domain)))
            except:
                pass

            # Take a break for Shodan's rate limits
            time.sleep(self.sleep)

        # Now perform Shodan host lookups
        self.c.execute('''CREATE TABLE 'ShodanHostLookups'
                    ('IP' text, 'OS' text, 'Organization' text, 'Port' text, 'Banner' text)''')

        for ip in ip_addresses:
            try:
                results = self.DC.run_shodan_lookup(ip)
                ip = results['ip_str']
                operating_system = results.get('os', 'n/a')
                org = results.get('org', 'n/a')
                # Collect the banners
                for item in results['data']:
                    port = item['port']
                    data = item['data'].rstrip()
                    self.c.execute("INSERT INTO ShodanHostLookups VALUES (?,?,?,?,?)",
                                   (ip, operating_system, org, port, data))
                    self.conn.commit()
            except:
                pass

        # TODO: Figure out why this data is so often wrong/oudated and if it should be included going forward
        # vuln_data = []
        #         try:
        #             # Check for any vulns Shodan knows about
        #             for item in results["vulns"]:
        #                 temp = {}
        #                 cve = item.replace("!", "")
        #                 print(yellow("[!] This host is flagged for {}".format(cve)))
        #                 # Shodan API requires at least a one second delay between requests
        #                 time.sleep(5)
        #                 exploits = self.DC.run_shodan_exploit_search(cve)
        #                 for vuln in exploits["matches"]:
        #                     if vuln.get("cve")[0] == cve:
        #                         cve_description = vuln.get("description")
        #                         temp['host'] = ip
        #                         temp['cve'] = cve
        #                         temp['cve_description'] = cve_description
        #                         vuln_data.append(temp)
        #         except:
        #             pass
        #     except:
        #         pass

        #     # Take a break for Shodan's rate limits
        #     time.sleep(self.sleep)

        # # Add buffer rows for the next table
        # row += 2

        # if vuln_data:
        #     # Write headers for Shodan Vuln search table
        #     shodan_worksheet.write(row, 0, "Shodan Vulnerabilities", bold)
        #     row += 1
        #     shodan_worksheet.write(row, 0, "IP Address", bold)
        #     shodan_worksheet.write(row, 1, "CVE", bold)
        #     shodan_worksheet.write(row, 2, "Description", bold)
        #     row += 1

        #     for vuln in vuln_data:
        #         shodan_worksheet.write(row, 0, vuln['host'])
        #         shodan_worksheet.write(row, 1, vuln['cve'])
        #         shodan_worksheet.write(row, 2, vuln['cve_description'])
        #         row += 1

    def create_censys_table(self, scope, verbose):
        """Function to add a Censys.io table to the DB with Censys host information and certificate
        details.
        """
        # Create the Censys table
        self.c.execute('''CREATE TABLE CensysResults
                    ('Host' text, 'IP' text, 'Country' text, 'Ports' text)''')

        for target in scope:
            try:
                results = self.DC.run_censys_search_address(target)
                for result in results:
                    ports = []
                    for port in result["protocols"]:
                        ports.append(port)
                    self.c.execute("INSERT INTO CensysResults VALUES (?,?,?,?)",
                                   (target, result['ip'], result['location.country'], ', '.join(ports)))
                    self.conn.commit()
            except:
                pass

            # Take a break for Censys's rate limits
            time.sleep(self.sleep)

        # Collect certificate data from Censys if verbose is set
        if verbose:
            self.c.execute('''CREATE TABLE 'Certificates'
                        ('Host' text, 'Subject' text, 'Issuer' text)''')
            for target in scope:
                try:
                    cert_data = self.DC.run_censys_search_cert(target)
                    for cert in cert_data:
                        self.c.execute("INSERT INTO 'Certificates' VALUES (?,?,?)",
                                       (target, cert["parsed.subject_dn"], cert["parsed.issuer_dn"]))
                        self.conn.commit()
                except:
                    pass

                # Take a break for Censys's rate limits
                time.sleep(self.sleep)

    def create_people_table(self, domain, client):
        """Function to add tables of publicly available information related to individuals, including
        email addresses and social media profiles.
        """
        # Setup lists for holding results
        unique_emails = None
        unique_people = None
        unique_twitter = None

        # Get the "people" data -- emails, names, and social media handles
        harvester_emails, harvester_people, harvester_twitter = self.PC.harvest_all(domain)
        hunter_json = self.PC.harvest_emailhunter(domain)

        # Process the collected data
        unique_emails, unique_people, unique_twitter, job_titles, linkedin, phone_nums = \
        self.PC.process_harvested_lists(harvester_emails, harvester_people, \
        harvester_twitter, hunter_json)

        # If we have emails, record them and check HaveIBeenPwned
        if unique_emails:
            self.c.execute('''CREATE TABLE 'PublicEmailAddresses' 
                           ('Email_Address' text, 'Breaches' text, 'Pastes' text)''')

            print(green("[+] Checking emails with HaveIBeenPwned."))

            try:
                for email in unique_emails:
                    # Make sure we drop that @domain.com result Harvester often includes
                    if email == '@' + domain or email == " ":
                        pass
                    else:
                        pwned = self.PC.pwn_check(email)
                        pastes = self.PC.paste_check(email)
                        if pwned:
                            hits = []
                            for pwn in pwned:
                                hits.append(pwn)
                            pwned_results = ", ".join(hits)
                        else:
                            pwned_results = "None Found"

                        if pastes:
                            pastes_results = pastes
                        else:
                            pastes_results = "None Found"

                        self.c.execute("INSERT INTO PublicEmailAddresses VALUES (?,?,?)",
                                        (email, pwned_results, pastes_results))
                        self.conn.commit()

                    # Give HIBP a rest for a few seconds
                    time.sleep(self.hibp_sleep)
            except Exception as error:
                print(red("[!] Error checking emails with HaveIBeenPwned's database!"))
                print(red("L.. Detail: {}".format(error)))

        print(green("[+] Gathering Twitter account data for identified profiles."))

        # If we have Twitter handles, check Twitter for user data
        if unique_twitter:
            # Setup Twitter Profiles table
            self.c.execute('''CREATE TABLE 'TwitterProfiles' 
                           ('Handle' text, 'RealName' text, 'FollowerCount' text, 'Location' text,
                           'Description' text)''')

            try:
                # Collect any available Twitter info for discovered handles
                for handle in unique_twitter:
                    data = self.PC.harvest_twitter(handle)
                    if data:
                        self.c.execute("INSERT INTO TwitterProfiles VALUES (?,?,?,?,?)",
                                        (data['handle'], data['real_name'], data['followers'],
                                        data['location'],  data['user_description']))
                        self.conn.commit()
            except:
                pass

        # If we have names, try to find LinkedIn profiles for them
        if unique_people:
            # Create the EmployeeData table
            self.c.execute('''CREATE TABLE 'EmployeeData' 
                           ('Name' text, 'JobTitle' text, 'PhoneNumber' text, 'LinkedIn' text)''')

            try:
                # Try to find possible LinkedIn profiles for people
                for person in unique_people:
                    # Insert the name into the table to start
                    self.c.execute("INSERT INTO EmployeeData VALUES (?,NULL,NULL,NULL)", (person,))
                    self.conn.commit()
                    # Record their job title, if we have one from Hunter
                    if person in job_titles:
                        for name, title in job_titles.items():
                            if name == person:
                                self.c.execute("UPDATE EmployeeData SET JobTitle = ? WHERE Name = ?",
                                                (title, person))
                                self.conn.commit()

                    # Record their phone number, if we have one from Hunter
                    if person in phone_nums:
                        for name, number in phone_nums.items():
                            if name == person:
                                self.c.execute("UPDATE EmployeeData SET PhoneNumber = ? WHERE Name = ?",
                                                (number, person))
                                self.conn.commit()

                    # Record their verified LinkedIn profile, if we have one from Hunter
                    if person in linkedin:
                        print(green("[+] Hunter has a LinkedIn link for {}.".format(person)))
                        for name, link in linkedin.items():
                            if name == person:
                                self.c.execute("UPDATE EmployeeData SET LinkedIn = ? WHERE Name = ?",
                                                (link, person))
                                self.conn.commit()

                    # If all else fails, search for LinkedIn profile links and record all candidates
                    else:
                        data = self.PC.harvest_linkedin(person, client)
                        if data:
                            linkedin_results = ", ".join(data)
                            self.c.execute("UPDATE EmployeeData SET LinkedIn = ? WHERE Name = ?",
                                            (linkedin_results, person))
                            self.conn.commit()
            except:
                pass

    def create_foca_table(self, domain, extensions, del_files, verbose):
        """Function to add a FOCA worksheet containing pyFOCA results."""
        # Set domain to look at and choose if files should be deleted
        domain_name = domain

        # Prepare extensions to Google
        exts = extensions.split(',')
        supported_exts = ['all', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt']
        for i in exts:
            if i.lower() not in supported_exts:
                print(red("[!] You've provided an unsupported file extension for --file. \
Please try again."))
                exit()
        if "all" in exts:
            exts = supported_exts[1:]

        # Setup Google settings -- pages to look through and timeout
        page_results = 10
        # socket.setdefaulttimeout(float(t))
        socket.setdefaulttimeout(5)

        print(green("[+] Performing file discovery under {}.".format(domain_name)))
        parser = pyfoca.Metaparser(domain_name, page_results, exts, del_files, verbose)
        metadata = parser.grab_meta()
        parser.clean_up()

        if metadata:
            # Setup the file metadata table
            self.c.execute('''CREATE TABLE 'FoundFileMetadata'
                           ('Filename' text, 'CreationDate' text, 'Author' text, 'ProducedBy' text, 'ModificationDate' text)''')
            # Write out the metadata for each found file
            for result in metadata:
                self.c.execute("INSERT INTO FoundFileMetadata VALUES (?,?,?,?,?)",
                (result[0],result[1],result[2],result[3],result[4]))
                self.conn.commit()

    # TODO: Update this with URLCrazy for the new database storage
    def create_cymon_worksheet(self, target):
        """Function to check the provided the target against Cymon.io's database of threat feeds
        and then print the results.
        """
        if helpers.is_ip(target):
            domains_results, ip_results = self.DC.search_cymon_ip(target)
            if domains_results:
                print(yellow("\n[+] Associated Domains:"))
                # Print out associated domains for the IP
                for result in domains_results:
                    print("URL:\t %s" % result['name'])
                    print("Created: %s" % result['created'])
                    print("Updated: %s\n" % result['updated'])
            if ip_results:
                print(yellow("[+] Recorded Malicious Events:"))
                # Print out security events for the IP
                for result in ip_results:
                    print("Title:\t\t %s" % result['title'])
                    print("Description:\t %s" % result['description'])
                    print("Created:\t %s" % result['created'])
                    print("Updated:\t %s" % result['updated'])
                    print("Details:\t %s\n" % result['details_url'])
        else:
            results = self.DC.search_cymon_domain(target)
            # Print out information for the domain
            if results:
                print(yellow("\n[+] Cymon.io events for %s" % target))
                print("URL:\t %s" % results['name'])
                print("Created: %s" % results['created'])
                print("Updated: %s" % results['updated'])
                for source in results['sources']:
                    print("Source:\t {}".format(source))
                for ip in results['ips']:
                    print("IP:\t {}".format(ip))
                print("")

        print(green("[+] Cymon search completed!"))

    def create_cloud_table(self, client, domain, wordlist=None, fix_wordlist=None):
        """Function to add a cloud worksheet for findings related to AWS."""
        print(green("[+] Looking for AWS buckets and accounts for target..."))
        verified_buckets, verified_accounts = self.DC.enumerate_buckets(client, domain, wordlist, fix_wordlist)

        if verified_buckets and verified_accounts:
            # Setup cloud table
            self.c.execute('''CREATE TABLE 'CloudResults'
                           ('Name' text, 'BucketURI' text, 'BucketARN' text, 'PublicAccess' text
                           )''')
            # Write S3 Bucket table contents
            for bucket in verified_buckets:
                if bucket['exists']:
                    self.c.execute("INSERT INTO 'CloudResults' VALUES (?,?,?,?)",
                                   (bucket['bucketName'], bucket['bucketUri'], bucket['arn'], bucket['public']))
                    self.conn.commit()

            # # Write headers for AWS Account table
            # cloud_worksheet.write(row, 0, "AWS Accounts", bold)
            # row += 1
            # cloud_worksheet.write(row, 0, "Account Alias", bold)
            # cloud_worksheet.write(row, 1, "Account ID", bold)
            # cloud_worksheet.write(row, 2, "Account Signin URI", bold)
            # row += 1
            # # Write AWS Account table contents
            # for account in verified_accounts:
            #     if account['exists']:
            #         cloud_worksheet.write(row, 0, account['accountAlias'])
            #         if account['accountId'] is None:
            #             cloud_worksheet.write(row, 1, "Unknown")
            #         else:
            #             cloud_worksheet.write(row, 1, account['accountId'])
            #         cloud_worksheet.write(row, 2, account['signinUri'])
            #         row += 1

            print(green("[+] AWS searches are complete and results are in the Cloud worksheet."))
        else:
            print(yellow("[*] Could not access the AWS API to enumerate S3 buckets and accounts."))
