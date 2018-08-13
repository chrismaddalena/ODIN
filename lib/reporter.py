#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module brings the other modules together for generating an SQLite3 database."""

import socket
from time import sleep
import base64
import datetime
import sqlite3
import re
from xml.etree import ElementTree  as ET
from colors import red, green, yellow
from lib import domain_tools, email_tools, pyfoca, helpers, screenshots
import sys
import os


class Reporter(object):
    """A class that can be used to call upon the other modules to collect results and then format
    a report saved as a SQLite3 database for easy review and queries. These results can then be
    converted to a Neo4j graph database using the grapher.py library or an HTML report using
    the htmlreporter.py library.
    """
    sleep = 10
    hibp_sleep = 3

    def __init__(self, report_path, report_name):
        """Everything that should be initiated with a new object goes here."""
        # Create the report database -- NOT in memory to allow for multiprocessing and archiving
        self.report_path = report_path
        if os.path.isfile(report_name):
            confirm = input(red("[!] A report for this client already exists. Are you sure you \
want to overwrite it? (Y\\N) "))
            if confirm == "Y" or confirm == "y":
                os.remove(report_name)
            else:
                print(red("[!] Exiting..."))
                exit()

        # Initiate the new class objects
        self.DC = domain_tools.DomainCheck()
        self.PC = email_tools.PeopleCheck()
        # Connect to our database
        self.conn = sqlite3.connect(report_name)
        self.c = self.conn.cursor()

    def create_tables(self):
        """Function to create the database tables."""
       # Create the 'hosts' table
        self.c.execute('''CREATE TABLE 'hosts' ('id' INTEGER PRIMARY KEY, 'host_address' text,
                       'in_scope_file' text, 'source' text)''')
        # Create the 'company_info' table
        self.c.execute('''CREATE TABLE 'company_info'
                    ('company_name' text, 'logo' text, 'website' text, 'employees' text,
                    'year_founded' text, 'website_overview' text, 'corporate_keyword' text,
                    'email_address' text, 'phone_number' text, 'physical_address' text
                    )''')
        # Create the 'dns' table
        self.c.execute('''CREATE TABLE 'dns'
                    ('id' INTEGER PRIMARY KEY, 'domain' text, 'ns_record' text, 'a_record' text,
                    'mx_record' text, 'txt_record' text, 'soa_record' text, 'dmarc' text,
                    'vulnerable_cache_snooping' text)''')
        # Create the 'subdomains' table
        self.c.execute('''CREATE TABLE 'subdomains'
            ('id' INTEGER PRIMARY KEY,'domain' text, 'subdomain' text, 'ip_address' text,
            'domain_frontable' text)''')
        # Create the 'certificate' table
        self.c.execute('''CREATE TABLE 'certificates'
                    ('id' INTEGER PRIMARY KEY, 'host' text, 'subject' text, 'issuer' text,
                    'censys_fingerprint' text, 'signature_algo' text, 'self_signed' text,
                    'start_date' text, 'expiration_date' text, 'alternate_names' text)''')
        # Create the 'ip_history' table
        self.c.execute('''CREATE TABLE 'ip_history'
                    ('id' INTEGER PRIMARY KEY, 'domain' text, 'netblock_owner' text,
                    'ip_address' text)''')
        # Create the 'whois_data' table
        self.c.execute('''CREATE TABLE 'whois_data'
                    ('id' INTEGER PRIMARY KEY, 'domain' text, 'registrar' text, 'expiration' text,
                    'organization' text, 'registrant' text, 'admin_contact' text,
                    'tech_contact' text, 'address' text, 'dns_sec' text)''')
        # Create the 'rdap_data' table
        self.c.execute('''CREATE TABLE 'rdap_data'
                    ('id' INTEGER PRIMARY KEY, 'ip_address' text, 'rdap_source' text,
                    'organization' text, 'network_cidr' text, 'asn' text, 'country_code' text,
                    'robtex_related_domains' text)''')
        # Create the 'shodan_search' table
        self.c.execute('''CREATE TABLE 'shodan_search'
                    ('id' INTEGER PRIMARY KEY, 'domain' text, 'ip_address' text, 'hostname' text,
                    'os' text, 'port' text, 'banner_data' text)''')
        # Create the 'shodan_host_lookup' table
        self.c.execute('''CREATE TABLE 'shodan_host_lookup'
                    ('id' INTEGER PRIMARY KEY, 'ip_address' text, 'os' text, 'organization' text,
                    'port' text, 'banner_data' text)''')
        # Create the 'email_address' table
        self.c.execute('''CREATE TABLE 'email_addresses'
                        ('email_address' text, 'breaches' text, 'pastes' text)''')
        # Create the 'twitter' table
        self.c.execute('''CREATE TABLE 'twitter' 
                        ('handle' text, 'real_name' text, 'follower_count' text, 'location' text,
                        'description' text)''')
        # Create the 'employee_data' table
        self.c.execute('''CREATE TABLE 'employee_data' 
                        ('name' text, 'job_title' text, 'phone_number' text,
                        'linkedin_url' text)''')
        # Create the 'file_metadata' table
        self.c.execute('''CREATE TABLE 'file_metadata'
                        ('filename' text, 'creation_date' text, 'author' text, 'produced_by' text,
                        'modification_date' text)''')
        # Create the 'urlcrazy' table
        self.c.execute('''CREATE TABLE 'urlcrazy'
                    ('domain' text, 'a_record' text, 'mx_record' text, 'cymon_hit' text,
                    'urlvoid_ip' text, 'hostname' text, 'domain_age' text, 'google_rank' text,
                    'alexa_rank' text, 'asn' text, 'asn_name' text, 'urlvoid_hit' text,
                    'urlvoid_engines' text)''')
        # Create the 'cloud' table
        self.c.execute('''CREATE TABLE 'cloud'
                        ('name' text, 'bucket_uri' text, 'bucket_arn' text, 'publicly_accessible' text
                        )''')

    def close_out_reporting(self):
        """Function to check the new database and tables and close the connections."""
        # Grab all table names for confirmation
        self.c.execute("SELECT NAME FROM sqlite_master WHERE TYPE = 'table'")
        written_tables = self.c.fetchall()
        for table in written_tables:
            print(green("[+] The {} table was created successfully.".format(table[0])))
        # Close the connection to the database
        self.conn.close()

    def prepare_scope(self, ip_list, domain_list, scope_file=None, domain=None):
        """Function to split a provided scope file into IP addresses and domain names."""
        # Generate the scope lists from the supplied scope file, if there is one
        scope = []
        if scope_file:
            scope = self.DC.generate_scope(scope_file)

        if domain:
            # Just in case the domain is not in the scope file, it's added here
            if not any(domain in d for d in scope):
                print(yellow("[*] The provided domain, {}, was not found in your scope file, so \
it has been added to the scope for OSINT.".format(domain)))
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
            self.c.execute("INSERT INTO hosts VALUES (NULL,?,?,?)", (target, True, "Scope File"))
            self.conn.commit()

        return scope, ip_list, domain_list

    def create_company_info_table(self, domain):
        """Function to generate a table of company information provided via Full Contact."""
        # Try to collect the info from Full Contact
        info_json = self.PC.full_contact_company(domain)

        if info_json is not None:
            # try:
            # INSERT the data from Full Contact
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
                corp_keywords= ", ".join(info_json['keywords'])
            else:
                corp_keywords = None
            # The NULLS will be replaced below if the data is available
            self.c.execute("INSERT INTO company_info VALUES (?,?,?,?,?,?,?,NULL,NULL,NULL)",
                            (name, logo, website, approx_employees, year_founded, website_overview,
                                corp_keywords))
            self.conn.commit()

            # If Full Contact returned any social media info, add columns for the service
            temp = []
            for profile in info_json['details']['profiles']:
                service = profile
                profile_url = info_json['details']['profiles'][profile]['url']
                # Check if we already have a column for this social media service and append if so
                if service in temp:
                    self.c.execute("UPDATE company_info SET %s = %s || ', ' || '%s'"  % (service, service, profile_url))
                    self.conn.commit()
                else:
                    self.c.execute("ALTER TABLE company_info ADD COLUMN " + service + " text")
                    self.c.execute("UPDATE company_info SET '%s' = '%s'" % (service, profile_url))
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
                    for key, value in address.items():
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
#             except:
#                 print(red("[!] No data found for {} in Full Contact's database. This may not be \
# the company's primary domain used for their website.".format(domain)))

    def create_domain_report_table(self, organization, scope, ip_list, domain_list, whoxy_limit):
        """Function to generate a domain report consisting of information like DNS records and
        subdomains.
        """
        # Get whois records and lookup other domains registerd to the same org
        for domain in domain_list:
            results = {}
            try:
                # Run whois lookup using standard whois
                results = self.DC.run_whois(domain)
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
                    whois_org = results['org']
                    registrant = results['registrant']
                    admin_email = results['admin_email']
                    tech_email = results['tech_email']
                    address = results['address'].rstrip()
                    if results['dnssec'] == "unsigned":
                        dnssec = results['dnssec']
                    else:
                        dnssec = ', '.join(results['dnssec'])

                    self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                                    (domain, registrar, expiration_date, whois_org, registrant,
                                    admin_email, tech_email, address, dnssec))
                    self.conn.commit()
            except Exception as error:
                print(red("[!] There was an error running whois for {}!".format(domain)))
                print(red("L.. Details: {}".format(error)))

            # If whois failed, try a WhoXY whois lookup
            # This is only done if whois failed so we can save on API credits
            if not results:
                try:
                    # Run a whois lookup using the WhoXY API
                    whoxy_results = self.DC.run_whoxy_whois(domain)
                    if whoxy_results:
                        registrar = whoxy_results['registrar']
                        expiration_date = whoxy_results['expiry_date']
                        whoxy_org = whoxy_results['organization']
                        registrant = whoxy_results['registrant']
                        address = whoxy_results['address']
                        admin_contact = whoxy_results['admin_contact']
                        tech_contact = whoxy_results['tech_contact']

                        self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,NULL)",
                                        (domain, registrar, expiration_date, whoxy_org, registrant,
                                        admin_contact, tech_contact, address))
                except Exception as error:
                    print(red("[!] There was an error running WhoXY whois for {}!".format(domain)))
                    print(red("L.. Details: {}".format(error)))

        # Fetch any organization names found from whois lookups + provided organziation
        all_orgs = []
        self.c.execute("SELECT organization FROM whois_data")
        whois_orgs = self.c.fetchall()
        for org in whois_orgs:
            all_orgs.append(org[0])
        if not organization in all_orgs:
            all_orgs.append(organization)
        for org_name in all_orgs:
            # We definitely do not want to do a reverse lookup for every domain linked to a domain
            # privacy organization, so attempt to filter those
            whois_privacy = ["privacy", "private", "proxy", "whois", "guard", "muumuu", \
                             "dreamhost", "protect", "registrant", "aliyun", "internet", \
                             "whoisguard", "perfectprivacy"]
            # Split-up the org name and test if any piece matches a whois privacy keyword
            if not any(x.strip(",").strip().lower() in whois_privacy for x in org_name.split(" ")):
                print(green("[+] Performing WhoXY reverse domain lookup with organization name {}.".format(org_name)))
                try:
                    # Try to find other domains using the organization name from the whois record
                    reverse_whoxy_results, total_results = self.DC.run_whoxy_company_search(org_name)
                    if reverse_whoxy_results:
                        if total_results > whoxy_limit:
                            print((yellow("[*] WhoXY returned {} reverse whois results for \
{}. This is above your WhoXY limit of {}.\nAdding these to the list of domain names would mean \
ODIN would perform employee and email searches, Shodan searches, and Censys certificate searches \
for each of these domains. This can be very hard on API credits and may take a long time. \
ODIN won't use these domains for asset and email discovery this time. It is better to review \
these domains manually and then consider running ODIN again with a list of domains you find \
interesting.".format(total_results, org_name, whoxy_limit))))
                        else:
                            print((yellow("[*] WhoXY returned {} reverse whois results for \
{}. This is equal to or below the limit of {}, so ODIN will add these to the list of domains \
to resolve them, collect DNS records, and search Shodan and \
Censys.".format(total_results, org_name, whoxy_limit))))
                        for result in reverse_whoxy_results:
                            rev_domain = reverse_whoxy_results[result]['domain']
                            registrar = reverse_whoxy_results[result]['registrar']
                            expiration_date = reverse_whoxy_results[result]['expiry_date']
                            org = reverse_whoxy_results[result]['organization']
                            registrant = reverse_whoxy_results[result]['registrant']
                            address = reverse_whoxy_results[result]['address']
                            admin_contact = reverse_whoxy_results[result]['admin_contact']
                            tech_contact = reverse_whoxy_results[result]['tech_contact']

                            # Add any new domain names to the master list
                            if not rev_domain in domain_list:
                                if not total_results > whoxy_limit:
                                    domain_list.append(rev_domain)
                                    self.c.execute("INSERT INTO hosts VALUES (NULL,?,?,?)",
                                                    (rev_domain, False, "WhoXY"))

                                self.c.execute("INSERT INTO whois_data VALUES (NULL,?,?,?,?,?,?,?,?,NULL)",
                                                (rev_domain, registrar, expiration_date, org, registrant,
                                                admin_contact, tech_contact, address))

                except Exception as error:
                    print(red("[!] There was an error running WhoXY reverse whois for {}!".format(org_name)))
                    print(red("L.. Details: {}".format(error)))
            else:
                print(yellow("[*] Whois organization looks like it's a whois privacy org -- {} -- \
so this one has been skipped for WhoXY reverse lookups.".format(org_name)))

        # Master list of domains may include new domains now, so resume looping through domain_list
        for domain in domain_list:
            print(green("[+] Fetching DNS records for {}.".format(domain)))
            vulnerable_dns_servers = []
            # Get the DNS records for each domain, starting with NS
            try:
                temp = []
                ns_records_list = self.DC.get_dns_record(domain, "NS")
                for rdata in ns_records_list.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                ns_records = ", ".join(x.strip(".") for x in temp)
                # Record name server that resolve cached queries
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
                        # Add A record IP to a temp list
                        temp.append(item.to_text())
                        # Check if this a known IP and add it to hosts if not
                        self.c.execute("SELECT count(*) FROM hosts WHERE host_address=?", (item.to_text(),))
                        res = self.c.fetchone()
                        if res[0] == 0:
                            self.c.execute("INSERT INTO 'hosts' VALUES (Null,?,?,?)",
                                            (item.to_text(), False, "Domain DNS"))
                            self.conn.commit()
                            # Also add A record IP addreses it to the master list
                            if not item.to_text() in ip_list:
                                ip_list.append(item.to_text())
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
                mx_records = ", ".join(x.strip(".") for x in temp)
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
            # Get the _DMARC TXT record
            try:
                temp = []
                dmarc_record = self.DC.get_dns_record("_dmarc." + domain, "TXT")
                for rdata in dmarc_record.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dmarc_record = ", ".join(temp)
            except:
                dmarc_record = "None"
            # INSERT the DNS records into the table
            self.c.execute("INSERT INTO 'dns' VALUES (NULL,?,?,?,?,?,?,?,?)",
                           (domain, ns_records, a_records, mx_records, txt_records, soa_records,
                            dmarc_record, ", ".join(vulnerable_dns_servers)))
            self.conn.commit()

        # Next phase, loop to collect the subdomain information
        # NetCraft, DNS Dumpster, and TLS certificates (Censys) are used for this
        for domain in domain_list:
            collected_subdomains = []
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
                    with open(self.report_path + domain + "_Domain_Map.png", "wb") as fh:
                        fh.write(base64.decodebytes(dumpster_results['image_data']))
                # Record the info from DNS Dumpster
                for result in dumpster_results['dns_records']['host']:
                    if result['reverse_dns']:
                        subdomain = result['domain']
                        ip = result['ip']
                        # asn = result['as']
                        # provider = result['provider']
                    else:
                        subdomain = result['domain']
                        ip = result['ip']
                        # asn = result['as']
                        # provider = result['provider']

                    # Avoid adding the base domain to our subdomains list
                    if not bool(re.search("^" + re.escape(domain), subdomain.rstrip("HTTP:"), re.IGNORECASE)):
                        collected_subdomains.append(subdomain.rstrip("HTTP:"))

            if netcraft_results:
                for result in netcraft_results:
                    # Avoid adding the base domain to our subdomains list
                    if not bool(re.search("^" + re.escape(domain), result, re.IGNORECASE)):
                        collected_subdomains.append(result)

            # Try to collect certificate data for the domain
            try:
                cert_data = self.DC.search_censys_certificates(domain)
                # Go through each certificate returned by Censys
                if cert_data:
                    for cert in cert_data:
                        subject = cert["parsed.subject_dn"]
                        issuer = cert["parsed.issuer_dn"]
                        fingerprint = cert["parsed.fingerprint_sha256"]
                        parsed_names = cert["parsed.names"]
                        signature_algo = cert["parsed.signature_algorithm.name"]
                        self_signed = cert["parsed.signature.self_signed"]
                        start_date = cert["parsed.validity.start"]
                        exp_date = cert["parsed.validity.end"]

                        cert_domain = self.DC.parse_cert_subdomain(subject)

                        # Insert the certiticate info into the certificates table
                        self.c.execute("INSERT INTO 'certificates' VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                                    (cert_domain, subject, issuer, fingerprint, signature_algo,
                                    self_signed, start_date, exp_date, ", ".join(parsed_names)))
                        self.conn.commit()

                        # Add the collected names to the list of subdomains
                        collected_subdomains.append(cert_domain)
                        collected_subdomains.extend(parsed_names)

                    # Filter out any uninteresting domains caught in the net and remove duplicates
                    # Also removes wildcards, i.e. *.google.com doesn't resolve to anything
                    collected_subdomains = self.DC.filter_subdomains(domain, collected_subdomains)
                    unique_collected_subdomains = set(collected_subdomains)

                    # Resolve the subdomains to IP addresses
                    for unique_sub in unique_collected_subdomains:
                        if not bool(re.match("^" + domain, unique_sub)):
                            try:
                                ip_address = socket.gethostbyname(unique_sub)
                                # Check if this a known IP and add it to hosts if not
                                self.c.execute("SELECT count(*) FROM hosts WHERE host_address=?", (ip_address,))
                                res = self.c.fetchone()
                                if res[0] == 0:
                                    self.c.execute("INSERT INTO 'hosts' VALUES (Null,?,?,?)",
                                                    (ip_address, False, "Subdomain Enumeration"))
                                    self.conn.commit()
                                    # Also add it to our list of IP addresses
                                    ip_list.append(ip_address)
                            except:
                                ip_address = "Lookup Failed"
                            # Check for any CDNs that can be used for domain fronting
                            frontable = self.DC.check_domain_fronting(unique_sub)
                            # Record the results for this subdomain
                            self.c.execute("INSERT INTO 'subdomains' VALUES (NULL,?,?,?,?)",
                                        (domain, unique_sub, ip_address, frontable))
                            self.conn.commit()
            except:
                pass

            # Take a break for Censys's rate limits
            sleep(self.sleep)

        # Loop through domains to collect IP history from NetCraft
        for domain in domain_list:
            ip_history = []
            try:
                ip_history = self.DC.fetch_netcraft_domain_history(domain)
            except:
                print(red("[!] There was a problem collecting domain history from NetCraft for {}.".format(domain)))

            if ip_history:
                for result in ip_history:
                    net_owner = result[0]
                    ip_address = result[1]
                    self.c.execute("INSERT INTO ip_history VALUES (NULL,?,?,?)",
                                   (domain, net_owner, ip_address))
                    self.conn.commit()
                    # Check if this a known IP and add it to hosts if not
                    # self.c.execute("SELECT count(*) FROM hosts WHERE host_address=?", (ip_address,))
                    # res = self.c.fetchone()
                    # if res[0] == 0:
                    #     self.c.execute("INSERT INTO 'hosts' VALUES (Null,?,?,?)",
                    #                    (ip_address, False, "Netcraft Domain IP History"))
                    #     self.conn.commit()
                        # Also add it to our list of IP addresses
                        # ip_list.append(ip_address)

        # The RDAP lookups are only for IPs, but we get the IPs for each domain name, too
        self.c.execute("SELECT host_address FROM hosts")
        collected_hosts = self.c.fetchall()
        for target in collected_hosts:
            try:
                # Slightly change output and record target if it's a domain
                target = target[0]
                if helpers.is_ip(target):
                    target_ip = target
                    # for_output = target
                elif target == "":
                    pass
                else:
                    target_ip = socket.gethostbyname(target)

                # Log RDAP lookups
                results = self.DC.run_rdap(target_ip)
                if results:
                    rdap_source = results['asn_registry']
                    org = results['network']['name']
                    net_cidr = results['network']['cidr']
                    asn = results['asn']
                    country_code = results['asn_country_code']

                    # Check Robtex for results for the current target
                    robtex = self.DC.lookup_robtex_ipinfo(target_ip)
                    if robtex:
                        results = []
                        for result in robtex['pas']:
                            results.append(result['o'])
                        robtex_results = ", ".join(results)
                    else:
                        robtex_results = "None"

                    self.c.execute("INSERT INTO rdap_data VALUES (NULL,?,?,?,?,?,?,?)",
                                   (target_ip, rdap_source, org, net_cidr, asn, country_code,
                                    robtex_results))
                    self.conn.commit()
            except socket.error:
                print(red("[!] Could not resolve {}!".format(target)))
            except Exception as error:
                print(red("[!] The RDAP lookup failed for {}!".format(target)))
                print(red("L.. Details: {}".format(error)))

    def create_shodan_table(self, ip_list, domain_list):
        """Function to create a Shodan table with Shodan search results."""
        num_of_addresses = len(ip_list)
        seconds = num_of_addresses * self.sleep
        minutes = seconds/60
        print(yellow("[*] ODIN has {} IP addresses, so Shodan searches part will take about {} \
minutes with the {} second API request delay.".format(num_of_addresses, minutes, self.sleep)))

        for domain in domain_list:
            try:
                shodan_search_results = self.DC.run_shodan_search(domain)
                if shodan_search_results['total'] > 0:
                    for result in shodan_search_results['matches']:
                        ip_address = result['ip_str']
                        hostnames = ", ".join(result['hostnames'])
                        operating_system = result['os']
                        port = result['port']
                        data = result['data']

                        self.c.execute("INSERT INTO shodan_search VALUES (NULL,?,?,?,?,?,?)",
                                       (domain, ip_address, hostnames, operating_system, port, data))
                        self.conn.commit()
                else:
                    print(yellow("[*] No Shodan results for {}.".format(domain)))
            except:
                pass

            # Take a break for Shodan's rate limits
            sleep(self.sleep)

        for ip in ip_list:
            try:
                shodan_lookup_results = self.DC.run_shodan_lookup(ip)
                if shodan_lookup_results:
                    ip_address = shodan_lookup_results['ip_str']
                    operating_system = shodan_lookup_results.get('os', 'n/a')
                    org = shodan_lookup_results.get('org', 'n/a')
                    # Collect the banners
                    for item in shodan_lookup_results['data']:
                        port = item['port']
                        data = item['data'].rstrip()
                        self.c.execute("INSERT INTO shodan_host_lookup VALUES (NULL,?,?,?,?,?)",
                                    (ip_address, operating_system, org, port, data))
                        self.conn.commit()
            except:
                pass

            # Take a break for Shodan's rate limits
            sleep(self.sleep)

    def create_people_table(self, domain_list, client):
        """Function to add tables of publicly available information related to individuals,
        including email addresses and social media profiles.
        """
        # Setup lists for holding results
        unique_emails = None
        unique_people = None
        unique_twitter = None

        for domain in domain_list:
            # Get the "people" data -- emails, names, and social media handles
            harvester_emails, harvester_people, harvester_twitter = self.PC.harvest_all(domain)
            hunter_json = self.PC.harvest_emailhunter(domain)

            # Process the collected data
            unique_emails, unique_people, unique_twitter, job_titles, linkedin, phone_nums = \
            self.PC.process_harvested_lists(harvester_emails, harvester_people, \
            harvester_twitter, hunter_json)
    
            # If we have emails, record them and check HaveIBeenPwned
            if unique_emails:
                print(green("[+] Checking emails with HaveIBeenPwned. There is a {} second delay \
between requests.".format(self.hibp_sleep)))
                for email in unique_emails:
                    self.c.execute("INSERT INTO email_addresses VALUES (?,NULL,NULL)",(email,))
                    self.conn.commit()
                    try:
                        # Make sure we drop that @domain.com result Harvester often includes
                        if email == '@' + domain or email == " ":
                            print(yellow("[*] Discarding an email address: {}".format(email)))
                            pass
                        else:
                            print(green("[+] Checking {} with HIBP".format(email)))
                            pwned = self.PC.pwn_check(email)
                            pastes = self.PC.paste_check(email)
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
                                    temp_pastes.append("Source:{} Title:{} ID:{}".format(paste['Source'], paste['Title'], paste['Id']))
                                pastes_results = ", ".join(temp_pastes)
                            else:
                                pastes_results = "None Found"

                            self.c.execute("UPDATE email_addresses SET breaches=?,pastes=? WHERE email_address=?",
                                            (pwned_results, pastes_results, email))
                            self.conn.commit()

                        # Give HIBP a rest for a few seconds
                        sleep(self.hibp_sleep)
                    except Exception as error:
                        print(red("[!] Error checking {} with HaveIBeenPwned's database!".format(email)))
                        print(red("L.. Detail: {}".format(error)))

            # If we have Twitter handles, check Twitter for user data
            if unique_twitter:
                print(green("[+] Gathering Twitter account data for identified profiles."))
                try:
                    # Collect any available Twitter info for discovered handles
                    for handle in unique_twitter:
                        data = self.PC.harvest_twitter(handle)
                        if data:
                            self.c.execute("INSERT INTO twitter VALUES (?,?,?,?,?)",
                                        (data['handle'], data['real_name'], data['followers'],
                                            data['location'],  data['user_description']))
                            self.conn.commit()
                except:
                    pass

            # If we have names, try to find LinkedIn profiles for them
            if unique_people:
                print(green("[+] Searching for LinkedIn profiles for identified employees."))
                try:
                    # Try to find possible LinkedIn profiles for people
                    for person in unique_people:
                        # Insert the name into the table to start
                        self.c.execute("INSERT INTO employee_data VALUES (?,NULL,NULL,NULL)", (person,))
                        self.conn.commit()
                        # Record their job title, if we have one from Hunter
                        if person in job_titles:
                            for name, title in job_titles.items():
                                if name == person:
                                    self.c.execute("UPDATE employee_data SET JobTitle = ? WHERE Name = ?",
                                                (title, person))
                                    self.conn.commit()

                        # Record their phone number, if we have one from Hunter
                        if person in phone_nums:
                            for name, number in phone_nums.items():
                                if name == person:
                                    self.c.execute("UPDATE employee_data SET PhoneNumber = ? WHERE Name = ?",
                                                (number, person))
                                    self.conn.commit()

                        # Record their verified LinkedIn profile, if we have one from Hunter
                        if person in linkedin:
                            print(green("[+] Hunter has a LinkedIn link for {}.".format(person)))
                            for name, link in linkedin.items():
                                if name == person:
                                    self.c.execute("UPDATE employee_data SET LinkedIn = ? WHERE Name = ?",
                                                (link, person))
                                    self.conn.commit()

                        # If all else fails, search for LinkedIn profile links and record all candidates
                        else:
                            data = self.PC.harvest_linkedin(person, client)
                            if data:
                                linkedin_results = ", ".join(data)
                                self.c.execute("UPDATE employee_data SET LinkedIn = ? WHERE Name = ?",
                                            (linkedin_results, person))
                                self.conn.commit()
                except:
                    pass

    def create_foca_table(self, domain, extensions, del_files, download_dir, verbose):
        """Function to add a FOCA worksheet containing pyFOCA results."""
        # Set domain to look at and choose if files should be deleted
        domain_name = domain

        # Prepare extensions to Google
        exts = extensions.split(',')
        supported_exts = ['all', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'key']
        for i in exts:
            if i.lower() not in supported_exts:
                print(red("[!] You've provided an unsupported file extension for --file."))
                print(red("L.. Discarding: {}".format(i)))
                exts.remove(i)
        if "all" in exts:
            exts = supported_exts[1:]

        # Setup Google settings -- pages to look through and timeout
        page_results = 10
        # socket.setdefaulttimeout(float(t))
        socket.setdefaulttimeout(5)

        print(green("[+] Performing file discovery under {}.".format(domain_name)))
        parser = pyfoca.Metaparser(domain_name, page_results, exts, del_files, download_dir, verbose)
        metadata = parser.grab_meta()
        parser.clean_up()

        if metadata:
            # Write out the metadata for each found file
            for result in metadata:
                self.c.execute("INSERT INTO file_metadata VALUES (?,?,?,?,?)",
                               (result[0],result[1],result[2],result[3],result[4]))
                self.conn.commit()

    def create_urlcrazy_table(self, client, domain):
        """Function to add a worksheet for URLCrazy results."""
        # Check if urlcrazy is available and proceed with recording results
        urlcrazy_results = self.DC.run_urlcrazy(client, domain)
        if not urlcrazy_results:
            pass
        else:
            # Record each typosquatted domain
            for result in urlcrazy_results:
                domain = result['domain']
                a_records = result['a-records']
                mx_records = result['mx-records']
                malicious = result['malicious']

                self.c.execute("INSERT INTO urlcrazy VALUES (?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                               (domain, a_records, mx_records, malicious))
                self.conn.commit()

                # Check each domain with URLVoid for reputation data
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

                        rep_data = tree[0]
                        if len(rep_data) == 0:
                            pass
                        else:
                            target = ET.tostring(rep_data[0], method='text').rstrip().decode('ascii')
                            domain_age = ET.tostring(rep_data[3], method='text').rstrip().decode('ascii')
                            google_rank = ET.tostring(rep_data[4], method='text').rstrip().decode('ascii')
                            alexa_rank = ET.tostring(rep_data[5], method='text').rstrip().decode('ascii')

                            if rep_data[11]:
                                ip_data = rep_data[11]
                                ip_add = ET.tostring(ip_data[0], method='text').rstrip().decode('ascii')
                                hostnames = ET.tostring(ip_data[1], method='text').rstrip().decode('ascii')
                                asn = ET.tostring(ip_data[2], method='text').rstrip().decode('ascii')
                                asn_name = ET.tostring(ip_data[3], method='text').rstrip().decode('ascii')
                            else:
                                ip_add = None
                                hostnames = None
                                asn = None
                                asn_name = None

                            self.c.execute('''UPDATE urlcrazy
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
                                        (ip_add, hostnames, domain_age, google_rank, alexa_rank, asn,
                                            asn_name, count, engines, target))
                            self.conn.commit()
                    except:
                        print(red("[!] There was an error getting the data for {}.".format(domain)))

    def create_cloud_table(self, client, domain, wordlist=None, fix_wordlist=None):
        """Function to add a cloud worksheet for findings related to AWS and Digital Ocean."""
        verified_buckets, verified_accounts = self.DC.enumerate_buckets(client, domain, wordlist, fix_wordlist)

        if verified_buckets and verified_accounts:
            # Write S3 Bucket table contents
            for bucket in verified_buckets:
                if bucket['exists']:
                    self.c.execute("INSERT INTO 'cloud' VALUES (?,?,?,?)",
                                   (bucket['bucketName'], bucket['bucketUri'],
                                   bucket['arn'], bucket['public']))
                    self.conn.commit()

            print(green("[+] AWS and Digital Ocean searches are complete."))
        else:
            print(yellow("[*] Could not access the AWS API to enumerate S3 buckets and accounts."))

    def capture_web_snapshots(self, output_dir):
        """Function to take a screenshot of discovered web services."""
        camera = screenshots.Screenshotter()
        output_dir += "screenshots/"

        # TODO: Take Shodan results and look for common web ports for screenshots
        self.c.execute("SELECT host_address FROM hosts")
        target_list = self.c.fetchall()

        for target in target_list:
            camera.take_screenshot(target[0], output_dir)
