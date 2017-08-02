#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module brings the other modules together for
generating an XLSX report.
"""

import socket
import time
from xml.etree import ElementTree  as ET
from colors import red, green, yellow
from lib import domain_tools, email_tools, pyfoca


class Reporter(object):
    """A class that can be used to call upon the other
    modules to collect results and then format a report
    saved as an XLSX spreadsheet.
    """
    ip_addresses = []
    domains_list = []
    sleep = 10
    hibp_sleep = 3

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Initiate the new class objects
        self.DC = domain_tools.DomainCheck()
        self.PC = email_tools.PeopleCheck()

    def prepare_scope(self, scope_file, domain=None):
        """Function to split the user's scope file into IP
        addresses and domain names.
        """
        # Generate the scope lists from the supplied scope file, if there is one
        scope = []
        scope = self.DC.generate_scope(scope_file)

        if domain:
            # Just in case the domain is not in the scope file, it's added here
            if not any(domain in d for d in scope):
                print(yellow("[*] The provided domain was not found in your \
scope file, so it has been added to the scope for OSINT."))
                scope.append(domain)

        # Create lists of IP addresses and domain names from scope
        for item in scope:
            if self.DC.is_ip(item):
                self.ip_addresses.append(item)
            elif item == "":
                pass
            else:
                self.domains_list.append(item)

        return scope, self.ip_addresses, self.domains_list

    def create_domain_report(self, workbook, scope, ip_addresses, domains_list, dns, verbose):
        """Function to generate a domain report consisting of information like
        DNS records and subdomains.
        """
        # Setup the Domain Info worksheet
        dom_worksheet = workbook.add_worksheet("Domain Info")
        bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
        row = 0

        if verbose:
            print(yellow("[*] Verbose output Enabled -- Enumeration of RDAP contact \
information is enabled, so you may get a lot of it if scope includes a large cloud provider."))
        else:
            print(yellow("[*] Verbose output Disabled -- Enumeration of contact information \
will be skipped."))

        # Write headers for the DNS records table
        dom_worksheet.write(row, 0, "DNS Records", bold)
        row += 1
        dom_worksheet.write(row, 0, "Domain", bold)
        dom_worksheet.write(row, 1, "NS Record(s)", bold)
        dom_worksheet.write(row, 2, "A Record(s)", bold)
        dom_worksheet.write(row, 3, "MX Record(s)", bold)
        dom_worksheet.write(row, 4, "TXT Record(s)", bold)
        dom_worksheet.write(row, 5, "SOA Records", bold)
        row += 1

        # Get the DNS records for each domain
        for domain in domains_list:
            # Record the domain
            dom_worksheet.write(row, 0, domain)
            # Get NS records
            try:
                temp = []
                ns_records = self.DC.get_dns_record(domain, "NS")
                for rdata in ns_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dom_worksheet.write(row, 1, "{}".format(", ".join(temp)))
            except:
                dom_worksheet.write(row, 1, "None")
            # Get the A records
            try:
                temp = []
                a_records = self.DC.get_dns_record(domain, "A")
                for rdata in a_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dom_worksheet.write(row, 2, "{}".format(", ".join(temp)))
            except:
                dom_worksheet.write(row, 2, "None")
            # Get MX records
            try:
                temp = []
                mx_records = self.DC.get_dns_record(domain, "MX")
                for rdata in mx_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dom_worksheet.write(row, 3, "{}".format(", ".join(temp)))
            except:
                dom_worksheet.write(row, 3, "None")
            # Get TXT records
            try:
                temp = []
                txt_records = self.DC.get_dns_record(domain, "TXT")
                for rdata in txt_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dom_worksheet.write(row, 4, "{}".format(", ".join(temp)))
            except:
                dom_worksheet.write(row, 4, "None")
            # Get SOA records
            try:
                temp = []
                soa_records = self.DC.get_dns_record(domain, "SOA")
                for rdata in soa_records.response.answer:
                    for item in rdata.items:
                        temp.append(item.to_text())
                dom_worksheet.write(row, 5, "{}".format(", ".join(temp)))
            except:
                dom_worksheet.write(row, 5, "None")
            # Add a row for next domain
            row += 1
        # Add buffer rows for the next table
        row += 2

        # Write headers for whois table
        dom_worksheet.write(row, 0, "Whois Results", bold)
        row += 1
        dom_worksheet.write(row, 0, "Domain", bold)
        dom_worksheet.write(row, 1, "Registrar", bold)
        dom_worksheet.write(row, 2, "Expiration", bold)
        dom_worksheet.write(row, 3, "Organization", bold)
        dom_worksheet.write(row, 4, "Registrant", bold)
        dom_worksheet.write(row, 5, "Admin Contact", bold)
        dom_worksheet.write(row, 6, "Tech Contact", bold)
        dom_worksheet.write(row, 7, "Address", bold)
        dom_worksheet.write(row, 8, "DNSSEC", bold)
        row += 1

        # The whois lookups are only for domain names
        for domain in domains_list:
            try:
                # Run whois lookup
                print(green("[+] Running whois for {}".format(domain)))
                results = self.DC.run_whois(domain)
                # Log whois results to domain report
                if results:
                    dom_worksheet.write(row, 0, "{}".format(results['domain_name'][0].lower()))
                    dom_worksheet.write(row, 1, "{}".format(results['registrar']))
                    dom_worksheet.write(row, 2, "{}".format(results['expiration_date']))
                    dom_worksheet.write(row, 3, "{}".format(results['org']))
                    dom_worksheet.write(row, 4, "{}".format(results['registrant']))
                    dom_worksheet.write(row, 5, "{}".format(results['admin_email']))
                    dom_worksheet.write(row, 6, "{}".format(results['tech_email']))
                    dom_worksheet.write(row, 7, "{}".format(results['address'].rstrip()))
                    dom_worksheet.write(row, 8, "{}".format(results['dnssec']))
                    row += 1
            except Exception as e:
                print(red("[!] There was an error running whois for {}!".format(domain)))
                print(red("L.. Details: {}".format(e)))
        # Add buffer rows for the next table
        row += 2

        # Write headers for RDAP table
        dom_worksheet.write(row, 0, "RDAP Results", bold)
        row += 1
        dom_worksheet.write(row, 0, "IP Address", bold)
        dom_worksheet.write(row, 1, "RDAP Source", bold)
        dom_worksheet.write(row, 2, "Organization", bold)
        dom_worksheet.write(row, 3, "Network CIDR(s)", bold)
        dom_worksheet.write(row, 4, "ASN", bold)
        dom_worksheet.write(row, 5, "Country Code", bold)
        row += 1

        # The RDAP lookups are only for IPs, but we get the IPs for each domain name, too
        for target in scope:
            try:
                # Slightly change output and recorded target if it's a domain
                if self.DC.is_ip(target):
                    target_ip = target
                    for_output = target
                    print(green("[+] Running RDAP lookup for {}".format(for_output)))
                else:
                    target_ip = socket.gethostbyname(target)
                    for_output = "{} ({})".format(target_ip, target)
                    print(green("[+] Running RDAP lookup for {}".format(for_output)))

                # Log RDAP lookups
                results = self.DC.run_rdap(target_ip)
                if results:
                    dom_worksheet.write(row, 0, for_output)
                    dom_worksheet.write(row, 1, results['asn_registry'])
                    dom_worksheet.write(row, 2, results['network']['name'])
                    dom_worksheet.write(row, 3, results['network']['cidr'])
                    dom_worksheet.write(row, 4, results['asn'])
                    dom_worksheet.write(row, 5, results['asn_country_code'])

                # Verbose mode is optional to allow users to NOT be overwhelmed by contact data
                if verbose:
                    row += 1
                    for object_key, object_dict in results['objects'].items():
                        if results['objects'] is not None:
                            for item in results['objects']:
                                name = results['objects'][item]['contact']['name']
                                if name is not None:
                                    dom_worksheet.write(row, 1, "Contact Name:")
                                    dom_worksheet.write(row, 2, name)
                                    row += 1

                                title = results['objects'][item]['contact']['title']
                                if title is not None:
                                    dom_worksheet.write(row, 1, "Contact's Title:")
                                    dom_worksheet.write(row, 2, title)
                                    row += 1

                                role = results['objects'][item]['contact']['role']
                                if role is not None:
                                    dom_worksheet.write(row, 1, "Contact's Role:")
                                    dom_worksheet.write(row, 2, role)
                                    row += 1

                                email = results['objects'][item]['contact']['email']
                                if email is not None:
                                    dom_worksheet.write(row, 1, "Contact's Email:")
                                    dom_worksheet.write(row, 2, email[0]['value'])
                                    row += 1

                                phone = results['objects'][item]['contact']['phone']
                                if phone is not None:
                                    dom_worksheet.write(row, 1, "Contact's Phone:")
                                    dom_worksheet.write(row, 2, phone[0]['value'])
                                    row += 1

                                address = results['objects'][item]['contact']['address']
                                if address is not None:
                                    dom_worksheet.write(row, 1, "Contact's Address:")
                                    dom_worksheet.write(row, 2, address[0]['value'])
                                    row += 1
            except Exception  as e:
                print(red("[!] The RDAP lookup failed for {}!".format(target)))
                print(red("L.. Details: {}".format(e)))

        # Add buffer rows for the next table
        row += 2

        # Write headers for URLVoid table
        dom_worksheet.write(row, 0, "URLVoid Results", bold)
        row += 1
        dom_worksheet.write(row, 0, "Domain", bold)
        dom_worksheet.write(row, 1, "IP", bold)
        dom_worksheet.write(row, 2, "Hostname", bold)
        dom_worksheet.write(row, 3, "Domain Age", bold)
        dom_worksheet.write(row, 4, "Google Rank", bold)
        dom_worksheet.write(row, 5, "Alexa Rank", bold)
        dom_worksheet.write(row, 6, "ASN #", bold)
        dom_worksheet.write(row, 7, "ASN Name", bold)
        dom_worksheet.write(row, 8, "Malicious Content Flags", bold)
        row += 1

        # Check each domain with URLVoid for reputation and some Alexa data
        for domain in domains_list:
            tree = self.DC.run_urlvoid_lookup(domain)
            # Check to see if urlvoid shows the domain flagged by any engines
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

                    print(yellow("[*] URLVoid found malicious activity \
reported for {}!".format(domain)))
                    dom_worksheet.write(row, 8, "Count {}: {}".format(count, engines))

            rep_data = tree[0]
            ip_data = rep_data[11]

            dom_worksheet.write(row, 0, ET.tostring(rep_data[0], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 1, ET.tostring(ip_data[0], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 2, ET.tostring(ip_data[1], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 3, ET.tostring(rep_data[3], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 4, ET.tostring(rep_data[4], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 5, ET.tostring(rep_data[5], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 6, ET.tostring(ip_data[2], method='text')
                                .rstrip().decode('ascii'))
            dom_worksheet.write(row, 7, ET.tostring(ip_data[3], method='text')
                                .rstrip().decode('ascii'))
            row += 1

        # Add buffer rows for the next table
        row += 2

        if dns:
            # TODO: This is udner construction
            # Write headers for the DNS brute force table
            dom_worksheet.write(row, 0, "DNS Brute Force", bold)
            row += 1
            dom_worksheet.write(row, 0, "Return Name", bold)
            dom_worksheet.write(row, 1, "Record Type", bold)
            dom_worksheet.write(row, 2, "Data", bold)
            row += 1

            print(green("[+] DNS brute forcing has been enabled, so proceeding..."))
            for domain in domains_list:
                subs = self.DC.run_dns_bruteforce(domain)

                for result in subs:
                    return_name, record_type, data = result
                    dom_worksheet.write(row, 0, return_name, bold)
                    dom_worksheet.write(row, 1, record_type, bold)
                    dom_worksheet.write(row, 2, data, bold)

    def create_urlcrazy_worksheet(self, workbook, client, domain):
        """Function to add a worksheet for URLCrazy results."""
        # Check if urlcrazy is available and proceed with recording results
        urlcrazy_results = self.DC.run_urlcrazy(client, domain)
        if not urlcrazy_results:
            pass
        else:
            # Setup urlcrazy worksheet
            urlcrazy_worksheet = workbook.add_worksheet("URLCrazy")
            bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
            row = 0

            # Write headers for typosquatting domain table
            urlcrazy_worksheet.write(row, 0, "Typosquatting", bold)
            row += 1
            urlcrazy_worksheet.write(row, 0, "Domain", bold)
            urlcrazy_worksheet.write(row, 1, "A-Records", bold)
            urlcrazy_worksheet.write(row, 2, "MX-Records", bold)
            urlcrazy_worksheet.write(row, 3, "Malicious", bold)
            row += 1
            for result in urlcrazy_results:
                urlcrazy_worksheet.write(row, 0, result['domain'])
                urlcrazy_worksheet.write(row, 1, result['a-records'])
                urlcrazy_worksheet.write(row, 2, result['mx-records'])
                urlcrazy_worksheet.write(row, 3, result['malicious'])
                row += 1

    def create_shodan_worksheet(self, workbook, ip_addresses, domains_list):
        """Function to add a Shodan worksheet with Shodan search results."""
        # Setup the Shodan worksheet
        shodan_worksheet = workbook.add_worksheet("Shodan Results")
        bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
        row = 0

        # Write headers for Shodan search table
        shodan_worksheet.write(row, 0, "Shodan Search Results", bold)
        row += 1
        shodan_worksheet.write(row, 0, "IP Address", bold)
        shodan_worksheet.write(row, 1, "Hostname(s)", bold)
        shodan_worksheet.write(row, 2, "OS", bold)
        shodan_worksheet.write(row, 3, "Port(s)", bold)
        shodan_worksheet.write(row, 4, "Data", bold)
        row += 1

        for domain in domains_list:
            try:
                results = self.DC.run_shodan_search(domain)
                if not results['total'] == 0:
                    # shodan_worksheet.write(row, 0, "{} Shodan results found \
# for:".format(results['total']))
                    for result in results['matches']:
                        shodan_worksheet.write(row, 0, result['ip_str'])
                        shodan_worksheet.write(row, 1, ", ".join(result['hostnames']))
                        shodan_worksheet.write(row, 2, result['os'])
                        shodan_worksheet.write(row, 3, result['port'])
                        shodan_worksheet.write(row, 4, result['data'])
                        row += 1
            except:
                pass

            # Take a break for Shodan's rate limits
            time.sleep(self.sleep)

        # Add buffer rows for the next table
        row += 2

        # Write headers for Shodan host lookup table
        shodan_worksheet.write(row, 0, "Shodan Host Lookup Results", bold)
        row += 1
        shodan_worksheet.write(row, 0, "IP Address", bold)
        shodan_worksheet.write(row, 1, "OS", bold)
        shodan_worksheet.write(row, 2, "Organization", bold)
        shodan_worksheet.write(row, 3, "Port(s)", bold)
        shodan_worksheet.write(row, 4, "Banner(s)", bold)
        row += 1

        vuln_data = []
        for ip in ip_addresses:
            try:
                results = self.DC.run_shodan_lookup(ip)
                shodan_worksheet.write(row, 0, results['ip_str'])
                shodan_worksheet.write(row, 1, results.get('os', 'n/a'))
                shodan_worksheet.write(row, 2, results.get('org', 'n/a'))
                # Collect the banners
                for item in results['data']:
                    shodan_worksheet.write(row, 3, item['port'])
                    shodan_worksheet.write(row, 4, item['data'].rstrip())
                    row += 1
                try:
                    # Check for any vulns Shodan knows about
                    for item in results["vulns"]:
                        temp = {}
                        cve = item.replace("!", "")
                        print(yellow("[!] This host is flagged for {}".format(cve)))
                        # Shodan API requires at least a one second delay between requests
                        time.sleep(5)
                        exploits = self.DC.run_shodan_exploit_search(cve)
                        for vuln in exploits["matches"]:
                            if vuln.get("cve")[0] == cve:
                                cve_description = vuln.get("description")
                                temp['host'] = ip
                                temp['cve'] = cve
                                temp['cve_description'] = cve_description
                                vuln_data.append(temp)
                except Exception as e:
                    pass
            except Exception as e:
                pass

            # Take a break for Shodan's rate limits
            time.sleep(self.sleep)

        # Add buffer rows for the next table
        row += 2

        if vuln_data:
            # Write headers for Shodan Vuln search table
            shodan_worksheet.write(row, 0, "Shodan Vulnerabilities", bold)
            row += 1
            shodan_worksheet.write(row, 0, "IP Address", bold)
            shodan_worksheet.write(row, 1, "CVE", bold)
            shodan_worksheet.write(row, 2, "Description", bold)
            row += 1

            for vuln in vuln_data:
                shodan_worksheet.write(row, 0, vuln['host'])
                shodan_worksheet.write(row, 1, vuln['cve'])
                shodan_worksheet.write(row, 2, vuln['cve_description'])
                row += 1

    def create_censys_worksheet(self, workbook, scope, verbose):
        """Function to add a Censys.io worksheet with Censys host
        information and certificate details.
        """
        # Setup the Censys worksheet
        censys_worksheet = workbook.add_worksheet("Censys Results")
        bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
        row = 0

        # Write headers for Censys search table
        censys_worksheet.write(row, 0, "Censys Search Results", bold)
        row += 1
        censys_worksheet.write(row, 0, "Host", bold)
        censys_worksheet.write(row, 1, "Target Assoc. IP(s)", bold)
        censys_worksheet.write(row, 2, "Location", bold)
        censys_worksheet.write(row, 3, "Port(s)", bold)
        row += 1

        for target in scope:
            try:
                results = self.DC.run_censys_search_address(target)
                censys_worksheet.write(row, 0, target)
                for result in results:
                    censys_worksheet.write(row, 1, result['ip'])
                    censys_worksheet.write(row, 2, result['location.country'])
                    for prot in result["protocols"]:
                        censys_worksheet.write(row, 3, prot)
                        row += 1
            except Exception as e:
                pass

            # Take a break for Censys's rate limits
            time.sleep(self.sleep)

        # Add buffer rows for the next table
        row += 2

        # Collect certificate data from Censys if verbose is set
        if verbose:
            censys_worksheet.write(row, 0, "Host", bold)
            censys_worksheet.write(row, 1, "Cert Subject", bold)
            censys_worksheet.write(row, 2, "Cert Issuer", bold)
            row += 1
            for target in scope:
                try:
                    cert_data = self.DC.run_censys_search_cert(target)
                    censys_worksheet.write(row, 0, target)
                    for cert in cert_data:
                        censys_worksheet.write(row, 1, cert["parsed.subject_dn"])
                        censys_worksheet.write(row, 2, cert["parsed.issuer_dn"])
                        row += 1
                except Exception as e:
                    pass

                # Take a break for Censys's rate limits
                time.sleep(self.sleep)

    def create_people_worksheet(self, workbook, domain, client):
        """Function to add a people worksheet with information
        related to individuals, including email addresses and social
        media profiles.
        """
        # Setup email worksheet
        email_worksheet = workbook.add_worksheet("People & Emails")
        bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
        row = 0

        # Get the "people" data -- emails, names, and social media handles
        try:
            unique_emails, unique_people, unique_twitter = self.PC.harvest_all(domain)
        except Exception as e:
            print(red("[!] Error harvesting contact information!"))
            print(red("L.. Details: {}".format(e)))

        # If we have emails, record them and check HaveIBeenPwned
        if unique_emails:
            # Write headers for email table
            email_worksheet.write(row, 0, "Public Email Addresses", bold)
            row += 1
            email_worksheet.write(row, 0, "Addresses", bold)
            row += 1
            # Check if list can be divided/printed in 3 columns
            if len(unique_emails) % 3 != 0:
                unique_emails.append(" ")

            for a, b, c in zip(unique_emails[::3], unique_emails[1::3], unique_emails[2::3]):
                email_worksheet.write(row, 0, a)
                email_worksheet.write(row, 1, b)
                email_worksheet.write(row, 2, c)
                row += 1

            # Add buffer rows for the next table
            row += 2

            # Write headers for HIBP table
            email_worksheet.write(row, 0, "HaveIBeenPwned Checks", bold)
            row += 1
            email_worksheet.write(row, 0, "Email", bold)
            email_worksheet.write(row, 1, "Breaches", bold)
            email_worksheet.write(row, 2, "Pastes", bold)
            row += 1

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
                            email_worksheet.write(row, 1, ", ".join(hits))
                        if pastes:
                            email_worksheet.write(row, 2, pastes)

                        if pwned or pastes:
                            email_worksheet.write(row, 0, email)
                            row += 1

                    # Give HIBP a rest for a few seconds
                    time.sleep(self.hibp_sleep)
                # Add buffer rows for next table
                row += 2
            except Exception as e:
                print(red("[!] Error checking emails with HaveIBeenPwned's database!"))
                print(red("L.. Detail: {}".format(e)))

        # If we have Twitter handles, cehck Twitter for user data
        if unique_twitter:
            # Write headers for Twitter table
            email_worksheet.write(row, 0, "Twitter Data", bold)
            row += 1
            email_worksheet.write(row, 0, "Handle", bold)
            email_worksheet.write(row, 1, "Real Name", bold)
            email_worksheet.write(row, 2, "Followers", bold)
            email_worksheet.write(row, 3, "Location", bold)
            email_worksheet.write(row, 4, "Description", bold)
            row += 1

            try:
                # Collect any available Twitter info for discovered handles
                for handle in unique_twitter:
                    data = self.PC.harvest_twitter(handle)
                    if data:
                        email_worksheet.write(row, 0, data['handle'])
                        email_worksheet.write(row, 1, data['real_name'])
                        email_worksheet.write(row, 2, data['followers'])
                        email_worksheet.write(row, 3, data['location'])
                        email_worksheet.write(row, 4, data['user_description'])
                        row += 1

                # Add buffer rows for next table
                row += 2
            except Exception as e:
                pass

        # If we have names, try to find LinkedIn profiles for them
        if unique_people:
            # Write headers for LinkedIn table
            email_worksheet.write(row, 0, "LinkedIn Profiles", bold)
            row += 1
            email_worksheet.write(row, 0, "Name", bold)
            email_worksheet.write(row, 1, "Possible Profile(s)", bold)
            row += 1

            try:
            # Try to find possible LinkedIn profiles for people
                for person in unique_people:
                    data = self.PC.harvest_linkedin(person, client)
                    if data:
                        email_worksheet.write(row, 0, person)
                        email_worksheet.write(row, 1, ", ".join(data))
                        row += 1

                # Add buffer rows for next table
                row += 2
            except Exception as e:
                pass

    def create_foca_worksheet(self, workbook, domain, extensions, del_files, verbose):
        """Function to add a FOCA worksheet containing pyFOCA results."""
        # Setup FOCA worksheet
        foca_worksheet = workbook.add_worksheet("File Metadata")
        bold = workbook.add_format({'bold': True, 'font_color': 'blue'})
        row = 0

        # Set domain to look at and choose if files should be deleted
        domain_name = domain

        # Prepare extensions to Google
        exts = extensions.split(',')
        supported_exts = ['all', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt']
        for i in exts:
            if i.lower() not in supported_exts:
                print(red("[!] You've provided an unsupported file extension \
for --file. Please try again."))
                exit()
        if "all" in exts:
            exts = supported_exts[1:]

        # Setup Google settings -- pages to look through and timeout
        # page_results = int(p)
        page_results = 2
        # socket.setdefaulttimeout(float(t))
        socket.setdefaulttimeout(5)

        print(green("[+] File discovery was enabled, so activating PyFOCA -- sit tight..."))
        parser = pyfoca.Metaparser(domain_name, page_results, exts, del_files, verbose)
        metadata = parser.grab_meta()
        parser.clean_up()

        if metadata:
            # Write headers for File Metadata table
            foca_worksheet.write(row, 0, "File Metadata", bold)
            row += 1
            foca_worksheet.write(row, 0, "Filename", bold)
            foca_worksheet.write(row, 1, "Creation Date", bold)
            foca_worksheet.write(row, 2, "Author", bold)
            foca_worksheet.write(row, 3, "Produced By", bold)
            foca_worksheet.write(row, 4, "Modification Date", bold)
            row += 1

            for result in metadata:
                foca_worksheet.write(row, 0, result[0])
                foca_worksheet.write(row, 1, result[1])
                foca_worksheet.write(row, 2, result[2])
                foca_worksheet.write(row, 3, result[3])
                foca_worksheet.write(row, 4, result[4])
                row += 1


    def create_cymon_worksheet(self, target):
        """Function to check the provided the target against Cymon.io's
        database of threat feeds and then print the results.
        """
        if self.DC.is_ip(target):
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