#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This script opens the provided ODIN SQLite database and generates an HTML report."""

import sqlite3
import sys
import os
import html
from colors import red, green, yellow

class HTMLReporter(object):
    """A class that opens an ODIN database file and generates an HTML report."""

    def __init__(self, report_path, database_path):
        """Everything that should be initiated with a new object goes here."""
        self.report_path = report_path

        if not os.path.exists(report_path):
            try:
                os.makedirs(report_path)
            except OSError as error:
                print(red("[!] Could not create the HTML report directory!"))
                print(red("L.. Details: {}".format(error)))

        try:
            self.conn = sqlite3.connect(database_path)
            self.c = self.conn.cursor()
        except Exception as error:
                print(red("[!] Could not open the database file!"))
                print(red("L.. Details: {}".format(error)))

    def close_out_reporting(self):
        """Function to check the new database and tables and close the connections."""
        confirm = input(green("[+] Job's done! Do you wan to view the HTML report now? (Y\\N) "))
        if confirm == "Y" or confirm == "y":
            os.system("open '{}/report.html'".format(self.report_path))
        else:
            print(green("[+] Exiting..."))
            exit()
        # Close the connection to the database
        self.conn.close()

    def generate_link_tables(self):
        """Function to create link tables between the hosts table and tables with IP address and
        domain info. Each table is named <something>_link and uses a link_id as its primary key.
        """
        try:
            self.c.execute('''CREATE TABLE 'dns_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'dns_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(dns_id) REFERENCES dns(id))
                    ''')
        except:
            print("[!] Could not create DNS link table! ")
            
        try:
            self.c.execute('''CREATE TABLE 'whois_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'whois_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(whois_id) REFERENCES whois_data(id))
                    ''')
        except:
            print("[!] Could not create Whois link table! ")

        try:
            self.c.execute('''CREATE TABLE 'rdap_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'rdap_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(rdap_id) REFERENCES rdap_data(id))
                    ''')
        except:
            print("[!] Could not create RDAP link table! ")

        try:
            self.c.execute('''CREATE TABLE 'subdomain_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'subdomain_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(subdomain_id) REFERENCES subdomains(id))
                    ''')
        except:
            print("[!] Could not create Subdomain link table! ")

        try:
            self.c.execute('''CREATE TABLE 'shodan_search_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'shodan_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(shodan_id) REFERENCES shodan_host_lookup(id))
                    ''')
        except:
            print("[!] Could not create Shodan Search link table! ")

        try:
            self.c.execute('''CREATE TABLE 'shodan_host_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'shodan_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(shodan_id) REFERENCES shodan_search(id))
                    ''')
        except:
            print("[!] Could not create Shodan Host link table! ")

        try:
            self.c.execute('''CREATE TABLE 'ip_hist_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'hist_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(hist_id) REFERENCES ip_history(id))
                    ''')
        except:
            print("[!] Could not create IP History link table! ")


        try:
            self.c.execute('''CREATE TABLE 'certificate_link'
                    ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'cert_id' text, 
                    FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(cert_id) REFERENCES certificates(id))
                    ''')
        except:
            print("[!] Could not create Certificate link table! ")

    def link_the_tables(self):
        """Function to populate the link tables."""
        # Link hosts and the dns records
        self.c.execute('SELECT id,domain FROM dns')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'dns_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the whois records
        self.c.execute('SELECT id,domain FROM whois_data')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'whois_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the rdap records
        self.c.execute('SELECT id,ip_address FROM rdap_data')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'rdap_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the subdomain records
        self.c.execute('SELECT id,domain FROM subdomains')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'subdomain_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the shodan host lookup records
        self.c.execute('SELECT id,ip_address FROM shodan_host_lookup')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'shodan_host_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the shodan search records
        self.c.execute('SELECT id,domain FROM shodan_search')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'subdomain_search_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the certificates records
        self.c.execute('SELECT id,host FROM certificates')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'certificate_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

        # Link hosts and the IP history records
        self.c.execute('SELECT id,domain FROM ip_history')
        records = self.c.fetchall()
        for row in records:
            for x in row[1].split(","):
                for host_info in self.c.execute('SELECT id,host_address FROM hosts'):
                    if x.strip() == host_info[1]:
                        self.c.execute("INSERT INTO 'ip_hist_link' VALUES (NULL,?,?)", (host_info[0], row[0]))
                        self.conn.commit()

    def create_report_page(self):
        """Function to create the main reports.html page in the report directory."""
        with open(self.report_path + "report.html", "w") as report:
            self.c.execute("SELECT * FROM company_info")
            company_info = self.c.fetchone()
            name = company_info[0]
            logo = company_info[1]
            website = company_info[2]
            employees = company_info[3]
            founded = company_info[4]

            content = """
            <html>
            <head></head>
            <title>ODIN Report for {}</title>
            <body>
            <h1>ODIN Report for {}</h1>
            <img src='{}' alt='Company Logo' style="width:250px;" />
            <p>Website: <a href='{}'>{}</a></p>
            <p>Employees: {}</p>
            <p>Founded: {}</p>
            <h2>Table of Contents</h2>
            <li><a href='hosts.html'>Hosts Report</li>
            <li><a href='people.html'>Social & Email</li>
            <li><a href='domains.html'>Domain Data</li>
            <li><a href='subdomains.html'>Subdomains</li>
            <li><a href='networks.html'>IP Address Data</li>
            <li><a href='shodan.html'>Shodan Data</a></li>
            <li><a href='certificates.html'>Certificates</li>
            <li><a href='cloud.html'>The Cloud</a></li>
            </body>
            </html>
            """.format(name, name, logo, website, website, employees, founded)

            report.write(content)

    def create_hosts_page(self):
        """Function to create the hosts.html page in the report directory."""
        with open(self.report_path + "hosts.html", "w") as report:
            self.c.execute("SELECT host_address,source FROM hosts WHERE in_scope_file=0")
            out_of_scope = self.c.fetchall()
            self.c.execute("SELECT host_address FROM hosts WHERE in_scope_file=1")
            in_scope = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Hosts Report</title>
            <body>
            <h1>Hosts Report</h1>
            <h2>All Hosts</h2>
            <p>This table reflects the hosts/targets provided on the command line and the optional scope file:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Host</th>
            </tr>
            """

            for row in in_scope:
                for x in row[0].split(","):
                    content += "<tr><th>{}</th></tr>".format(x)
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Discovered Hosts</h2>
            <p>This table reflects the hosts/targets identified by ODIN:</p>
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Host</th>
            <th>Source</th>
            </tr>
            """

            for row in out_of_scope:
                content += "<tr><th>{}</th><th>{}</th></tr>".format(row[0], row[1])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_people_page(self):
        """Function to create the people.html page in the report directory."""
        with open(self.report_path + "people.html", "w") as report:
            self.c.execute("SELECT * FROM email_addresses")
            emails = self.c.fetchall()
            self.c.execute("SELECT * FROM employee_data")
            employees = self.c.fetchall()
            self.c.execute("SELECT * FROM twitter")
            twitter = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Email & Social Report</title>
            <body>
            <h1>Email & Social Report</h1>
            <h2>Public Email Addresses & Related Breach Data</h2>
            <p>This table contains discovered email addresses and links to data breaches and posts from
            Have I Been Pwned's database:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Email Address</th>
            <th>Data Breach</th>
            <th>Paste</th>
            </tr>
            """

            for row in emails:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Employee Data</h2>
            <p>This table contains any data ODIN was able to collect about employees of the organization:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Employee Name</th>
            <th>Job Title</th>
            <th>LinkedIn URL</th>
            </tr>
            """

            for row in employees:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"


            content += """
            <h2>Twitter Profiles</h2>
            <p>This table contains the data collected about Twitter accounts potentally linked to the organization:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Handle</th>
            <th>Real Name</th>
            <th>Follower Count</th>
            <th>Location</th>
            <th>Description</th>
            </tr>
            """

            for row in twitter:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], row[4])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_certificates_page(self):
        """Function to create the certificates.html page in the report directory."""
        with open(self.report_path + "certificates.html", "w") as report:
            self.c.execute("SELECT host,subject,issuer FROM certificates")
            certificates = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Certificates Report</title>
            <body>
            <h1>SSL/TLS Certificates</h1>
            <h2>Discovered Certificates</h2>
            <p>This table contains the SSL/TLS certificates ODIN was able to find:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>Subject</th>
            <th>Issuer</th>
            </tr>
            """

            for row in certificates:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_cloud_page(self):
        """Function to create the cloud.html page in the report directory."""
        with open(self.report_path + "cloud.html", "w") as report:
            self.c.execute("SELECT name,bucket_uri,bucket_arn,publicly_accessible FROM cloud")
            all_cloud = self.c.fetchall()
            self.c.execute("SELECT name,bucket_uri,bucket_arn,publicly_accessible FROM cloud WHERE publicly_accessible=1")
            public_cloud = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Cloud Report</title>
            <body>
            <h1>Cloud Report</h1>
            <h2>Publicly Accessible Resources</h2>
            <p>This table contains the list of S3 buckets and Digital Ocean Spaces ODIN was able to find and access:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Name</th>
            <th>URI</th>
            </tr>
            """

            for row in public_cloud:
                content += "<tr><th>{}</th><th>{}</th></tr>".format(row[0], row[1])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>All Discovered Resources</h2>
            <p>This table contains the list of all S3 buckets and Digital Ocean Spaces ODIN was able to identify:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Name</th>
            <th>URI</th>
            </tr>
            """

            for row in all_cloud:
                content += "<tr><th>{}</th><th>{}</th></tr>".format(row[0], row[1])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_domains_page(self):
        """Function to create the people.html page in the report directory."""
        with open(self.report_path + "domains.html", "w") as report:
            self.c.execute("SELECT domain,registrar,expiration FROM whois_data")
            registration_data = self.c.fetchall()
            self.c.execute("SELECT domain,organization,admin_contact,tech_contact,address FROM whois_data")
            whois_contacts = self.c.fetchall()
            self.c.execute("SELECT domain,ns_record,a_record,mx_record,txt_record,soa_record,dmarc FROM dns")
            dns_records = self.c.fetchall()
            self.c.execute("SELECT domain,ns_record,vulnerable_cache_snooping FROM dns WHERE vulnerable_cache_snooping IS NOT NULL")
            cache_snoop = self.c.fetchall()
            self.c.execute("SELECT domain,netblock_owner,ip_address FROM ip_history")
            ip_history = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Domain Names Report</title>
            <body>
            <h1>Domain Names Report</h1>
            <h2>Domain Registration</h2>
            <p>This table contains the domain registration data for the reviewed domain names:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>Registrar</th>
            <th>Expiration</th>
            </tr>
            """

            for row in registration_data:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Whois Contacts</h2>
            <p>This table contains the contact information tied to the domain names:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>Organization</th>
            <th>Admin Contact</th>
            <th>Tech Contact</th>
            <th>Address</th>
            </tr>
            """

            for row in whois_contacts:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], row[4])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>DNS Records</h2>
            <p>This table contains the DNS records for the domain names:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>NS Record(s)</th>
            <th>A Record(s)</th>
            <th>MX Record(s)</th>
            <th>TXT Record(s)</th>
            <th>SOA Record</th>
            <th>DMARC Record</th>
            </tr>
            """

            for row in dns_records:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Name Server Cache Snooping</h2>
            <p>This table contains name servers vulnerable to DNS cache snooping:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>NS Record(s)</th>
            <th>Vulnerable Name Server</th>
            </tr>
            """

            for row in cache_snoop:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>IP History</h2>
            <p>This table contains IP history for domain names collected from Netcraft:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Domain</th>
            <th>Netblock Owner</th>
            <th>IP Address</th>
            </tr>
            """

            for row in ip_history:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_subdomains_page(self):
        """Function to create the subdomains.html page in the report directory."""
        with open(self.report_path + "subdomains.html", "w") as report:
            self.c.execute("SELECT domain,subdomain,ip_address,source FROM subdomains")
            subdomains = self.c.fetchall()
            self.c.execute("SELECT domain,subdomain,domain_frontable FROM subdomains WHERE domain_frontable <> 0")
            frontable = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Subdomains</title>
            <body>
            <h1>Subdomains</h1>
            """


            if frontable:
                content += """
                <h2>Frontable Subdomains</h2>
                <p>This table contains subdomains that may be used for domain fronting:
                <table style="width:100%" align="left" border="1">
                <tr>
                <th>Base Domain</th>
                <th>Subdomain</th>
                <th>CDN Information</th>
                </tr>
                """
                
                for row in frontable:
                    content += "<tr><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2])
                content += "</table><p><br /><br /></p>"    

            content += """
            <h2>Discovered Subdomains</h2>
            <p>This table contains all of the subdomains ODIN identified, the IP address, and the source of the subdomain:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Base Domain</th>
            <th>Subdomain</th>
            <th>IP Address</th>
            <th>Source</th>
            </tr>
            """

            for row in subdomains:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_networks_page(self):
        """Function to create the networks.html page in the report directory."""
        with open(self.report_path + "networks.html", "w") as report:
            self.c.execute("SELECT ip_address,rdap_source,organization,network_cidr,asn,country_code FROM rdap_data")
            rdap_data = self.c.fetchall()
            self.c.execute("SELECT ip_address,robtex_related_domains FROM rdap_data")
            related_domains = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>IP Address Report</title>
            <body>
            <h1>IP Address Report</h1>
            <h2>RDAP Records</h2>
            <p>This table contains information pulled from RDAP for each analyzed IP address:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>IP Address</th>
            <th>RDAP Source</th>
            <th>Organization</th>
            <th>Network CIDR</th>
            <th>ASN</th>
            <th>Country Code</th>
            </tr>
            """

            for row in rdap_data:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], row[4], row[5])
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Related Domains</h2>
            <p>This table contains domain names known to be tied to these IP addresses (via Robtex):
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>IP Address</th>
            <th>Related Domain</th>
            </tr>
            """

            for row in related_domains:
                content += "<tr><th>{}</th><th>{}</th></tr>".format(row[0], row[1])
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def create_shodan_page(self):
        """Function to create the shodan.html page in the report directory."""
        with open(self.report_path + "shodan.html", "w") as report:
            self.c.execute("SELECT ip_address,os,organization,port,banner_data FROM shodan_host_lookup")
            shodan_lookup = self.c.fetchall()
            self.c.execute("SELECT domain,ip_address,hostname,os,port,banner_data FROM shodan_search")
            shodan_search = self.c.fetchall()

            content = """
            <html>
            <head></head>
            <title>Shodan Data</title>
            <body>
            <h1>Shodan Data</h1>
            <h2>Shodan Search Results</h2>
            <p>This table contains the results for Shodan searches on domain names:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>Search Term</th>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>OS</th>
            <th>Port</th>
            <th>Banner</th>
            </tr>
            """

            for row in shodan_search:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], row[4], html.escape(row[5]))
            content += "</table><p><br /><br /></p>"

            content += """
            <h2>Shodan Host Lookups</h2>
            <p>This table contains the information Shodan has on the identified IP addresses:
            <table style="width:100%" align="left" border="1">
            <tr>
            <th>IP Address</th>
            <th>OS</th>
            <th>Organization</th>
            <th>Port</th>
            <th>Banner</th>
            </tr>
            """

            for row in shodan_lookup:
                content += "<tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>".format(row[0], row[1], row[2], row[3], html.escape(row[4]))
            content += "</table><p><br /><br /></p>"

            content += """
            </body>
            </html>
            """

            report.write(content)

    def generate_full_report(self):
        """Function to generate all report pages."""
        self.generate_link_tables()
        self.create_report_page()
        self.create_hosts_page()
        self.create_domains_page()
        self.create_networks_page()
        self.create_subdomains_page()
        self.create_certificates_page()
        self.create_shodan_page()
        self.create_people_page()
        self.create_cloud_page()
        self.close_out_reporting()
