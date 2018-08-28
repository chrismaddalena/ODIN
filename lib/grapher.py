#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions and Cypher queries necessary to convert the provided SQLite3
database to a Neo4j graph database. This module can also be run independently to convert a
SQLite3 database at a later time.
"""

import sys
import sqlite3

import click
from neo4j.v1 import GraphDatabase
from colors import red, green, yellow

# Try importing helpers.py two different ways to allow for graphers.py to be executed independantly
try:
    from lib import helpers
except:
    import helpers


class Grapher(object):
    """A class for converting the ODIN SQLite3 database to a Neo4j graph database."""

    def __init__(self, database_path):
        """Everything that should be initiated with a new object goes here."""
        # Connect to our database
        try:
            self.conn = sqlite3.connect(database_path)
            self.c = self.conn.cursor()
            self.neo4j_driver = helpers.setup_gdatabase_conn()
        except Exception as error:
                print(red("[!] Could not open the database file!"))
                print(red("L.. Details: {}".format(error)))

    def _graph_company(self):
        """Create nodes for the organization names and link them to domains based on whois records
        and Full Contact API results.
        """
        org_names = []
        try:
            self.c.execute("SELECT organization FROM whois_data")
            whois_orgs = self.c.fetchall()
            for org in whois_orgs:
                org_names.append(org[0])
        except:
            pass

        try:
            self.c.execute("SELECT company_name,website,website_overview,employees,year_founded FROM company_info")
            company_info = self.c.fetchone()
            org_names.append(company_info[0])
            org_names = set(org_names)
        except:
            pass

        if len(org_names) > 0:
            for org in org_names:
                query = """
                MERGE (x:Organization {Name:"%s"})
                RETURN x
                """% (org)
                helpers.execute_query(self.neo4j_driver, query)

        if company_info:
            query = """
            MATCH (x:Organization {Name:'%s'})
            SET x += {Website:'%s', WebsiteOverview:"%s", Employees:'%s', YearFounded:'%s'}
            RETURN x
            """% (company_info[0], company_info[1], company_info[2], company_info[3], company_info[4])
            helpers.execute_query(self.neo4j_driver, query)

        for org in org_names:
            query = """
            MATCH (o:Organization {Name:"%s"})
            MATCH (d:Domain) WHERE d.Organization="%s"
            MERGE (o)-[r:OWNS]->(d)
            RETURN o,r,d
            """% (org, org)
            helpers.execute_query(self.neo4j_driver, query)

    def _graph_hosts(self):
        """Convert the hosts table into Neo4j graph nodes."""
        self.c.execute("SELECT host_address,in_scope_file,source FROM hosts")
        all_hosts = self.c.fetchall()

        for row in all_hosts:
            if row[1] == 0:
                scoped = False
            else:
                scoped = True
            if helpers.is_ip(row[0]):
                query = """
                MERGE (x:IP {Address:'%s', Scoped:'%s', Source:'%s'})
                RETURN x
                """% (row[0], scoped, row[2])
                helpers.execute_query(self.neo4j_driver, query)
            else:
                query = """
                MERGE (x:Domain {Name:'%s', Scoped:'%s', Source:'%s'})
                RETURN x
                """ % (row[0], scoped, row[2])
                helpers.execute_query(self.neo4j_driver, query)

    def _graph_subdomains(self):
        """Convert the subdomains table into Neo4j graph nodes with relationships to the domain
        nodes.
        """
        self.c.execute("SELECT domain,subdomain,ip_address,domain_frontable FROM subdomains")
        all_subdomains = self.c.fetchall()

        for row in all_subdomains:
            query = """
            MERGE (x:Subdomain {Name:'%s', Address:"%s", DomainFrontable:'%s'})
            """ % (row[1], row[2], row[3])
            helpers.execute_query(self.neo4j_driver, query)

            query = """
            MATCH (a:Subdomain {Name:'%s'})
            MATCH (b:Domain {Name:'%s'})
            MATCH (c:IP {Address:"%s"})
            CREATE UNIQUE (c)<-[r1:RESOLVES_TO]-(a)-[r2:SUBDOMAIN_OF]->(b)
            RETURN a,b,c
            """ % (row[1], row[0], row[2])
            helpers.execute_query(self.neo4j_driver, query)

    def _graph_certificates(self):
        """Convert the certificates table into Neo4j graph nodes with relationships to the domain
        nodes.
        """
        self.c.execute("SELECT host,subject,issuer,start_date,expiration_date,self_signed,signature_algo,censys_fingerprint,alternate_names FROM certificates")
        all_certificates = self.c.fetchall()

        for row in all_certificates:
            if row[5]:
                self_signed = False
            else:
                self_signed = True
            query = """
            CREATE (a:Certificate {Subject:"%s", Issuer:"%s", StartDate:"%s", ExpirationDate:"%s", SelfSigned:"%s", SignatureAlgo:"%s", CensysFingerprint:"%s"})
            RETURN a
            """ % (row[1], row[2], row[3], row[4], self_signed, row[6], row[7])
            helpers.execute_query(self.neo4j_driver, query)

            alt_names = row[8].split(",")
            for name in alt_names:
                query = """
                MATCH (a:Subdomain {Name:"%s"})
                MATCH (b:Certificate {CensysFingerprint:"%s"})
                MERGE (a)<-[r:ISSUED_FOR]-(b)
                """ % (name.strip(), row[7])
                helpers.execute_query(self.neo4j_driver, query)
                query = """
                MATCH (a:Domain {Name:"%s"})
                MATCH (b:Certificate {CensysFingerprint:"%s"})
                MERGE (a)<-[r:ISSUED_FOR]-(b)
                """ % (name.strip(), row[7])
                helpers.execute_query(self.neo4j_driver, query)

    def _update_dns(self):
        """Update domain nodes with DNS information."""
        self.c.execute("SELECT domain,ns_record,a_record,mx_record,txt_record,soa_record,dmarc,vulnerable_cache_snooping FROM dns")
        dns_data = self.c.fetchall()

        for row in dns_data:
            query = """
            MATCH (a:Domain {Name:"%s"})
            SET a += {NameServers:"%s", Address:"%s", MXRecords:'%s', TXTRecords:'%s', SOARecords:'%s', DMARC:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            helpers.execute_query(self.neo4j_driver, query)

            for address in row[2].split(","):
                query = """
                MATCH (a:Domain {Name:'%s'})
                MATCH (b:IP {Address:'%s'})
                CREATE UNIQUE (a)-[r:RESOLVES_TO]->(b)
                RETURN a,r,b
                """ % (row[0], address)
                helpers.execute_query(self.neo4j_driver, query)

    def _update_rdap(self):
        """Update host nodes with RDAP information."""
        self.c.execute("SELECT ip_address,rdap_source,organization,network_cidr,asn,country_code,robtex_related_domains FROM rdap_data")
        all_rdap = self.c.fetchall()

        for row in all_rdap:
            query = """
            MATCH (a:IP {Address:'%s'})
            SET a += {RDAPSource:'%s', Organization:"%s", CIDR:'%s', ASN:'%s', CountryCode:'%s', RelatedDomains:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            helpers.execute_query(self.neo4j_driver, query)

    def _update_whois(self):
        """Update domain nodes with whois information."""
        self.c.execute("SELECT domain,registrar,expiration,organization,registrant,admin_contact,tech_contact,address,dns_sec FROM whois_data")
        all_whois = self.c.fetchall()

        for row in all_whois:
            query = """
            MATCH (a:Domain {Name:'%s'})
            SET a += {Registrar:"%s", Expiration:'%s', Organization:"%s", Registrant:"%s", Admin:"%s", Tech:"%s", ContactAddress:"%s", DNSSEC:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
            helpers.execute_query(self.neo4j_driver, query)

    def _graph_shodan(self):
        """Convert the Shodan tables with ports added as Neo4j graph nodes linked to hosts."""
        self.c.execute("SELECT ip_address,port,banner_data,os,organization FROM shodan_host_lookup")
        all_shodan_lookup = self.c.fetchall()

        for row in all_shodan_lookup:
            query = """
            MATCH (a:IP {Address:'%s'})
            CREATE UNIQUE (b:Port {Number:'%s', OS:'%s', Organization:"%s", Hostname:''})<-[r:HAS_PORT]-(a)
            SET a.Organization = "%s"
            RETURN a,b
            """ % (row[0], row[1], row[3], row[4], row[4])
            helpers.execute_query(self.neo4j_driver, query)

        self.c.execute("SELECT domain,ip_address,port,banner_data,os,hostname FROM shodan_search")
        all_shodan_search = self.c.fetchall()

        for row in all_shodan_search:
            query = """
            MATCH (a:Port)<-[:HAS_PORT]-(b:IP {Address:'%s'})
            SET a.Hostname = "%s"
            RETURN a
            """ % (row[1], row[5])
            helpers.execute_query(self.neo4j_driver, query)

    def convert(self):
        """Executes the necessary Neo4j queries to convert a complete ODIN SQLite3 database to a
        Neo4j graph database.
        """
        self._graph_hosts()
        print(green("[+] Hosts done"))
        self._graph_subdomains()
        print(green("[+] Subdomains done"))
        self._graph_certificates()
        print(green("[+] Certificates done"))
        self._update_dns()
        print(green("[+] DNS done"))
        self._update_whois()
        print(green("[+] Whois done"))
        self._update_rdap()
        print(green("[+] RDAP done"))
        self._graph_shodan()
        print(green("[+] Shodan done"))
        self._graph_company()
        print(green("[+] Company done"))

    def clear_neo4j_database(self):
        """Clear the current Neo4j database by detaching and deleting all nodes."""
        query = """MATCH (n) DETACH DELETE n"""
        result = helpers.execute_query(self.neo4j_driver, query)

    def execute_query_for_json(self, query):
        """Execute the provided query and return the JSON response."""
        result = helpers.execute_query(self.neo4j_driver, query)

        return result


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
@click.command(context_settings=CONTEXT_SETTINGS)

# Declare our CLI options
@click.option('-d', '--database', help="The path to your completed ODIN database file.", \
              type=click.Path(exists=True, readable=True, resolve_path=True), required=True)
@click.option('--nuke', is_flag=True, help="Nuke the Neo4j database to start over. This destroys \
ALL data to start fresh.")
@click.option('-q', '--query', help="Execute the provided query.")

def visualize(database, nuke, query):
    print(green("[+] Loading ODIN database file {}").format(database))
    graph = Grapher(database)

    if query:
        print(green("[+] Executing this query and then exiting:"))
        print(yellow(query))
        result = graph.execute_query_for_json(query)
        print(green("[+] Query successfully executed."))
        exit()

    if nuke:
        confirm = input(red("\n[!] Preparing to nuke the Neo4j database! This wipes out all nodes for a \
fresh start. Proceed? (Y\\N) "))
        if confirm.lower() == "y":
            graph.clear_neo4j_database()
            print(green("[+] Database successfully wiped!\n"))
        else:
            print(red("[!] Then remove the --nuke flag and try again..."))
            exit()

    graph.convert()

if __name__ == "__main__":
    visualize()
