#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import sqlite3
import click
from neo4j.v1 import GraphDatabase
from colors import red, green, yellow
from helpers import setup_gdatabase_conn, is_ip, execute_query


class Grapher(object):
    """A class for converting the ODIN SQLite3 database to a Neo4j graph database."""

    def __init__(self, database_path):
        """Everything that should be initiated with a new object goes here."""
        # Connect to our database
        try:
            self.conn = sqlite3.connect(database_path)
            self.c = self.conn.cursor()
            self.neo4j_driver = setup_gdatabase_conn()
        except Exception as error:
                print(red("[!] Could not open the database file!"))
                print(red("L.. Details: {}".format(error)))

    def _graph_hosts(self):
        """Convert the hosts table into Neo4j graph nodes."""
        self.c.execute("SELECT host_address,in_scope_file,source FROM hosts")
        all_hosts = self.c.fetchall()

        for row in all_hosts:
            if is_ip(row[0]):
                query = """
                MERGE (x:IP {Address:'%s', Scoped:'%s', Source:'%s'})
                RETURN x
                """% (row[0], row[1], row[2])
                execute_query(self.neo4j_driver, query)
            else:
                query = """
                MERGE (x:Domain {Name:'%s', Scoped:'%s', Source:'%s'})
                RETURN x
                """ % (row[0], row[1], row[2])
                execute_query(self.neo4j_driver, query)

    def _graph_subdomains(self):
        """Convert the subdomains table into Neo4j graph nodes with relationships to the domain
        nodes.
        """
        self.c.execute("SELECT domain,subdomain,ip_address,domain_frontable FROM subdomains")
        all_subdomains = self.c.fetchall()

        for row in all_subdomains:
            query = """
            MATCH (b:Domain {Name:'%s'})
            MATCH (c:IP {Address:'%s'})
            CREATE UNIQUE (c)<-[r1:RESOLVES_TO]-(a:Subdomain {Name:'%s', Address:'%s', DomainFrontable:'%s'})-[r2:SubdomainOf]->(b)
            RETURN a,b,c
            """ % (row[0], row[2], row[1], row[2], row[3])
            execute_query(self.neo4j_driver, query)

    def _graph_certificates(self):
        """Convert the certificates table into Neo4j graph nodes with relationships to the domain
        nodes.
        """
        self.c.execute("SELECT host,subject,issuer,start_date,expiration_date,self_signed,signature_algo,censys_fingerprint,alternate_names FROM certificates")
        all_certificates = self.c.fetchall()

        for row in all_certificates:
            query = """
            MATCH (b:Subdomain {Name:'%s'})
            MERGE (a:Certificate {Subject:"%s", Issuer:"%s", StartDate:"%s", ExpirationDate:"%s", SelfSigned:"%s", SignatureAlgo:"%s", CensysFingerprint:"%s"})-[r:ISSUED_FOR]->(b)
            RETURN a,b
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
            execute_query(self.neo4j_driver, query)

            for name in row[8]:
                query = """
                MATCH (a:Subdomain {Name:'%s'})
                Match (b:Certificate {CensysFingerprint:"%s"})
                MERGE (a)<-[r:ISSUED_FOR]-(b)
                """ % (name, row[7])
                execute_query(self.neo4j_driver, query)

    def _update_dns(self):
        """Update domain nodes with DNS information."""
        self.c.execute("SELECT domain,ns_record,a_record,mx_record,txt_record,soa_record,dmarc,vulnerable_cache_snooping FROM dns")
        dns_data = self.c.fetchall()

        for row in dns_data:
            query = """
            MATCH (a:Domain {Name:'%s'})
            SET a += {NameServers:'%s', ARecords:'%s', MXRecords:'%s', TXTRecords:'%s', SOARecords:'%s', DMARC:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            execute_query(self.neo4j_driver, query)

            for address in row[2].split(","):
                query = """
                MATCH (a:Domain {Name:'%s'})
                MATCH (b:IP {Address:'%s'})
                CREATE UNIQUE (a)-[r:RESOLVES_TO]->(b)
                RETURN a,r,b
                """ % (row[0], address)
                execute_query(self.neo4j_driver, query)

    def _update_rdap(self):
        """Update host nodes with RDAP information."""
        self.c.execute("SELECT ip_address,rdap_source,organization,network_cidr,asn,country_code,robtex_related_domains FROM rdap_data")
        all_rdap = self.c.fetchall()

        for row in all_rdap:
            query = """
            MATCH (a:IP {Address:'%s'})
            SET a += {RDAPSource:'%s', Organization:'%s', CIDR:'%s', ASN:'%s', CountryCode:'%s', Robtex:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6])
            execute_query(self.neo4j_driver, query)

    def _update_whois(self):
        """Update domain nodes with whois information."""
        self.c.execute("SELECT domain,registrar,expiration,organization,registrant,admin_contact,tech_contact,address,dns_sec FROM whois_data")
        all_whois = self.c.fetchall()

        for row in all_whois:
            query = """
            MATCH (a:Domain {Name:'%s'})
            SET a += {Registrar:'%s', Expiration:'%s', Organization:'%s', Registrant:'%s', Admin:'%s', Tech:'%s', Address:'%s', DNSSEC:'%s'}
            RETURN a
            """ % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
            execute_query(self.neo4j_driver, query)

    def _graph_shodan(self):
        """Convert the Shodan tables with ports added as Neo4j graph nodes linked to hosts."""
        self.c.execute("SELECT domain,ip_address,port,banner_data,os,hostname FROM shodan_search")
        all_shodan_search = self.c.fetchall()

        for row in all_shodan_search:
            query = """
            MATCH (c:Domain {Name:'%s'})
            MATCH (b:IP {Address:'%s'})
            CREATE UNIQUE (a:Port {Number:'%s', OS:'%s', Hostname:'%s', Organization:''})<-[r:HAS_PORT]-(b)<-[:RESOLVES_TO]-(c)
            RETURN a,b
            """ % (row[0], row[1], row[2], row[4], row[5])
            execute_query(self.neo4j_driver, query)

        self.c.execute("SELECT ip_address,port,banner_data,os,organization FROM shodan_host_lookup")
        all_shodan_lookup = self.c.fetchall()

        for row in all_shodan_lookup:
            query = """
            MATCH (a:IP {Address:'%s'})
            MERGE (b:Port {Number:'%s', OS:'%s', Organization:'%s', Hostname:''})<-[r:HAS_PORT]-(a)
            RETURN a,b
            """ % (row[0], row[1], row[3], row[4])
            execute_query(self.neo4j_driver, query)


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

    def clear_neo4j_database(self):
        """Clear the current Neo4j database by detaching and deleting all nodes."""
        query = """MATCH (n) DETACH DELETE n"""
        result = execute_query(self.neo4j_driver, query)

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

def visualize(database, nuke):
    print(green("[+] Loading ODIN database file {}").format(database))
    graph = Grapher(database)

    if nuke:
        confirm = input(red("\n[!] Preparing to nuke the Neo4j database! This wipes out all nodes for a \
fresh start. Proceed? (Y\\N) "))
        if confirm == "Y" or confirm == "y":
            graph.clear_neo4j_database()
            print(green("[+] Database successfully wiped!\n"))
        else:
            print(red("[!] Then remove the --nuke flag and try again..."))
            exit()

    graph.convert()

if __name__ == "__main__":
    visualize()
