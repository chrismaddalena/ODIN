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
from neo4j import GraphDatabase

# Try importing helpers.py two different ways to allow for grapher.py to be executed independently
try:
    from lib import helpers
except:
    import helpers


class Grapher(object):
    """A class for converting the ODIN SQLite3 database to a Neo4j graph database."""

    def __init__(self, database_path):
        """Everything that should be initiated with a new object goes here.

        Parameters:
        database_path   The full filepath to the SQLite3 database
        """
        # Connect to the SQLite3 database
        try:
            self.conn = sqlite3.connect(database_path)
            self.c = self.conn.cursor()
            self.neo4j_driver = helpers.setup_gdatabase_conn()
        except Exception as error:
            click.secho("[!] Could not open the database file!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")

    def _graph_company(self):
        """Create nodes for the organization names and link them to domains based on WHOIS records
        and Full Contact API results.
        """
        org_names = []
        company_info = []
        try:
            self.c.execute(
                "SELECT company_name,website,website_overview,employee_count,year_founded FROM company_info"
            )
            company_info = self.c.fetchone()
            org_names.append(company_info[0])
        except:
            pass
        org_names = set(org_names)
        if len(org_names) > 0:
            for org in org_names:
                query = """
                MERGE (x:Organization {Name:"%s"})
                RETURN x
                """ % (
                    org
                )
                helpers.execute_query(self.neo4j_driver, query)
        else:
            query = """
            MERGE (x:Organization {Name:"Target"})
            RETURN x
            """
            helpers.execute_query(self.neo4j_driver, query)

        if company_info:
            query = """
            MATCH (x:Organization {Name:'%s'})
            SET x += {Website:'%s', WebsiteOverview:"%s", Employees:'%s', YearFounded:'%s'}
            RETURN x
            """ % (
                company_info[0],
                company_info[1],
                company_info[2],
                company_info[3],
                company_info[4],
            )
            helpers.execute_query(self.neo4j_driver, query)

        for org in org_names:
            if len(org_names) == 1:
                # Associate the domain nodes with the organization
                query = """
                MATCH (d:Domain)`
                SET d += {Organization:'%s'}
                RETURN d
                """ % (
                    org
                )
                helpers.execute_query(self.neo4j_driver, query)
                # Create the relationships between the organization node and the domain nodes
                query = """
                MATCH (o:Organization {Name:"%s"})
                MATCH (d:Domain) WHERE d.Organization="%s"
                MERGE (o)-[r:OWNS]->(d)
                RETURN o,r,d
                """ % (
                    org,
                    org,
                )
                helpers.execute_query(self.neo4j_driver, query)
            else:
                query = """
                MATCH (o:Organization {Name:"%s"})
                MATCH (d:Domain) WHERE d.Organization="%s"
                MERGE (o)-[r:OWNS]->(d)
                RETURN o,r,d
                """ % (
                    org,
                    org,
                )
                helpers.execute_query(self.neo4j_driver, query)

    def _graph_hosts(self):
        """Convert the hosts table into Neo4j graph nodes."""
        self.c.execute("SELECT host,in_scope_file,source FROM hosts")
        all_hosts = self.c.fetchall()
        with click.progressbar(
            all_hosts, label="Creating Domain and IP nodes", length=len(all_hosts)
        ) as bar:
            for row in bar:
                if row[1] == 0:
                    scoped = False
                else:
                    scoped = True
                if helpers.is_ip(row[0]):
                    query = """
                    MERGE (x:IP {Address:'%s', Scoped:'%s', Source:'%s'})
                    RETURN x
                    """ % (
                        row[0],
                        scoped,
                        row[2],
                    )
                    helpers.execute_query(self.neo4j_driver, query)
                else:
                    query = """
                    MERGE (x:Domain {Name:'%s', Scoped:'%s', Source:'%s'})
                    RETURN x
                    """ % (
                        row[0],
                        scoped,
                        row[2],
                    )
                    helpers.execute_query(self.neo4j_driver, query)

    def _graph_subdomains(self):
        """Convert the subdomains table into Neo4j graph nodes with relationships to the domain
        and other subdomain nodes.
        """
        self.c.execute(
            "SELECT domain,subdomain,domain_frontable,domain_takeover FROM subdomains"
        )
        all_subdomains = self.c.fetchall()
        with click.progressbar(
            all_subdomains, label="Creating Subdomain nodes", length=len(all_subdomains)
        ) as bar:
            # Enforce unique nodes for subdomains
            query = """
            CREATE CONSTRAINT ON (a:Subdomain) ASSERT a.Name IS UNIQUE
            """
            helpers.execute_query(self.neo4j_driver, query)
            # Loop over each subdomain to create nodes
            for row in bar:
                # Start with the full domain info and then split it apart
                # If we have a subdomain of a subdomain we want to create that relationship
                base_domain = row[0]
                subdomain = row[1]
                partial_subdomain = ".".join(subdomain.split(".")[1:])
                domain_frontable = row[2]
                domain_takeover = row[3]
                # Create the subdomain node
                query = """
                MERGE (x:Subdomain {Name:'%s'})
                ON CREATE SET x.Takeover = "%s", x.DomainFrontable = '%s'
                ON MATCH SET x.Takeover = "%s", x.DomainFrontable = '%s'
                """ % (
                    subdomain,
                    domain_takeover,
                    domain_frontable,
                    domain_takeover,
                    domain_frontable,
                )
                helpers.execute_query(self.neo4j_driver, query)
                # Check if the partial subdomain is the base domain
                if partial_subdomain == base_domain:
                    query = """
                    MATCH (b:Domain {Name:'%s'})
                    MERGE (a:Subdomain {Name:'%s'})
                    ON CREATE SET a.Takeover = "%s", a.DomainFrontable = '%s'
                    MERGE (a)<-[r2:HAS_SUBDOMAIN]-(b)
                    RETURN a,b
                    """ % (
                        base_domain,
                        subdomain,
                        domain_takeover,
                        domain_frontable,
                    )
                    helpers.execute_query(self.neo4j_driver, query)
                # If not, the subdomain is a subdomain of another subdomain, so create that relationship
                else:
                    query = """
                    MERGE (a:Subdomain {Name:'%s'})
                    ON CREATE SET a.Takeover = "%s", a.DomainFrontable = '%s'
                    MERGE (b:Subdomain {Name:'%s'})
                    MERGE (a)<-[r2:HAS_SUBDOMAIN]-(b)
                    RETURN a,b
                    """ % (
                        subdomain,
                        domain_takeover,
                        domain_frontable,
                        partial_subdomain,
                    )
                    helpers.execute_query(self.neo4j_driver, query)

    def _graph_certificates(self):
        """Convert the certificates table into Neo4j graph nodes with relationships to the domain
        nodes.
        """
        self.c.execute(
            "SELECT host,subject,issuer,start_date,expiration_date,self_signed,signature_algo,censys_fingerprint,alternate_names FROM certificates"
        )
        all_certificates = self.c.fetchall()
        with click.progressbar(
            all_certificates,
            label="Creating Certificate nodes",
            length=len(all_certificates),
        ) as bar:
            for row in bar:
                if row[5]:
                    self_signed = False
                else:
                    self_signed = True
                query = """
                CREATE (a:Certificate {Subject:"%s", Issuer:"%s", StartDate:"%s", ExpirationDate:"%s", SelfSigned:"%s", SignatureAlgo:"%s", CensysFingerprint:"%s"})
                RETURN a
                """ % (
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    self_signed,
                    row[6],
                    row[7],
                )
                helpers.execute_query(self.neo4j_driver, query)
                alt_names = row[8].split(",")
                for name in alt_names:
                    query = """
                    MERGE (a:Subdomain {Name:"%s"})
                    MERGE (b:Certificate {CensysFingerprint:"%s"})
                    MERGE (a)<-[r:ISSUED_FOR]-(b)
                    """ % (
                        name.strip(),
                        row[7],
                    )
                    helpers.execute_query(self.neo4j_driver, query)
                    query = """
                    MERGE (a:Domain {Name:"%s"})
                    MERGE (b:Certificate {CensysFingerprint:"%s"})
                    MERGE (a)<-[r:ISSUED_FOR]-(b)
                    """ % (
                        name.strip(),
                        row[7],
                    )
                    helpers.execute_query(self.neo4j_driver, query)

    def _update_dns(self):
        """Update domain nodes with DNS information."""
        self.c.execute(
            "SELECT domain,subdomain,ns_record,a_record,cname_record,mx_record,txt_record,soa_record,dmarc_record FROM dns"
        )
        dns_data = self.c.fetchall()

        with click.progressbar(
            dns_data, label="Updating Domain nodes with DNS info", length=len(dns_data)
        ) as bar:
            for row in bar:
                domain = row[0]
                subdomain_bool = row[1]
                ns_record = row[2]
                a_record = row[3]
                cname_record = row[4]
                mx_record = row[5]
                txt_record = row[6]
                soa_record = row[7]
                dmarc_record = row[8]
                partial_subdomain = ".".join(domain.split(".")[1:])

                if not subdomain_bool:
                    query = """
                    MATCH (a:Domain {Name:"%s"})
                    SET a += {NameServers:"%s", Address:"%s", MXRecords:'%s', TXTRecords:'%s', SOARecords:'%s', DMARC:'%s', CNAME:'%s'}
                    RETURN a
                    """ % (
                        domain,
                        ns_record,
                        a_record,
                        mx_record,
                        txt_record,
                        soa_record,
                        dmarc_record,
                        cname_record,
                    )
                    helpers.execute_query(self.neo4j_driver, query)
                    for address in a_record.split(","):
                        query = """
                        MATCH (a:Domain {Name:'%s'})
                        MATCH (b:IP {Address:'%s'})
                        MERGE (a)-[r:RESOLVES_TO]->(b)
                        RETURN a,r,b
                        """ % (
                            domain,
                            address,
                        )
                        helpers.execute_query(self.neo4j_driver, query)
                else:
                    self.c.execute(
                        "SELECT domain, subdomain, domain_frontable, domain_takeover FROM subdomains WHERE subdomain == domain"
                    )
                    sub_record = self.c.fetchone()
                    if sub_record[0] != 0:
                        base_domain = sub_record[0]
                        partial_subdomain = ".".join(domain.split(".")[1:])
                        domain_frontable = sub_record[2]
                        domain_takeover = sub_record[3]

                    if partial_subdomain == base_domain:
                        query = """
                        MATCH (b:Domain {Name:'%s'})
                        MERGE (a:Subdomain {Name:'%s'})
                        ON CREATE SET a.Takeover = "%s", a.DomainFrontable = '%s'
                        MERGE (a)<-[r2:HAS_SUBDOMAIN]-(b)
                        RETURN a,b
                        """ % (
                            base_domain,
                            domain,
                            domain_takeover,
                            domain_frontable,
                        )
                        helpers.execute_query(self.neo4j_driver, query)
                    # If not, the subdomain is a subdomain of another subdomain, so create that relationship
                    else:
                        query = """
                        MERGE (a:Subdomain {Name:'%s'})
                        ON CREATE SET a.Takeover = "%s", a.DomainFrontable = '%s'
                        MERGE (b:Subdomain {Name:'%s'})
                        MERGE (a)<-[r2:HAS_SUBDOMAIN]-(b)
                        RETURN a,b
                        """ % (
                            domain,
                            domain_takeover,
                            domain_frontable,
                            partial_subdomain,
                        )
                        helpers.execute_query(self.neo4j_driver, query)

    def _update_rdap(self):
        """Update host nodes with RDAP information."""
        self.c.execute(
            "SELECT ip_address,rdap_source,organization,network_cidr,asn,country_code FROM rdap_data"
        )
        all_rdap = self.c.fetchall()
        with click.progressbar(
            all_rdap, label="Updating IP nodes with RDAP info", length=len(all_rdap)
        ) as bar:
            for row in bar:
                query = """
                MATCH (a:IP {Address:'%s'})
                SET a += {RDAPSource:'%s', Organization:"%s", CIDR:'%s', ASN:'%s', CountryCode:'%s'}
                RETURN a
                """ % (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )
                helpers.execute_query(self.neo4j_driver, query)

    def _update_whois(self):
        """Update domain nodes with WHOIS information."""
        self.c.execute(
            "SELECT domain,registrar,expiration,organization,registrant,admin_contact,tech_contact,address,dns_sec FROM whois_data"
        )
        all_whois = self.c.fetchall()
        with click.progressbar(
            all_whois,
            label="Updating Domain nodes with WHOIS info",
            length=len(all_whois),
        ) as bar:
            for row in bar:
                query = """
                MATCH (a:Domain {Name:'%s'})
                SET a += {Registrar:"%s", Expiration:'%s', Organization:"%s", Registrant:"%s", Admin:"%s", Tech:"%s", ContactAddress:"%s", DNSSEC:'%s'}
                RETURN a
                """ % (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                )
                helpers.execute_query(self.neo4j_driver, query)

    def _graph_shodan(self):
        """Convert the Shodan tables with ports added as Neo4j graph nodes linked to hosts."""
        self.c.execute(
            "SELECT ip_address,port,banner_data,os,organization FROM shodan_host_lookup"
        )
        all_shodan_lookup = self.c.fetchall()
        with click.progressbar(
            all_shodan_lookup,
            label="Creating Port nodes",
            length=len(all_shodan_lookup),
        ) as bar:
            for row in bar:
                query = """
                MATCH (a:IP {Address:'%s'})
                MERGE (b:Port {Number:'%s', OS:'%s', Organization:"%s", Hostname:''})<-[r:HAS_PORT]-(a)
                SET a.Organization = "%s"
                RETURN a,b
                """ % (
                    row[0],
                    row[1],
                    row[3],
                    row[4],
                    row[4],
                )
                helpers.execute_query(self.neo4j_driver, query)

        self.c.execute(
            "SELECT domain,ip_address,port,banner_data,os,hostname FROM shodan_search"
        )
        all_shodan_search = self.c.fetchall()
        with click.progressbar(
            all_shodan_search,
            label="Creating Port and IP relationships",
            length=len(all_shodan_search),
        ) as bar:
            for row in bar:
                query = """
                MATCH (a:Port)<-[:HAS_PORT]-(b:IP {Address:'%s'})
                SET a.Hostname = "%s"
                RETURN a
                """ % (
                    row[1],
                    row[5],
                )
                helpers.execute_query(self.neo4j_driver, query)

    def convert(self):
        """Executes the necessary Neo4j queries to convert a complete ODIN SQLite3 database to a
        Neo4j graph database.
        """
        self._graph_hosts()
        self._graph_subdomains()
        self._graph_certificates()
        self._update_dns()
        self._update_whois()
        self._update_rdap()
        self._graph_shodan()
        self._graph_company()

    def clear_neo4j_database(self):
        """Clear the current Neo4j database by detaching and deleting all nodes."""
        query = "MATCH (n) DETACH DELETE n"
        helpers.execute_query(self.neo4j_driver, query)


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
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command(context_settings=CONTEXT_SETTINGS)
# Declare our CLI options
@click.option(
    "-d",
    "--database",
    help="The path to your completed ODIN database file.",
    type=click.Path(exists=True, readable=True, resolve_path=True),
    required=True,
)
@click.option(
    "--nuke",
    is_flag=True,
    help="Nuke the Neo4j database to start over. This destroys \
ALL data to start fresh.",
)
def visualize(database, nuke):
    click.secho("[+] Loading ODIN database file {}".format(database), fg="green")
    graph = Grapher(database)
    if nuke:
        if click.confirm(
            click.style(
                "[!] You set the --nuke option. This wipes out all nodes for a \
fresh start. Proceed?",
                fg="red",
            ),
            default=True,
        ):
            graph.clear_neo4j_database()
            click.secho("[+] Database successfully wiped!\n", fg="green")
        else:
            click.secho("[!] Then remove the --nuke flag and try again...", fg="red")
            exit()
    graph.convert()
    click.secho("\n[+] Data successfully graphed!", fg="green")


if __name__ == "__main__":
    visualize()
