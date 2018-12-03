#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains the tools required for collecting and parsing DNS records.
"""

import click
import dns.resolver


class DNSCollector(object):
    """Class to retrieve DNS records and perform some basic analysis."""
    # Setup a DNS resolver so a timeout can be set
    # No timeout means a very, very long wait if a domain has no records
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""

    def get_dns_record(self,domain,record_type):
        """Collect the specified DNS record type for the target domain.

        Parameters:
        domain          The domain to be used for DNS record collection
        record_type     The DNS record type to collect
        """
        answer = self.resolver.query(domain,record_type)
        return answer

    def parse_dns_answer(self,dns_record):
        """Parse the provided DNS record and return a list containing each item.

        Parameters:
        dns_record      The DNS record to be parsed
        """
        temp = []
        for rdata in dns_record.response.answer:
            for item in rdata.items:
                temp.append(item.to_text())
        return ", ".join(temp)

    def return_dns_record_list(self,domain,record_type):
        """Collect and parse a DNS record for the given domain and DNS record type and then return
        a list.

        Parameters:
        domain          The domain to be used for DNS record collection
        record_type     The DNS record type to collect
        """
        record = self.get_dns_record(domain,record_type)
        return self.parse_dns_answer(record)

    def check_dns_cache(self,name_server):
        """Check if the given name server is vulnerable to DNS cache snooping.

        Code adapted for ODIN from work done by z0mbiehunt3r with DNS Snoopy:
        https://github.com/z0mbiehunt3r/dns-snoopy

        Parameters:
        name_server     The name server to check
        """
        vulnerable_dns_servers = ""
        # Domains that are commonly resolved and can be used for testing DNS servers
        common_domains = ["google.es","google.com","facebook.com","youtube.com","yahoo.com",
                          "live.com","baidu.com","wikipedia.org","blogger.com","msn.com",
                          "twitter.com","wordpress.com","amazon.com","adobe.com",
                          "microsoft.com","amazon.co.uk","facebook.com"]
        # Attempt to check the name server
        answers = self.get_dns_record(name_server,"A")
        nameserver_ip = str(answers.rrset[0])
        for domain in common_domains:
            if self.dns_cache_request(domain,nameserver_ip):
                vulnerable_dns_servers = name_server
                break
        return vulnerable_dns_servers

    def dns_cache_request(self,domain,nameserver_ip,check_ttl=False):
        """Perform cache requests against the name server for the provided domain.

        Parameters:
        domain              The domain to check for cache snooping
        nameserver_ip       The IP address of the name server to check
        check_ttl           A flag to check the cached TTL or not (Default: False)
        """
        query = dns.message.make_query(domain,dns.rdatatype.A,dns.rdataclass.IN)
        # Negate recursion desired bit
        query.flags ^= dns.flags.RD
        dns_response = dns.query.udp(q=query,where=nameserver_ip)
        """
        Check length major of 0 to avoid those answers with root servers in authority section
        ;; QUESTION SECTION:
        ;www.facebook.com.        IN    A

        ;; AUTHORITY SECTION:
        com.            123348    IN    NS    d.gtld-servers.net.
        com.            123348    IN    NS    m.gtld-servers.net.
        [...]
        com.            123348    IN    NS    a.gtld-servers.net.
        com.            123348    IN    NS    g.gtld-servers.net.    `
        """
        if len(dns_response.answer) > 0 and check_ttl:
            # Get cached TTL
            # ttl_cached = dns_response.answer[0].ttl
            # First, get NS for the first cached domain
            cached_domain_dns = self.get_dns_record(domain,"NS")[0]
            # After, resolve its IP address
            cached_domain_dns_IP = self.get_dns_record(cached_domain_dns,"A")
            # Now, obtain original TTL
            query = dns.message.make_query(domain,dns.rdatatype.A,dns.rdataclass.IN)
            query.flags ^= dns.flags.RD
            dns_response = dns.query.udp(q=query,where=cached_domain_dns_IP)
            # ttl_original = dns_response.answer[0].ttl
            # cached_ago = ttl_original-ttl_cached
        elif len(dns_response.answer) > 0:
            return 1
        return 0

    def check_office_365(self,domain):
        """Checks if the provided domain is an Office 365 tenant. If records are returned, the
        domain is an Office 365 tenant. Otherwise, the look-up will fail (NXDOMAIN).

        Parameters:
        domain      The domain to check for Office 365
        """
        # Office 365 tenant domains will always be the domain and domain TLD with "." converted to a "-"
        # There are slightly different domains for North America, China, and international customers
        domain = domain.replace(".","-")
        na_o365 = domain + ".mail.protection.outlook.com"
        china_o365 = domain + ".mail.protection.partner.outlook.cn"
        international_o365 = domain + ".mail.protection.outlook.de"
        # Check if any of the domains resolve -- NXDOMAIN means the domain is not a tenant
        try:
            answer = self.get_dns_record(na_o365,"A")
            return "Yes;" + na_o365
        except:
            pass
        try:
            answer = self.get_dns_record(china_o365,"A")
            return "Yes;" + china_o365
        except:
            pass
        try:
            answer = self.get_dns_record(international_o365,"A")
            return "Yes; " + international_o365
        except:
            pass
        return "No"
