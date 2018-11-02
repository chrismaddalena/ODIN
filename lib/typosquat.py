#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of tools and functions used for generating lookalike domain names,
determining if they are registered, and then deermining if the registered domains have been
linked to malicious activity.

This was once based on URLCrazy, but reliance on a Ruby utility was undesirable and could
return way too many results for certain domains. This is now based on Jon Oberhide's script
for generating lookalike domain names:

https://github.com/duo-labs/lookalike-domains
"""

import os
import sys
import operator

import whois
import click
import requests
from cymon import Cymon
from xml.etree import ElementTree as ET

from lib import helpers,dns


class TypoCheck(object):
    """A class containing the tools for generating lookalike domain names and performing some
    checks to see if they have been registered and if the registered domains have been flagged
    for any suspicious or malicious activities.
    """
    dns_collector = dns.DNSCollector()
    # The number of lookalike domains that will checked before stopping
    domain_limit = 30
    # Timeout, in seconds, used for web requests
    requests_timeout = 15

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect the API keys from the config file
        try:
            self.cymon_api_key = helpers.config_section_map("Cymon")["api_key"]
            self.cymon_api = Cymon(self.cymon_api_key)
        except Exception:
            self.cymon_api = Cymon()
            click.secho("[!] Did not find a Cymon API key.",fg="yellow")
        try:
            self.urlvoid_api_key = helpers.config_section_map("URLVoid")["api_key"]
        except Exception:
            self.urlvoid_api_key = ""
            click.secho("[!] Did not find a URLVoid API key.",fg="yellow")

    def find_all(self,needle,haystack):
        """Search for the needle in the haystack.
        
        Parameters:
        haystack    The item to search 
        needle      The item to search for
        """
        start = 0
        while True:
            start = haystack.find(needle,start)
            if start == -1: return
            yield start
            start += len(needle)

    def quadrantize(self,pos,domain):
        """Used to modify the final rank of the lookalike domain.

        Parameters:
        pos         Position
        domain      The lookalike domain being ranked
        """
        pos = pos + 1
        chunk = len(domain)/4.0
        if pos <= chunk*1:
            return 1
        elif pos <= chunk*2:
            return 2
        elif pos <= chunk*3:
            return 3
        else:
            return 4

    def generate_homoglyphs(self,domain,naked,tld):
        """Generate and rank the homoglyph replacements in the domain name.

        Parameters:
        domain      The domain name being analyzed
        naked       The "naked" domain name (name without the TLD) being analyzed
        tld         The top level domain (TLD) of the domain name being analyzed
        """
        # Replacements with rankings
        replacers = [
            ('rn','m',1.0), # rn and m are high!
            ('l','t',1.0),  # l and t are high!
            ('r','i',0.6),  # r and i are medium, if you squint!
            ('n','m',0.6),  # n and m are medium
            ('d','cl',0.6), # d and cl are medium, spacing stands out
            ('vv','w',0.6), # vv and w are medium, spacing stands out
            ('l','i',0.3),  # l and i are medium/low, l is too tall and stands out
            ('j','i',0.3),  # j and i are low, j sticks out below
            ('l','1',0.3),  # l and 1 are low, 1 stands out due to width 
            ('o','c',0.3),  # o and c are low
            ('u','v',0.3),  # u and v are low
            ('nn','m',0.3), # nn and m are low
        ]
        # Favor replacements that occur towards the middle of the domain
        # Ddd the quadrant rank to the replacement rank to favor the ranking
        # Quadrant rank order: 3rd, 2nd, 4th, 1st
        quadrant_rank = {
            1:0.01,
            2:0.03,
            3:0.04,
            4:0.02,
        }
        domains = []
        replacements = []
        # Find all the candidate replacements
        for search,replace,rank in replacers:
            for pos in list(self.find_all(search,naked)):
                replacements.append((search,replace,pos,rank))
            for pos in list(self.find_all(replace,naked)):
                replacements.append((replace,search,pos,rank))
        # First pass of single replacements
        for find,replace,pos,rank in replacements:
            candidate = naked[:pos] + replace + naked[pos+len(find):]
            final_rank = rank + quadrant_rank[self.quadrantize(pos,naked)]
            domains.append(('%s.%s' % (candidate,tld),final_rank))
        # TODO: second pass of multiple replacements to provide more quantity
        # We could also do alternate TLDs with single pass
        return domains

    def generate_alt_tlds(self,domain,naked,tld):
        """Generate and rank the alternate TLD replacements for the domain name.

        Parameters:
        domain      The domain name being analyzed
        naked       The "naked" domain name (name without the TLD) being analyzed
        tld         The top level domain (TLD) of the domain name being analyzed
        """
        # Preferred TLDs: .com, .net, .org, .biz, .company
        # Note: The .co and .cm TLDs are not supported by Route 53:
        #   https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar-tld-list.html#C
        domains = []
        alt_tlds = [
            ('com',1.0),
            ('co',0.9),
            ('cm',0.9),
            ('net',0.8),
            ('org',0.8),
            ('io',0.5),
            ('biz',0.5),
            ('company',0.5),
        ]
        for alt_tld,rank in alt_tlds:
            alt = '%s.%s' % (naked,alt_tld)
            domains.append((alt,rank))
        return domains

    def generate_suffixes(self,domain,naked,tld):
        """Generate and rank the domain name with added suffixes and prefixes.

        Parameters:
        domain      The domain name being analyzed
        naked       The "naked" domain name (name without the TLD) being analyzed
        tld         The top level domain (TLD) of the domain name being analyzed
        """
        # Preferred fixes: -secure, -login, -logon, -secure-login, -secure-logon
        domains = []
        suffixes = [
            ('-secure',0.8),
            ('-login',0.6),
            ('-logon',0.6),
            ('-secure-login',0.4),
            ('-secure-logon',0.4),
        ]
        for suffix, rank in suffixes:
            alt = '%s%s.%s' % (naked, suffix, tld)
            domains.append((alt, rank))
        prefixes = [
            ('secure-',0.7),
            ('login-',0.5),
            ('logon-',0.5),
            ('secure-login-',0.3),
            ('secure-logon-',0.3),
        ]
        for prefix, rank in prefixes:
            alt = '%s%s.%s' % (prefix,naked,tld)
            domains.append((alt,rank))
        return domains

    def check_availability(self,domain):
        """Check whether or not the domain is registered.

        Parameters:
        domain      The domain name to be checked
        """
        try:
            who = whois.whois(domain)
            if who['status']:
                return True
            else:
                return False
        except:
            return False

    def run_domain_twister(self,domain,limit=domain_limit):
        """Generate lookalike domain names for the given domain. Then confirm if the domains have
        been registered and collect DNS records. The domain names and IP addresses are checked
        against Cymon.io's threat feeds. If a result is found (200 OK), then the domain or IP has
        been reported to be part of some sort of malicious activity relatively recently.

        This function returns a list of domains, A-records, MX-records, and the results from Cymon.

        A Cymon API key is recommended, but not required.

        Parameters:
        domain      The base domain used for generating lookalike domains
        limit       An upper limit on how many lookalike domain names to check
        """
        naked,_,tld = domain.rpartition('.')
        domain_data = []
        candidates = {
            'alt_tlds':self.generate_alt_tlds(domain,naked,tld),
            'homoglyphs':self.generate_homoglyphs(domain,naked,tld),
            'suffixes':self.generate_suffixes(domain,naked,tld),
        }
        for kind in candidates.keys():
            # Sort by the ranking score before checking availability
            ranked = sorted(candidates[kind],key=operator.itemgetter(1),reverse=True)
            for name,rank in ranked:
                # If the domain is registered, collect the DNS records for further analysis
                if self.check_availability(name):
                    try:
                        a_records = self.dns_collector.return_dns_record_list(name,"A")
                    except:
                        a_records = "None"
                    try:
                        mx_records = self.dns_collector.return_dns_record_list(name,"MX")
                    except:
                        mx_records = "None"
                else:
                    a_records = "None"
                    mx_records = "None"
                data = {'name':name,'rank':rank,'a_records':a_records,'mx_records':mx_records}
                domain_data.append(data)
                if len(domain_data) >= int(limit):
                    break
        twister_results = []
        for candidate in domain_data:
            # Search for domains and IP addresses tied to the domain name
            try:
                results = self.search_cymon_domain(candidate['name'])
                if results:
                    malicious_domain = 1
                else:
                    malicious_domain = 0
            except Exception as error:
                malicious_domain = 0
                click.secho("\n[!] There was an error checking {} with Cymon.io!".format(candidate['name']),fg="red")
            # Search for domains and IP addresses tied to the A-record IP
            for record in candidate['a_records']:
                try:
                    results = self.search_cymon_ip(record)
                    if results:
                        malicious_ip = 1
                    else:
                        malicious_ip = 0
                except Exception as error:
                    malicious_ip = 0
                    click.secho("\n[!] There was an error checking {} with Cymon.io!".format(domain[1]),fg="red")
            if malicious_domain == 1:
                cymon_result = "Yes"
            elif malicious_ip == 1:
                cymon_result = "Yes"
            else:
                cymon_result = "No"
            temp = {}
            temp['domain'] = candidate['name']
            temp['rank'] = candidate['rank']
            temp['a_records'] = candidate['a_records']
            temp['mx_records'] = candidate['mx_records']
            temp['malicious'] = cymon_result
            twister_results.append(temp)
        return twister_results

    def run_urlvoid_lookup(self,domain):
        """Collect reputation data from URLVoid for the target domain. This returns an ElementTree
        object.

        A URLVoid API key is required.

        Parameters:
        domain      The domain name to check with URLVoid
        """
        if not helpers.is_ip(domain):
            try:
                if self.urlvoid_api_key != "":
                    url = "http://api.urlvoid.com/api1000/{}/host/{}".format(self.urlvoid_api_key,domain)
                    response = requests.get(url,timeout=self.requests_timeout)
                    tree = ET.fromstring(response.content)
                    return tree
                else:
                    click.secho("[*] No URLVoid API key, so skipping this test.",fg="green")
                    return None
            except Exception as error:
                click.secho("[!] Could not load URLVoid for reputation check!",fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
                return None
        else:
            click.secho("[!] Target is not a domain, so skipping URLVoid queries.",fg="red")

    def search_cymon_ip(self,ip_address):
        """Get reputation data from Cymon.io for target IP address. This returns two dictionaries
        for domains and security events.

        A Cymon API key is not required, but is recommended.

        Parameters:
        ip_address  The IP address to check with Cymon
        """
        try:
            # Search for IP and domains tied to the IP
            data = self.cymon_api.ip_domains(ip_address)
            domains_results = data['results']
            # Search for security events for the IP
            data = self.cymon_api.ip_events(ip_address)
            ip_results = data['results']
            return domains_results,ip_results
        except Exception:
            # click.secho("[!] Cymon.io returned a 404 indicating no results.",fg="red")
            return None

    def search_cymon_domain(self,domain):
        """Get reputation data from Cymon.io for target domain. This returns a dictionary for
        the IP addresses tied to the domain.

        A Cymon API key is not required, but is recommended.

        Parameters:
        domain      The domain name to check with Cymon
        """
        try:
            # Search for domains and IP addresses tied to the domain
            results = self.cymon_api.domain_lookup(domain)
            return results
        except Exception:
            # click.secho("[!] Cymon.io returned a 404 indicating no results.",fg="red")
            return None
