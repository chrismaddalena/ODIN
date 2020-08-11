#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of tools and functions used for generating lookalike domain names,
determining if they are registered, and then deermining if the registered domains have been
linked to malicious activity.

Based on Jon Oberhide's script for generating lookalike domain names:

https://github.com/duo-labs/lookalike-domains
"""

import operator
import os
import sys
from xml.etree import ElementTree as ET

import click
import requests

import whois
from lib import dns_toolkit, helpers


class TypoCheck(object):
    """Generate and review look-a-like names for a given domain name. """

    dns_collector = dns_toolkit.DNSCollector()

    def __init__(self):
        # Collect the API keys from the config file
        try:
            self.urlvoid_api_key = helpers.config_section_map("URLVoid")["api_key"]
        except Exception:
            self.urlvoid_api_key = ""
            click.secho("[!] Did not find a URLVoid API key.", fg="yellow")
        try:
            self.virustotal_api_key = helpers.config_section_map("VirusTotal")[
                "api_key"
            ]
        except Exception:
            self.virustotal_api_key = ""
            click.secho("[!] Did not find a VirusTotal API key.", fg="yellow")

    def _find_all(self, needle, haystack):
        """
        Search for the needle in the haystack.

        **Parameters**

        ``haystack``
            The item to search
        ``needle``
            The item to search for
        """
        start = 0
        while True:
            start = haystack.find(needle, start)
            if start == -1:
                return
            yield start
            start += len(needle)

    def _quadrantize(self, pos, domain):
        """
        Modify the final rank of the look-a-like domain.

        **Parameters**

        ``pos``
            Position
        ``domain``
            The lookalike domain being ranked
        """
        pos = pos + 1
        chunk = len(domain) / 4.0
        if pos <= chunk * 1:
            return 1
        elif pos <= chunk * 2:
            return 2
        elif pos <= chunk * 3:
            return 3
        else:
            return 4

    def _generate_homoglyphs(self, domain, naked, tld):
        """
        Generate and rank the homoglyph replacements in the domain name.

        **Parameters**

        ``domain``
            The domain name being analyzed
        ``naked``
            The "naked" domain name (name without the TLD) being analyzed
        ``tld``
            The top level domain (TLD) of the domain name being analyzed
        """
        # Replacements with rankings
        replacers = [
            ("rn", "m", 1.0),  # rn and m are high!
            ("l", "t", 1.0),  # l and t are high!
            ("r", "i", 0.6),  # r and i are medium, if you squint!
            ("n", "m", 0.6),  # n and m are medium
            ("d", "cl", 0.6),  # d and cl are medium, spacing stands out
            ("vv", "w", 0.6),  # vv and w are medium, spacing stands out
            ("l", "i", 0.3),  # l and i are medium/low, l is too tall and stands out
            ("j", "i", 0.3),  # j and i are low, j sticks out below
            ("l", "1", 0.3),  # l and 1 are low, 1 stands out due to width
            ("o", "c", 0.3),  # o and c are low
            ("u", "v", 0.3),  # u and v are low
            ("nn", "m", 0.3),  # nn and m are low
        ]
        # Favor replacements that occur towards the middle of the domain
        # Ddd the quadrant rank to the replacement rank to favor the ranking
        # Quadrant rank order: 3rd, 2nd, 4th, 1st
        quadrant_rank = {
            1: 0.01,
            2: 0.03,
            3: 0.04,
            4: 0.02,
        }
        domains = []
        replacements = []
        # Find all the candidate replacements
        for search, replace, rank in replacers:
            for pos in list(self._find_all(search, naked)):
                replacements.append((search, replace, pos, rank))
            for pos in list(self._find_all(replace, naked)):
                replacements.append((replace, search, pos, rank))
        # First pass of single replacements
        for find, replace, pos, rank in replacements:
            candidate = naked[:pos] + replace + naked[pos + len(find) :]
            final_rank = rank + quadrant_rank[self._quadrantize(pos, naked)]
            domains.append(("%s.%s" % (candidate, tld), final_rank))
        # TODO: second pass of multiple replacements to provide more quantity
        # We could also do alternate TLDs with single pass
        return domains

    def _generate_alt_tlds(self, domain, naked, tld):
        """
        Generate and rank the alternate TLD replacements for the domain name.

        **Parameters**

        ``domain``
            The domain name being analyzed
        ``naked``
            The "naked" domain name (name without the TLD) being analyzed
        ``tld``
            The top level domain (TLD) of the domain name being analyzed
        """
        # Preferred TLDs: .com, .net, .org, .biz, .company
        # Note: The .co and .cm TLDs are not supported by Route 53:
        #   https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar-tld-list.html#C
        domains = []
        alt_tlds = [
            ("com", 1.0),
            ("co", 0.9),
            ("cm", 0.9),
            ("net", 0.8),
            ("org", 0.8),
            ("io", 0.5),
            ("biz", 0.5),
            ("company", 0.5),
        ]
        for alt_tld, rank in alt_tlds:
            alt = "%s.%s" % (naked, alt_tld)
            domains.append((alt, rank))
        return domains

    def _generate_suffixes(self, domain, naked, tld):
        """
        Generate and rank the domain name with added suffixes and prefixes.

        **Parameters**

        ``domain``
            The domain name being analyzed
        ``naked``
            The "naked" domain name (name without the TLD) being analyzed
        ``tld``
            The top level domain (TLD) of the domain name being analyzed
        """
        # Preferred fixes: -secure, -login, -logon, -secure-login, -secure-logon
        domains = []
        suffixes = [
            ("-secure", 0.8),
            ("-login", 0.6),
            ("-logon", 0.6),
            ("-secure-login", 0.4),
            ("-secure-logon", 0.4),
        ]
        for suffix, rank in suffixes:
            alt = "%s%s.%s" % (naked, suffix, tld)
            domains.append((alt, rank))
        prefixes = [
            ("secure-", 0.7),
            ("login-", 0.5),
            ("logon-", 0.5),
            ("secure-login-", 0.3),
            ("secure-logon-", 0.3),
        ]
        for prefix, rank in prefixes:
            alt = "%s%s.%s" % (prefix, naked, tld)
            domains.append((alt, rank))
        return domains

    def _check_availability(self, domain):
        """
        Check whether or not the provided domain is registered.

        **Parameters**

        ``domain``
            The domain name to be checked
        """
        try:
            who = whois.whois(domain)
            if who["status"]:
                return True
            else:
                return False
        except:
            return False

    def run_domain_twister(self, domain, limit=30):
        """
        Generate look-a-like domain names for the given domain, determine if the domains are
        registered, and collect DNS records.

        This function returns a list of domains, A-records, and MX-records.

        **Parameters**

        ``domain``
            The base domain used for generating lookalike domains
        ``limit``
            An upper limit on how many lookalike domain names to check (Default: 30)
        """
        naked, _, tld = domain.rpartition(".")
        domain_data = []
        candidates = {
            "alt_tlds": self._generate_alt_tlds(domain, naked, tld),
            "homoglyphs": self._generate_homoglyphs(domain, naked, tld),
            "suffixes": self._generate_suffixes(domain, naked, tld),
        }
        for kind in candidates.keys():
            # Sort by the ranking score before checking availability
            ranked = sorted(candidates[kind], key=operator.itemgetter(1), reverse=True)
            for name, rank in ranked:
                # If the domain is registered, collect the DNS records for further analysis
                if self._check_availability(name):
                    try:
                        a_records = self.dns_collector.return_dns_record_list(name, "A")
                    except:
                        a_records = "None"
                    try:
                        mx_records = self.dns_collector.return_dns_record_list(
                            name, "MX"
                        )
                    except:
                        mx_records = "None"
                else:
                    a_records = "None"
                    mx_records = "None"
                data = {
                    "name": name,
                    "rank": rank,
                    "a_records": a_records,
                    "mx_records": mx_records,
                }
                domain_data.append(data)
                if len(domain_data) >= int(limit):
                    break
        twister_results = []
        for candidate in domain_data:
            temp = {}
            temp["domain"] = candidate["name"]
            temp["rank"] = candidate["rank"]
            temp["a_records"] = candidate["a_records"]
            temp["mx_records"] = candidate["mx_records"]
            twister_results.append(temp)
        return twister_results

    def query_urlvoid(self, domain, timeout=15):
        """
        Collect reputation data from URLVoid for the target domain. This returns an ElementTree object.

        A URLVoid API key is required.

        **Parameter**

        ``domain``
            The domain name for the search
        ``timeout``
            Number of seconds to wait for a response from URLVoid (Default: 15)
        """
        if not helpers.is_ip(domain):
            try:
                if self.urlvoid_api_key != "":
                    url = "http://api.urlvoid.com/api1000/{}/host/{}".format(
                        self.urlvoid_api_key, domain
                    )
                    response = requests.get(url, timeout=timeout)
                    tree = ET.fromstring(response.content)
                    return tree
                else:
                    click.secho(
                        "[*] No URLVoid API key, so skipping this test.", fg="green"
                    )
                    return None
            except Exception as error:
                click.secho(
                    "[!] Could not load URLVoid for reputation check!", fg="red"
                )
                click.secho("L.. Details: {}".format(error), fg="red")
                return None
        else:
            click.secho(
                "[!] Target is not a domain, so skipping URLVoid queries.", fg="red"
            )

    def query_virustotal(self, domain, ignore_case=False):
        """
        Query VirusTotal for the provided domain name to retrieve a domain report.

        **Parameters**

        ``domain``
            The domain to name for the search
        ``ignore_case``
            Pass domain name to VirusTotal API without setting it to all lowercase (Default: False)
        """
        if self.virustotal_api_key:
            if not ignore_case:
                domain = domain.lower()
            try:
                req = self.session.get(
                    self.virustotal_domain_report_uri.format(
                        self.virustotal_api_key, domain
                    )
                )
                vt_data = req.json()
            except Exception:
                vt_data = None
            return vt_data
        else:
            return None
