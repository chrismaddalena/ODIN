#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for analyzing domains and subdomains to determine if a domain
takeover is possible via dangling DNS records, cloud services, and various hosting providers.
"""

from . import dns


class TakeoverChecks(object):
    """Class with tools to check for potential domain and subdomain takeovers."""
    dns_toolkit = dns.DNSCollector()

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        pass

    def check_domain_fronting(self, subdomain):
        """Function to check the A records for a given subdomain and look for references to various
        CDNs to flag the submdomain for domain frontability.

        Many CDN keywords provided by rvrsh3ll on GitHub:
        https://github.com/rvrsh3ll/FindFrontableDomains
        """
        try:
            # Get the A record(s) for the subdomain
            query = self.dns_toolkit.get_dns_record(subdomain, "a")
            # Look for records matching known CDNs
            for item in query.response.answer:
                for text in item.items:
                    target = text.to_text()
                    if "s3.amazonaws.com" in target:
                        return "S3 Bucket: {}".format(target)
                    if "cloudfront" in target:
                        return "Cloudfront: {}".format(target)
                    elif "appspot.com" in target:
                        return "Google: {}".format(target)
                    elif "googleplex.com" in target:
                        return "Google: {}".format(target)
                    elif "msecnd.net" in target:
                        return "Azure: {}".format(target)
                    elif "aspnetcdn.com" in target:
                        return "Azure: {}".format(target)
                    elif "azureedge.net" in target:
                        return "Azure: {}".format(target)
                    elif "a248.e.akamai.net" in target:
                        return "Akamai: {}".format(target)
                    elif "secure.footprint.net" in target:
                        return "Level 3: {}".format(target)
                    elif "cloudflare" in target:
                        return "Cloudflare: {}".format(target)
                    elif 'unbouncepages.com' in target:
                        return "Unbounce: {}".format(target)
                    elif 'secure.footprint.net' in target:
                        return "Level 3: {}".format(target)
                    else:
                        return False
        except Exception:
            return False