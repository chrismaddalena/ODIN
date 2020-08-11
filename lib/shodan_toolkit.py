#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module uses the Shodan library to interact with shodan.io to lookup and search for hostnames
and IP addresses.

Shodan API: https://developer.shodan.io/api
"""

import logging

import click
import requests

import shodan

from . import helpers

logger = logging.getLogger(__name__)


class ShodanTools(object):
    """Interact with Shodan.io to search for IP addresses and domain names."""

    # Set the timeout, in seconds, for the web requests
    requests_timeout = 10

    # The Shodan API endpoint for DNS resolution
    shodan_dns_resolve_uri = (
        "https://api.shodan.io/dns/resolve?hostnames={hostname}&key={key}"
    )

    def __init__(self):
        try:
            self.shodan_api_key = helpers.config_section_map("Shodan")["api_key"]
            self.shodan_api = shodan.Shodan(self.shodan_api_key)
        except Exception:
            self.shodan_api = None
            logger.warning("No Shodan API key found")

    def search_shodan(self, target):
        """
        Search Shodan for a target. This uses the Shodan ``search`` command and returns
        the target results dictionary from Shodan.

        A Shodan API key is required.

        **Parameters**

        ``target``
            The domain to search for on Shodan
        """
        if self.shodan_api is None:
            pass
        else:
            try:
                target_results = self.shodan_api.search(target)
                logger.debug("Received results for search, %s", target)
                return target_results
            except shodan.APIError as e:
                logger.error(
                    "Shodan API returned an API error:  %s", getattr(e, "__dict__", {}),
                )
                pass

    def resolve_target(self, target):
        """
        Resolve a hosname to an IP address using the Shodan API's DNS endpoint.

        A Shodan API key is required.

        **Parameters**

        ``target``
            The hostname to resolve to an IP address using Shodan
        """
        if not helpers.is_ip(target):
            try:
                resolved = requests.get(
                    self.shodan_dns_resolve_uri.format(
                        hostname=target, key=self.shodan_api_key
                    ),
                    timeout=self.requests_timeout,
                )
                target_ip = resolved.json()[target]
                return target_ip
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ) as e:
                logger.exception(
                    "Request timed out or failed while contacting Shodan:  %s",
                    getattr(e, "__dict__", {}),
                )
            except Exception as e:
                logger.exception(
                    "General exception occured while contacting Shodan:  %s",
                    getattr(e, "__dict__", {}),
                )
            return None
        else:
            logger.warning(
                "Only a hostname can be resolved to an IP address, not %s", target
            )

    def query_ipaddr(self, target):
        """
        Collect information for an IP address from Shodan. This uses the Shodan ``host`` command
        and returns the target results dictionary from Shodan.

        A Shodan API key is required.

        **Parameters**

        ``target``
            The IP address to use for the Shodan query
        """
        if self.shodan_api is None:
            pass
        else:
            try:
                target_results = self.shodan_api.host(target)
                return target_results
            except shodan.APIError as error:
                if error == "Invalid IP":
                    logger.warning(
                        "Shodan flagged %s as an invalid IP address, but it might be valid and reference an internal asset",
                        target,
                    )
                else:
                    logger.error(
                        "Shodan API returned an API error:  %s",
                        getattr(e, "__dict__", {}),
                    )
