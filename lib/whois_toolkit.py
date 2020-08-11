#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains the tools to collect ownership information for domain names and
IP addresses/ranges and discover additional domain names. Ownership is checked using
WHOIS records and RDAP records. Domains are discovered via reverse WHOIS look-ups
using WhoXY.
"""

import logging
import warnings

import click
import requests

import whois
from ipwhois import IPWhois

from . import helpers

logger = logging.getLogger(__name__)


class Identify(object):
    """Identify the owners of domain names and IP addresses using WHOIS and RDAP."""

    # Set the timeout, in seconds, for the web requests
    timeout = 15

    # The endpoints used for the web requests
    whoxy_api_endpoint = "http://api.whoxy.com/?key={key}&whois={domain}"
    whoxy_balance_uri = "http://api.whoxy.com/?key={key}&account=balance"
    reverse_whoxy_api_endpoint = (
        "http://api.whoxy.com/?key={key}&reverse=whois&company={company}"
    )

    def __init__(self):
        try:
            self.whoxy_api_key = helpers.config_section_map("WhoXY")["api_key"]
            try:
                balance_endpoint = self.whoxy_balance_uri.format(key=self.whoxy_api_key)
                balance_json = requests.get(
                    balance_endpoint, timeout=self.timeout
                ).json()
                live_whois_balance = balance_json["live_whois_balance"]
                reverse_whois_balance = balance_json["reverse_whois_balance"]
                if live_whois_balance < 50:
                    logger.warning(
                        "You are low on WhoXY whois credits: %s credits",
                        live_whois_balance,
                    )
                if reverse_whois_balance < 50:
                    logger.warning(
                        "You are low on WhoXY reverse whois credits: %s credits",
                        reverse_whois_balance,
                    )
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ) as e:
                logger.error(
                    "Request to WhoXY timed out or encountered too many redirects"
                )
        except Exception:
            self.whoxy_api_key = None
            logger.warning("No WhoXY API key found")

    def query_whois(self, domain):
        """
        Perform a WHOIS lookup for the provided target domain. The WHOIS results are returned
        as a dictionary.

        This can fail, usually if the domain is protected by a WHOIS privacy service or the
        registrar has their own WHOIS service.

        **Parameters**

        ``domain``
            The domain to use for the WHOIS query
        """
        try:
            who = whois.whois(domain)
            logger.debug("Received WHOIS results: %s", who)
            results = {}
            # Check if info was returned before proceeding because sometimes records are protected
            if who.registrar:
                results["domain_name"] = who.domain_name
                results["registrar"] = who.registrar
                results["expiration_date"] = who.expiration_date
                results["registrant"] = who.name
                results["org"] = who.org
                if who.emails:
                    results["admin_email"] = who.emails[0]
                    results["tech_email"] = who.emails[1]
                else:
                    results["admin_email"] = "N/A"
                    results["tech_email"] = "N/A"
                if who.address:
                    results["address"] = "{}, {} {}, {}, {}".format(
                        who.address, who.city, who.zipcode, who.state, who.country
                    )
                else:
                    results["address"] = "N/A"
                results["dnssec"] = who.dnssec
            else:
                logger.error(
                    "WHOIS record for %s came back empty. You might try looking at dnsstuff.com.",
                    domain,
                )
            return results
        except Exception as e:
            logger.exception(
                "General exception occured while performing WHOIS lookup:  %s",
                getattr(e, "__dict__", {}),
            )

    def parse_whoxy_results(self, whoxy_data, reverse=False):
        """
        Parse JSON from WhoXY to create a dict.

        **Parameters**

        ``whoxy_data``
            The raw WhoXY API results to be parsed

        ``reverse``
            Boolean value to flag the WhoXY data as reverse WHOIS results (Default: False)
        """
        results = {}
        results["domain"] = whoxy_data["domain_name"]
        # Check for the registrar information
        if "domain_registrar" in whoxy_data:
            results["registrar"] = whoxy_data["domain_registrar"]["registrar_name"]
        elif "registrar" in whoxy_data:
            results["registrar"] = whoxy_data["registrar_name"]
        else:
            results["registrar"] = "N/A"
        # Check for an expiration date
        if "expiry_date" in whoxy_data:
            results["expiry_date"] = whoxy_data["expiry_date"]
        else:
            results["expiry_date"] = "N/A"
        # Check for a company name
        if "company_name" in whoxy_data:
            results["organization"] = whoxy_data["registrant_contact"]["company_name"]
        else:
            results["organization"] = "N/A"
        # Check for a registrant's name
        if "full_name" in whoxy_data:
            results["registrant"] = whoxy_data["registrant_contact"]["full_name"]
        else:
            results["registrant"] = "N/A"
        # A few pieces of information are unavailable from WhoXY's reverse WHOIS lookups
        if reverse:
            results["address"] = "Unavailable for Reverse WHOIS"
            results["admin_contact"] = "Unavailable for Reverse WHOIS"
            results["tech_contact"] = "Unavailable for Reverse WHOIS"
        # Try to assemble different pieces of information from the record
        else:
            try:
                reg_address = whoxy_data["registrant_contact"]["mailing_address"]
                reg_city = whoxy_data["registrant_contact"]["city_name"]
                reg_state = whoxy_data["registrant_contact"]["state_name"]
                reg_zip = whoxy_data["registrant_contact"]["zip_code"]
                reg_email = whoxy_data["registrant_contact"]["email_address"]
                reg_phone = whoxy_data["registrant_contact"]["phone_number"]
                results["address"] = "{} {}, {} {} {} {}".format(
                    reg_address, reg_city, reg_state, reg_zip, reg_email, reg_phone
                )
            except:
                results["address"] = "N/A"
            try:
                admin_name = whoxy_data["administrative_contact"]["full_name"]
                admin_address = whoxy_data["administrative_contact"]["mailing_address"]
                admin_city = whoxy_data["administrative_contact"]["city_name"]
                admin_state = whoxy_data["administrative_contact"]["state_name"]
                admin_zip = whoxy_data["administrative_contact"]["zip_code"]
                admin_email = whoxy_data["administrative_contact"]["email_address"]
                admin_phone = whoxy_data["administrative_contact"]["phone_number"]
                results["admin_contact"] = "{} {} {}, {} {} {} {}".format(
                    admin_name,
                    admin_address,
                    admin_city,
                    admin_state,
                    admin_zip,
                    admin_email,
                    admin_phone,
                )
            except:
                results["admin_contact"] = "N/A"
            try:
                tech_name = whoxy_data["technical_contact"]["full_name"]
                tech_address = whoxy_data["technical_contact"]["mailing_address"]
                tech_city = whoxy_data["technical_contact"]["city_name"]
                tech_state = whoxy_data["technical_contact"]["state_name"]
                tech_zip = whoxy_data["technical_contact"]["zip_code"]
                tech_email = whoxy_data["technical_contact"]["email_address"]
                tech_phone = whoxy_data["technical_contact"]["phone_number"]
                results["tech_contact"] = "{} {} {}, {} {} {} {}".format(
                    tech_name,
                    tech_address,
                    tech_city,
                    tech_state,
                    tech_zip,
                    tech_email,
                    tech_phone,
                )
            except:
                results["tech_contact"] = "N/A"
        return results

    def query_whoxy_whois(self, domain):
        """
        Perform a WHOIS lookup for the provided target domain using WhoXY's API. The WHOIS
        results are returned as a dictionary.

        **Parameters**

        ``domain``
            Domain name to use for the WhoXY WHOIS query
        """
        if self.whoxy_api_key:
            try:
                results = requests.get(
                    self.whoxy_api_endpoint.format(
                        key=self.whoxy_api_key, domain=domain
                    ),
                    timeout=self.timeout,
                ).json()
                if results["status"] == 1:
                    whois_results = self.parse_whoxy_results(results)
                    return whois_results
                else:
                    logger.info(
                        "WhoXY returned status code 0, error/no results, for WHOIS lookup on %s",
                        domain,
                    )
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ):
                logger.exception(
                    "Request to WhoXY time dout or ebcountered too many redirects"
                )
            except Exception as e:
                logger.exception(
                    "General exception occured while performing WhoXY WHOIS lookup:  %s",
                    getattr(e, "__dict__", {}),
                )

    def query_whoxy_company(self, company):
        """
        Search WhoXY for a company name and return the associated domain names. The
        information is returned as a dictionary.

        **Parameters**

        ``company``
            Company name for the WhoXY reverse WHOIS search
        """
        if self.whoxy_api_key:
            try:
                results = requests.get(
                    self.reverse_whoxy_api_endpoint.format(
                        key=self.whoxy_api_key, company=company
                    ),
                    timeout=self.timeout,
                ).json()
                if results["status"] == 1 and results["total_results"] > 0:
                    whois_results = {}
                    total_results = results["total_results"]
                    for domain in results["search_result"]:
                        domain_name = domain["domain_name"]
                        temp = self.parse_whoxy_results(domain, True)
                        whois_results[domain_name] = temp
                    return whois_results, total_results
                else:
                    logger.info(
                        "WhoXY returned status code 0, error/no results, for WHOIS lookup on %s",
                        domain,
                    )
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ):
                logger.exception(
                    "Request to WhoXY time dout or ebcountered too many redirects"
                )
            except Exception as e:
                logger.exception(
                    "General exception occured while performing WhoXY WHOIS lookup:  %s",
                    getattr(e, "__dict__", {}),
                )

    def query_rdap(self, ip_address):
        """
        Perform an RDAP lookup for an IP address. An RDAP lookup object is returned.

        **Parameters**

        ``ip_address``
            IP address to use for the RDAP look-up
        """
        try:
            with warnings.catch_warnings():
                # Hide the 'allow_permutations has been deprecated' warning until ipwhois removes it
                warnings.filterwarnings("ignore", category=UserWarning)
                rdapwho = IPWhois(ip_address)
                results = rdapwho.lookup_rdap(
                    asn_methods=["dns", "whois", "http"], depth=1
                )
            return results
        except Exception as e:
            logger.exception(
                "General exception occured while performing RDAP query:  %s",
                getattr(e, "__dict__", {}),
            )
