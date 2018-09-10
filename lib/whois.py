#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains the tools to collect ownership information for domain names and
IP addresses/ranges and discover additional domain names. Ownership is checked using
whois records and RDAP records. Domains are discovered via reverse whois look-ups
using WhoXY.
"""

import warnings

import click
import whois
import requests
from ipwhois import IPWhois

from . import helpers


class Identify(object):
    """Class for identifying the owners of domain names and IP addresses using whois and RDAP."""
    robtex_api = "https://freeapi.robtex.com/ipquery/"
    whoxy_balance_uri = "http://api.whoxy.com/?key={}&account=balance"
    whoxy_api_endpoint = "http://api.whoxy.com/?key={}&whois={}"
    reverse_whoxy_api_endpoint = "http://api.whoxy.com/?key={}&reverse=whois&company={}"

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        try:
            self.whoxy_api_key = helpers.config_section_map("WhoXY")["api_key"]
            try:
                balance_endpoint = self.whoxy_balance_uri.format(self.whoxy_api_key)
                balance_json = requests.get(balance_endpoint).json()
                live_whois_balance = balance_json['live_whois_balance']
                reverse_whois_balance = balance_json['reverse_whois_balance']
                if live_whois_balance < 50:
                    click.secho("[*] You are low on WhoXY whois credits: {} credits".format(live_whois_balance), fg="yellow")
                if reverse_whois_balance < 50:
                    click.secho("[*] You are low on WhoXY reverse whois credits: {} credits".format(reverse_whois_balance), fg="yellow")
            except Exception:
                click.secho("[*] Error checking credit balance with WhoXY. There could be issues \
communicating with WhoXY later.", fg="yellow")
        except Exception:
            self.whoxy_api_key = None
            click.secho("[!] Did not find a WhoXY API key.", fg="yellow")

    def run_whois(self, domain):
        """Perform a whois lookup for the provided target domain. The whois results are returned
        as a dictionary.

        This can fail, usually if the domain is registered through a registrar outside of
        North America.
        """
        try:
            who = whois.whois(domain)
            results = {}
            # Check if info was returned before proceeding because sometimes records are protected
            if who.registrar:
                results['domain_name'] = who.domain_name
                results['registrar'] = who.registrar
                results['expiration_date'] = who.expiration_date
                results['registrant'] = who.name
                results['org'] = who.org
                results['admin_email'] = who.emails[0]
                results['tech_email'] = who.emails[1]
                results['address'] = "{}, {}{}, {}, {}".format(who.address, \
                    who.city, who.zipcode, who.state, who.country)
                results['dnssec'] = who.dnssec
            else:
                click.secho("[*] Whois record for {} came back empty. Could be privacy protection, \
GDPR, or the registrar. You might try looking at dnsstuff.com.".format(domain), fg="yellow")
            return results
        except Exception as error:
            click.secho("[!] The whois lookup for {} failed!".format(domain), fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")

    def parse_whoxy_results(self, whoxy_data, reverse=False):
        """Take JSON returned by WhoXY API queries and parse the data into a simpler dictionary."""
        results = {}
        results['domain'] = whoxy_data['domain_name']

        if "domain_registrar" in whoxy_data:
            results['registrar'] = whoxy_data['domain_registrar']['registrar_name']
        elif "registrar" in whoxy_data:
            results['registrar'] = whoxy_data['registrar_name']
        else:
            results['registrar'] = "None Listed"

        if "expiry_date" in whoxy_data:
            results['expiry_date'] = whoxy_data['expiry_date']
        else:
            results['expiry_date'] = "None Listed"

        if "company_name" in whoxy_data:
            results['organization'] = whoxy_data['registrant_contact']['company_name']
        else:
            results['organization'] = "None Listed"

        if "full_name" in whoxy_data:
            results['registrant'] = whoxy_data['registrant_contact']['full_name']
        else:
            results['registrant'] = "None Listed"

        if reverse:
            results['address'] = "Unavailable for Reverse Whois"
            results['admin_contact'] = "Unavailable for Reverse Whois"
            results['tech_contact'] = "Unavailable for Reverse Whois"
        else:
            try:
                reg_address = whoxy_data['registrant_contact']['mailing_address']
                reg_city = whoxy_data['registrant_contact']['city_name']
                reg_state = whoxy_data['registrant_contact']['state_name']
                reg_zip = whoxy_data['registrant_contact']['zip_code']
                reg_email = whoxy_data['registrant_contact']['email_address']
                reg_phone = whoxy_data['registrant_contact']['phone_number']
                results['address'] = "{} {}, {} {} {} {}".format(reg_address, reg_city, reg_state, reg_zip, reg_email, reg_phone)
            except:
                results['address'] = "None Listed"

            try:
                admin_name = whoxy_data['administrative_contact']['full_name']
                admin_address = whoxy_data['administrative_contact']['mailing_address']
                admin_city = whoxy_data['administrative_contact']['city_name']
                admin_state = whoxy_data['administrative_contact']['state_name']
                admin_zip = whoxy_data['administrative_contact']['zip_code']
                admin_email = whoxy_data['administrative_contact']['email_address']
                admin_phone = whoxy_data['administrative_contact']['phone_number']
                results['admin_contact'] = "{} {} {}, {} {} {} {}".format(admin_name, admin_address, admin_city, admin_state, admin_zip, admin_email, admin_phone)
            except:
                results['admin_contact'] = "None Listed"

            try:
                tech_name = whoxy_data['technical_contact']['full_name']
                tech_address = whoxy_data['technical_contact']['mailing_address']
                tech_city = whoxy_data['technical_contact']['city_name']
                tech_state = whoxy_data['technical_contact']['state_name']
                tech_zip = whoxy_data['technical_contact']['zip_code']
                tech_email = whoxy_data['technical_contact']['email_address']
                tech_phone = whoxy_data['technical_contact']['phone_number']
                results['tech_contact'] = "{} {} {}, {} {} {} {}".format(tech_name, tech_address, tech_city, tech_state, tech_zip, tech_email, tech_phone)
            except:
                results['tech_contact'] = "None Listed"

        return results

    def run_whoxy_whois(self, domain):
        """Perform a whois lookup for the provided target domain using WhoXY's API. The whois
        results are returned as a dictionary.
        """
        if self.whoxy_api_key:
            try:
                results = requests.get(self.whoxy_api_endpoint.format(self.whoxy_api_key, domain)).json()
                if results['status'] == 1:
                    whois_results = self.parse_whoxy_results(results)
                    return whois_results
                else:
                    click.secho("[*] WhoXY returned status code 0, error/no results, for whois \
lookup on {}.".format(domain), fg="yellow")
            except requests.exceptions.RequestException as error:
                click.secho("[!] Error connecting to WhoXY for whois on {}!".format(domain), fg="red")
                click.secho("L.. Details: {}".format(error), fg="red")

    def run_whoxy_company_search(self, company):
        """Use WhoXY's API to search for a company name and return the associated domain names. The
        information is returned as a dictionary.
        """
        if self.whoxy_api_key:
            try:
                results = requests.get(self.reverse_whoxy_api_endpoint.format(self.whoxy_api_key, company)).json()
                if results['status'] == 1 and results['total_results'] > 0:
                    whois_results = {}
                    total_results = results['total_results']
                    for domain in results['search_result']:
                        domain_name = domain['domain_name']
                        temp = self.parse_whoxy_results(domain, True)
                        whois_results[domain_name] = temp
                    return whois_results, total_results
                else:
                    click.secho("[*] WhoXY returned status code 0, error/no results, for reverse \
company search.", fg="yellow")
            except requests.exceptions.RequestException as error:
                click.secho("[!] Error connecting to WhoXY for reverse company search!", fg="yellow")
                click.secho("L.. Details: {}".format(error), fg="yellow")

    def run_rdap(self, ip_address):
        """Perform an RDAP lookup for an IP address. An RDAP lookup object is returned.

        From IPWhois: IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides
        a far better data structure than legacy whois and REST lookups (previous implementation).
        RDAP queries allow for parsing of contact information and details for users, organizations,
        and groups. RDAP also provides more detailed network information.
        """
        try:
            with warnings.catch_warnings():
                # Hide the 'allow_permutations has been deprecated' warning until ipwhois removes it
                warnings.filterwarnings("ignore",category=UserWarning)
                rdapwho = IPWhois(ip_address)
                results = rdapwho.lookup_rdap(depth=1)
            return results
        except Exception as error:
            click.secho("[!] Failed to collect RDAP information for {}!".format(ip_address), fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")

    def lookup_robtex_ipinfo(self, ip_address):
        """Lookup information about a target IP address with Robtex."""
        if helpers.is_ip(ip_address):
            request = requests.get(self.robtex_api + ip_address)
            ip_json = request.json()
            return ip_json
        else:
            click.secho("[!] The provided IP for Robtex is invalid!", fg="red")