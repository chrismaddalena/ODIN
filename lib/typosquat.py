#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of tools and functions used for generating lookalike domain names,
determining if they are registered, and then deermining if the registered domains have been
linked to malicious activity.
"""

import os
import csv
import subprocess

import click
import requests
from cymon import Cymon
from xml.etree import ElementTree as ET

from lib import helpers


class TypoCheck(object):
    """A class containing the tools for performing OSINT against IP addresses and domain names."""
    # Cymon.io API endpoint
    cymon_api = "https://api.cymon.io/v2"

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect the API keys from the config file
        try:
            self.cymon_api_key = helpers.config_section_map("Cymon")["api_key"]
            self.cymon_api = Cymon(self.cymon_api_key)
        except Exception:
            self.cymon_api = Cymon()
            click.secho("[!] Did not find a Cymon API key.", fg="yellow")
        try:
            self.urlvoid_api_key = helpers.config_section_map("URLVoid")["api_key"]
        except Exception:
            self.urlvoid_api_key = ""
            click.secho("[!] Did not find a URLVoid API key.", fg="yellow")

    def run_urlcrazy(self, client, target, cymon_api=cymon_api):
        """Run urlcrazy to locate typosquatted domains related to the target domain. The full
        output is saved to a csv file and then domains with A-records are analyzed to see if
        they may be in use for malicious purposes. The domain names and IP addresses are checked
        against Cymon.io's threat feeds. If a result is found (200 OK), then the domain or IP has
        been reported to be part of some sort of malicious activity relatively recently.

        The function returns a list of domains, A-records, MX-records, and the results from Cymon.

        A Cymon API key is recommended, but not required.
        """
        # Check to see if urlcrazy is available
        try:
            urlcrazy_present = subprocess.getstatusoutput("urlcrazy")
        except OSError as error:
            if error.errno == os.errno.ENOENT:
                # The urlcrazy command was not found
                click.secho("[!] A test call to urlcrazy failed, so skipping urlcrazy run.", fg="yellow")
                click.secho("L.. Details: {}".format(error), fg="yellow")
                urlcrazy_present = "1"
            else:
                # Something else went wrong while trying to run urlcrazy
                click.secho("[!] A test call to urlcrazy failed, so skipping urlcrazy run.", fg="yellow")
                click.secho("L.. Details: {}".format(error), fg="yellow")
                urlcrazy_present = "1"
            return urlcrazy_present

        if urlcrazy_present[0] == 0:
            outfile = "reports/{}/crazy_temp.csv".format(client)
            final_csv = "reports/{}/{}_urlcrazy.csv".format(client, target)
            domains = []
            a_records = []
            mx_records = []
            squatted = {}
            click.secho("[+] Running urlcrazy for {}".format(target), fg="green")
            try:
                cmd = "urlcrazy -f csv -o '{}' {}".format(outfile, target)
                with open(os.devnull, "w") as devnull:
                    subprocess.check_call(cmd, stdout=devnull, shell=True)
                with open(outfile, "r", encoding = "ISO-8859-1") as results:
                    reader = csv.DictReader(row.replace("\0", "") for row in results)
                    for row in reader:
                        if len(row) != 0:
                            if row['CC-A'] != "?":
                                domains.append(row['Typo'])
                                a_records.append(row['DNS-A'])
                                mx_records.append(row['DNS-MX'])

                squatted = zip(domains, a_records, mx_records)

                session = requests.Session()
                session.headers = {'content-type':'application/json', 'accept':'application/json'}
                # Add the Cymon API, if available, to the headers
                if self.cymon_api_key != None:
                    session.headers.update({'Authorization': 'Token {0}' \
                        .format(self.cymon_api_key)})

                # Search for domains and IP addresses tied to the domain name
                urlcrazy_results = []
                for domain in squatted:
                    try:
                        request = session.get(cymon_api + "/ioc/search/domain/" + domain[0], verify=False)
                        # results = json.loads(r.text)
                        if request.status_code == 200:
                            if request.json()['total'] > 0:
                                malicious_domain = 1
                            else:
                                malicious_domain = 0
                        else:
                            malicious_domain = 0
                    except Exception as error:
                        malicious_domain = 0
                        click.secho("[!] There was an error checking {} with Cymon.io!"
                                   .format(domain[0]), fg="red")
                    # Search for domains and IP addresses tied to the A-record IP
                    try:
                        r = session.get(cymon_api + "/ioc/search/ip/" + domain[1], verify=False)
                        # results = json.loads(r.text)
                        if r.status_code == 200:
                            if request.json()['total'] > 0:
                                malicious_ip = 1
                            else:
                                malicious_ip = 0
                        else:
                            malicious_ip = 0
                    except Exception as error:
                        malicious_ip = 0
                        click.secho("[!] There was an error checking {} with Cymon.io!"
                                   .format(domain[1]), fg="red")

                    if malicious_domain == 1:
                        cymon_result = "Yes"
                    elif malicious_ip == 1:
                        cymon_result = "Yes"
                    else:
                        cymon_result = "No"

                    temp = {}
                    temp['domain'] = domain[0]
                    temp['a-records'] = domain[1]
                    temp['mx-records'] = domain[2]
                    temp['malicious'] = cymon_result
                    urlcrazy_results.append(temp)

                os.rename(outfile, final_csv)
                return urlcrazy_results

            except Exception as error:
                click.secho("[!] Execution of urlcrazy failed!", fg="red")
                click.secho("L.. Details: {}".format(error), fg="red")
        else:
            click.secho("[*] Skipping typosquatting checks because the urlcrazy command failed \
to be found.", fg="yellow")

    def run_urlvoid_lookup(self, domain):
        """Collect reputation data from URLVoid for the target domain. This returns an ElementTree
        object.

        A URLVoid API key is required.
        """
        if not helpers.is_ip(domain):
            try:
                if self.urlvoid_api_key != "":
                    url = "http://api.urlvoid.com/api1000/{}/host/{}"\
                        .format(self.urlvoid_api_key, domain)
                    response = requests.get(url)
                    tree = ET.fromstring(response.content)
                    return tree
                else:
                    click.secho("[*] No URLVoid API key, so skipping this test.", fg="green")
                    return None
            except Exception as error:
                click.secho("[!] Could not load URLVoid for reputation check!", fg="red")
                click.secho("L.. Details: {}".format(error), fg="red")
                return None
        else:
            click.secho("[!] Target is not a domain, so skipping URLVoid queries.", fg="red")

    def search_cymon_ip(self, target):
        """Get reputation data from Cymon.io for target IP address. This returns two dictionaries
        for domains and security events.

        A Cymon API key is not required, but is recommended.
        """
        try:
            # Search for IP and domains tied to the IP
            data = self.cymon_api.ip_domains(target)
            domains_results = data['results']
            # Search for security events for the IP
            data = self.cymon_api.ip_events(target)
            ip_results = data['results']
            return domains_results, ip_results
        except Exception:
            click.secho("[!] Cymon.io returned a 404 indicating no results.", fg="red")

    def search_cymon_domain(self, target):
        """Get reputation data from Cymon.io for target domain. This returns a dictionary for
        the IP addresses tied to the domain.

        A Cymon API key is not required, but is recommended.
        """
        try:
            # Search for domains and IP addresses tied to the domain
            results = self.cymon_api.domain_lookup(target)
            return results
        except Exception:
            click.secho("[!] Cymon.io returned a 404 indicating no results.", fg="red")
