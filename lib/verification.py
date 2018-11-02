#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module contains tools to help verify the ownership of a list of IP addresses and/or
domains. This is accomplished via certificates, WHOIS data, and IP ownership data.

This is based on the verification script created by Ninjasl0th. The original code is here:

https://github.com/NinjaSl0th/IP-Check
"""

import sys
import ssl
import csv
import socket
from time import sleep

import click
import OpenSSL
import requests
from netaddr import iter_iprange,IPNetwork

from lib import helpers


# Set a socket timeout so the verification does not take ages for long lists
socket.setdefaulttimeout(5)


def prepare_scope(scope_file,expanded_scope):
    """Parse IP ranges inside the provided scope file to expand IP ranges. This supports ranges
    with hyphens, underscores, and CIDRs.

    Parameters:
    scope_file          A file containing domain name and IP addresses/ranges
    expanded_scope      A list object for storing to expanded scope list
    """
    try:
        with open(scope_file,"r") as scope_file:
            for target in scope_file:
                target = target.rstrip()
                # Record individual IPs and expand CIDRs
                if helpers.is_ip(target):
                    ip_list = list(IPNetwork(target))
                    for address in sorted(ip_list):
                        str_address = str(address)
                        expanded_scope.append(str_address)
                # Sort IP ranges from domain names and expand the ranges
                if not helpers.is_domain(target):
                    # Check for hyphenated ranges like those accepted by Nmap, e.g. 192.168.1.1-50
                    if "-" in target:
                        target = target.rstrip()
                        parts = target.split("-")
                        startrange = parts[0]
                        b = parts[0]
                        dot_split = b.split(".")
                        temp = "."
                        # Join the values using a "." so it makes a valid IP
                        combine = dot_split[0],dot_split[1],dot_split[2],parts[1]
                        endrange = temp.join(combine)
                        # Calculate the IP range
                        ip_list = list(iter_iprange(startrange,endrange))
                        # Iterate through the range and remove ip_list
                        for x in ip_list:
                            temp = str(x)
                            expanded_scope.append(temp)
                    # Check if range has an underscore, e.g. 192.168.1.2_192.168.1.155
                    elif "_" in target:
                        target = target.rstrip()
                        parts = target.split("_")
                        startrange = parts[0]
                        endrange = parts[1]
                        ip_list = list(iter_iprange(startrange,endrange))
                        for address in ip_list:
                            str_address = str(address)
                            expanded_scope.append(str_address)
                else:
                    expanded_scope.append(target.rstrip())
            click.secho("[+] Scope list expanded to {} items. Proceeding with verification \
checks.".format(len(expanded_scope)),fg="green")
    except IOError as error:
        click.secho("[!] Parsing of scope file failed!",fg="red")
        click.secho("L.. Details: {}".format(error),fg="red")


def reverse_lookup(target):
    """Attempt to resolve the provided IP address to a hostname.

    Parameters:
    target      The target to look-up
    """
    try:
        check = socket.gethostbyaddr(target)
        return check[0]
    except:
        return None


def get_certificate(target):
    """Attempt to collect SSL/TLS certificate information for the given host.
    
    Parameters:
    target      The domain name to be used for certificate collection
    """
    # Attempt to connect over port 443
    try:
        cert = ssl.get_server_certificate((target,443))
    # If it can't connect, return nothing/fail
    except:
        return None
    # Try to use OpenSSL to pull certificate information
    try:
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert)
        subj = certificate.get_subject()
        comp = subj.get_components()
        for i in comp:
            if 'CN' in i[0].decode("utf-8"):
                return i[1].decode("utf-8")
            elif 'CN' not in i[0].decode("utf-8"):
                continue
            else:
                return None
    # If OpenSSL fails to get information, return nothing/fail
    except:
        return None


def perform_whois(expanded_scope,output):
    """Look-up the provided IP address in the ARIN database.
    
    Parameters:
    expanded_scope      A list of domain name and IP addresses (no ranges)
    output              A list object for storing the output
    """
    total_addresses = len(expanded_scope)
    with click.progressbar(expanded_scope,
                           label='Collecting information on addresses',
                           length=total_addresses) as bar:
        for address in bar:
            if not helpers.is_ip(address):
                pass
            else:
                # Try to send GET request to the ARIN REST API for IP values
                try:
                    r = requests.get("http://whois.arin.net/rest/ip/" + address + ".json",timeout=10)
                    tmp = r.json()
                    try:
                        name = tmp['net']['customerRef']['@name']
                        # start = tmp['net']['netBlocks']['netBlock']['startAddress']['$']
                        # end = tmp['net']['netBlocks']['netBlock']['endAddress']['$']
                        hostname = reverse_lookup(address)
                        cn = get_certificate(address)
                        output[address] = address,name,hostname,cn
                    except:
                        # The formatting of ARIN data may change if an org is used for the contact
                        name = tmp['net']['orgRef']['@name']
                        # start = tmp['net']['netBlocks']['netBlock']['startAddress']['$']
                        # end = tmp['net']['netBlocks']['netBlock']['endAddress']['$']
                        hostname = reverse_lookup(address)
                        cn = get_certificate(address)
                        output[address] = address,name,hostname,cn
                except:
                    pass
            # Pause for just a sec to not destroy ARIN with requests
            sleep(1)


def print_output(results,report_path):
    """Write the final results to a csv.
    
    Parameters:
    results        The results to be written to the file
    report_path    File path for the report output
    """
    with open(report_path,"w") as csv_report:
        writer = csv.writer(csv_report)
        writer.writerow(["Address","Organization","Hostname","Certificate CN"])
        result_values = list(results.values())
        for values in result_values:
            writer.writerow(values)
