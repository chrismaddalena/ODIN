#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This module contains tools to help verify the ownership of a list of IP addresses and/or
domains. This is accomplished via certificates, whois data, and IP ownership data.

Credit to the creator of original version of this script, Ninjasl0th!
https://github.com/NinjaSl0th/IP-Check
"""


from time import sleep
import sys
import ssl
import csv
import socket
import OpenSSL
import requests
from netaddr import iter_iprange, IPNetwork
from colors import green, yellow
from lib import helpers


def update_progress(progress):
    """Helper function to update progress of the verification checks."""
    sys.stdout.write('Progress: [{0}] {1}%\n'.format('#' * int((progress / 10)), progress))
    # Flush stdout to keep the progress "bar" updated
    sys.stdout.flush()


def prepare_scope(ifile, ip_list, breakrange):
    """Function to get the targets from the file and put them into a scope array."""
    # Open the file and readlines so each line is separate
    pre_parse = open(ifile, "r").readlines()
    # Start iterating through each line
    for i in pre_parse:
        i = i.rstrip()
        # Check if the range includes a -
        # Example 192.168.1.1-50 becomes 192.168.1.1,192.168.1.50
        if "-" in i:
            a = i.split("-")
            startrange = a[0]
            b = a[0]
            dot_split = b.split(".")
            j = "."
            # Join the values using a "." so it makes a valid IP
            combine = dot_split[0], dot_split[1], dot_split[2], a[1]
            endrange = j.join(combine)
            # Calculate the IP range
            expanded_range = list(iter_iprange(startrange, endrange))
            # Iterate through the range and remove the IPList
            for address in expanded_range:
                print(address)
                a = str(address)
                # Append the ip_list
                ip_list.append(a)
        # Check if the range includes a _
        # Ranges like 192.168.1.2_192.168.1.155 will have all ip_list between it and append it.
        elif "_" in i:
            a = i.split("_")
            startrange = a[0]
            endrange = a[1]
            expanded_range = list(iter_iprange(startrange, endrange))
            for address in expanded_range:
                a = str(address)
                # Append the ip_list to the array
                ip_list.append(a)
        # Identify and expand CIDRs
        elif breakrange:
            if "/" in i:
                expanded_range = list(IPNetwork(i))
                for e in sorted(expanded_range):
                    st = str(e)
                    ip_list.append(st)
            else:
                ip_list.append(i.rstrip())
        # Line is probably not an IP range, so add it to the list
        else:
            ip_list.append(i.rstrip())


def reverse_lookup(target):
    """Function to get reverse DNS information."""
    # Check if the IP is a CIDR value because we can't navigate to a CIDR value
    if "/" in target:
        # Return None so that we at least akcnowledge there is nothing
        return None
    else:
        print(green("[+] Trying a reverse DNS lookup for {}.".format(target)))
        ip_address = target
        try:
            # Try and get the hostname via sockets :D
            check = socket.gethostbyaddr(ip_address)
            return check[0]
        except:
            return None


def get_certificate(target):
    """Function to get SSL certificate information."""
    # Return None becasue we can't navigate to a CIDR for SSL
    if "/" in target:
        return None
    try:
        # Attempt to connect over port 443
        print(green("[+] Trying to get certificate information for {}.".format(target)))
        cert = ssl.get_server_certificate((target, 443))
    except:
        # If it can't connect, return nothing/fail
        return None
    try:
        # Use OpenSSL to pull cert information
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        subj = certificate.get_subject()
        comp = subj.get_components()
        for i in comp:
            if 'CN' in i[0].decode("utf-8"):
                return i[1].decode("utf-8")
            elif 'CN' not in i[0].decode("utf-8"):
                continue
            else:
                return None
    except:
        # If OpenSSL fails to get information, return nothing/fail
        return None

def perform_whois(ip_list, output):
    """Function to lookup IP or CIDR in the ARIN database."""
    update_progress(0)
    total = len(ip_list)
    prog = 0.0
    for address in ip_list:
        if not helpers.is_ip(address):
            print(yellow("[*] {} is not a valid IP address, so skipping it.".format(address)))
        elif "/" in address:
            try:
                r = requests.get("http://whois.arin.net/rest/cidr/" + address + ".json")
                if str(r.status_code) == '404':
                    # IF ARIN gives us a 4 oh 4, then try the next cidr value.
                    continue
                else:
                    pass
            except:
                # Die, because we can't connect
                exit("Cannot connect to ARIN!")
            tmp = r.json()
            if "orgRef" not in tmp:
                name = 'None'
            else:
                name = tmp['net']['orgRef']['@name']
            start = tmp['net']['netBlocks']['netBlock']['startAddress']['$']
            end = tmp['net']['netBlocks']['netBlock']['endAddress']['$']
            hostname = reverse_lookup(address)
            cn = get_certificate(address)
            output[address] = address, name, start, end, hostname, cn

        else:
            try:
                # Send GET request to the ARIN RESTFUL API for IP values
                r = requests.get("http://whois.arin.net/rest/ip/" + address + ".json")
                tmp = r.json()
            except:
                # Die, because we can't connect
                exit("Cannot connect to ARIN!")

            try:
                name = tmp['net']['customerRef']['@name']
                start = tmp['net']['netBlocks']['netBlock']['startAddress']['$']
                end = tmp['net']['netBlocks']['netBlock']['endAddress']['$']
                hostname = reverse_lookup(address)
                cn = get_certificate(address)
                output[address] = address, name, start, end, hostname, cn
            except:
                # The formatting of ARIN data may change if there is an org as the contact info
                name = tmp['net']['orgRef']['@name']
                start = tmp['net']['netBlocks']['netBlock']['startAddress']['$']
                end = tmp['net']['netBlocks']['netBlock']['endAddress']['$']
                hostname = reverse_lookup(address)
                cn = get_certificate(address)
                output[address] = address, name, start, end, hostname, cn
            prog += 1
            update_progress(int(prog / total * 100))
        # Pause for just a sec to not destroy ARIN with requests
        sleep(1)


def print_output(out, ofile):
    """Helper function to output the final dict to a csv."""
    writer = csv.writer(open(ofile, 'w'))
    a = list(out.values())
    for i in a:
        writer.writerow(i)
