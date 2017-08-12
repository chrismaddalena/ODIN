#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions needed to
check a target's SSL/TLS status. This is based on
original work by TrullJ (https://github.com/TrullJ/ssllabs).
"""

import time
import socket
import OpenSSL
import ssl
import requests
from IPy import IP
from colors import green, red, yellow

SSL_API_ENDPOINT = "https://api.ssllabs.com/api/v2/"


def is_ip(value):
    """Checks if the provided string is an IP address or not. If
    the check fails, it will be assumed the string is a domain
    in most cases.

    IPy is used to determine if a string is a valid IP address. A True or
    False is returned.
    """
    try:
        IP(value)
    except ValueError:
        return False
    return True


def request_api(path, payload={}):
    """This is a helper method that takes the path to the relevant API call and
    the user-defined payload and requests the data/server test from Qualys SSL Labs.
    Returns JSON formatted data
    """
    url = SSL_API_ENDPOINT + path

    try:
        response = requests.get(url, params=payload)
    except requests.exception.RequestException as error:
        print(error)

    data = response.json()
    return data


def results_from_cache(host, publish="off", start_new="off", from_cache="on", all="done"):
    """This function returns results from SSL Labs' cache (previously run scans)."""
    if is_ip(host):
        print(red("[!] Your target host must be a domain, not an IP address! \
SSL Labs will onyl scan domains."))
        exit()
    else:
        path = "analyze"
        payload = {'host': host, 'publish': publish, 'start_new': start_new, 'from_cache': from_cache, 'all': all}
        data = request_api(path, payload)
        return data


def new_scan(host, publish = "off", start_new = "on", all = "done", ignoreMismatch = "on"):
    """This function requests SSL Labs to run new scan for the target domain."""
    if is_ip(host):
        print(red("[!] Your target host must be a domain, not an IP address! \
SSL Labs will onyl scan domains."))
        exit()
    else:
        path = "analyze"
        payload = {'host': host, 'publish': publish, 'start_new': start_new, 'all': all, 'ignoreMismatch': ignoreMismatch}
        results = request_api(path, payload)

        payload.pop('start_new')

        while results['status'] != 'READY' and results['status'] != 'ERROR':
            print("Scan in progress, please wait for the results.")
            time.sleep(30)
            results = request_api(path, payload)

        return results


def get_results(target, test_type):
    """Function to run a new scan or request information from SSL Labs'
    cache (old scans). The API is not well documented, but it is usable.
    If SSL Labs can get the data, this function will print the results
    for various SSL/TLS checks, such as SSL potocol support and POODLE.
    A Status Unavailable result will be returned if SSL labs does not
    have the information. This can happen if the scan is inconclusive due
    to  timeout.

    Docs: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
    """
    # Create scanner based on type - new or cached results
    if test_type == 1:
        data = new_scan(target)
        print(green("[+] Running a new SSL Labs scan - this will take some time..."))
    if test_type == 2:
        data = results_from_cache(target)
        print(green("[+] Getting results from SSL Labs's cache (if there is a cached test)..."))

    # Print the server name
    try:
        print(green("Server Name: %s" % data['endpoints'][0]['serverName']))
    except Exception as error:
        print(red("Server Name: Unavailable -- {}".format(error)))

    # Print the IP address
    try:
        print(green("IP Address: %s" % data['endpoints'][0]['ipAddress']))
    except:
        print(red("[!] IP Address: Unavailable!"))

    # Print the SSL Labs grade
    try:
        print(green("Grade: %s" % data['endpoints'][0]['grade']))
    except Exception as e:
        print(red("Grade: Unavailable"))
    try:
        print(green("SGrade: %s" % data['endpoints'][0]['gradeTrustIgnored']))
    except:
        print(red("SGrade: Unavailable"))

    # Check for SSL protocol support
    ssl2 = "No"
    ssl3 = "No"
    try:
        for proto in data['endpoints'][0]['details']['protocols']:
            if "SSL" in proto['name'] and proto['version'] == "2.0":
                ssl2 = "Yes"
            if "SSL" in proto['name'] and proto['version'] == "3.0":
                ssl3 = "Yes"
        print(green("SSLv2: %s" % ssl2))
        print(green("SSLv3: %s" % ssl3))
    except:
        print(red("SSLv2/3: SSL version support information unavailable"))

    # Check for RC4 cipher support (Bar Mitzvah)
    try:
            rc4 = data['endpoints'][0]['details']['supportsRc4']
            if rc4:
                rc4 ="Yes"
            else:
                rc4 = "No"
            print(green("RC4: %s" % rc4))
    except:
        print(red("RC4: Status unavailable"))

    # Check for CRIME
    try:
        crime = "No"
        if data['endpoints'][0]['details']['compressionMethods']!= 0 and result['endpoints'][0]['details']['supportsNpn'] == False:
            crime ="Yes"
            print(green("CRIME: %s" % crime))
        else:
            print(green("CRIME: %s" % crime))
    except:
        print(red("CRIME: Status unavailable"))

    # Check for FREAK
    try:
        print(green("FREAK: %s" % data['endpoints'][0]['details']['freak']))
    except:
        print(red("FREAK: Status unavailable"))

    # Check for POODLE SSL/TLS
    try:
        poodle_ssl = "No"
        if data['endpoints'][0]['details']['poodle'] == True:
            poodle_ssl = "Yes"
        print(green("POODLE SSL: %s" % poodle_ssl))
    except:
        print(red("POODLE SSL: Status unavailable"))

    try:
        poodle_tls = data['endpoints'][0]['details']['poodle_tls']
        if poodle_tls == 1:
            print(green("POODLE TLS: No"))
        elif poodle_tls == 2:
            print(green("POODLE TLS: Yes"))
        else:
            print(green("POODLE TLS: Status Unavailable"))
    except:
        print(green("POODLE TLS: Status Unavailable"))

    # Check for Heartbleed
    try:
        print(green("Heartbleed: %s" % data['endpoints'][0]['details']['heartbleed']))
    except:
        print(red("Heartbleed: Status unavailable"))

    # Check for Renegotiation Support
    try:
        reneg = data['endpoints'][0]['details']['renegSupport']
        if reneg != 0:
            print(green("Renegotiation: Yes"))
        else:
            print(green("Renegotiation: No"))
    except:
        print(red("Renegotiation: Status unavailable"))

    # Check for OpenSSL CCS Injection
    try:
        ccs = data['endpoints'][0]['details']['openSslCcs']
        if ccs == 1:
            print(green("OpenSSL CCS Injection: No"))
        elif ccs == 3:
            print(green("OpenSSL CCS Injection: Yes"))
        else:
            print(green("OpenSSL CCS Injection: No"))
    except:
        print(red("OpenSSL CCS Injection: Status unavailable"))

    # Check the DHE suites
    try:
        dhe = "No"
        for suite in data['endpoints'][0]['details']['suites']['list']:
            try:
                if "DHE" in suite['name']:
                    try:
                        if suite['q'] == 0:
                            dhe = "Yes"
                            print(green("Possible Insecure DHE: %s" % suite['name']))
                    except:
                        print(green("Secure Suite: %s" % suite['name']))
            except:
                    print(red("DHE Suites: DHE suite information unavailable"))
    except:
        print(red("DHE Suites: DHE suite information unavailable"))


def check_ssl(target):
    """Get SSL certificate information for the target IP address or domain."""
    # Return None because we can't navigate to a CIDR for SSL certificates
    if "/" in target:
        print(red("[!] Cannot get certicate information for a CIDR. \
Supply a single IP or domain and port."))
        return None
    else:
        try:
            ip, port = target.split(":")
        except:
            ip = target
            port = 443
        next
    try:
        print(yellow("Target:\t\t{}".format(ip)))
        print(yellow("Port:\t\t{}".format(port)))
        cert = ssl.get_server_certificate((ip, port))
    except Exception as error:
        # If it can't connect, then return nothing/fail
        print(yellow("[!] Could not connect or no certificate was found."))
        print(yellow("L.. Details: {}".format(error)))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(s)
        ssl_sock.connect((ip, port))
        peerName = ssl_sock.getpeername()
        print(yellow("Peer Name:\t{}:{}".format(peerName[0], peerName[1])))
        print(yellow("Ciphers:"))
        for c in ssl_sock.cipher():
            print(yellow("\t\t{}".format(c)))
        print(yellow("Version:\t{}".format(ssl_sock.version())))
    except Exception as error:
        print(red("[!] Viper failed to make an SSL wrapped socket!"))
        print(red("L.. Details: {}".format(error)))
    try:
        # Use OpenSSL to collect certificate information
        c = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        subj = c.get_subject()
        comp = subj.get_components()
        print(yellow("\nCertificate Details:"))
        for i in comp:
            print(yellow("{}\t\t{}".format(i[0].decode('ascii'), i[1].decode('ascii'))))
    except Exception as error:
        # If OpenSSL fails to get information, return nothing/fail
        print(red("[!] Viper failed to get the certfication information!"))
        print(red("L.. Details: {}".format(error)))