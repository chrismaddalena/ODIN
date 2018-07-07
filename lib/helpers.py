#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions for ODIN and ODIN's custom libraries. These functions are shared between
libraries.
"""

import configparser
from IPy import IP
from colors import red


try:
    CONFIG_PARSER = configparser.ConfigParser()
    CONFIG_PARSER.read("auth/keys.config")
except configparser.Error as error:
    print(red("[!] Could not open keys.config file inside the auth directory -- make sure it \
exists and is readable."))
    print(red("L.. Details: {}".format(error)))

def config_section_map(section):
    """This function helps by reading a config file section and returning a dictionary object 
    that can be referenced for configuration settings.
    """
    try:
        section_dict = {}
        # Parse the config file's sections into options
        options = CONFIG_PARSER.options(section)
        # Loop through each option
        for option in options:
            # Get the section and option and add it to the dictionary
            section_dict[option] = CONFIG_PARSER.get(section, option)
            if section_dict[option] == -1:
                print("[-] Skipping: {}".format(option))

        # Return the dictionary of settings and values
        return section_dict
    except configparser.Error as error:
        print(red("[!] There was an error with: {}".format(section)))
        print(red("L.. Details: {}".format(error)))

def is_ip(value):
    """Checks if the provided string is an IP address or not. If the check fails, it will be 
    assumed the string is a domain in most cases.

    IPy is used to determine if a string is a valid IP address. A True or False is returned.
    """
    try:
        IP(value)
    except ValueError:
        return False
    return True

def is_domain(value):
    """A very basic check to see if the provided string contians any letters. This is useful for
    determining if a string should be treated as an IP address range or a domain.

    For example, is_ip() will recognize an idnvidual IP address or a CIDR, but will not validate a
    range like 192.168.1.0-50. Ranges will never contain letters, so this serves to separate domain
    names with hyphens from IP address ranges.
    """
    result = any(check.isalpha() for check in value)

    return result