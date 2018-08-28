#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions for ODIN's custom libraries. These functions are used across different modules.
"""

import sys
import configparser

from IPy import IP
from neo4j.v1 import GraphDatabase
from colors import red, yellow, green


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
    """A very basic check to see if the provided string contains any letters. This is useful for
    determining if a string should be treated as an IP address range or a domain.

    The is_ip() function will recognize an indvidual IP address or a CIDR, but will not validate a
    range like 192.168.1.0-50. Ranges will never contain letters, so this serves to separate domain
    names with hyphens from IP address ranges with hyphens.
    """
    result = any(check.isalpha() for check in value)

    return result

def setup_gdatabase_conn():
    """Function to setup the database connection to the active Neo4j project meant to contain the
    ODIN data.
    """
    try:
        database_uri = config_section_map("GraphDatabase")["uri"]
        database_user = config_section_map("GraphDatabase")["username"]
        database_pass = config_section_map("GraphDatabase")["password"]
        print(yellow("[*] Attempting to connect to your Neo4j project using {}:{} @ {}."
                .format(database_user, database_pass, database_uri)))
        neo4j_driver = GraphDatabase.driver(database_uri, auth=(database_user, database_pass))
        print(green("[+] Success!"))
        return neo4j_driver
    except Exception:
        neo4j_driver = None
        print(red("[!] Could not create a database connection using the details provided in \
your database.config! Please check the URI, username, and password. Also, make sure your Neo4j \
project is running. Note that the bolt port can change."))
        exit()

def execute_query(driver, query):
    """Execute the provided query using the provided Neo4j database connection and driver."""
    with driver.session() as session:
        results = session.run(query)

    return results
