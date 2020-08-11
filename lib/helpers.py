#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions for ODIN's custom libraries. These functions are used across different modules.
"""

import configparser
import os
import sys

import click
from neo4j import GraphDatabase
from selenium import webdriver
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from IPy import IP
from netaddr import IPNetwork, iter_iprange

# Load the config file
try:
    config_file_loc = os.path.join(
        os.path.dirname(__file__), "..", "auth", "keys.config"
    )
    CONFIG_PARSER = configparser.ConfigParser()
    CONFIG_PARSER.read(config_file_loc)
except configparser.Error as error:
    click.secho(
        "[!] Could not open keys.config file inside the auth directory -- make sure it exists and is readable.",
        fg="red",
    )
    click.secho("L.. Details: {}".format(error), fg="red")


def config_section_map(section: str):
    """
    Read a config file section and returning a dictionary object that can be referenced
    for configuration settings.

    **Parameters**

    ``section``
        Config section to be collected from the config file
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
                click.secho("[*] Skipping: {}".format(option), fg="yellow")
        # Return the dictionary of settings and values
        return section_dict
    except configparser.Error as error:
        click.secho("[!] There was an error with: {}".format(section), fg="red")
        click.secho("L.. Details: {}".format(error), fg="red")


def is_ip(value: str):
    """
    Use IPy to determine if the provided string is an IP address or not. If the check
    fails, it will be assumed the string is a domain in most cases.

    **Parameters**

    ``value``
        String to be determined to be evaluated
    """
    try:
        IP(value)
    except ValueError:
        return False
    return True


def is_domain(value: str):
    """
    Check to see if the provided string contains any letters. This is useful for determining
    if a string should be treated as an IP address range or a domain.

    **Parameters**

    ``value``
        String to be determined to be evaluated as a domain name or not
    """
    # The `is_ip()` function will not validate an IP range with hyphens
    # Ranges will not contain alpha characters
    result = any(check.isalpha() for check in value)
    return result


def setup_gdatabase_conn():
    """Setup the database connection to the configured Neo4j database."""
    try:
        database_uri = config_section_map("GraphDatabase")["uri"]
        database_user = config_section_map("GraphDatabase")["username"]
        database_pass = config_section_map("GraphDatabase")["password"]
        click.secho(
            "[*] Attempting to connect to your Neo4j project using {}:{} @ {}.".format(
                database_user, database_pass, database_uri
            ),
            fg="yellow",
        )
        neo4j_driver = GraphDatabase.driver(
            database_uri, auth=(database_user, database_pass)
        )
        click.secho("[+] Success!", fg="green")
        return neo4j_driver
    except Exception:
        neo4j_driver = None
        click.secho(
            "[!] Could not create a database connection using the details provided in your config file!",
            fg="red",
        )
        exit()


def execute_query(driver: GraphDatabase.driver, query: str):
    """
    Execute the provided query using the provided Neo4j database connection and driver.

    **Parameters**

    ``driver``
        Neo4j bolt driver object

    ``query``
        Cypher query to be executed against the Neo4j database
    """
    with driver.session() as session:
        results = session.run(query)
    return results


def setup_headless_chrome(unsafe=False):
    """
    Setup a Selenium webdriver using headless Chrome. If this fails, fallback to
    PhantomJS. PhantomJS is a last resort, but better than nothing for the time being.

    **Parameters**

    ``unsafe``
        Boolean to set Chrome's ``--no-sandbox`` option (Default: False)
    """
    browser = None
    try:
        chrome_driver_path = config_section_map("WebDriver")["driver_path"]
        # Try loading the driver as a test
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--enable-javascript")
        # Setup 'capabilities' to ignore expired/self-signed certs so a screenshot is captured
        chrome_capabilities = DesiredCapabilities.CHROME.copy()
        chrome_capabilities["acceptSslCerts"] = True
        chrome_capabilities["acceptInsecureCerts"] = True
        # For Kali users, Chrome will get angry if the root user is used and requires --no-sandbox
        if unsafe:
            chrome_options.add_argument("--no-sandbox")
        browser = webdriver.Chrome(
            chrome_options=chrome_options,
            executable_path=chrome_driver_path,
            desired_capabilities=chrome_capabilities,
        )
        click.secho("[*] Headless Chrome browser test was successful!", fg="yellow")
        return browser
    # Catch issues with the web driver or path
    except WebDriverException:
        click.secho(
            "[!] Could not load the Chrome web driver in your keys.config!",
            fg="yellow",
        )
    # Catch issues loading the value from the config file
    except Exception:
        click.secho(
            "[!] Could not load the Chrome web driver in your keys.config!",
            fg="yellow",
        )
    return browser


def generate_scope(scope_file: str):
    """
    Parse IP ranges inside the provided scope file to expand IP ranges. This supports ranges
    with hyphens, underscores, and CIDRs.

    **Parameters**

    ``scope_file``
        Path to file containing domain names and IP addresses/ranges
    """
    scope = []
    try:
        with open(scope_file, "r") as scope_file:
            for target in scope_file:
                target = target.rstrip()

                # Record individual IPs and expand CIDRs
                if is_ip(target):
                    ip_list = list(IPNetwork(target))
                    for address in sorted(ip_list):
                        str_address = str(address)
                        scope.append(str_address)

                # Sort IP ranges from domain names and expand the ranges
                if not is_domain(target):
                    # Check for hyphenated ranges like those accepted by Nmap
                    # Ex: 192.168.1.1-50 will become 192.168.1.1 ... 192.168.1.50
                    if "-" in target:
                        target = target.rstrip()
                        parts = target.split("-")
                        startrange = parts[0]
                        b = parts[0]
                        dot_split = b.split(".")
                        temp = "."
                        # Join the values using a "." so it makes a valid IP
                        combine = dot_split[0], dot_split[1], dot_split[2], parts[1]
                        endrange = temp.join(combine)
                        # Calculate the IP range
                        ip_list = list(iter_iprange(startrange, endrange))
                        # Iterate through the range and remove ip_list
                        for x in ip_list:
                            temp = str(x)
                            scope.append(temp)
                    # Check if range has an underscore because underscores are fine, I guess?
                    # Ex: 192.168.1.2_192.168.1.155
                    elif "_" in target:
                        target = target.rstrip()
                        parts = target.split("_")
                        startrange = parts[0]
                        endrange = parts[1]
                        ip_list = list(iter_iprange(startrange, endrange))
                        for address in ip_list:
                            str_address = str(address)
                            scope.append(str_address)
                else:
                    scope.append(target.rstrip())
    except IOError as error:
        click.secho("[!] Parsing of scope file failed!", fg="red")
        click.secho("L.. Details: {}".format(error), fg="red")
    return scope
