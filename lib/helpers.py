#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions for ODIN's custom libraries. These functions are used across different modules.
"""

import sys
import configparser

import click
from IPy import IP
from neo4j.v1 import GraphDatabase
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException,NoSuchElementException,WebDriverException


try:
    CONFIG_PARSER = configparser.ConfigParser()
    CONFIG_PARSER.read("auth/keys.config")
except configparser.Error as error:
    click.secho("[!] Could not open keys.config file inside the auth directory -- make sure it \
exists and is readable.", fg="red")
    click.secho("L.. Details: {}".format(error), fg="red")

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
                click.secho("[*] Skipping: {}".format(option), fg="yellow")

        # Return the dictionary of settings and values
        return section_dict
    except configparser.Error as error:
        click.secho("[!] There was an error with: {}".format(section), fg="red")
        click.secho("L.. Details: {}".format(error), fg="red")

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
        click.secho("[*] Attempting to connect to your Neo4j project using {}:{} @ {}."
                .format(database_user, database_pass, database_uri), fg="yellow")
        neo4j_driver = GraphDatabase.driver(database_uri, auth=(database_user, database_pass))
        click.secho("[+] Success!", fg="green")
        return neo4j_driver
    except Exception:
        neo4j_driver = None
        click.secho("[!] Could not create a database connection using the details provided in \
your database.config! Please check the URI, username, and password. Also, make sure your Neo4j \
project is running. Note that the bolt port can change.", fg="red")
        exit()

def execute_query(driver, query):
    """Execute the provided query using the provided Neo4j database connection and driver."""
    with driver.session() as session:
        results = session.run(query)

    return results

def setup_headless_chrome():
    """Attempt to setup a Selenium webdriver using headless Chrome. If this fails, fallback to
    PhantomJS. PhantomJS is a last resort, but better than nothing for the time being."""
    try:
        chrome_driver_path = config_section_map("WebDriver")["driver_path"]
        # Try loading the driver as a test
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        browser = webdriver.Chrome(chrome_options=chrome_options, executable_path=chrome_driver_path)
        click.secho("[*] Headless Chrome browser test was successful!", fg="yellow")
    # Catch issues with the web driver or path
    except WebDriverException:
        chrome_driver_path = None
        browser = webdriver.PhantomJS()
        click.secho("[!] There was a problem with the specified Chrome web driver in your \
keys.config! Please check it. For now ODIN will try to use PhantomJS for HaveIBeenPwned.", fg="yellow")
    # Catch issues loading the value from the config file
    except Exception:
        chrome_driver_path = None
        browser = webdriver.PhantomJS()
        click.secho("[!] Could not load a Chrome webdriver for Selenium, so we will tryuse \
to use PantomJS for haveIBeenPwned.", fg="yellow")

    return browser
