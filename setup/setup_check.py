#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import configparser
from configparser import NoSectionError,NoOptionError,ParsingError

import click
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException


class SetupReview(object):
    """Class used for reviewing the provided keys.config file for ODIN."""
    def __init__(self, auth_file):
        """Everything begins here."""
        click.secho("[+] This tool will check to make sure your keys.config file is present and contains \
the API keys used by ODIN.", fg="green")
        self.how_do_we_look = 0
        try:
            self.CONFIG_PARSER = configparser.ConfigParser()
            self.CONFIG_PARSER.read(auth_file)
            click.secho("[*] Loaded {} file with these sections:\n".format(auth_file), fg="green")
            for section in self.CONFIG_PARSER.sections():
                click.secho("\t* " + section, fg="green")
        except Exception as error:
            click.secho("[!] Could not open keys.config file -- make sure it exists and is readable.", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            exit()

    def config_section_map(self, section):
        """This function helps by reading a config file section and returning a dictionary object
        that can be referenced for configuration settings.
        """
        section_dict = {}
        # Parse the config file's sections into options
        options = self.CONFIG_PARSER.options(section)
        # Loop through each option
        for option in options:
            try:
                # Get the section and option and add it to the dictionary
                section_dict[option] = self.CONFIG_PARSER.get(section, option)
                if section_dict[option] == -1:
                    click.secho("[*] Skipping: {}".format(option), fg="yellow")
            except:
                click.secho("[!] There was an error with: {}".format(option), fg="red")
                section_dict[option] = None

        # Return the dictionary of settings and values
        return section_dict

    def check_api(self):
        """Function to check each section of the keys.config file and perform any necessary tests."""
        try:
            SHODAN_API_KEY = self.config_section_map("Shodan")["api_key"]
            if SHODAN_API_KEY == "":
                click.secho("\n[!] No Shodan API key!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found Shodan API key:", fg="green")
                click.secho("... API Key:\t\t{}".format(SHODAN_API_KEY), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the Shodan API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")

        try:
            CYMON_API_KEY = self.config_section_map("Cymon")["api_key"]
            if CYMON_API_KEY == "":
                click.secho("\n[!] No Cymon API key!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found Cymon key:", fg="green")
                click.secho("... API Key:\t\t{}".format(CYMON_API_KEY), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the Cymon API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            URLVOID_API_KEY = self.config_section_map("URLVoid")["api_key"]
            if URLVOID_API_KEY == "":
                click.secho("\n[!] No URLVoid API key!", fg="red")
                self.how_do_we_look += 1
            click.secho("\n[+] Found URLVoid API key:", fg="green")
            click.secho("... API Key:\t\t{}".format(URLVOID_API_KEY), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the URLVoid API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            CENSYS_API_ID = self.config_section_map("Censys")["api_id"]
            CENSYS_API_SECRET = self.config_section_map("Censys")["api_secret"]
            if CENSYS_API_ID == "" or CENSYS_API_SECRET == "":
                click.secho("\n[!] No Censys API ID or secret!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found Censys API info:", fg="green")
                click.secho("... API ID:\t\t{}".format(CENSYS_API_ID), fg="yellow")
                click.secho("... API Secret:\t\t{}".format(CENSYS_API_SECRET), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the Censys API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            CONSUMER_KEY = self.config_section_map("Twitter")["consumer_key"]
            CONSUMER_KEY_SECRET = self.config_section_map("Twitter")["key_secret"]
            ACCESS_TOKEN = self.config_section_map("Twitter")["access_token"]
            ACCESS_TOKEN_SECRET = self.config_section_map("Twitter")["token_secret"]
            if CONSUMER_KEY == "" or CONSUMER_KEY_SECRET == "" \
            or ACCESS_TOKEN == "" or ACCESS_TOKEN_SECRET == "":
                click.secho("\n[!] Missing Twitter tokens!", fg="red")
                self.how_do_we_look += 1
            else:        
                click.secho("\n[+] Found Twitter tokens:", fg="green")
                click.secho("... Key:\t\t{}".format(CONSUMER_KEY), fg="yellow")
                click.secho("... Key Secret:\t\t{}".format(CONSUMER_KEY_SECRET), fg="yellow")
                click.secho("... Token: \t\t{}".format(ACCESS_TOKEN), fg="yellow")
                click.secho("... Token Secret:\t{}".format(ACCESS_TOKEN_SECRET), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the Twitter tokens!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            HUNTER_API = self.config_section_map("EmailHunter")["api_key"]
            if HUNTER_API == "":
                click.secho("\n[!] No EmailHunter API key!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found EmailHunter API info:", fg="green")
                click.secho("... API Key:\t\t{}".format(HUNTER_API), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the EmailHunter API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            CONTACT_API = self.config_section_map("Full Contact")["api_key"]
            if CONTACT_API == "":
                click.secho("\n[!] No Full Contact API key!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found Full Contact API info:", fg="green")
                click.secho("... API Key:\t\t{}".format(CONTACT_API), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the Full Contact API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            WEB_DRIVER = self.config_section_map("WebDriver")["driver_path"]
            if WEB_DRIVER == "":
                click.secho("\n[!] No Chrome web driver filepath found!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found filepath for a Chrome web driver:", fg="green")
                click.secho("... File Path:\t\t{}".format(WEB_DRIVER), fg="yellow")
            try:
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--window-size=1920x1080")
                webdriver.Chrome(chrome_options=chrome_options, executable_path=WEB_DRIVER)
                click.secho("... Browser Test:\tSuccess!", fg="green")
            except WebDriverException as error:
                click.secho("... Browser Test:\tFAILED, WebDriverException!", fg="red")
                click.secho("{}".format(error), fg="red")
                self.how_do_we_look += 1
            except Exception as error:
                click.secho("... Browser Test:\t\t FAILED, general exception!", fg="red")
                self.how_do_we_look += 1
        except Exception as error:
            click.secho("\n[!] Could not get the filepath for your Chrome wbedriver binary!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            NEO4J_URI = self.config_section_map("GraphDatabase")["uri"]
            NEO4J_USER = self.config_section_map("GraphDatabase")["username"]
            NEO4J_PASS = self.config_section_map("GraphDatabase")["password"]
            if NEO4J_URI == "" or NEO4J_USER == "" or NEO4J_PASS == "":
                click.secho("\n[!] Incomplete Neo4j connection info!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found Neo4j connection info:", fg="green")
                click.secho("... URI:\t\t{}".format(NEO4J_URI), fg="yellow")
                click.secho("... User:\t\t{}".format(NEO4J_USER), fg="yellow")
                click.secho("... Pass:\t\t{}".format(NEO4J_PASS), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get your Neo4j connection info!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            AWS_KEY = self.config_section_map("AWS")["access_key"]
            AWS_SECRET = self.config_section_map("AWS")["secret"]
            if AWS_KEY == "" or AWS_SECRET == "":
                click.secho("\n[!] Missing AWS access tokens!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found AWS acsess token details:", fg="green")
                click.secho("... Key:\t\t{}".format(AWS_KEY), fg="yellow")
                click.secho("... Secret:\t\t{}".format(AWS_SECRET), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get your AWS token info!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        try:
            WHOXY_API = self.config_section_map("WhoXY")["api_key"]
            if WHOXY_API == "":
                click.secho("\n[!] No WhoXY API key!", fg="red")
                self.how_do_we_look += 1
            else:
                click.secho("\n[+] Found WhoXY API info:", fg="green")
                click.secho("... API Key:\t\t{}".format(WHOXY_API), fg="yellow")
        except Exception as error:
            click.secho("\n[!] Could not get the WhoXY API key!", fg="red")
            click.secho("L.. Details: {}".format(error), fg="red")
            self.how_do_we_look += 1

        if self.how_do_we_look == 0:
            click.secho("\n[+] It looks like keys.config is filled out! Just check to make sure those \
all of the information is correct!", fg="green")
        else:
            click.secho("\n[!] Warning: It looks like there is still some work to do before API access is ready. \
No API keys are required, but using them is encouraged!", fg="yellow")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        click.secho("[!] Provide your keys.config for review", fg="red")
        click.secho("L.. Usage: setup_check.py auth/keys.config", fg="red")
    elif len(sys.argv) > 2:
        click.secho("[!] Too many arguments", fg="red")
        click.secho("L.. Usage: setup_check.py auth/keys.config", fg="red")
    else:
        auth_file = sys.argv[1]
        if os.path.isfile(auth_file):
            file_name = auth_file.split("/")
            if file_name[-1] == "keys.config":
                checkup = SetupReview(auth_file)
                checkup.check_api()
            else:
                click.secho("[!] This file path does not appear to include a keys.config file. Are \
you sure you specified a file names keys.config?", fg="red")
        else:
            click.secho("[!] Could not open the specified keys.config file: {}".format(auth_file), fg="red")
            click.secho("L.. Usage: setup_check.py auth/keys.config", fg="red")
