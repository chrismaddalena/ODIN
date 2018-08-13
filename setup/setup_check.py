#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import configparser
from configparser import NoSectionError,NoOptionError,ParsingError
import sys
from colors import red, green, yellow
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException


class SetupReview(object):
    """Class used for reviewing the provided keys.config file for ODIN."""
    def __init__(self, auth_file):
        """Everything begins here."""
        print(green("[+] This tool will check to make sure your keys.config file is present and contains \
the API keys used by ODIN."))
        self.how_do_we_look = 0
        try:
            self.CONFIG_PARSER = configparser.ConfigParser()
            self.CONFIG_PARSER.read(auth_file)
            print(green("[*] Loaded {} file with these sections:\n".format(auth_file)))
            for section in self.CONFIG_PARSER.sections():
                print(green("\t* " + section))
        except Exception as error:
            print(red("[!] Could not open keys.config file -- make sure it exists and is readable."))
            print(red("L.. Details: {}".format(error)))
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
                    print("[-] Skipping: {}".format(option))
            except:
                print("[!] There was an error with: {}".format(option))
                section_dict[option] = None

        # Return the dictionary of settings and values
        return section_dict

    def check_all(self):
        """Function to check each section of the keys.config file and perform any necessary tests."""
        try:
            SHODAN_API_KEY = self.config_section_map("Shodan")["api_key"]
            if SHODAN_API_KEY == "":
                print(red("\n[!] No Shodan API key!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found Shodan API key:"))
                print(yellow("... API Key:\t\t{}".format(SHODAN_API_KEY)))
        except Exception as error:
            print(red("\n[!] Could not get the Shodan API key!"))
            print(red("L.. Details: {}".format(error)))

        try:
            CYMON_API_KEY = self.config_section_map("Cymon")["api_key"]
            if CYMON_API_KEY == "":
                print(red("\n[!] No Cymon API key!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found Cymon key:"))
                print(yellow("... API Key:\t\t{}".format(CYMON_API_KEY)))
        except Exception as error:
            print(red("\n[!] Could not get the Cymon API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            URLVOID_API_KEY = self.config_section_map("URLVoid")["api_key"]
            if URLVOID_API_KEY == "":
                print(red("\n[!] No URLVoid API key!"))
                self.how_do_we_look += 1
            print(green("\n[+] Found URLVoid API key:"))
            print(yellow("... API Key:\t\t{}".format(URLVOID_API_KEY)))
        except Exception as error:
            print(red("\n[!] Could not get the URLVoid API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            CENSYS_API_ID = self.config_section_map("Censys")["api_id"]
            CENSYS_API_SECRET = self.config_section_map("Censys")["api_secret"]
            if CENSYS_API_ID == "" or CENSYS_API_SECRET == "":
                print(red("\n[!] No Censys API ID or secret!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found Censys API info:"))
                print(yellow("... API ID:\t\t{}".format(CENSYS_API_ID)))
                print(yellow("... API Secret:\t\t{}".format(CENSYS_API_SECRET)))
        except Exception as error:
            print(red("\n[!] Could not get the Censys API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            CONSUMER_KEY = self.config_section_map("Twitter")["consumer_key"]
            CONSUMER_KEY_SECRET = self.config_section_map("Twitter")["key_secret"]
            ACCESS_TOKEN = self.config_section_map("Twitter")["access_token"]
            ACCESS_TOKEN_SECRET = self.config_section_map("Twitter")["token_secret"]
            if CONSUMER_KEY == "" or CONSUMER_KEY_SECRET == "" \
            or ACCESS_TOKEN == "" or ACCESS_TOKEN_SECRET == "":
                print(red("\n[!] Missing Twitter tokens!"))
                self.how_do_we_look += 1
            else:        
                print(green("\n[+] Found Twitter tokens:"))
                print(yellow("... Key:\t\t{}".format(CONSUMER_KEY)))
                print(yellow("... Key Secret:\t\t{}".format(CONSUMER_KEY_SECRET)))
                print(yellow("... Token: \t\t{}".format(ACCESS_TOKEN)))
                print(yellow("... Token Secret:\t{}".format(ACCESS_TOKEN_SECRET)))
        except Exception as error:
            print(red("\n[!] Could not get the Twitter tokens!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            HUNTER_API = self.config_section_map("EmailHunter")["api_key"]
            if HUNTER_API == "":
                print(red("\n[!] No EmailHunter API key!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found EmailHunter API info:"))
                print(yellow("... API Key:\t\t{}".format(HUNTER_API)))
        except Exception as error:
            print(red("\n[!] Could not get the EmailHunter API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            CONTACT_API = self.config_section_map("Full Contact")["api_key"]
            if CONTACT_API == "":
                print(red("\n[!] No Full Contact API key!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found Full Contact API info:"))
                print(yellow("... API Key:\t\t{}".format(CONTACT_API)))
        except Exception as error:
            print(red("\n[!] Could not get the Full Contact API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            WEB_DRIVER = self.config_section_map("WebDriver")["driver_path"]
            if WEB_DRIVER == "":
                print(red("\n[!] No Chrome web driver filepath found!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found filepath for a Chrome web driver:"))
                print(yellow("... File Path:\t\t{}".format(WEB_DRIVER)))
            try:
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--window-size=1920x1080")
                browser = webdriver.Chrome(chrome_options=chrome_options, executable_path=WEB_DRIVER)
                print(yellow("... Browser Test:\tSuccess!"))
            except WebDriverException as error:
                print(red("... Browser Test:\tFAILED, WebDriverException!"))
                self.how_do_we_look += 1
            except Exception as error:
                print(red("... Browser Test:\t\t FAILED, general exception!"))
                self.how_do_we_look += 1
        except Exception as error:
            print(red("\n[!] Could not get the filepath for your Chrome wbedriver binary!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            NEO4J_URI = self.config_section_map("GraphDatabase")["uri"]
            NEO4J_USER = self.config_section_map("GraphDatabase")["username"]
            NEO4J_PASS = self.config_section_map("GraphDatabase")["password"]
            if NEO4J_URI == "" or NEO4J_USER == "" or NEO4J_PASS == "":
                print(red("\n[!] Incomplete Neo4j connection info!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found Neo4j connection info:"))
                print(yellow("... URI:\t\t{}".format(NEO4J_URI)))
                print(yellow("... User:\t\t{}".format(NEO4J_USER)))
                print(yellow("... Pass:\t\t{}".format(NEO4J_PASS)))
        except Exception as error:
            print(red("\n[!] Could not get your Neo4j connection info!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            AWS_KEY = self.config_section_map("AWS")["access_key"]
            AWS_SECRET = self.config_section_map("AWS")["secret"]
            if AWS_KEY == "" or AWS_SECRET == "":
                print(red("\n[!] Missing AWS access tokens!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found AWS acsess token details:"))
                print(yellow("... Key:\t\t{}".format(AWS_KEY)))
                print(yellow("... Secret:\t\t{}".format(AWS_SECRET)))
        except Exception as error:
            print(red("\n[!] Could not get your AWS token info!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        try:
            WHOXY_API = self.config_section_map("WhoXY")["api_key"]
            if WHOXY_API == "":
                print(red("\n[!] No WhoXY API key!"))
                self.how_do_we_look += 1
            else:
                print(green("\n[+] Found WhoXY API info:"))
                print(yellow("... API Key:\t\t{}".format(WHOXY_API)))
        except Exception as error:
            print(red("\n[!] Could not get the WhoXY API key!"))
            print(red("L.. Details: {}".format(error)))
            self.how_do_we_look += 1

        if self.how_do_we_look == 0:
            print(green("\n[+] It looks like keys.config is filled out! Just check to make sure those \
all of the information is correct!"))
        else:
            print(yellow("\n[!] Warning: It looks like there is still some work to do before API access is ready. \
No API keys are required, but using them is encouraged!"))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(red("[!] Provide your keys.config for review"))
        print(red("L.. Usage: setup_check.py auth/keys.config"))
    elif len(sys.argv) > 2:
        print(red("[!] Too many arguments"))
        print(red("L.. Usage: setup_check.py auth/keys.config"))
    else:
        auth_file = sys.argv[1]
        if os.path.isfile(auth_file):
            file_name = auth_file.split("/")
            if file_name[-1] == "keys.config":
                checkup = SetupReview(auth_file)
                checkup.check_all()
            else:
                print(red("[!] This file path does not appear to include a keys.config file. Are \
you sure you specified a file names keys.config?"))
        else:
            print(red("[!] Could not open the specified keys.config file: {}".format(auth_file)))
            print(red("L.. Usage: setup_check.py auth/keys.config"))
