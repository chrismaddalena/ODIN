#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import configparser
from time import sleep

print("[+] This tool will check to make sure your auth/keys.config \
file is present and contains the API keys used by O.D.I.N.")
print("L.. Make sure you run this from inside the /setup directory! \
i.e. python3 setup_check.py, NOT setup/setup_check.py")
sleep(2)

how_do_we_look = 0

def config_section_map(section):
    """This function helps by reading a config file section and returning a
    dictionary object that can be referenced for configuration settings.
    """
    section_dict = {}
    # Parse the config file's sections into options
    options = CONFIG_PARSER.options(section)
    # Loop through each option
    for option in options:
        try:
            # Get the section and option and add it to the dictionary
            section_dict[option] = CONFIG_PARSER.get(section, option)
            if section_dict[option] == -1:
                print("[-] Skipping: {}".format(option))
        except:
            print("[!] There was an error with: {}".format(option))
            section_dict[option] = None

    # Return the dictionary of settings and values
    return section_dict

if os.path.isfile('../auth/keys.config'):
    print("[+] Found the auth/keys.config file!")
else:
    print("[!] Could not find the auth/keys.config file with your API keys!")
    exit()

try:
    CONFIG_PARSER = configparser.ConfigParser()
    CONFIG_PARSER.read("../auth/keys.config")
except Exception as error:
    print("[!] Could not open keys.config file inside the auth directory -- make sure it exists and is readable.")
    print("L.. Details: {}".format(error))
    exit()

try:
    SHODAN_API_KEY = config_section_map("Shodan")["api_key"]
    if SHODAN_API_KEY == "":
        print("[!] No Shodan API key!")
        how_do_we_look += 1
    else:
        print("[+] Found Shodan API key:")
        print("... API Key:\t\t{}".format(SHODAN_API_KEY))
except Exception as error:
    print("[!] Could not get the Shodan API key!")
    print("L.. Details: {}".format(error))

try:
    CYMON_API_KEY = config_section_map("Cymon")["api_key"]
    if CYMON_API_KEY == "":
        print("[!] No Cymon API key!")
        how_do_we_look += 1
    else:
        print("[+] Found Cymon key:")
        print("... API Key:\t\t{}".format(CYMON_API_KEY))
except Exception as errpr:
    print("[!] Could not get the Cymon API key!")
    print("L.. Details: {}".format(error))
    how_do_we_look += 1

try:
    URLVOID_API_KEY = config_section_map("URLVoid")["api_key"]
    if URLVOID_API_KEY == "":
        print("[!] No URLVoid API key!")
        how_do_we_look += 1
    print("[+] Found URLVoid API key:")
    print("... API Key:\t\t{}".format(URLVOID_API_KEY))
except Exception as error:
    print("[!] Could not get the URLVoid API key!")
    print("L.. Details: {}".format(error))
    how_do_we_look += 1

try:
    CENSYS_API_ID = config_section_map("Censys")["api_id"]
    CENSYS_API_SECRET = config_section_map("Censys")["api_secret"]
    if CENSYS_API_ID == "" or CENSYS_API_SECRET == "":
        print("[!] No Censys API ID or secret!")
        how_do_we_look += 1
    else:
        print("[+] Found Censys API info:")
        print("... API ID:\t\t{}".format(CENSYS_API_ID))
        print("... API Secret:\t\t{}".format(CENSYS_API_SECRET))
except Exception as error:
    print("[!] Could not get the Censys API key!")
    print("L.. Details: {}".format(error))
    how_do_we_look += 1

try:
    CONSUMER_KEY = config_section_map("Twitter")["consumer_key"]
    CONSUMER_KEY_SECRET = config_section_map("Twitter")["key_secret"]
    ACCESS_TOKEN = config_section_map("Twitter")["access_token"]
    ACCESS_TOKEN_SECRET = config_section_map("Twitter")["token_secret"]
    if CONSUMER_KEY == "" or CONSUMER_KEY_SECRET == "" \
    or ACCESS_TOKEN == "" or ACCESS_TOKEN_SECRET == "":
        print("[!] Missing Twitter tokens!")
        how_do_we_look += 1
    else:        
        print("[+] Found Twitter tokens:")
        print("... Consumer Key:\t{}".format(CONSUMER_KEY))
        print("... Consumer Key Secret: {}".format(CONSUMER_KEY_SECRET))
        print("... Access Token: \t{}".format(ACCESS_TOKEN))
        print("... Access Token Secret: {}".format(ACCESS_TOKEN_SECRET))
except Exception as error:
    print("[!] Could not get the Twitter tokens!")
    print("L.. Details: {}".format(error))
    how_do_we_look += 1

if how_do_we_look == 0:
    print("[+] Looks like ../auth/keys.config and all the API keys are good to go! \
Just check to make sure those keys are correct!")
else:
    print("[!] Looks like there is still some work to do before API access is ready :(")
