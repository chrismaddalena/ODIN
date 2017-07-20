#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import configparser
from time import sleep

print("[+] This tool will check to make sure your auth/keys.config file is present and contains the API keys used by O.D.I.N.")
print("L.. Make sure you run this from inside the /setup directory! i.e. python3 setup_check.py, NOT setup/setup_check.py")
sleep(2)

how_do_we_look = 0

def config_section_map(section):
	"""This function helps by reading a config file section and returning a
	dictionary object that can be referenced for configuration settings.
	"""
	section_dict ={}
	# Parse the config file's sections into options
	options = config_parser.options(section)
	# Loop through each option
	for option in options:
		try:
			# Get the section and option and add it to the dictionary
			section_dict[option] = config_parser.get(section, option)
			if section_dict[option] == -1:
				DebugPrint("[-] Skipping: {}".format(option))
		except:
			print(red("[!] There was an error with: {}".format(option)))
			section_dict[option] = None

	# Return the dictionary of settings and values
	return section_dict

if os.path.isfile('../auth/keys.config'):
    print("[+] Found the auth/keys.config file!")
else:
	print("[!] Could not find the auth/keys.config file with your API keys!")
	exit()

try:
	config_parser = configparser.ConfigParser()
	config_parser.read("../auth/keys.config")
except Exception as e:
	print(red("[!] Could not open keys.config file inside the auth directory -- make sure it exists and is readable."))
	print(red("L.. Details: {}".format(e)))
	exit()

try:
	SHODAN_API_KEY = config_section_map("Shodan")["api_key"]
	print("[+] Found Shodan API key!")
except Exception as e:
	print("[!] Could not get the Shodan API key!")
	print("L.. Details: {}".format(e))

try:
	CYMON_API_KEY = config_section_map("Cymon")["api_key"]
	print("[+] Found Censys Cymon key!")
except Exception as e:
	print("[!] Could not get the Cymon API key!")
	print("L.. Details: {}".format(e))
	how_do_we_look += 1

try:
	URLVOID_API_KEY = config_section_map("URLVoid")["api_key"]
	print("[+] Found URLVoid API key!")
except Exception as e:
	print("[!] Could not get the URLVoid API key!")
	print("L.. Details: {}".format(e))
	how_do_we_look += 1

try:
	CENSYS_API_ID = config_section_map("Censys")["api_id"]
	CENSYS_API_SECRET = config_section_map("Censys")["api_secret"]
	print("[+] Found Censys API key!")
except Exception as e:
	print("[!] Could not get the Censys API key!")
	print("L.. Details: {}".format(e))
	how_do_we_look += 1

try:
	consumer_key = config_section_map("Twitter")["consumer_key"]
	consumer_key_secret = config_section_map("Twitter")["key_secret"]
	access_token = config_section_map("Twitter")["access_token"]
	access_token_secret = config_section_map("Twitter")["token_secret"]
	print("[+] Found Twitter tokens!")
except Exception as e:
	print("[!] Could not get the Twitter tokens!")
	print("L.. Details: {}".format(e))
	how_do_we_look += 1

if how_do_we_look == 0:
	print("[+] Looks like ../auth/keys.config and all the API keys are good to go!")
else:
	print("[+] Looks like there is still some work to do before API access is ready :(")
