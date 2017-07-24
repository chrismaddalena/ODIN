#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

"""
Helper functions for ODIN and ODIN's custom libraries. These functions are shared
between libraries.
"""

try:
	config_parser = configparser.ConfigParser()
	config_parser.read("auth/keys.config")
except Exception as e:
	print(red("[!] Could not open keys.config file inside the auth directory -- make sure it exists and is readable."))
	print(red("L.. Details: {}".format(e)))

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
