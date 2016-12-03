#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
from bs4 import BeautifulSoup
import requests
import time
from colors import red, green, yellow


def discover(client, target):
	"""Discover files available on the target domain
	The 'Start' parameter is used here to allow for iterating through X pages
	Edit setup/google_filetypes.txt to customize your search terms
	"""
	print(green("""Viper will now perform  variety of Google searches to try to find publicly files. If this breaks, you might be blocked by Google with a CAPTCHA. They do that sometimes when their keywords are used.
	"""))
	f = 'reports/{}/File_Report - {}.txt'.format(client,target)
	my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'} # Google-friendly user-agent

	with open(f,'w') as report:
		# Create File Report in client folder
		report.write("### File Discovery Report for {} ###\n".format(target))
		# Use Google Hacking queries
		print(green("[+] Using Google to find documents"))
		print(yellow("[-] Warning: Google sometimes blocks automated queries like this by using a CAPTCHA. This may fail. If it does, try again later or use a VPN/proxy."))
		report.write("\n--- GOOGLE HACKING Results ---\n")
		# Perform search and grab just the URLs for each result
		try:
			for start in range(0,10):
				with open('setup/google_filetypes.txt') as googles:
					url = "https://www.google.com/search?q=site:%s+" % target
					terms = googles.readlines()
					totalTerms = len(terms)
					for i in range (totalTerms-1):
						url = url + "filetype:%s+OR+" % terms[i].rstrip()
					url = url + "filetype:%s&start=%s" % (terms[totalTerms-1].rstrip(), str(start*10))

				r = requests.get(url, headers = my_headers)
				status = r.status_code
				soup = BeautifulSoup(r.text, "html.parser")

				for cite in soup.findAll('cite'):
					try:
						report.write("{}\n".format(cite.text))
					except:
						if not status == 200:
							report.write("Viper did not receive a 200 OK! You can double check by using this search query:\n")
							report.write("Query: {}".format(url))
						continue

				# Take a break to avoid Google blocking our IP
				time.sleep(10)
		except Exception as e:
			print("Error: {}".format(e))
			print(red("[!] Requests failed! It could be the internet connection or a CAPTCHA. Try again later."))
			report.write("Search failed due to a bad connection or a CAPTCHA. You can try manually running this search: {} \n".format(url))
