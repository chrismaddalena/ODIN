#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import pwnedcheck
import sys
import urllib2
from colors import red, green

sys.path.append('lib/theharvester/')
from theHarvester import *

# Number of commands
total = 2 # Tests
harvesterDomains = 6 # Search engines used with theHarvester
# Headers for use with urllib2
user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
headers = { 'User-Agent' : user_agent }

def harvest(client,domain):
	print green("""
Viper will now attempt to find email addresses and potentially vulnerable accounts. TheHarvester will be used to find email addresses, names, and social media accounts. Emails will be checked against the HaveIBeenPwned database. This may take a few minutes.
	""")

	client = client
	domain = domain
	harvestLimit = 100
	harvestStart = 0
	# Create drectory for client reports and report
	if not os.path.exists("reports/%s" % client):
		try:
			os.makedirs("reports/%s" % client)
		except:
			print red("[!] Could not create reports directory!")

	file = "reports/%s/Email_Report.txt" % client

	print green("[+] Running The Harvester (1/%s)" % total)
	# Search trhough most of Harvester's supported engines
	# No Baidu because it always seems to hang or take way too long
	print "[-] Harvesting Google (1/%s)" % harvesterDomains
	search = googlesearch.search_google(domain,harvestLimit,harvestStart)
	search.process()
	googleHarvest = search.get_emails()
	print "[-] Harvesting LinkedIn (2/%s)" % harvesterDomains
	search = linkedinsearch.search_linkedin(domain,harvestLimit)
	search.process()
	linkHarvest = search.get_people()
	print "[-] Harvesting Twitter (3/%s)" % harvesterDomains
	search = twittersearch.search_twitter(domain,harvestLimit)
	search.process()
	twitHarvest = search.get_people()
	print "[-] Harvesting Yahoo (4/%s)" % harvesterDomains
	search = yahoosearch.search_yahoo(domain,harvestLimit)
	search.process()
	yahooHarvest = search.get_emails()
	print "[-] Harvesting Bing (5/%s)" % harvesterDomains
	search = bingsearch.search_bing(domain,harvestLimit,harvestStart)
	search.process('no')
	bingHarvest = search.get_emails()
	print "[-] Harvesting Jigsaw (6/%s)" % harvesterDomains
	search = jigsaw.search_jigsaw(domain,harvestLimit)
	search.process()
	jigsawHarvest = search.get_people()

	# Combine lists and strip out duplicate findings for unique lists
	totalEmails = googleHarvest + bingHarvest + yahooHarvest
	temp = []
	for email in totalEmails:
		email = email.lower()
		temp.append(email)
	unique = set(temp)
	uniqueEmails = list(unique)
	# Do the same with people, but keep Twitter handles separate
	totalPeople = linkHarvest + jigsawHarvest
	unique = set(totalPeople)
	uniquePeople = list(unique)
	# Process Twitter handles to kill duplicates
	handles = []
	for twit in twitHarvest:
		# Split handle from account description and strip rogue periods
		handle = twit.split(' ')[0]
		handle = handle.rstrip('.')
		handles.append(handle.lower())
	unique = set(handles)
	uniqueTwitter = list(unique)

	print green("[+] Harvester found a total of %s emails and %s names across all engines" % (len(uniqueEmails),len(uniquePeople) + len(uniqueTwitter)))
	print green("[+] Running emails through HaveIBeenPwned and writing report (2/%s)" % total)
	with open(file, 'w') as report:
		report.write("### Email & People Report for %s ###\n\n" % domain)
		report.write("---THEHARVESTER Results---\n")
		report.write("Emails checked with HaveIBeenPwned for breaches and pastes:\n\n")
		for email in uniqueEmails:
			# Make sure we drop that @domain.com result Harvester always includes
			if email == '@' + domain:
				pass
			else:
				# Check haveibeenpwned data breaches
				try:
					pwned = pwnedcheck.check(email)
				except:
					print red("[!] Could not parse JSON. Moving on...")
				# If no results for breaches we return None
				if not pwned:
					report.write("%s\n" % email)
					pass
				else:
					report.write("%s (Pwned:" % email)
					for pwn in pwned:
						report.write(' + ' + pwn)
					report.write(")\n")
				# Check haveibeenpwned for pastes from Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, and AdHocUrl
				url = "https://haveibeenpwned.com/api/v2/pasteaccount/" + email
				page = urllib2.Request(url, None, headers)
				# We must use Try because an empty result is like a 404 and causes an error
				try:
					source = urllib2.urlopen(page).read()
					report.write("Pastes: " + source + "\n")
				except:
					pass

		report.write("\n---PEOPLE Results---\n")
		report.write("Names and social media accounts (Twitter and LinkedIn):\n\n")
		for person in uniquePeople:
			report.write("%s\n" % person)
		report.write("\nTwitter handles potentially related to %s:\n\n" % client)
		for twit in uniqueTwitter:
			# Drop the lonely @ Harvester often includes and common false positives
			if twit == '@' or twit == '@-moz-keyframes' or twit == '@keyframes' or twit == '@media':
				pass
			else:
				report.write("%s\n" % twit)

	report.close()
