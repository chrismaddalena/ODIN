#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import pwnedcheck
import sys
import urllib2

sys.path.append('lib/theharvester/')
from theHarvester import *

# Number of commands
total = 2 # Tests
harvesterDomains = 6 # Search engines used with theHarvester
# Headers for use with urllib2
user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
headers = { 'User-Agent' : user_agent }

def harvest(client,domain):
	print """Viper will now attempt to find email addresses and potentially vulnerable accounts. TheHarvester will be used to find email addresses, names, and social media accounts. Emails will be checked against the HaveIBeenPwned database. This may take a few minutes.
	"""

	client = client
	domain = domain
	harvestLimit = 100
	harvestStart = 0

	# Create drectory for client reports
	if not os.path.exists("reports/%s" % client):
		try:
			os.mkdir("reports/%s" % client)
		except:
			print "[!] Could not create reports directory!"
	print "[+] Running The Harvester (1/%s)" % total
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
	unique = set(totalEmails)
	uniqueEmails = list(unique)
	# Do the same with people, but keep Twitter handles separate
	totalPeople = linkHarvest + jigsawHarvest
	unique = set(totalPeople)
	uniquePeople = list(unique)
	unique = set(twitHarvest)
	uniqueTwitter = list(unique)

	print "[+] Harvester found a total of %s emails and %s names across all engines" % (len(uniqueEmails),len(uniquePeople) + len(uniqueTwitter))
	uniqueEmails.append("foo@bar.com")
	print "[+] Running emails through haveibeenpwned and writing report (2/%s)" % total
	file = "reports/%s/Email_Report.txt" % client
	with open(file, 'w') as report:
		report.write("### Email & People Report for %s ###\n" % domain)
		report.write("---TheHarvester Results---\n")
		report.write("Emails checked with HaveIBeenPwned for breaches and pastes\n")
		for email in uniqueEmails:
			# Make sure we drop that @domain.com result Harvester always includes
			if email == '@' + domain:
				pass
			else:
				report.write('\n' + 'Email: ' + email + '\n')
				report.write('Pwned: ')
				# Check haveibeenpwned data breaches
				pwned = pwnedcheck.check(email)
				# If no results for breaches we return None
				if not pwned:
					report.write('None' + '\n')
				else:
					report.write('\n')
					for pwn in pwned:
						report.write('+ ' + pwn + '\n')
				# Check haveibeenpwned for pastes from Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, and AdHocUrl
				url = "https://haveibeenpwned.com/api/v2/pasteaccount/" + email
				page = urllib2.Request(url, None, headers)
				# We must use Try because an empty result is like a 404 and causes an error
				try:
					source = urllib2.urlopen(page).read()
					report.write("Pastes: " + source + "\n")
				except:
					report.write("Pastes: No pastes\n")
		report.write("\n---People Results---\n")
		report.write("Names and social media accounts (Twitter and LinkedIn)\n\n")
		for person in uniquePeople:
			report.write(person + '\n')
		for twit in uniqueTwitter:
			# Drop the lonely @ Harvester often includes
			if twit == '@':
				pass
			else:
				report.write(twit + '\n')

	report.close()
