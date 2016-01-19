#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import pwnedcheck
import sys

sys.path.append('lib/theharvester/')
from theHarvester import *

# Number of commands
total = 5
harvesterDomains = 6

def harvest(client,domain):
	print """
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
	totalPeople = linkHarvest + twitHarvest + jigsawHarvest
	unique = set(totalPeople)
	uniquePeople = list(unique)
	print "[+] Harvester found a total of %s emails and %s names across all engines" % (len(uniqueEmails),len(uniquePeople))

	print "[+] Running emails through haveibeenpwned and writing report (2/%s)" % total
	file = "reports/%s/Email_Report.txt" % client
	with open(file, 'w') as report:
		report.write("### Email Report for %s ###\n" % domain)
		for email in uniqueEmails:
			report.write('\n' + 'Email: ' + email + '\n')
			report.write('Pwned: ')
			pwned = pwnedcheck.check(email)
			if not pwned:
				report.write('None' + '\n')
			else:
				for pwn in pwned:
					report.write(pwn)
	report.close()

	#print pwnedcheck.check("chris.maddalena@gmail.com")
	# No longer necessary
	#with open('harvest.txt') as harvest:
		# Skip to the emails
	#	for line in harvest:
	#		if line.strip() == "[+] Emails found:":
	#			break
	#	for line in harvest:
	#		if line.strip() == '[+] Hosts found in search engines:':
	#			break
	#		print line
