#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import pwnedcheck
import sys
import urllib2
import tweepy
from colors import *

sys.path.append('lib/theharvester/')
from theHarvester import *

# Try to setup Twitter OAuth
try:
	twitter_key_file = open('auth/twitter.txt', 'r')
	twitter_key_line = twitter_key_file.readlines()
	consumer_key = twitter_key_line[1].rstrip()
	consumer_secret = twitter_key_line[2].rstrip()
	access_token = twitter_key_line[3].rstrip()
	access_token_secret = twitter_key_line[4].rstrip()
	twitAuth = tweepy.OAuthHandler(consumer_key, consumer_secret)
	twitAuth.set_access_token(access_token, access_token_secret)
	twitAPI = tweepy.API(twitAuth)
	twitter_key_file.close()
except:
	twitAPI = None

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
					pwns = []
					for pwn in pwned:
						pwns.append(pwn)
					report.write(', '.join(pwns))
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
		if twitAPI is None:
			print red("[!] Twitter API is not setup, so collecting just handles!")
		for twit in uniqueTwitter:
			# Drop the lonely @ Harvester often includes and common false positives
			if twit == '@' or twit == '@-moz-keyframes' or twit == '@keyframes' or twit == '@media':
				pass
			elif twitAPI is None:
				report.write("%s\n" % twit)
			else:
				try:
					user = twitAPI.get_user(twit.strip('@'))
					report.write("Real Name: %s\n" % user.name)
					report.write("Twitter Handle: %s\n" % user.screen_name)
					report.write("Location: %s\n" % user.location)
					report.write("Followers: %s\n" % user.followers_count)
					try:
						report.write("User Description: %s\n" % user.description.encode('utf8'))
					except Exception as e:
						print red("[!] There was an issue with the description for %s!" % twit)
						print red("Error: %s" % e)
					# Check if the Twitter user's "real" name appears in our list of unique people
					# If it does, remove them from the list (for later) and create link for their LinkedIn profile
					if user.name in uniquePeople:
						url = 'http://www.bing.com/search?q=site:linkedin.com ' + '"' + user.name + '"' + ' ' + '"' + client + '"'
						url = url.replace(' ','%20')
						report.write("LinkedIn Profile: %s\n\n" % url)
						uniquePeople.remove(user.name)
				except:
					print red("[!] Error involving %s. This may not be a real user or there may be an issue with one of the user objects." % twit)
		for person in uniquePeople:
			report.write("%s\n" % person)
			# We use Bing because you'll get a nice profile snapshot in the results without logging-in
			url = 'http://www.bing.com/search?q=site:linkedin.com ' + '"' + person + '"' + ' ' + '"' + client + '"'
			url = url.replace(' ','%20')
			report.write("LinkedIn: %s\n\n" % url)
