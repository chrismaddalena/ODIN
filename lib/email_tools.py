#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import requests
import tweepy
from colors import *
from lib.theharvester import *
import time
from bs4 import BeautifulSoup

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

# Headers for use with requests
user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
headers = { 'User-Agent' : user_agent }

class InvalidEmail(Exception):
	pass

def pwnCheck(email):
	PWNED_API_URL = "https://haveibeenpwned.com/api/breachedaccount/%s"
	try:
		r = requests.get(PWNED_API_URL % email)
		return r.json
	except HTTPError as e:
		if e.code == 400:
			raise InvalidEmail("Email address does not appear to be a valid email")
		return []

def harvest(client,domain):
	print(green("""
Viper will now attempt to find email addresses and potentially vulnerable accounts. TheHarvester will be used to find email addresses, names, and social media accounts. Emails will be checked against the HaveIBeenPwned database. (Thanks, Troy Hunt!) This may take a few minutes.
	"""))

	client = client
	domain = domain
	harvestLimit = 100
	harvestStart = 0

	file = "reports/{}/Email_Report.txt".format(client)

	print(green("[+] Running The Harvester"))
	# Search trhough most of Harvester's supported engines
	# No Baidu because it always seems to hang or take way too long
	print("[-] Harvesting Google")
	search = googlesearch.search_google(domain,harvestLimit,harvestStart)
	search.process()
	googleHarvest = search.get_emails()
	print("[-] Harvesting LinkedIn")
	search = linkedinsearch.search_linkedin(domain,harvestLimit)
	search.process()
	linkHarvest = search.get_people()
	print("[-] Harvesting Twitter")
	search = twittersearch.search_twitter(domain,harvestLimit)
	search.process()
	twitHarvest = search.get_people()
	print("[-] Harvesting Yahoo")
	search = yahoosearch.search_yahoo(domain,harvestLimit)
	search.process()
	yahooHarvest = search.get_emails()
	print("[-] Harvesting Bing")
	search = bingsearch.search_bing(domain,harvestLimit,harvestStart)
	search.process('no')
	bingHarvest = search.get_emails()
	print("[-] Harvesting Jigsaw")
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

	print(green("[+] Harvester found a total of {} emails and {} names across all engines".format(len(uniqueEmails),len(uniquePeople) + len(uniqueTwitter))))
	print(green("[+] Running emails through HaveIBeenPwned and writing report"))
	with open(file, 'w') as report:
		report.write("### Email & People Report for {} ###\n\n".format(domain))
		report.write("---THEHARVESTER Results---\n")
		report.write("Emails checked with HaveIBeenPwned for breaches and pastes:\n\n")
		for email in uniqueEmails:
			# Make sure we drop that @domain.com result Harvester always includes
			if email == '@' + domain:
				pass
			else:
				# Check haveibeenpwned data breaches
				try:
					pwned = pwnCheck(email)
				except:
					print(red("[!] Could not parse JSON. Moving on..."))
				# If no results for breaches we return None
				if not pwned:
					report.write("{}\n".format(email))
					pass
				else:
					report.write("{} (Pwned:".format(email))
					pwns = []
					for pwn in pwned:
						pwns.append(pwn)
					report.write(', '.join(pwns))
					report.write(")\n")
				# Check haveibeenpwned for pastes from Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, and AdHocUrl
				url = "https://haveibeenpwned.com/api/v2/pasteaccount/{}".format(email)
				page = requests.get(url, headers=headers)
				# We must use Try because an empty result is like a 404 and causes an error
				try:
					source = page.text
					report.write("Pastes: {}\n".format(source))
				except:
					pass
				time.sleep(2)

		report.write("\n---PEOPLE Results---\n")
		report.write("Names and social media accounts (Twitter and LinkedIn):\n\n")
		if twitAPI is None:
			print(red("[!] Twitter API is not setup, so collecting just handles!"))
		for twit in uniqueTwitter:
			# Drop the lonely @ Harvester often includes and common false positives
			if twit == '@' or twit == '@-moz-keyframes' or twit == '@keyframes' or twit == '@media':
				pass
			elif twitAPI is None:
				report.write("{}\n".format(twit))
			else:
				try:
					user = twitAPI.get_user(twit.strip('@'))
					report.write("Real Name: {}\n".format(user.name))
					report.write("Twitter Handle: {}\n".format(user.screen_name))
					report.write("Location: {}\n".format(user.location))
					report.write("Followers: {}\n".format(user.followers_count))
					try:
						report.write("User Description: {}\n\n".format(user.description.encode('utf8')))
					except Exception as e:
						print(red("[!] There was an issue with the description for {}!".format(twit)))
						print(red("Error: {}".format(e)))
					# Check if the Twitter user's "real" name appears in our list of unique people
					# If it does, remove them from the list (for later) and create link for their LinkedIn profile
					if user.name in uniquePeople:
						url = 'http://www.bing.com/search?q=site:linkedin.com ' + '"' + user.name + '"' + ' ' + '"' + client + '"'
						url = url.replace(' ','%20')
						report.write("LinkedIn Profile: {}\n\n".format(url))
						uniquePeople.remove(user.name)
				except:
					print(red("[!] Error involving {}. This may not be a real user or there may be an issue with one of the user objects.".format(twit)))
		for person in uniquePeople:
			report.write("{}\n".format(person))
			# We use Bing because you'll get a nice profile snapshot in the results without logging-in
			url = 'http://www.bing.com/search?q=site:linkedin.com ' + '"' + person + '"' + ' ' + '"' + client + '"'
			url = url.replace(' ','%20')
			report.write("LinkedIn: {}\n\n".format(url))
