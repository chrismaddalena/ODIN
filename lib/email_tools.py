#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import requests
import tweepy
from colors import *
from lib.theharvester import *
import time
from bs4 import BeautifulSoup as BS

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

# Try to get the user's Full Contact API key
try:
	contact_key_file = open('auth/fullcontactkey.txt', 'r')
	contact_key_line = contact_key_file.readlines()
	CONTACT_API_KEY = contact_key_line[1].rstrip()
	contact_key_file.close()
except:
	CONTACT_API_KEY = None

# Headers for use with requests
user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
headers = { 'User-Agent' : user_agent }


def pwnCheck(email):
	"""Use HIBP's API to check for the target's email in security breaches
	"""
	PWNED_API_URL = "https://haveibeenpwned.com/api/breachedaccount/{}".format(email)
	try:
		r = requests.get(PWNED_API_URL)
		return r.json()
	except:
		return []


def pasteCheck(email):
	"""Use HIBP's API to check for the target's email in pastes across multiple
	paste websites, e.g. slexy, ghostbin, pastebin
	"""
	PASTE_API_URL = "https://haveibeenpwned.com/api/v2/pasteaccount/{}".format(email)
	try:
		r = requests.get(PASTE_API_URL)
		return r.text
	except:
		return []


def fullContactEmail(email):
	"""Use the Full Contact API to collect social information for the target
	"""
	if CONTACT_API_KEY is None:
		print(red("[!] No Full Contact API key, so skipping these searches."))
	else:
		base_url = 'https://api.fullcontact.com/v2/person.json'
		payload = {'email':email, 'apiKey':CONTACT_API_KEY}
		resp = requests.get(base_url, params=payload)
		if resp.status_code == 200:
			return resp.json()


def harvest(client, domain):
	"""Use TheHarvester to discover email addresses and employee names and
	pull-in information from HIBP and Twitter
	"""

	print(green("""Viper will now attempt to find email addresses and potentially vulnerable accounts. TheHarvester will be used to find email addresses, names, and social media accounts. Emails will be checked against the HaveIBeenPwned database. (Thanks, Troy Hunt!) This may take a few minutes.
	"""))

	harvestLimit = 100
	harvestStart = 0
	f = "reports/{}/People_Report.txt".format(client)

	print(green("[+] Running The Harvester"))
	# Search trhough most of Harvester's supported engines
	# No Baidu because it always seems to hang or take way too long
	print(green("[-] Harvesting Google"))
	search = googlesearch.search_google(domain,harvestLimit,harvestStart)
	search.process()
	googleHarvest = search.get_emails()
	print(green("[-] Harvesting LinkedIn"))
	search = linkedinsearch.search_linkedin(domain,harvestLimit)
	search.process()
	linkHarvest = search.get_people()
	print(green("[-] Harvesting Twitter"))
	search = twittersearch.search_twitter(domain,harvestLimit)
	search.process()
	twitHarvest = search.get_people()
	print(green("[-] Harvesting Yahoo"))
	search = yahoosearch.search_yahoo(domain,harvestLimit)
	search.process()
	yahooHarvest = search.get_emails()
	print(green("[-] Harvesting Bing"))
	search = bingsearch.search_bing(domain,harvestLimit,harvestStart)
	search.process('no')
	bingHarvest = search.get_emails()
	print(green("[-] Harvesting Jigsaw"))
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
	with open(f, 'w') as report:
		report.write("### Email & People Report for {} ###\n\n".format(domain))
		report.write("---THEHARVESTER Results---\n")
		report.write("Emails checked with HaveIBeenPwned for breaches and pastes:\n\n")
		for email in uniqueEmails:
			# Make sure we drop that @domain.com result Harvester always includes
			if email == '@' + domain:
				pass
			else:
				# Check haveibeenpwned data breaches
				# We must use Try because an empty result is like a 404 and causes an error
				try:
					pwned = pwnCheck(email)
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
				except Exception as e:
					print(red("[!] Error involving {}!").format(email))
					print(red("[!] Error: {}".format(e)))
				# Check haveibeenpwned for pastes from Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, and AdHocUrl
				try:
					pastes = pasteCheck(email)
					if pastes:
						report.write("Pastes: {}\n".format(pastes))
				except Exception as e:
					print(red("[!] Error involving {}!").format(email))
					print(red("[!] Error: {}".format(e)))
				time.sleep(3)

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
						links = getLinked(user.name, client)
						report.write("Related LinkedIn Links:\n")
						for link in links:
							report.write("{}\n".format(link))
						report.write("\n")
						uniquePeople.remove(user.name)
				except:
					print(red("[!] Error involving {}. This may not be a real user or there may be an issue with one of the user objects.".format(twit)))
		for person in uniquePeople:
			report.write("{}\n".format(person))
			links = getLinked(person, client)
			report.write("Related LinkedIn Links:\n")
			for link in links:
				report.write("{}\n".format(link))
			report.write("\n")


def getLinked(target, company):
	"""Construct a Bing search URL and scrape for LinkedIn profile links related to the target's name.
	"""
	url = 'http://www.bing.com/search?q=site:linkedin.com ' + '"' + target + '"' + ' ' + '"' + company + '"'
	html = requests.get(url)
	soup = BS(html.text, "html.parser")
	result = soup.findAll('li', {'class': 'b_algo'})
	name = target.split(" ")
	refs = []
	for i in result:
		link = i.a['href']  # Get Hrefs from bing's source
		if '/dir/' in link or '/title/' in link or 'groupItem' in link or not 'linkedin.com' in link:
			continue
		else:
			if name[0].lower() in link or name[1].lower() in link:
				refs.append(link)
	nodupLinks = set(refs)  # try and remove duplicates
	return nodupLinks
