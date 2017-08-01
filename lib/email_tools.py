#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used
for seeking out individuals and collecting data, such as
email addresses and social media account data.
"""

import requests
import tweepy
from colors import red, green, yellow
from bs4 import BeautifulSoup as BS
from lib.theharvester import googlesearch, linkedinsearch, \
twittersearch, yahoosearch, bingsearch, jigsaw
from lib import helpers


class PeopleCheck(object):
    """A class containing the tools for performing OSINT for people."""

    # Headers for use with Requests
    user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
    headers = {'User-Agent' : user_agent}

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect the API keys from the config file
        try:
            consumer_key = helpers.config_section_map("Twitter")["consumer_key"]
            consumer_key_secret = helpers.config_section_map("Twitter")["key_secret"]
            access_token = helpers.config_section_map("Twitter")["access_token"]
            access_token_secret = helpers.config_section_map("Twitter")["token_secret"]
            twit_auth = tweepy.OAuthHandler(consumer_key, consumer_key_secret)
            twit_auth.set_access_token(access_token, access_token_secret)
            self.twit_api = tweepy.API(twit_auth)
        except:
            self.twit_api = None
            print(yellow("[!] Could not setup OAuth for Twitter API."))

        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except:
            print(yellow("[!] Could not fetch Full Contact API key."))

    def pwn_check(self, email):
        """Use HIBP's API to check for the target's email in public security breaches."""
        pwned_api_endpoint = "https://haveibeenpwned.com/api/breachedaccount/{}".format(email)
        try:
            request = requests.get(pwned_api_endpoint)
            return request.json()
        except requests.exceptions.RequestException as error:
            print(red("[!] Error with HIBP request: {}".format(error)))
            return []
        except ValueError:
            # This is likely an "all clear" -- no hits in HIBP
            return []

    def paste_check(self, email):
        """Use HIBP's API to check for the target's email in pastes across multiple
        paste websites, e.g. slexy, ghostbin, pastebin
        """
        paste_api_endpoint = "https://haveibeenpwned.com/api/v2/pasteaccount/{}".format(email)
        try:
            request = requests.get(paste_api_endpoint)
            return request.text
        except requests.exceptions.RequestException as error:
            print(red("[!] Error with HIBP request: {}".format(error)))
            return []
        except ValueError:
            # This is likely an "all clear" -- no hits in HIBP
            return []

    def full_contact_email(self, email):
        """Use the Full Contact API to collect social information for the target."""
        if self.contact_api_key is None:
            print(red("[!] No Full Contact API key, so skipping these searches."))
        else:
            base_url = 'https://api.fullcontact.com/v2/person.json'
            payload = {'email':email, 'apiKey':self.contact_api_key}
            resp = requests.get(base_url, params=payload)
            if resp.status_code == 200:
                return resp.json()

    def harvest_all(self, domain):
        """Use TheHarvester to discover email addresses and employee names."""
        # Set the search configuration for TheHarvester
        harvest_limit = 100
        harvest_start = 0

        print(green("[+] Running The Harvester"))
        # Search through most of Harvester's supported engines
        # No Baidu because it always seems to hang or take way too long
        print(green("[-] Harvesting Google"))
        search = googlesearch.search_google(domain, harvest_limit, harvest_start)
        search.process()
        google_harvest = search.get_emails()

        print(green("[-] Harvesting LinkedIn"))
        search = linkedinsearch.search_linkedin(domain, harvest_limit)
        search.process()
        link_harvest = search.get_people()

        print(green("[-] Harvesting Twitter"))
        search = twittersearch.search_twitter(domain, harvest_limit)
        search.process()
        twit_harvest = search.get_people()

        print(green("[-] Harvesting Yahoo"))
        search = yahoosearch.search_yahoo(domain, harvest_limit)
        search.process()
        yahoo_harvest = search.get_emails()

        print(green("[-] Harvesting Bing"))
        search = bingsearch.search_bing(domain, harvest_limit, harvest_start)
        search.process('no')
        bing_harvest = search.get_emails()

        print(green("[-] Harvesting Jigsaw"))
        search = jigsaw.search_jigsaw(domain, harvest_limit)
        search.process()
        jigsaw_harvest = search.get_people()

        # Combine lists and strip out duplicate findings for unique lists
        total_emails = google_harvest + bing_harvest + yahoo_harvest
        temp = []
        for email in total_emails:
            email = email.lower()
            temp.append(email)
        unique = set(temp)
        unique_emails = list(unique)

        # Do the same with people, but keep Twitter handles separate
        total_people = link_harvest + jigsaw_harvest
        unique = set(total_people)
        unique_people = list(unique)

        # Process Twitter handles to kill duplicates
        handles = []
        for twit in twit_harvest:
            # Split handle from account description and strip rogue periods
            handle = twit.split(' ')[0]
            handle = handle.rstrip('.')
            handles.append(handle.lower())
        unique = set(handles)
        unique_twitter = list(unique)

        print(green("[+] Harvester found a total of {} emails and {} \
names across all engines".format(len(unique_emails), len(unique_people) + len(unique_twitter))))

        # Return the results for emails, people, and Twitter accounts
        return unique_emails, unique_people, unique_twitter

    def harvest_twitter(self, handle):
        """Function to lookup the provided handle on Twitter using Tweepy."""
        if self.twit_api is None:
            print(yellow("[*] Twitter API access is not setup, \
so skipping Twitter handle lookups."))
        else:
            # Drop the lonely @ Harvester often includes and common false positives
            if handle == '@' or handle == '@-moz-keyframes' or \
                handle == '@keyframes' or handle == '@media':
                print(yellow("[*] Skipping dead end Twitter handle, {}".format(handle)))
            else:
                try:
                    print(green("[+] Looking up {} on Twitter".format(handle)))
                    user_data = {}
                    user = self.twit_api.get_user(handle.strip('@'))
                    user_data['real_name'] = user.name
                    user_data['handle'] = user.screen_name
                    user_data['location'] = user.location
                    user_data['followers'] = user.followers_count
                    user_data['user_description'] = user.description

                    return user_data
                except Exception as error:
                    print(red("[!] Error involving {} -- could be an invalid \
account.".format(handle)))
                    print(red("L.. Details: {}".format(error)))

    def harvest_linkedin(self, target, company):
        """Construct a Bing search URL and scrape for LinkedIn profile links related
        to the target's name and company.
        """
        print(green("[+] Looking for potential LinkedIn profiles \
for {} at {}".format(target, company)))
        url = 'http://www.bing.com/search?q=site:linkedin.com%20"{}"%20"{}"'.format(target, company)
        html = requests.get(url)
        soup = BS(html.text, "html.parser")
        result = soup.findAll('li', {'class': 'b_algo'})
        name = target.split(" ")
        refs = []
        for i in result:
            # Get href links from Bing's source
            link = i.a['href']
            if '/dir/' in link or '/title/' in link or 'groupItem' in link or \
                not 'linkedin.com' in link:
                continue
            else:
                if name[0].lower() in link or name[1].lower() in link:
                    refs.append(link)
                    # Take just the first result to avoid large, unmanageable lists
                    break
        # Remove duplicate results
        no_dups = set(refs)

        return no_dups
