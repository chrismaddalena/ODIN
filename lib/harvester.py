#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of classes and functions used for using search engines to find email
addresses and social media profiles for a target organization and domain.

While much of the original code has been removed, rearranged, or modified, this code was
seeded using functions pulled from Christian Martorella's TheHarvester tool.

The original code can be found here:

https://github.com/laramies/theHarvester
"""

from time import sleep

import click
import tweepy
import requests
from bs4 import BeautifulSoup as BS

from . import searchparser, helpers


class SearchTwitter:
    """Class for searching Google using 'site:twitter.com intitle:{keyword}' to find Twitter profiles."""

    def __init__(self, word, limit):
        """Everything that should be initiated with a new object goes here."""
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100116 Firefox/3.7"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        """Execute a Google search for site:twitter.com intitle:on+Twitter keyword."""
        try:
            urly = "https://"+ self.server + "/search?num=100&start=" + str(self.counter) + "&hl=en&meta=&q=site%3Atwitter.com%20intitle%3A%22on+Twitter%22%20" + self.word
        except Exception as error:
            print(error)
        headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:34.0) Gecko/20100101 Firefox/34.0'}
        try:
            req = requests.get(urly, headers=headers)
            self.results = req.content
            self.totalresults += str(self.results)
        except Exception as error:
            pass

    def get_people(self):
        """Parse the Google search results to get Twitter handles."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_twitter()

    def process(self):
        """Process the Google search results page by page up to the limit."""
        while (self.counter < self.limit):
            self.do_search()
            self.counter += 100


class SearchYahoo:
    """Class for searching Yahoo using a domain as the keyword to collect email addresses."""

    def __init__(self, word, limit):
        """Everything that should be initiated with a new object goes here."""
        self.word = word
        self.totalresults = ""
        self.server = "search.yahoo.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        """Execute a Yahoo search for the given domain to find email addresses."""
        headers = { 'User-Agent' : self.userAgent }
        try:
            urly = "http://" + self.server + "/search?p=\"%40" + self.word + "\"&b=" + str(self.counter) + "&pz=10"
        except Exception as error:
            print(error)
        try:
            req = requests.get(urly, headers=headers)
            self.results = req.content
            self.totalresults += str(self.results)
        except Exception as error:
            pass

    def process(self):
        """Process the Yahoo search results page by page up to the limit."""
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            sleep(1)
            self.counter += 10

    def get_emails(self):
        """Parse the Yahoo search results to get the email addresses."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_emails()


class SearchGoogle:
    """Class for searching Google using a domain as the keyword to collect email addresses."""

    def __init__(self, word, limit, start):
        """Everything that should be initiated with a new object goes here."""
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = limit
        self.counter = start

    def do_search(self):
        """Execute a Google search for the given domain to find email addresses."""
        headers = { 'User-Agent' : self.userAgent }
        try:
            urly = "http://" + self.server + "/search?num=" + self.quantity + "&start=" + str(self.counter) + "&hl=en&meta=&q=%40\"" + self.word + "\""
        except Exception as error:
            print(error)
        try:
            req = requests.get(urly, headers=headers)
            self.results = req.content
            self.totalresults += str(self.results)
        except Exception as error:
            pass

    def get_emails(self):
        """Parse Google search results to get email addresses."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_emails()

    def process(self):
        """Process the search results page by page up to the limit."""
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            sleep(1)
            self.counter += 100


class SearchBing:
    """Class for searching Bing using a domain as the keyword to collect email addresses."""

    def __init__(self, word, limit, start):
        """Everything that should be initiated with a new object goes here."""
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.bing.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "50"
        self.limit = int(limit)
        self.counter = start

    def do_search(self):
        """Execute a Bing search for the given domain to find email addresses."""
        headers = { 'User-Agent' : self.userAgent }
        try:
            urly = "http://" + self.server + "/search?q=%40" + self.word + "&count=50&first=" + str(self.counter)
        except Exception as error:
            print(error)
        try:
            req = requests.get(urly, headers=headers)
            self.results = req.content
            self.totalresults += str(self.results)
        except Exception as error:
            pass

    def get_emails(self):
        """Parse Bing search results to get email addresses."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_emails()

    def process(self):
        """Process the Bing search results page by page up to the limit."""
        while (self.counter < self.limit):
            self.do_search()
            sleep(1)
            self.counter += 50


class SearchEmailHunter:
    """Class for searching Email Hunter for email addresses tied to a domain."""
    emailhunter_api_url = "https://api.hunter.io/v2/domain-search?domain={}&api_key={}"

    def __init__(self, domain):
        """Everything that should be initiated with a new object goes here."""
        self.domain = domain
        try:
            self.emailhunter_api_key = helpers.config_section_map("EmailHunter")["api_key"]
        except Exception:
            self.emailhunter_api_key = ""
            click.secho("[!] Could not fetch EmailHunter API key.", fg="yellow")

    def do_search(self):
        """"Collect known email addresses for a domain and other information, such as names and job
        titles, using EmailHunter's API.

        A free EmailHunter API key is required.
        """
        results = None
        if self.emailhunter_api_key:
            request = requests.get(self.emailhunter_api_url.format(self.domain, self.emailhunter_api_key))
            results = request.json()
            if "errors" in results:
                click.secho("[!] The request to EmailHunter returned an error!", fg="red")
                click.secho("L.. Details: {}".format(results['errors']), fg="red")
                return None
            click.secho("\n[+] Hunter has contact data for {} people."
                            .format(len(results['data']['emails'])), fg="green")
        return results


class SearchLinkedIn:
    """Class to scrape LinkedIn profiles from Bing search results."""
    bing_search_query = 'http://www.bing.com/search?q=site:linkedin.com/in%20"{}"&count=50&first={}'

    def __init__(self, company, limit=100):
        """Everything that should be initiated with a new object goes here."""
        self.company = company
        self.limit = limit

    def do_search(self):
        """Construct a Bing search URL and scrape LinkedIn profile information related to the
        given company name.
        """
        profiles = {}
        counter = 0
        self.company = self.company.replace(" ", "%20")
        while (counter < self.limit):
            try:
                url = self.bing_search_query.format(self.company, counter)
                # self.browser.get(url)
                # soup = BS(self.browser.page_source, "html.parser")
                req = requests.get(url)
                soup = BS(req.text, "html.parser")
                results = soup.findAll('li', {'class': 'b_algo'})
                for hit in results:
                    # Get href links from Bing's source
                    link = hit.a['href']
                    link_text = hit.a.getText().strip(" ...")
                    name = link_text.split(" - ")[0].strip("| LinkedIn")
                    try:
                        job_title = link_text.split(" - ")[1]
                    except:
                        job_title = ""
                    if '/dir/' in link or '/title/' in link or 'groupItem' in link or not 'linkedin.com' in link:
                        continue
                    else:
                        profiles[name] = {'job_title': job_title, 'linkedin_profile': link}
            except requests.exceptions.RequestException:
                pass
            sleep(1)
            counter += 50
        return profiles


class Harvester:
    """Class to run all harvest modules and process the results."""

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        try:
            consumer_key = helpers.config_section_map("Twitter")["consumer_key"]
            consumer_key_secret = helpers.config_section_map("Twitter")["key_secret"]
            access_token = helpers.config_section_map("Twitter")["access_token"]
            access_token_secret = helpers.config_section_map("Twitter")["token_secret"]
            twit_auth = tweepy.OAuthHandler(consumer_key, consumer_key_secret)
            twit_auth.set_access_token(access_token, access_token_secret)
            # Setup Tweepy with a timeout value, the default is 60 seconds
            self.twit_api = tweepy.API(twit_auth, timeout=10)
        except Exception:
            self.twit_api = None
            click.secho("[!] Could not setup OAuth for Twitter API.", fg="yellow")

    def harvest_all(self, domain):
        """Discover email addresses and employee names using search engines like Google, Yahoo,
        and Bing.
        """
        # Set the search configuration for harvesting email addresses and social media profiles
        harvest_limit = 100
        harvest_start = 0
        # click.secho("[+] Beginning the harvesting of email addresses for {}...".format(domain), fg="green")
        # Google search
        search = SearchGoogle(domain, harvest_limit, harvest_start)
        search.process()
        google_harvest = search.get_emails()
        # Yahoo search
        search = SearchYahoo(domain, harvest_limit)
        search.process()
        yahoo_harvest = search.get_emails()
        # Bing search
        search = SearchBing(domain, harvest_limit, harvest_start)
        search.process()
        bing_harvest = search.get_emails()
        # Twitter search
        search = SearchTwitter(domain, harvest_limit)
        search.process()
        twit_harvest = search.get_people()
        # Combine lists and strip out duplicate findings for unique lists
        all_emails = google_harvest + bing_harvest + yahoo_harvest
        # click.secho("[+] The search engines returned {} emails and {} Twitter handles for {}."
        #              .format(len(all_emails), len(twit_harvest), domain), fg="green")
        # Return the results for emails, people, and Twitter accounts
        return all_emails, twit_harvest

    def process_harvested_lists(self, harvester_emails, harvester_twitter, hunter_json):
        """Take data harvested from EmailHunter and search engines, combine the data, make unique
        lists, and return the total results.
        """
        temp_emails = []
        twitter_handles = []
        harvester_people = []
        job_titles = {}
        linkedin = {}
        phone_nums = {}
        # Convert all emails from search engines to lowercase for de-duping
        for email in harvester_emails:
            email = email.lower()
            # Drop the occasional bad email address that is found, like 'n@gmail.com'
            # Also check for any truncated emails with ".."
            if len(email.split("@")[0]) > 1 and ".." not in email:
                temp_emails.append(email)
        # Process emails and people found by Hunter.io
        if hunter_json:
            for result in hunter_json['data']['emails']:
                email = result['value'].lower()
                temp_emails.append(email)

                if "first_name" in result and "last_name" in result:
                    if result['first_name'] is not None and result['last_name'] is not None:
                        person = result['first_name'] + " " + result['last_name']
                        harvester_people.append(person)
                        if "position" in result:
                            if result['position'] is not None:
                                job_titles[person] = result['position']
                        if "linkedin" in result:
                            if result['linkedin'] is not None:
                                linkedin[person] = result['linkedin']
                        if "phone_number" in result:
                            if result['phone_number'] is not None:
                                phone_nums[person] = result['phone_number']
                if "twitter" in email:
                    if result['twitter'] is not None:
                        harvester_twitter.append(result['twitter'])

        # Remove any duplicate results
        unique = set(temp_emails)
        unique_emails = list(unique)
        unique = set(harvester_people)
        unique_people = list(unique)

        for twit in harvester_twitter:
            # Split handle from account description and strip rogue periods
            handle = twit.split(' ')[0]
            handle = handle.rstrip('.')
            twitter_handles.append(handle.lower())
        unique = set(twitter_handles)
        unique_twitter = list(unique)

        click.secho("[+] Final unique findings: {} emails, {} people, {} Twitter handles."
                     .format(len(unique_emails), len(unique_people), len(unique_twitter)), fg="green")
        return unique_emails, unique_people, unique_twitter, job_titles, linkedin, phone_nums

    def harvest_twitter(self, handle):
        """Check the provided Twitter handle using Tweepy and the Twitter API."""
        if self.twit_api is None:
            click.secho("[*] Twitter API access is not setup, so skipping Twitter handle \
lookups.", fg="yellow")
        else:
            try:
                # click.secho("[+] Looking up {} on Twitter".format(handle), fg="green")
                user_data = {}
                user = self.twit_api.get_user(handle.strip('@'))
                user_data['real_name'] = user.name
                user_data['handle'] = user.screen_name
                user_data['location'] = user.location
                user_data['followers'] = user.followers_count
                user_data['user_description'] = user.description
                return user_data
            except Exception as error:
                click.secho("\n[!] Error involving {} -- could be an invalid account.".format(handle), fg="red")
                click.secho("L.. Details: {}".format(error), fg="red")