#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for seeking out individuals and collecting
data, such as email addresses and social media account data.
"""

import requests
import tweepy
from colors import red, green, yellow
from bs4 import BeautifulSoup as BS
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from http.cookiejar import CookieJar, Cookie
from time import sleep
import json
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
        except Exception:
            self.twit_api = None
            print(yellow("[!] Could not setup OAuth for Twitter API."))

        try:
            self.emailhunter_api_key = helpers.config_section_map("EmailHunter")["api_key"]
        except Exception:
            self.emailhunter_api_key = ""
            print(yellow("[!] Could not fetch EmailHunter API key."))

        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except Exception:
            self.contact_api_key = ""
            print(yellow("[!] Could not fetch Full Contact API key."))

        try:
            self.chrome_driver_path = helpers.config_section_map("WebDriver")["driver_path"]
            # Try loading the driver as a test
            self.chrome_options = Options()
            self.chrome_options.add_argument("--headless")
            self.chrome_options.add_argument("--window-size=1920x1080")
            self.browser = webdriver.Chrome(chrome_options=self.chrome_options, executable_path=self.chrome_driver_path)
        # Catch issues with the web driver or path
        except WebDriverException:
            self.chrome_driver_path = None
            self.browser = webdriver.PhantomJS()
            print(yellow("[!] There was a problem with the specified Chrome web driver in your \
keys.config! Please check it. For now ODIN will try to use PhantomJS for HaveIBeenPwned."))
        # Catch issues loading the value from the config file
        except Exception:
            self.chrome_driver_path = None
            self.browser = webdriver.PhantomJS()
            print(yellow("[!] Could not load a Chrome webdriver for Selenium, so we will tryuse \
to use PantomJS for haveIBeenPwned."))

    def pwn_check(self, email):
        """Use HIBP's API to check for the target's email in public security breaches."""
        try:
            # if self.chrome_driver_path:
            #     browser = webdriver.Chrome(executable_path = self.chrome_driver_path)
            # else:
            #     browser = webdriver.PhantomJS()
            self.browser.get('https://haveibeenpwned.com/api/v2/breachedaccount/{}'.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pwned = json.loads(json_text)
            # browser.close()

            return pwned
        except TimeoutException:
            print(red("[!] Connectionto HaveIBeenPwned timed out!"))
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            # print(red("[!] Connectionto HaveIBeenPwned timed out!"))
            return []

    def paste_check(self, email):
        """Use HIBP's API to check for the target's email in pastes across multiple paste websites.
        This includes sites like Slexy, Ghostbin, Pastebin.
        """
        try:
            # if self.chrome_driver_path:
            #     browser = webdriver.Chrome(executable_path = self.chrome_driver_path)
            # else:
            #     browser = webdriver.PhantomJS()
            self.browser.get('https://haveibeenpwned.com/api/v2/pasteaccount/{}'.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pastes = json.loads(json_text)
            # browser.close()

            return pastes
        except TimeoutException:
            print(red("[!] Connectionto HaveIBeenPwned timed out!"))
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            # print(red("[!] Connectionto HaveIBeenPwned timed out!"))
            return []

    def full_contact_email(self, email):
        """Use the Full Contact API to collect social information for the target email address."""
        if self.contact_api_key is None:
            print(red("[!] No Full Contact API key, so skipping these searches."))
        else:
            base_url = "https://api.fullcontact.com/v2/person.json"
            payload = {'email':email, 'apiKey':self.contact_api_key}
            resp = requests.get(base_url, params=payload)
            if resp.status_code == 200:
                return resp.json()

    def full_contact_company(self, domain):
        """Use the Full Contact API to collect company profile information for the target domain."""
        if self.contact_api_key is None:
            print(red("[!] No Full Contact API key, so skipping company lookup."))
            return None
        else:
            base_url = "https://api.fullcontact.com/v2/company/lookup.json"
            payload = {'domain':domain, 'apiKey':self.contact_api_key}
            resp = requests.get(base_url, params=payload)
            if resp.status_code == 200:
                return resp.json()

    def harvest_all(self, domain):
        """Use TheHarvester to discover email addresses and employee names."""
        # Set the search configuration for TheHarvester
        harvest_limit = 100
        harvest_start = 0

        print(green("[+] Beginning the harvesting of email addresses..."))
        # Search through most of Harvester's supported engines
        # No Baidu because it always seems to hang or take way too long
        print(green("[*] Harvesting Google"))
        search = googlesearch.search_google(domain, harvest_limit, harvest_start)
        search.process()
        google_harvest = search.get_emails()

        print(green("[*] Harvesting LinkedIn"))
        search = linkedinsearch.search_linkedin(domain, harvest_limit)
        search.process()
        link_harvest = search.get_people()

        print(green("[*] Harvesting Twitter"))
        search = twittersearch.search_twitter(domain, harvest_limit)
        search.process()
        twit_harvest = search.get_people()

        print(green("[*] Harvesting Yahoo"))
        search = yahoosearch.search_yahoo(domain, harvest_limit)
        search.process()
        yahoo_harvest = search.get_emails()

        print(green("[*] Harvesting Bing"))
        search = bingsearch.search_bing(domain, harvest_limit, harvest_start)
        search.process('no')
        bing_harvest = search.get_emails()

        print(green("[*] Harvesting Jigsaw"))
        search = jigsaw.search_jigsaw(domain, harvest_limit)
        search.process()
        jigsaw_harvest = search.get_people()

        # Combine lists and strip out duplicate findings for unique lists
        all_emails = google_harvest + bing_harvest + yahoo_harvest
        all_people = link_harvest + jigsaw_harvest

        print(green("[+] The search engines returned {} emails, {} names, and {} Twitter \
handles.".format(len(all_emails), len(all_people), len(twit_harvest))))

        # Return the results for emails, people, and Twitter accounts
        return all_emails, all_people, twit_harvest

    def harvest_twitter(self, handle):
        """Function to lookup the provided handle on Twitter using Tweepy."""
        if self.twit_api is None:
            print(yellow("[*] Twitter API access is not setup, so skipping Twitter handle \
lookups."))
        else:
            # Drop the lonely @ Harvester often includes and common false positives
            if handle == '@' or handle == '@-moz-keyframes' or \
                handle == '@keyframes' or handle == '@media' or handle == '@broofa.com':
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
        """Construct a Bing search URL and scrape for LinkedIn profile links related to the
        target's name and company.
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

    def harvest_emailhunter(self, domain):
        """"Call upon EmailHunter's API to collect known email addresses for a domain and other
        information, such as names, job titles, and the original source of the data.

        A free EmailHunter API key is required.
        """
        results = None

        if self.emailhunter_api_key:
            emailhunter_api_url = "https://api.hunter.io/v2/domain-search?\
domain={}&api_key={}".format(domain, self.emailhunter_api_key)
            request = requests.get(emailhunter_api_url)
            results = request.json()

            if "errors" in results:
                print(red("[!] The request to EmailHunter returned an error!"))
                print(red("L.. Details: {}".format(results['errors'])))
                return None

            print(green("[+] Hunter has contact data for {} \
people.".format(len(results['data']['emails']))))

        return results

    def process_harvested_lists(self, harvester_emails, harvester_people,\
    harvester_twitter, hunter_json):
        """Take data harvested from EmailHunter and TheHarvester, combine it, make unique lists,
        and return the total results.
        """
        temp_emails = []
        twitter_handles = []
        job_titles = {}
        linkedin = {}
        phone_nums = {}

        # Process emails found by TheHarvester
        for email in harvester_emails:
            email = email.lower()
            temp_emails.append(email)

        # Process emails and people found by Hunter
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

        print(green("[+] Final unique findings: {} emails, {} people, \
{} Twitter handles.".format(len(unique_emails), len(unique_people), len(unique_twitter))))

        return unique_emails, unique_people, unique_twitter, job_titles, linkedin, phone_nums
