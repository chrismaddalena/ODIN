#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of tools and functions used for seeking out individuals and collecting
data, such as email addresses and social media account data.
"""

import json
from time import sleep

import click
import tweepy
import requests
from bs4 import BeautifulSoup as BS
from http.cookiejar import CookieJar, Cookie
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException,NoSuchElementException,WebDriverException

from lib import helpers, harvester


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
            # Setup Tweepy with a timeout value, the default is 60 seconds
            self.twit_api = tweepy.API(twit_auth, timeout=10)
        except Exception:
            self.twit_api = None
            click.secho("[!] Could not setup OAuth for Twitter API.", fg="yellow")

        try:
            self.emailhunter_api_key = helpers.config_section_map("EmailHunter")["api_key"]
        except Exception:
            self.emailhunter_api_key = ""
            click.secho("[!] Could not fetch EmailHunter API key.", fg="yellow")

        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except Exception:
            self.contact_api_key = ""
            click.secho("[!] Could not fetch Full Contact API key.", fg="yellow")

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
            click.secho("[!] There was a problem with the specified Chrome web driver in your \
keys.config! Please check it. For now ODIN will try to use PhantomJS for HaveIBeenPwned.", fg="yellow")
        # Catch issues loading the value from the config file
        except Exception:
            self.chrome_driver_path = None
            self.browser = webdriver.PhantomJS()
            click.secho("[!] Could not load a Chrome webdriver for Selenium, so we will tryuse \
to use PantomJS for haveIBeenPwned.", fg="yellow")

    def pwn_check(self, email):
        """Check for the target's email in public security breaches using HIBP's API."""
        try:
            self.browser.get('https://haveibeenpwned.com/api/v2/breachedaccount/{}'.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pwned = json.loads(json_text)

            return pwned
        except TimeoutException:
            click.secho("[!] The connectionto HaveIBeenPwned timed out!", fg="red")
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            return []

    def paste_check(self, email):
        """Check for the target's email in pastes across multiple paste websites. This includes
        sites like Slexy, Ghostbin, Pastebin using HIBP's API.
        """
        try:
            self.browser.get('https://haveibeenpwned.com/api/v2/pasteaccount/{}'.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pastes = json.loads(json_text)

            return pastes
        except TimeoutException:
            click.secho("[!] The connection to HaveIBeenPwned timed out!", fg="red")
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            return []

    def full_contact_email(self, email):
        """Collect social information for the target email address using the Full Contact API."""
        # TODO: Implement the use of the People API -- Also, update this for v3 of the API.
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping these searches.", fg="red")
        else:
            base_url = "https://api.fullcontact.com/v2/person.json"
            payload = {'email':email, 'apiKey':self.contact_api_key}
            resp = requests.get(base_url, params=payload)
            if resp.status_code == 200:
                return resp.json()

    def full_contact_company(self, domain):
        """Collect company profile information for the target domain using the Full Contact API."""
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping company lookup.", fg="red")
            return None
        else:
            base_url = "https://api.fullcontact.com/v3/company.enrich"
            headers = {"Authorization":"Bearer %s" % self.contact_api_key}
            payload = {'domain':domain}
            resp = requests.post(base_url, data=json.dumps(payload), headers=headers)
            if resp.status_code == 200:
                return resp.json()

    def harvest_all(self, domain):
        """Discover email addresses and employee names using search engines like Google, Yahoo,
        and Bing.
        """
        # Set the search configuration for harvesting email addresses and social media profiles
        harvest_limit = 100
        harvest_start = 0

        click.secho("[+] Beginning the harvesting of email addresses for {}...".format(domain), fg="green")
        search = harvester.SearchGoogle(domain, harvest_limit, harvest_start)
        search.process()
        google_harvest = search.get_emails()

        search = harvester.SearchTwitter(domain, harvest_limit)
        search.process()
        twit_harvest = search.get_people()

        search = harvester.SearchYahoo(domain, harvest_limit)
        search.process()
        yahoo_harvest = search.get_emails()

        search = harvester.SearchBing(domain, harvest_limit, harvest_start)
        search.process()
        bing_harvest = search.get_emails()

        # Combine lists and strip out duplicate findings for unique lists
        all_emails = google_harvest + bing_harvest + yahoo_harvest

        click.secho("[+] The search engines returned {} emails and {} Twitter handles."
                     .format(len(all_emails), len(twit_harvest)), fg="green")

        # Return the results for emails, people, and Twitter accounts
        return all_emails, twit_harvest

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

    def harvest_linkedin(self, company, limit=100):
        """Construct a Bing search URL and scrape LinkedIn profile information related to the
        given company name.
        """
        profiles = {}
        counter = 0
        company = company.replace(" ", "%20")
        while (counter < limit):
            try:
                url = 'http://www.bing.com/search?q=site:linkedin.com/in%20"' + company + '"&count=50&first=' + str(counter)
                self.browser.get(url)
                soup = BS(self.browser.page_source, "html.parser")
                results = soup.findAll('li', {'class': 'b_algo'})
                for hit in results:
                    # Get href links from Bing's source
                    link = hit.a['href']
                    link_text = hit.a.getText().strip(" ...")
                    name = link_text.split(" - ")[0]
                    try:
                        job_title = link_text.split(" - ")[1]
                    except:
                        job_title = ""
                    if '/dir/' in link or '/title/' in link or 'groupItem' in link or \
                        not 'linkedin.com' in link:
                        continue
                    else:
                        profiles[name] = {'job_title': job_title, 'linkedin_profile': link}
            except TimeoutException:
                pass
            except NoSuchElementException:
                pass
            except WebDriverException:
                pass

            sleep(1)
            counter += 50

        return profiles


    def harvest_emailhunter(self, domain):
        """"Collect known email addresses for a domain and other information, such as names and job
        titles, using EmailHunter's API.

        A free EmailHunter API key is required.
        """
        results = None

        if self.emailhunter_api_key:
            emailhunter_api_url = "https://api.hunter.io/v2/domain-search?\
domain={}&api_key={}".format(domain, self.emailhunter_api_key)
            request = requests.get(emailhunter_api_url)
            results = request.json()

            if "errors" in results:
                click.secho("[!] The request to EmailHunter returned an error!", fg="red")
                click.secho("L.. Details: {}".format(results['errors']), fg="red")
                return None

            click.secho("[+] Hunter has contact data for {} people."
                         .format(len(results['data']['emails'])), fg="green")
        return results

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
