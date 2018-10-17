#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for checking email addresses against Have I Been Pwned's database of
security breaches and public pastes.
"""

import json

import click
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

from lib import helpers


class HaveIBeenPwned(object):
    """Class containing the tools for checking email addresses agaisnt the Have I Been Pwned
    breach and paste databases.
    """
    # Headers for use with Requests
    user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"
    headers = {'User-Agent' : user_agent}

    def __init__(self, webdriver):
        """Everything that should be initiated with a new object goes here."""
        self.browser = webdriver

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






