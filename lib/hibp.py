#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for checking email addresses against Have I Been Pwned's database of
security breaches and public pastes.
"""

import json

import click
from selenium.common.exceptions import TimeoutException,NoSuchElementException,WebDriverException

from lib import helpers


class HaveIBeenPwned(object):
    """Class containing the tools for checking email addresses against the Have I Been Pwned
    breach and paste databases.
    """
    # Set the timeout, in seconds, for the webdriver
    browser_timeout = 10
    # The Have I Been Pwned API endpoints
    hibp_paste_uri = "https://haveibeenpwned.com/api/v2/pasteaccount/{}"
    hibp_breach_uri = "https://haveibeenpwned.com/api/v2/breachedaccount/{}"

    def __init__(self,webdriver):
        """Everything that should be initiated with a new object goes here.

        Parameters:
        webdriver   A Selenium webdriver object to be used for web browsing
        """
        self.browser = webdriver
        self.browser.set_page_load_timeout(self.browser_timeout)

    def pwn_check(self,email):
        """Check for the target's email in public security breaches using HIBP's API.

        Parameters:
        email       The email address to look-up in Have I Been Pwned's breach database
        """
        try:
            self.browser.get(self.hibp_breach_uri.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pwned = json.loads(json_text)
            return pwned
        except TimeoutException:
            click.secho("[!] The connection to HaveIBeenPwned timed out!",fg="red")
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            return []

    def paste_check(self,email):
        """Check for the target's email in pastes across multiple paste websites. This includes
        sites like Slexy, Ghostbin, Pastebin using HIBP's API.

        Parameters:
        email       The email address to look-up in Have I Been Pwned's pastes database
        """
        try:
            self.browser.get(self.hibp_paste_uri.format(email))
            # cookies = browser.get_cookies()
            json_text = self.browser.find_element_by_css_selector('pre').get_attribute('innerText')
            pastes = json.loads(json_text)
            return pastes
        except TimeoutException:
            click.secho("[!] The connection to HaveIBeenPwned timed out!",fg="red")
            return []
        except NoSuchElementException:
            # This is likely an "all clear" -- no hits in HIBP
            return []
        except WebDriverException:
            return []
