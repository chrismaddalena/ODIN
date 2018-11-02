#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for taking screenshots of webpages."""

import click
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException,NoSuchElementException,WebDriverException

from lib import helpers


class Screenshotter(object):
    """Class containing the tools for taking screenshots of webpages."""
    # Set the timeout, in seconds, for the webdriver
    browser_timeout = 10

    def __init__(self,webdriver):
        """Everything that should be initiated with a new object goes here.

        Parameters:
        webdriver   A Selenium webdriver object to use for automated web browsing
        """
        self.browser = webdriver
        self.browser.set_page_load_timeout(self.browser_timeout)

    def take_screenshot(self,target,directory):
        """Function to take a screenshot of a target webpage.

        Parameters:
        target      The IP address or domain name to use for the web request
        directory   The directory where the saved screenshots will be stored
        """
        try:
            out_name = target.split("//")[1]
        except:
            out_name = target
            target = "http://" + target
            target_ssl = "https://" + target
        # Attempt to take a screenshot of the target using HTTP and HTTPS
        try:
            # Try HTTPS
            self.browser.get(target_ssl)
            # Attempt to dismiss any alerts
            try:
                alert = self.browser.switch_to.alert
                alert.dismiss()
            except:
                pass
            self.browser.save_screenshot(directory + out_name + "_ssl.png")
            # Try HTTP
            self.browser.get(target)
            # Attempt to dismiss any alerts
            try:
                alert = self.browser.switch_to.alert
                alert.dismiss()
            except:
                pass
            self.browser.save_screenshot(directory + out_name + ".png")
        except TimeoutException:
            pass
        except WebDriverException:
            pass
        except Exception:
            pass
