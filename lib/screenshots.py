#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for takin screenshots of webpages."""

import click
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

from lib import helpers


class Screenshotter(object):
    """Class containing the tools for taking screenshots of webpages."""

    def __init__(self, webdriver):
        """Everything that should be initiated with a new object goes here."""
        self.browser = webdriver

    def take_screenshot(self, target, directory):
        """Function to take a screenshot of a target webpage."""
        try:
            out_name = target.split("//")[1]
        except:
            out_name = target
            target = "http://" + target
            target_ssl = "https://" + target
        # Attempt to dismiss any alerts
        try:
            alert = self.browser.switch_to.alert
            alert.dismiss()
        except:
            pass
        # Attempt to take a screenshot of the target
        try: 
            self.browser.get(target)
            self.browser.save_screenshot(directory + out_name + ".png")
            self.browser.get(target_ssl)
            self.browser.save_screenshot(directory + out_name + "_ssl.png")
        except TimeoutException:
            pass
        except WebDriverException:
            pass
        except Exception:
            pass
