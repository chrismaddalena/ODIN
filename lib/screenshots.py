#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for takin screenshots of webpages."""

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from colors import red, green, yellow
from lib import helpers

class Screenshotter(object):
    """A class containing the tools for taking screenshots of webpages."""

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect settings from the config file
        try:
            self.chrome_driver_path = helpers.config_section_map("WebDriver")["driver_path"]
            # Try loading the driver as a test
            browser = webdriver.Chrome(executable_path = self.chrome_driver_path)
            browser.close()
            print(green("[*] Chrome web driver test was successful!"))
            self.browser_capable = True
        # Catch issues with the web driver or path
        except WebDriverException:
            self.chrome_driver_path = None
            self.browser_capable = False
        # Catch issues loading the value from the config file
        except Exception:
            self.chrome_driver_path = None
            self.browser_capable = False

        if self.browser_capable is False:
            print(yellow("[*] Chrome web driver test failed with the provided web driver \
executable. We will try PhantomJS."))
            try:
                webdriver.PhantomJS()
                self.browser_capable = True
                print(green("[*] PhantomJS test was successful!"))
            except WebDriverException:
                self.chrome_driver_path = None
                self.browser_capable = False
                print(red("[*] PhantomJS test failed, so we won't take web screenshots."))
            except Exception:
                self.chrome_driver_path = None
                self.browser_capable = False
                print(red("[*] PhantomJS test failed, so we won't take web screenshots."))

    def take_screenshot(self, target, directory):
        """Function to take a screenshot of a target webpage."""
        if self.browser_capable:
            if self.chrome_driver_path:
                browser = webdriver.Chrome(executable_path = self.chrome_driver_path)
            else:
                browser = webdriver.PhantomJS()

            try:
                out_name = target.split("//")[1]
            except:
                out_name = target
                target = "http://" + target

            browser.set_window_size(1120, 550)
            browser.get(target)
            browser.save_screenshot(directory + out_name + ".png")
            browser.close()
