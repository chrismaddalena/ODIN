#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for takin screenshots of webpages."""

import click
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

from lib import helpers


class Screenshotter(object):
    """A class containing the tools for taking screenshots of webpages."""

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect settings from the config file
        try:
            self.chrome_driver_path = helpers.config_section_map("WebDriver")["driver_path"]
            # Try loading the driver as a test
            self.chrome_options = Options()
            self.chrome_options.add_argument("--headless")
            self.chrome_options.add_argument("--window-size=1920x1080")
            self.chrome_options.add_argument('--ignore-certificate-errors')
            self.browser = webdriver.Chrome(chrome_options=self.chrome_options, executable_path=self.chrome_driver_path)
            self.browser_capable = True
            click.secho("[*] Headless Chrome for web screenshots test was successful!", fg="green")
        # Catch issues with the web driver or path
        except WebDriverException:
            self.chrome_driver_path = None
            self.browser_capable = False
            click.secho("[*] Headless Chrome for web screenshots failed! Will try PhantomJS...", fg="red")
        # Catch issues loading the value from the config file
        except Exception:
            self.chrome_driver_path = None
            self.browser_capable = False
            click.secho("[*] Headless Chrome for web screenshots failed! Will try PhantomJS...", fg="red")

        if self.browser_capable is False:
            try:
                self.browser = webdriver.PhantomJS()
                self.browser_capable = True
                click.secho("[*] PhantomJS for web screenshots test was successful!", fg="green")
            except WebDriverException:
                self.chrome_driver_path = None
                self.browser_capable = False
                click.secho("[*] PhantomJS test also failed, so we won't take web screenshots.", fg="red")
            except Exception:
                self.chrome_driver_path = None
                self.browser_capable = False
                click.secho("[*] PhantomJS test also failed, so we won't take web screenshots.", fg="red")

    def take_screenshot(self, target, directory):
        """Function to take a screenshot of a target webpage."""
        if self.browser_capable:
            try:
                out_name = target.split("//")[1]
            except:
                out_name = target
                target = "http://" + target
                target_ssl = "https://" + target

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
