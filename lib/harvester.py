#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of tools and functions used for using search engines to find email
addresses and scoail media profiles for a target organization and domain.

While much of the original code has been removed, rearranged, or modified, this code was
seeded using functions pulled from Christian Martorella's TheHarvester tool.

The original code can be found here:

https://github.com/laramies/theHarvester
"""

import re
import sys
import time
import string
import requests

from . import searchparser


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
        except Exception as error:
            print(error)
        self.results = req.content
        self.totalresults += str(self.results)

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
        except Exception as error:
            print(error)
        self.results = req.content
        self.totalresults += str(self.results)

    def process(self):
        """Process the Yahoo search results page by page up to the limit."""
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)
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
        except Exception as error:
            print(error)
        self.results = req.content
        self.totalresults += str(self.results)

    def get_emails(self):
        """Parse Google search results to get email addresses."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_emails()

    def process(self):
        """Process the search results page by page up to the limit."""
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)
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
        except Exception as error:
            print(error)
        self.results = req.content
        self.totalresults += str(self.results)

    def get_emails(self):
        """Parse Bing search results to get email addresses."""
        rawres = searchparser.Parser(self.totalresults, self.word)
        return rawres.parse_emails()

    def process(self):
        """Process the Bing search results page by page up to the limit."""
        while (self.counter < self.limit):
            self.do_search()
            time.sleep(1)
            self.counter += 50
