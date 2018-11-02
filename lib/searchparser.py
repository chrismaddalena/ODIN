#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains all of parsing tools used to extract email addresses and social media profile
handles and URLs from search results.

While much of the original code has been removed, rearranged, or modified, this code was
seeded using functions pulled from Christian Martorella's TheHarvester tool.

The original code can be found here:

https://github.com/laramies/theHarvester
"""

import re


class Parser:
    """Class for parsing search results to extract specific information, such as email addresses
    and social media profiles.
    """
    def __init__(self,results,word):
        """Everything that should be initiated with a new object goes here.

        Parameters:
        results     Results from a harvester.py module to search
        word        The word to search for
        """
        self.temp = []
        self.word = word
        self.results = results

    def generic_clean(self):
        """Remove generic HTML tags from the results and replace URL encoded characters."""
        self.results = re.sub('<em>','',self.results)
        self.results = re.sub('<b>','',self.results)
        self.results = re.sub('</b>','',self.results)
        self.results = re.sub('</em>','',self.results)
        self.results = re.sub('%2f',' ',self.results)
        self.results = re.sub('%3a',' ',self.results)
        self.results = re.sub('<strong>','',self.results)
        self.results = re.sub('</strong>','',self.results)
        self.results = re.sub('<wbr>','',self.results)
        self.results = re.sub('</wbr>','',self.results)
        for character in ('>',':','=','<','/','\\',';','&','%3A','%3D','%3C'):
            self.results = str.replace(self.results,character,' ')

    def parse_emails(self):
        """Search for and return email addresses in the search results."""
        self.generic_clean()
        reg_emails = re.compile(
            # Local part is required, charset is flexible
            # https://tools.ietf.org/html/rfc6531 (removed * and () as they provide FP mostly)
            '[a-zA-Z0-9.\-_+#~!$&\',;=:]+' +
            '@' +
            '[a-zA-Z0-9.-]*' + self.word)
        self.temp = reg_emails.findall(self.results)
        emails = self.unique()
        return emails

    def parse_twitter(self):
        """Search for and return Twitter handles in the search results."""
        # Reg Ex for finding profile links in the search results
        reg_profiles = re.compile('(?<=https:\/\/twitter.com\/)(.*?)(?=\/status|\&|\"|\<)')
        self.temp = reg_profiles.findall(self.results)
        profiles = self.unique()
        results = []
        for user in profiles:
            # Skip over handle/lists/list_name and statuses/status_id strings
            if not "/lists/" in user and not "statuses/" in user:
                user = user.replace('hashtag/','').replace('#!/','')
                # Filter out the generic Twitter links that have "/i/web/" in place of the username
                if user != " " and user != "i/web":
                    results.append(user)
        return results

    def unique(self):
        """Remove duplicate results and produce a unique list."""
        self.new = []
        for x in self.temp:
            if x.lower() not in self.new:
                self.new.append(x.lower())
        return self.new
