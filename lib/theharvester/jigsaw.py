import string
import requests
import sys
from . import myparser
import re

class search_jigsaw:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.jigsaw.com"
        self.hostname = "www.jigsaw.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        headers = { 'User-Agent' : self.userAgent }
        try:
            urly = "http://" + self.server + "/FreeTextSearch.xhtml?opCode=search&autoSuggested=True&freeText=" + self.word
        except Exception as e:
            print(e)
        try:
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.content
        self.totalresults += str(self.results)

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(str(self.results))
        if nextres != []:
            nexty = "1"
        else:
            nexty = "0"
        return nexty

    def get_people(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.people_jigsaw()

    def process(self):
        while (self.counter < self.limit):
            self.do_search()
            more = self.check_next()
            if more == "1":
                self.counter += 100
            else:
                break
