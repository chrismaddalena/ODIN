import requests
from . import myparser
import time
import sys

class search_yahoo:

    def __init__(self, word, limit):
        self.word = word
        self.totalresults = ""
        self.server = "search.yahoo.com"
        self.hostname = "search.yahoo.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        headers = { 'User-Agent' : self.userAgent }
        try:
            urly = "http://" + self.server + "/search?p=\"%40" + self.word + "\"&b=" + str(self.counter) + "&pz=10"
        except Exception as e:
            print(e)
        try:
            r = requests.get(urly, headers=headers)
        except Exception as e:
            print(e)
        self.results = r.content
        self.totalresults += str(self.results)

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)

            # print("\tSearching " + str(self.counter) + " results...")
            self.counter += 10

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()
