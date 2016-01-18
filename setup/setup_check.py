#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
from time import sleep

print "\nThis tool requires various lib/modules and API keys to function."
print "This script serves to check if you have those libs and keys."

sleep(2)

if os.path.isfile('../auth/shodankey.txt') == False:
    print "[!] Shodan API key is not setup!"
else:
    print '[+] FOUND: Shodan API key'

try:
    import shodan
    print '[+] FOUND: Shodan library'
except:
    print '[!] MISSING: Shodan library'

try:
    import whois
    print '[+] FOUND: Whois library'
except:
    print '[!] MISSING: Whois library'

try:
    import BeaitufulSoup
    print '[+] FOUND: BeautifulSoup library'
except:
    print '[!] MISSING: BeautifulSoup library'
