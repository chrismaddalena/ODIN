#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
from BeautifulSoup import BeautifulSoup
import urllib2

# Total commands
total = 17 # Tests

def discover(client,domain):
	print """Viper will now perform  variety of Google searches to try to find publicly files. If this breaks, you might be blocked by Google with a CAPTCHA. They do that sometimes when their keywords are used.
	"""

	client = client
	domain = domain
	# Create drectory for client reports
	if not os.path.exists("reports/%s" % client):
		try:
			os.mkdir("reports/%s" % client)
		except:
			print "[!] Could not create reports directory!"

	# Create File Report in client folder
	os.system('echo "### File Discovery Report for %s ###\n" >> reports/%s/File_Report.txt' % (domain,client))

	# Use goofile
	print "[+] Using goofile to find documents"
	os.system('echo "\n--- GOOFILE FILETYPE Results ---\n" >> reports/%s/File_Report.txt' % client)
	print "[-] Searching for doc (1/%s)" % total
	os.system('goofile -d %s-f doc >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for docx (2/%s)" % total
	os.system('goofile -d %s-f docx >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for pdf (3/%s)" % total
	os.system('goofile -d %s-f pdf >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for ppt (4/%s)" % total
	os.system('goofile -d %s-f ppt >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for pptx (5)/%s)" % total
	os.system('goofile -d %s-f pptx >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for txt (6/%s)" % total
	os.system('goofile -d %s-f txt >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for xls (7/%s)" % total
	os.system('goofile -d %s-f xls >> reports/%s/File_Report.txt' % (domain,client))
	print "[-] Searching for xlsx (8/%s)" % total
	os.system('goofile -d %s-f xlsx >> reports/%s/File_Report.txt' % (domain,client))

	# Use Google Hacking queries
	print "[+] Using Google to find documents"
	os.system('echo "\n--- GOOGLE HACKING Results ---\n" >> reports/%s/File_Report.txt' % client)
	browser = urllib2.build_opener()
	browser.addheaders = [('User-agent', 'Mozilla/5.0')] # Google-friendly user-agent

	# Perform search and grab just the URLs for each result
	# 'Start' is used here to allow for iterating through X pages
	print "[-] Searching for pdf (9/%s)" % total
	# PDF
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:pdf&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# DOC
	print "[-] Searching for doc (10/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:doc&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# DOCX
	print "[-] Searching for docx (11/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:docx&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

	for cite in soup.findAll('cite'):
		os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# XLS
	print "[-] Searching for xls (12/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:xls&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# XLSX
	print "[-] Searching for xlsx (13/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:xlsx&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# PPT
	print "[-] Searching for ppt (14/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:ppt&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# PPTX
	print "[-] Searching for pptx (15/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:pptx&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# TXT
	print "[-] Searching for txt (16/%s)" % total
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+filetype:txt&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))

	# Search for different login/logon/admin/administrator pages
	os.system('echo "\n--- GOOGLE HACKING LOGIN Results ---\n" >> reports/%s/File_Report.txt' % client)
	print "[-] Searching for keywords in login pages (17/%s)" % total
	# Login
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+intitle:login&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# Logon
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+intitle:logon&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# Admin
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+intitle:admin&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
	# Administrator
	for start in range(0,10):
		url = "https://www.google.com/search?q=site:%s+intitle:administrator&start=" % domain + str(start*10)
		page = browser.open(url)
		soup = BeautifulSoup(page)

		for cite in soup.findAll('cite'):
			os.system('echo %s >> reports/%s/File_Report.txt' % (cite.text,client))
