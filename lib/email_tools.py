#!/usr/bin/python2
# -*- coding: utf-8 -*-

import os
import pwnedcheck

# Number of commands
total = 5
harvesterDomains = 5

def harvest(client,domain):
	print """
	"""

	client = client
	domain = domain

	# Create drectory for client reports
	if not os.path.exists("reports/%s" % client):
		try:
			os.mkdir("reports/%s" % client)
		except:
			print "[!] Could not create reports directory!"
	print "[+] Running The Harvester (1/%s)" % total
	print "[-] Harvesting Google (1/%s)" % harvesterDomains
	os.system('theharvester -d %s -b google >> reports/%s/Harvester_Google.txt' % (domain,client))
	print "[-] Harvesting LinkedIn (2/%s)" % harvesterDomains
	os.system('theharvester -d %s -b linkedin >> reports/%s/Harvester_LinkedIn.txt' % (domain,client))
	print "[-] Harvesting Twitter (3/%s)" % harvesterDomains
	os.system('theharvester -d %s -b twitter >> reports/%s/Harvester_Twitter.txt' % (domain,client))
	print "[-] Harvesting Baidu (4/%s)" % harvesterDomains
	os.system('theharvester -d %s -b baidu >> reports/%s/Harvester_Baidu.txt' % (domain,client))
	print "[-] Harvesting Bing (5/%s)" % harvesterDomains
	os.system('theharvester -d %s -b bing >> reports/%s/Harvester_Bing.txt' % (domain,client))

def pwnedCheck():
	#print pwnedcheck.check("chris.maddalena@gmail.com")

	with open('harvest.txt') as harvest:
		# Skip to the emails
		for line in harvest:
			if line.strip() == "[+] Emails found:":
				break
		for line in harvest:
			if line.strip() == '[+] Hosts found in search engines:':
				break
			print line
