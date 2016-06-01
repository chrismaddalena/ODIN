#!/usr/bin/env python

import os
from time import sleep
import sys

def setup():
	downloadLibs()
	if not os.path.exists("../auth"):
		print "Adding the 'auth' directory."
		try:
			os.mkdir("../auth")
			sleep(2)
			shodanSetup()
		except:
			exit("run as sudo!")
	elif os.path.exists("../auth"):
		shodanSetup()
		cymonSetup()
		urlvoidSetup()
		twitterSetup()
	else:
		exit("[!] Could not proceed with setup! Try running as sudo!")
	print("[+] Setup complete!")

def shodanSetup():
	if os.path.isfile('../auth/shodankey.txt'):
		exit('The Shodan API key is already present!')
	else:
		f = open('../auth/'+'shodankey.txt', 'w')
		key = raw_input('Shodan API key: ')
		f.write('#Shodan API key\n')
		f.write(key+'\n')
		f.close()
	return

def cymonSetup():
	if os.path.isfile('../auth/cymonkey.txt'):
		exit('The Cymon API key is already present!')
	else:
		f = open('../auth/'+'cymonkey.txt', 'w')
		key = raw_input('Cymon API key: ')
		f.write('#Cymon API key\n')
		f.write(key+'\n')
		f.close()
	return

def urlvoidSetup():
	if os.path.isfile('../auth/urlvoidkey.txt'):
		exit('The URLVoid API key is already present!')
	else:
		f = open('../auth/'+'urlvoidkey.txt', 'w')
		key = raw_input('URLVoid API key: ')
		f.write('#URLVoid API key\n')
		f.write(key+'\n')
		f.close()
	return

def twitterSetup():
	if os.path.isfile('../auth/twitter.txt'):
		exit('The Twitter API is already setup!')
	else:
		f = open('../auth/'+'twitter.txt', 'w')
		key = raw_input('Twitter Customer Key: ')
		keySecret = raw_input('Twitter Customer Secret: ')
		toke = raw_input('Twitter Access Token: ')
		tokenSecret = raw_input('Twitter Access Token Secret: ')
		f.write('#Twitter API business\n')
		f.write(key+'\n')
		f.write(keySecret+'\n')
		f.write(token+'\n')
		f.write(tokenSecret+'\n')
		f.close()
	return

def downloadLibs():
	# Download theHarvester
	if not os.path.isfile('../lib/theharvester'):
		print "Downloading theHarvester.py"
		os.system('wget https://github.com/laramies/theHarvester/archive/master.zip -O ../lib/harvester.zip')
		os.system('unzip ../lib/harvester.zip -d ../lib/')
		os.system('mv ../lib/theHarvester-master ../lib/theharvester')
		os.system('rm ../lib/harvester.zip')
		os.system('mv ../lib/theharvester/lib/graphs.py ../lib/graphs.py')
		os.system('mv ../lib/theharvester/lib/hostchecker.py ../lib/hostchecker.py')
		os.system('mv ../lib/theharvester/lib/htmlExport.py ../lib/htmlExport.py')
		os.system('mv ../lib/theharvester/lib/markup.py ../lib/markup.py')
	else:
		print "TheHarvester is installed."

setup()
