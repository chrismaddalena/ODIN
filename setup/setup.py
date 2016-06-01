#!/usr/bin/env python

import os
from time import sleep
import sys
from colors import *

def setup():
	print green("[+] Setup will now download TheHarvester from GitHub and walk you through setting up your API keys.")
	print yellow("[!] Have your API keys ready, including your Twitter app keys and tokens!")
	#downloadLibs()
	if not os.path.exists("../auth"):
		print green("[+] Adding the 'auth' directory.")
		try:
			os.mkdir("../auth")
			sleep(2)
			shodanSetup()
			cymonSetup()
			urlvoidSetup()
			twitterSetup()
		except:
			exit("[!] Could not proceed with setup! Try running as sudo!")
	elif os.path.exists("../auth"):
		shodanSetup()
		cymonSetup()
		urlvoidSetup()
		twitterSetup()
	else:
		exit("[!] Could not proceed with setup! Try running as sudo!")
	print green("[+] Setup complete! If you need to re-run setup for a key: Go into /auth and delete the key file(s). Then re-run setup.")

def shodanSetup():
	if os.path.isfile('../auth/shodankey.txt'):
		print green('[+] The Shodan API key is already present!')
	else:
		f = open('../auth/'+'shodankey.txt', 'w')
		key = raw_input('Shodan API key: ')
		f.write('#Shodan API key\n')
		f.write(key+'\n')
		f.close()
	return

def cymonSetup():
	if os.path.isfile('../auth/cymonkey.txt'):
		print green('[+] The Cymon API key is already present!')
	else:
		f = open('../auth/'+'cymonkey.txt', 'w')
		key = raw_input('Cymon API key: ')
		f.write('#Cymon API key\n')
		f.write(key+'\n')
		f.close()
	return

def urlvoidSetup():
	if os.path.isfile('../auth/urlvoidkey.txt'):
		print green('[+] The URLVoid API key is already present!')
	else:
		f = open('../auth/'+'urlvoidkey.txt', 'w')
		key = raw_input('URLVoid API key: ')
		f.write('#URLVoid API key\n')
		f.write(key+'\n')
		f.close()
	return

def twitterSetup():
	if os.path.isfile('../auth/twitter.txt'):
		print green('[+] The Twitter app keys are already present!')
	else:
		f = open('../auth/'+'twitter.txt', 'w')
		key = raw_input('Twitter Customer Key: ')
		keySecret = raw_input('Twitter Customer Secret: ')
		token = raw_input('Twitter Access Token: ')
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
