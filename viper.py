#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  _____        __                          _   _________  _______
 / ___/__  ___/ /__ ___  ___ ___ _  ___   | | / /  _/ _ \/ __/ _ \
/ /__/ _ \/ _  / -_) _ \/ _ `/  ' \/ -_)  | |/ // // ___/ _// , _/
\___/\___/\_,_/\__/_//_/\_,_/_/_/_/\__/   |___/___/_/  /___/_/|_|

Developer: Chris Maddalena
"""

import sys
import os
from colors import *
from lib import *

domain = ""
client = ""

def main():
	# Clear the terminal window
	os.system('cls' if os.name == 'nt' else 'clear')
	asciis.printArt()
	# Main menu display
	try:
		print green("Welcome to Viper!\n")
		print red("Warning: Some functions will require running Viper with sudo (e.g. nmap SYN scans)!\n")
		print green("""Please select a job from the options below.

	1. Intelligence Gathering (Passive)	3. Reporting

	2. Penetration Testing (Active)		4. Phishing

	0. Exit
		""")
		option = raw_input("Your tool: ")
		if option == "1":
			setupTargets()
			intelMenu()
		if option == "2":
			pentestMenu()
		elif option == "3":
			reportingMenu()
		elif option == "4":
			phishingMenu()
		elif option == "0":
			print "Thank you for using Viper!"
			sys.exit()
		else:
			print red("[!] Invalid option - Select from the menu")
			main()
	except (KeyboardInterrupt):
		main()

#Intel menu options
def setupTargets():
	global client
	global domain
	print green("""
OSINT requires a client name and domain name. If the client has a generic name (e.g. ABC), try using a complete name for Shodan and Google searches.
	""")
	print red("[!] Warning: Apostrophes in the client name may cause issues with Shodan.")
	client = raw_input("Client's name: ")
	domain = raw_input("Enter the domain: ")

def intelMenu():
	global domain
	global client
	try:
		print green("""
The Shadow-Viper intelligence gathering toolkit:

Your current targets are %s and %s.

	1. Harvest email addresses	4. Check IPs with Shodan

	2. Collect domain information	5. Check IPs with Cymon

	3. Discover files		6. Change targets

	7. Knowing is half the battle

	0. Return
""" % (client,domain))
		option = raw_input("Select a tool: ")
		# Email tools
		if option == "1":
			email_tools.harvest(client,domain)
			intelMenu()
		# Domain tools
		elif option == "2":
			domain_tools.collect(client,domain)
			intelMenu()
		# Find files
		elif option == "3":
			file_discovery.discover(client,domain)
			intelMenu()
		# Lookup IPs on Shodan
		elif option == "4":
			infile = raw_input("File path to your text file of IP addresses: ")
			scan_tools.shodanIPSearch(infile)
			pentestMenu()
		# Lookup IPs in Cymon
		elif option == "5":
			infile = raw_input("File path to your text file of IP addresses: ")
			scan_tools.cymonIPEventSearch(infile)
			scan_tools.cymonIPDomainSearch(infile)
			pentestMenu()
		# Change targeted name and domain
		elif option == "4":
			print green("Enter new target information:")
			client = raw_input("Client's name: ")
			domain = raw_input("Enter the domain: ")
			intelMenu()
		# Could be something useful, but Saturday morning cartoon references
		elif option == "7":
			print red("G.") + "I." + blue(" Jooooe!")
			intelMenu()
		#Exit to main menu
		elif option == "0":
			main()
		else:
			print red("[!] Invalid option - Select from the menu")
			intelMenu()
	except (KeyboardInterrupt):
		main()

#Penetration testing menu options
def pentestMenu():
	try:
		print green("\nThe Pit-Viper penetration testing toolkit")

		print red("\nSome of these scans require running Viper with sudo!")

		print green("""
	1. Check your scope

	2. Network Scans - Active scanning with nmap and masscan (you pick)

	3. Run domain through Qualys SSL Labs (New Scan)

	4. Run domain through Qualys SSL Labs (Results From Cache)

	0. Return
		""")
		option = raw_input("Select a tool: ")

		# Check scope option
		if option == "1":
			print green("""
Viper will attempt to verify ownership of the provided IP addresses (single or CIDR ranges) using various tools: ARIN, whois, DNS, and SSL cert informaiton.
Please provide a list of IPs in a text file and Viper will output a CSV of results.
			""")
			# initialize our array for IP address storage
			ips = []
			# initialize our dict for info storage
			out = {}

			infile = raw_input("File path to your text file of IP addresses: ")
			outfile = raw_input("Output filename for CSV: ")
			CIDR = raw_input("Is there a CIDR (y/n?): ")
			try:
				if CIDR == "y":
					breakrange = True
				else:
					breakrange = False
				verify.infile(infile, ips, breakrange)
				verify.who(ips, out)
				verify.outfile(out, outfile)
			except Exception as e:
				print red("[!] Verification failed!")
				print red("[!] Error: %s" % e)
			pentestMenu()
		# Launch network scanning menu
		elif option == "2":
			scanMenu()
		# SSL check with Qualys
		elif option == "3":
			testType = 1
			target = raw_input("Enter full target URL for scan (e.g. www.google.com): ")
			ssllabsscanner.getResults(target,testType)
			pentestMenu()
		elif option == "4":
			testType = 2
			target = raw_input("Enter full target URL for scan (e.g. www.google.com): ")
			ssllabsscanner.getResults(target,testType)
			pentestMenu()
		elif option == "0":
			main()
		else:
			print red("[!] Invalid option - Select from the menu")
			pentestMenu()
	except (KeyboardInterrupt):
		main()

#Reporting menu options
def reportingMenu():
	try:
		print green("""
The Ninja-Viper reporting toolkit:

	1. Combine multiple Nessus reports (.nessus)

	2.

	3.

	4.

	0. Return
""")
		option = raw_input("Select a tool: ")
		# Joining Nessus report files
		if option == "1":
			print green("""
Viper can join multiple .nessus files into one report.

	1. Place your files into the same directory.
	2. Provide the directory and the first .nessus file.
	3. Provide name for the final .nessus file and report title.
			""")

			dir = raw_input("Diretory with Nessus files: ")
			first = raw_input("First Nessus file: ")
			output = raw_input("Name for final Nessus file: ")
			name = raw_input("Name for final report: ")
			jonessus.joiner(first,dir,output,name)
		elif option == "2":
			print "Under construction!"
		elif option == "3":
			print "Under construction!"
		elif option == "4":
			print "Under construction!"
		elif option == "0":
			main()
		else:
			print red("[!] Invalid option - Select from the menu")
			reportingMenu()
	except (KeyboardInterrupt):
		main()

#Phishing menu options
def phishingMenu():
	try:
		print green("""
The Swamp-Viper phishing toolkit:

	1. Parse list of names into first and last (csv)

	2. Randomize a list of targets

	3. Run urlcrazy

	4.

	0. Return
""")
		option = raw_input("Select a tool: ")
		# Parse a list of names to create a comma delimited version
		if option == "1":
			file = raw_input("Enter name of file with the names: ")
			phish_tools.parseName(file)
			phishingMenu()
		# Randomize the list of targets
		elif option == "2":
			file = raw_input("Enter the location of file of targets: ")
			output = raw_input("Enter a name for the output file (txt): ")
			try:
				print green ("[+] Attempting to read %s" % file)
				with open (file, 'r') as file:
					names = file.readlines()
				with open(output, "w") as file:
					temp = []
					temp = phish_tools.randomList(names)
					file.write(''.join(str(i) for i in temp))
				print green("[+] Successfully created a random list of targets written to %s" % output)
				phishingMenu()
			except Exception as e:
				print red("[!] Failed to open the file!")
				print red("[!] Error: %s" % e)
				phishingMenu()
		# Run urlcrazy
		elif option == "3":
			target = raw_input("Enter the domain: ")
			phish_tools.getURLs(target)
		elif option == "4":
			print "Under construction!"
		elif option == "0":
			main()
		else:
			print red("[!] Invalid option - Select from the menu")
			phishingMenu()
	except (KeyboardInterrupt):
		main()

# Network scanning options
def scanMenu():
	try:
		print green("""
Viper has shortcuts for many of the popular scanners. Select a scanner, provide a text file with IPs, and Viper will take care of the rest.
You can run full nmap SYN scans, the same with common scripts, or Masscan with full ports.
For custom Masscan scans, edit Viper's masscan.config file.
		""")
		print red("SYN scans require sudo! Start Viper with sudo if you want to use them.")
		print green("""
Select a scan to run:

	1. Full port nmap SYN scan (-sS -T4 -p-)

	2. Default 1000 port nmap SYN scan (-sS -T4)

	3. Full port masscan (-p0-65535)

	4. Masscan with conf file (-c)

	0. Return
		""")
		option = raw_input("Select an option: ")
		# nmap scan options
		if option == "1":
			try:
				scanType = 1
				scan_tools.runNMAP(scanType)
				pentestMenu()
			except Exception as e:
				print red("[!] The namp scan failed! Remember to use sudo to start Viper.")
				pentestMenu()
		elif option == "2":
			try:
				scanType = 2
				scan_tools.runNMAP(scanType)
				pentestMenu()
			except:
				print red("[!] The namp scan failed! Remember to use sudo to start Viper.")
				pentestMenu()
		# masscan scan options
		elif option == "3":
			scanType = 1
			scan_tools.runMasscan(1)
			pentestMenu()
		elif option == "4":
			scanType = 2
			scan_tools.runMasscan(2)
			pentestMenu()
		# Return to the pen test menu
		elif option == "0":
			pentestMenu()
		else:
			print red("[!] Invalid option - Select from the menu")
			scanMenu()
	except (KeyboardInterrupt):
		main()

if __name__ == "__main__":
	main()
