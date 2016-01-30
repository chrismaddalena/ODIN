#!/usr/bin/env python2
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
from colors import red, green, yellow, blue
from lib import *

domain = ""
client = ""

def main():
    # Clear the terminal window
    os.system('cls' if os.name == 'nt' else 'clear')
    asciis.printArt()
    try:
        print green("Welcome to Viper!\n")
        print red("Warning: Some functions will require running Viper with sudo (e.g. nmap SYN scans)!\n")
        print green("""Please select a job from the options below.

    1. Intelligence Gathering (Passive)

    2. Penetration Testing (Active)

    3. Reporting

    4. Phishing

    0. Exit
        """)
        option = raw_input("Your tool: ")
        if option == "1":
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
            print red("No tools for that job (invalid input).")
            main()
    except (KeyboardInterrupt):
        main()

#Intel menu options
def intelMenu():
    global domain
    global client
    print """
    """
    if client == "":
        client = raw_input("Client's name: ")
    if domain == "":
        domain = raw_input("Enter the domain: ")
    print green("""The Shadow-Viper intelligence gathering toolkit:

    1. Harvest email addresses and social media accounts

    2. Collect domain information

    3. Discover files for the domain

    4. Knowing is half the battle

    0. Return
    """)
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
    # I don't know yet!
    elif option == "4":
        print red("G.") + "I." + blue(" Jooooe!")
        intelMenu()
    #Exit to main menu
    elif option == "0":
        main()
    else:
        print red("The tool isn't here. Does it exist?.")
        intelMenu()

#Penetration testing menu options
def pentestMenu():
    print green("""The Pit-Viper penetration testing toolkit:

Some of these scans require running Viper with sudo!

    1. Check your scope

    2. Network - Active scanning with nmap and masscan (you pick)

    3. Web - Scanning with ZAP, Nikto, and other tools

    4.

    0. Return
    """)
    option = raw_input("Select a tool: ")
    if option == "1":
        print green("""
Viper will attempt to verify ownership of the provided IP addresses
using various tools: ARIN, whois, DNS, and SSL cert informaiton.
Please provide a list of IPs in a text file and Viper will output a CSV of results.""")
        # initialize our array for IP address storage
        ips = []
        # initialize our dict for info storage
        out = {}

        infile = raw_input("File with IPs:")
        outfile = raw_input("Output filename for CSV:")
        CIDR = raw_input("Is there a CIDR (y/n?):")
        if CIDR == "y":
            breakrange = True
        else:
            breakrange = False
        verify.infile(infile, ips, breakrange)
        verify.who(ips, out)
        verify.outfile(out, outfile)
        pentestMenu()
    elif option == "2":
        print green("""
Viper has shortcuts for many of the popular scanners.
Select a scanner, provide a text file with IPs, and Viper will take care of the rest.
You can run full nmap SYN scans, the same with common scripts, or Masscan with full ports.
For custom Masscan scans, edit Viper's masscan.config file.
""")
        print red("""SYN scans require sudo! Start Viper with sudo if you want to use them.
""")
        print green("""Select a scan to run:

    1. Standard nmap SYN full scan (-sSV -T4 -p-)

    2. With scripts nmap (-sSC)

    3. Standard full masscan (-p0-65535)

    4. Masscan with conf file (-c)

    0. Return
        """)
        option = raw_input("Select an option: ")
        if option == "1":
            scanType = 1
            scan_tools.runNMAP(scanType)
            pentestMenu()
        if option == "2":
            scanType = 2
            scan_tools.runNMAP(scanType)
            pentestMenu()
    elif option == "2":
        print "Under construction!"
    elif option == "3":
        print "Under construction!"
    elif option == "0":
        main()
    else:
        print red("The tool isn't here. Does it exist?.")
        pentestMenu()

#Reporting menu options
def reportingMenu():
    print green("""The Ninja-Viper reporting toolkit:

    1. Combine multiple Nessus reports (.nessus)

    2.

    3.

    4.

    0. Return
    """)
    option = raw_input("Select a tool: ")
    if option == "1":
        print "Under construction!"
    elif option == "2":
        print "Under construction!"
    elif option == "3":
        print "Under construction!"
    elif option == "4":
        print "Under construction!"
    elif option == "0":
        main()
    else:
        print red("The tool isn't here. Does it exist?.")
        reortingMenu()

#Phishing menu options
def phishingMenu():
    print green("""The Swamp-Viper phishing toolkit:

    1. Parse list of names into first and last (csv)

    2.

    3.

    4.

    0. Return
    """)
    option = raw_input("Select a tool: ")
    if option == "1":
        print "Under construction!"
    elif option == "2":
        print "Under construction!"
    elif option == "3":
        print "Under construction!"
    elif option == "4":
        print "Under construction!"
    elif option == "0":
        main()
    else:
        print red("The tool isn't here. Does it exist?.")
        phishingMenu()

if __name__ == "__main__":
    main()
