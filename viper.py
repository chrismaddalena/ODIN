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
from lib import *

domain = ""
client = ""

def main():
    # Clear the terminal window
    os.system('cls' if os.name == 'nt' else 'clear')
    asciis.printArt()
    try:
        print """Please select a job from the options below.

    1. Intelligence Gathering (Passive)

    2. Penetration Testing (Active)

    3. Reporting

    4. Phishing

    5. CVS

    0. Exit
        """
        option = raw_input("Your tool: ")
        if option == "1":
            intelMenu()
        if option == "2":
            pentestMenu()
        elif option == "3":
            reportingMenu()
        elif option == "4":
            phishingMenu()
        elif option == "5":
            cvsMenu()
        elif option == "0":
            print "The shed's door slams shut with a clang of its latch."
            sys.exit()
        else:
            print "No tools for that job (invalid input)."
            main()
    except (KeyboardInterrupt):
        main()

#Intel menu options
def intelMenu():
    global domain
    global client
    print """Enter the domain name you wish to target (e.g. clientcompany.com).
Then you will be asked to select the intelligence you want to gather.
    """
    if client == "":
        client = raw_input("Client's name: ")
    if domain == "":
        domain = raw_input("Enter the domain: ")
    print """The intelligence gathering toolkit:

    1. Harvest email addresses

    2. Collect domain information

    3. Discover files

    4.

    0. Return
    """
    option = raw_input("Select a tool: ")
    # Email tools
    if option == "1":
        email_tools.harvest(client,domain)
        email_tools.pwnedCheck()
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
        print "Under construction!"
    #Exit to main menu
    elif option == "0":
        main()
    else:
        print "The tool isn't here. Does it exist?."
        pentestMenu()

#Penetration testing menu options
def pentestMenu():
    print """
    The penetration testing toolkit:

    1.

    2.

    3.

    4.

    0. Return
    """
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
        print "The tool isn't here. Does it exist?."
        pentestMenu()

#Reporting menu options
def reportingMenu():
    print """
    The reprting toolkit:

    1.

    2.

    3.

    4.

    0. Return
    """
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
        print "The tool isn't here. Does it exist?."
        reortingMenu()

#Phising menu options
def phishingMenu():
    print """
    The phishing toolkit:

    1.

    2.

    3.

    4.

    0. Return
    """
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
        print "The tool isn't here. Does it exist?."
        phishingMenu()

#CVS menu options
def cvsMenu():
    print """
    The CVS Toolkit:

    1.

    2.

    3.

    4.

    0. Return
    """
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
        print "The tool isn't here. Does it exist?."
        cvsMenu()


if __name__ == "__main__":
    main()
