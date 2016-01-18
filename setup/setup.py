#!/usr/bin/env python

import os
from time import sleep
import sys

def setup():
    if not os.path.exists("../auth"):
        print "Adding the 'auth' directory."
        try:
            os.mkdir("../auth")
            sleep(2)
            shodanSetup()
        except:
            exit("run as sudo!")
    elif os.path.exists("../auth"):
        twittersetup()
        shodansetup()
    else:
        exit("Could not proceed with setup! Try running as sudo!")

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

setup()
