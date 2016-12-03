#!/usr/bin/env python
# Original - https://github.com/TrullJ/ssllabs

"""Add Docstring"""

import requests
import time
from colors import red, green, yellow, blue

API = "https://api.ssllabs.com/api/v2/"


def requestAPI(path, payload={}):
	"""This is a helper method that takes the path to the relevant API call and
	the user-defined payload and requests the data/server test from Qualys SSL Labs.
	Returns JSON formatted data
	"""
	url = API + path

	try:
		response = requests.get(url, params=payload)
	except requests.exception.RequestException as e:
		print(e)
		sys.exit(1)

	data = response.json()
	return data


def resultsFromCache(host, publish = "off", startNew = "off", fromCache = "on", all = "done"):
	"""This function returns results from SSL Labs' cache (previously run scans)
	"""
	path = "analyze"
	payload = {'host': host, 'publish': publish, 'startNew': startNew, 'fromCache': fromCache, 'all': all}
	data = requestAPI(path, payload)
	return data


def newScan(host, publish = "off", startNew = "on", all = "done", ignoreMismatch = "on"):
	"""This function requests SSL Labs to run new scan for the target domain
	"""
	path = "analyze"
	payload = {'host': host, 'publish': publish, 'startNew': startNew, 'all': all, 'ignoreMismatch': ignoreMismatch}
	results = requestAPI(path, payload)

	payload.pop('startNew')

	while results['status'] != 'READY' and results['status'] != 'ERROR':
		print("Scan in progress, please wait for the results.")
		time.sleep(30)
		results = requestAPI(path, payload)

	return results


def getResults(target, type):
	"""Function to run a new scan or request information from SSL Labs' cahce (old scans)
	This sorts through the LOADS of information returned by the scanner
	We need individual try/excepts in case one piece of information is unavailable for some reason
	This avoids the whole thing failing because of one litte variable
	Docs - https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
	"""
	testType = type
	# Create scanner based on type - new or cached results
	if testType == 1:
		data = newScan(target)
		print(green("[+] Running a new SSL Labs scan - this will take some time..."))
	if testType == 2:
		data = resultsFromCache(target)
		print(green("[+] Getting results from SSL Labs's cache (if there is a cached test)..."))

	# Server name
	try:
		print(green("Server Name: %s" % data['endpoints'][0]['serverName']))
	except:
		print(red("Server Name: Unavailable"))

	# IP address
	try:
		print(green("IP Address: %s" % data['endpoints'][0]['ipAddress']))
	except:
		print(red("[!] IP Address: Unavailable!"))

	# SSL Labs Grades
	try:
		print(green("Grade: %s" % data['endpoints'][0]['grade']))
	except Exception as e:
		print(red("Grade: Unavailable"))
	try:
		print(green("SGrade: %s" % data['endpoints'][0]['gradeTrustIgnored']))
	except:
		print(red("SGrade: Unavailable"))

	# SSL versions
	ssl2 = "No"
	ssl3 = "No"
	try:
		for proto in data['endpoints'][0]['details']['protocols']:
			if "SSL" in proto['name'] and proto['version'] == "2.0":
				ssl2 = "Yes"
			if "SSL" in proto['name'] and proto['version'] == "3.0":
				ssl3 = "Yes"
		print(green("SSLv2: %s" % ssl2))
		print(green("SSLv3: %s" % ssl3))
	except:
		print(red("SSLv2/3: SSL version support information unavailable"))

	# CRIME
	try:
		crime = "No"
		if data['endpoints'][0]['details']['compressionMethods']!= 0 and result['endpoints'][0]['details']['supportsNpn'] == False:
			crime ="Yes"
			print(green("CRIME: %s" % crime))
		else:
			print(green("CRIME: %s" % crime))
	except:
		print(red("CRIME: Status unavailable"))

	# FREAK
	try:
		print(green("FREAK: %s" % data['endpoints'][0]['details']['freak']))
	except:
		print(red("FREAK: Status unavailable"))

	# POODLE SSL
	try:
		poodleSSL = "No"
		if data['endpoints'][0]['details']['poodle'] == True:
			poodleSSL = "Yes"
		print(green("POODLE SSL: %s" % poodleSSL))
		poodleTLS = data['endpoints'][0]['details']['poodleTls']
		if poodleTLS == 1:
			print(green("POODLE TLS: No"))
		if poodleTLS == 2:
			print(green("POODLE TLS: Yes"))
	except:
		print(red("POODLE SSL: Status unavailable"))

	# POODLE TLS
	try:
		poodleTLS = data['endpoints'][0]['details']['poodleTls']
		if poodleTLS == 2:
			print(green("POODLE TLS: Yes"))
		elif poodleTLS == 1:
			print(green("POODLE TLS: No"))
		else:
			print(green("POODLE TLS: Failed check"))
	except:
		print(red("POODLE TLS: Status unavailable"))

	# Heartbleed
	try:
		print(green("Heartbleed: %s" % data['endpoints'][0]['details']['heartbleed']))
	except:
		print(red("Heartbleed: Status unavailable"))

	# Renegotiation Support
	try:
		reneg = data['endpoints'][0]['details']['renegSupport']
		if reneg != 0:
			print(green("Renegotiation: Yes"))
		else:
			print(green("Renegotiation: No"))
	except:
		print(red("Renegotiation: Status unavailable"))

	# OpenSSL CCS Injection
	try:
		ccs = data['endpoints'][0]['details']['openSslCcs']
		if ccs == 1:
			print(green("OpenSSL CCS Injection: No"))
		elif ccs == 3:
			print(green("OpenSSL CCS Injection: Yes"))
		else:
			print(green("OpenSSL CCS Injection: No"))
	except:
		print(red("OpenSSL CCS Injection: Status unavailable"))

	# DHE suites
	try:
		dhe = "No"
		for suite in data['endpoints'][0]['details']['suites']['list']:
			try:
				if "DHE" in suite['name']:
					try:
						if suite['q'] == 0:
							dhe = "Yes"
							print(green("Possible Insecure DHE: %s" % suite['name']))
					except:
						print(green("Secure Suite: %s" % suite['name']))
			except:
					print(red("DHE Suites: DHE suite information unavailable"))
	except:
		print(red("DHE Suites: DHE suite information unavailable"))

	# RC4
	try:
			rc4 = data['endpoints'][0]['details']['supportsRc4']
			if rc4:
				rc4 ="Yes"
			else:
				rc4 = "No"
			print(green("RC4: %s" % rc4))
	except:
		print(red("RC4: Status unavailable"))
