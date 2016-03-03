#!/usr/bin/env python
# Original - https://github.com/TrullJ/ssllabs

"""Add Docstring"""

import requests
import time
from colors import red, green, yellow, blue

API = "https://api.ssllabs.com/api/v2/"

def requestAPI(path, payload={}):

	"""This is a helper method that takes the path to the relevant
		API call and the user-defined payload and requests the
		data/server test from Qualys SSL Labs.

		Returns JSON formatted data"""

	url = API + path

	try:
		response = requests.get(url, params=payload)
	except requests.exception.RequestException as e:
		print e
		sys.exit(1)

	data = response.json()
	return data

def resultsFromCache(host, publish = "off", startNew = "off", fromCache = "on", all = "done"):

	path = "analyze"
	payload = {'host': host, 'publish': publish, 'startNew': startNew, 'fromCache': fromCache, 'all': all}
	data = requestAPI(path, payload)
	return data

def newScan(host, publish = "off", startNew = "on", all = "done", ignoreMismatch = "on"):

	path = "analyze"
	payload = {'host': host, 'publish': publish, 'startNew': startNew, 'all': all, 'ignoreMismatch': ignoreMismatch}
	results = requestAPI(path, payload)

	payload.pop('startNew')

	while results['status'] != 'READY' and results['status'] != 'ERROR':
		print("Scan in progress, please wait for the results.")
		time.sleep(30)
		results = requestAPI(path, payload)

	return results

def getResults(target,type):
	testType = type
	# Create scanner based on type - new or cached results
	if testType == 1:
		data = newScan(target)
		print green("[+] Running a new SSL Labs scan - this will take some time...")
	if testType == 2:
		data = resultsFromCache(target)
		print green("[+] Getting results from SSL Labs's cache (if there is a cached test)...")
	# Sorting through the LOADS of information returned by the scanner
	# We need individual try/excepts in case one piece of information is unavailable for some reason
	# This avoids the whole thing failing because of one litte variable
	# Server name
	try:
		print green("Server Name: %s" % data['endpoints'][0]['serverName'])
	except:
		print red("[!] Could not retrieve server name!")
	# IP Address
	try:
		print green("IP Address: %s" % data['endpoints'][0]['ipAddress'])
	except Exception as e:
		print red("[!] Could not retrieve server name!")
		print red("[!] Error: %s" % e)
	# Grades
	try:
		print green("Grade: %s" % data['endpoints'][0]['grade'])
	except Exception as e:
		print red("[!] Could not retrieve SSL Labs grade!")
		print red("[!] Error: %s" % e)
	try:
		print green("SGrade: %s" % data['endpoints'][0]['gradeTrustIgnored'])
	except Exception as e:
		print red("[!] Could not retrieve SSL Labs grade!")
		print red("[!] Error: %s" % e)
	# CRIME
	try:
		crime = "No"
			if data['endpoints'][0]['details']['compressionMethods']!= 0 and result['endpoints'][0]['details']['supportsNpn'] == False:
				crime ="Yes"
	except Exception as e:
		print red("[!] Could not determine CRIME vulnerability!")
		print red("[!] Error: %s" % e)
	# FREAK
	try:
		print green("Freak: %s" % data['endpoints'][0]['details']['freak'])
	except Exception as e:
		print red("[!] Could not detemrine FREAK vulnerability!")
		print red("[!] Error: %s" % e)
	# Poodle vuln check
	try:
		poodleSSL = "No"
		if data['endpoints'][0]['details']['poodle'] == True:
			poodleSSL = "Yes"
		print green("Poodle SSL: %s" % poodleSSL)
		poodleTLS = data['endpoints'][0]['details']['poodleTls']
		if poodleTLS == 1:
			print green("Poodle TLS: No")
		if poodleTLS == 2:
			print green("Poodle TLS: Yes")
	except Exception as e:
		print red("[!] Could not retrieve info for Poodle vuln!")
		print red("[!] Error: %s" % e)
	# Heartbleed
	try:
		print green("Heartbleed: %s" % data['endpoints'][0]['details']['heartbleed'])
	except Exception as e:
		print red("[!] Could not retrieve info for Heartbleed vuln!")
		print red("[!] Error: %s" % e)
	# Renegotiation Support
	try:
		reneg = data['endpoints'][0]['details']['renegSupport']
		if reneg != 0:
			print green("Renegotiation: Yes")
		else:
			print green("Renegotiation: No")
	except Exception as e:
		print red("[!] Could not retrieve info for Heartbleed vuln!")
		print red("[!] Error: %s" % e)
	# OpenSSL CCS Injection
	try:
		ccs = data['endpoints'][0]['details']['openSslCcs']
		if ccs == 1:
			print green("OpenSSL CCS Injection: No")
		elif ccs == 3:
			print green("OpenSSL CCS Injection: Yes")
		else:
			print green("OpenSSL CCS Injection: No")
	except Exception as e:
		print red("[!] Could not retrieve info for OpenSSL CCS Injection vuln!")
		print red("[!] Error: %s" % e)
	# DHE suites
	try:
		dhe = "No"
		for suite in data['endpoints'][0]['details']['suites']['list']:
			try:
				if "DHE" in suite['name']:
					try:
						if suite['q'] == 0:
							dhe = "Yes"
							print green("Possible Insecure DHE: %s" % suite['name'])
					except:
						print green("Secure Suite: %s" % suite['name'])
			except Exception as e:
					print red("[!] Problem finding DHE suites!")
					print red("Error: %s" % e)
	except Exception as e:
		print red("[!] Could not retrieve info for DHE suites!")
		print red("[!] Error: %s" % e)
	# SSL versions
	ssl2 = "No"
	ssl3 = "No"
	try:
		for proto in data['endpoints'][0]['details']['protocols']:
			if "SSL" in proto['name'] and proto['version'] == "2.0":
				ssl2 = "Yes"
			if "SSL" in proto['name'] and proto['version'] == "3.0":
				ssl3 = "Yes"
		print green("SSLv2: %s" % ssl2)
		print green("SSLv3: %s" % ssl3)
	except Exception as e:
		print red("[!] Could not retrieve SSL support information!")
		print red("[!] Error: %s" % e)
	# RC4
	try:
			rc4 = data['endpoints'][0]['details']['supportsRc4']
			if rc4:
				rc4 ="Yes"
			else:
				rc4 = "No"
			print green("RC4: %s" % rc4)
	except Exception as e:
		print red("[!] Could not retrieve RC4 support information!")
		print red("[!] Error: %s" % e)
