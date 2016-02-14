#!/usr/bin/env python

"""Add Docstring"""

import requests
import time

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
	














