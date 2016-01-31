#!/usr/bin/env python
# Credit to by buddy, Roy Firestein, for the original script
# https://github.com/eSentire/nessus_join

import os
import xml.dom.minidom
from optparse import OptionParser

def parse_targets(domxml, set_value=None):
	pref = domxml.getElementsByTagName('ServerPreferences')[0]
	for p in pref.childNodes:
		for c in p.childNodes:
			if c.nodeType == c.ELEMENT_NODE and c.childNodes[0].data == 'TARGET':
				if set_value:
					c.nextSibling.nextSibling.childNodes[0].data = set_value
					return domxml
				else:
					return c.nextSibling.nextSibling.childNodes[0].data.split(",")

def joiner(first,dir,output,name):
	files = []
	files.append(os.path.realpath(first))
	dir_nessus = os.path.realpath(dir)
	nessus_files = os.listdir(dir_nessus)
	scan_result = []
	targets = []
	counter = 0

	if nessus_files.__contains__(os.path.basename(files[0])):
		nessus_files.remove(os.path.basename(files[0]))
	for nes_file in nessus_files:
		files.append(os.path.join(dir_nessus, nes_file))

	for nes_file in files:
		nessus_xml = open(nes_file, 'r').read()
		if counter == 0:
			# first Nessus scan
			first_dom = xml.dom.minidom.parseString(nessus_xml)

			# Save report scope
			targets = parse_targets(first_dom)

			first_dom.getElementsByTagName('Report')[0].setAttribute('name', name)
		else:
			try:
				dom = xml.dom.minidom.parseString(nessus_xml)
				test = dom.getElementsByTagName('ReportHost')
			except:
				# if no element "ReportHost", skip this
				print "Could not parse %s" %nes_file
				continue
			for host in dom.getElementsByTagName('ReportHost'):
				scan_result.append(host)
			# Save targets
			target = parse_targets(dom)
			for t in target:
				if t not in targets:
					targets.append(t)
				else:
					print "Duplicate range (%s) found in %s" %(t, nes_file)
		counter=counter+1

	for node in scan_result:
		first_dom.getElementsByTagName('Report')[0].appendChild(node)

	# Update TARGETS perferences
	first_dom = parse_targets(first_dom, set_value=",".join(targets))

	# Save new combined report
	fh = open(output, 'w')
	fh.write(first_dom.toxml(encoding="utf-8"))
	fh.close()
