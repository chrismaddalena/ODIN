#!/usr/bin/python3

import click
import os
import requests
import socket
import re
import time
import subprocess
import sys
from colors import *
import PyPDF2
from PyPDF2 import PdfFileReader


curr_time = time.time()
total_files = 0
ed_from = 0


class metaparser:
	"""This class will search a domain for files and then attempt to extract
	metadata from any discovered files.
	"""
	def __init__(self, domain_name, page_results, exts, del_files, verbose):
		self.container = list()
		self.offset = [0]
		self.data_exists = [0]
		self.top_row = [' | File Name','Creation Date','Author','Produced By','Modification Date','Last Saved By']
		self.top_rowf = ['Folders','Operating System(s)','Printers','Software','Users','Emails']
		self.domain_name = domain_name
		self.page_results = page_results
		self.total_success = 0
		self.exts = exts
		self.del_files = del_files
		self.verbose = verbose

		while len(self.offset) < len(self.top_row):
			self.offset.append(0)
			self.data_exists.append(0)

	def process_file(self, curr_file):
		"""Function to process the provided file. If the file is a PDF, the PyPDF2
		library will be used. Otherwise, the extract tool is used, so extract must
		be installed. This is the one piece that requires Linux.
		"""
		global ed_from
		author = '-'
		date = '-'
		generator = '-'
		created = '-'
		producer = '-'
		modded = '-'
		last_saved = '-'
		if ".pdf" in curr_file:
			try:
				pdf_file = PdfFileReader(open(curr_file, 'rb'))
				if pdf_file.getIsEncrypted():
					pdf_file.decrypt('')
				docInfo = pdf_file.getDocumentInfo()
				if not docInfo:
					return
				last_saved = '-'
				# Looks at the entire dictionary to parse for information
				if "/CreationDate" in docInfo:
					data = docInfo["/CreationDate"].strip("D:|'")
					year = data[0:4]
					date = data[4:6] + "/" + data[6:8]
					created_time = data[8:10] + ":" + data[10:12]
					created_time = time.strftime("%I:%M %p", time.strptime(created_time, "%H:%M"))
					created = date + "/" + year + " " + created_time
					
				if "/Author" in docInfo:
					author = docInfo["/Author"] + " "
					if len(author) <=1:
						author = "-"

				if "/Producer" in docInfo:
					producer = docInfo["/Producer"].strip("(Windows)")
					producer = re.sub(r'[^\w]', ' ', producer)
					if len(producer) == 0:
						producer = "-"
					while True:
						if "  " in producer:
							producer = producer.replace("  ", " ")
						else:
							break

				if "/ModDate" in docInfo:
					data = docInfo["/ModDate"].strip("D:|'")
					year = data[0:4]
					date = data[4:6] + "/" + data[6:8]
					modded_time = data[8:10] + ":" + data[10:12]
					modded_time = time.strftime("%I:%M %p", time.strptime(modded_time, "%H:%M"))
					modded = date + "/" + year + " "  + modded_time

				# Strips '/' off filename (if it includes directory name)
				if "/" in curr_file:
					curr_file = curr_file[curr_file.rfind("/")+1:]
				if "\\" in curr_file:
					curr_file = curr_file.replace("\\","")

				# Trim information if it's too long
				if len(curr_file) > 15:
					curr_file = curr_file[:15] + "..." + curr_file[-13:]
				if len(producer) > 30:
					producer = producer[:20] + " [snipped] "
				if len(author) > 20:
					author = author[:20] + " [snipped] "

				# Appends each piece of information
				# Output will show ONLY if at least ONE file has data in a column
				self.container.append([curr_file, created, author, producer, modded, last_saved])
			except Exception as e:
				return
		else:
			try:
				curr_file = curr_file.replace(" ","\ ").replace("(", "\(").replace(")", "\)")
				output = subprocess.check_output('extract -V ' + curr_file, shell=True).decode('utf-8').split('\n')
				if "extract: not found" in output[0]:
					print(red("[!] PyFOCA requires the 'extract' command."))
					print(red("L.. Please install extract by typing 'apt-get install extract' in terminal."))
					exit()

				for i in output:
					if "creator" in i:
						author = i[i.find("-")+2:]
						rem_alphanumeric = re.compile('\W')
						author = re.sub(rem_alphanumeric, ' ', author)
						while True:
							if "  " in author:
								author = author.replace("  ", " ")
							elif author[0] == " ":
								author = author[1:]
							else:
								break
					elif "date" in i and "creation" not in i:
						year = i[i.find('-')+2:(i.find('-')+2)+4]
						date = i[i.find(year)+5:(i.find(year)+5)+5].replace("-","/")
						modded_time = i[i.find(":")-2:i.rfind(":")-1]
						modded_time = time.strftime("%I:%M %p", time.strptime(modded_time, "%H:%M"))
						modded = date + "/" + year + " " + modded_time
					elif "generator" in i:
						producer = i[i.find('-')+2:]
					elif "creation" in i:
						year = i[i.find('-')+2:(i.find('-')+2)+4]
						date = i[i.find(year)+5:(i.find(year)+5)+5].replace("-","/")
						created_time = i[i.find(":")-2:i.rfind(":")-1]
						created_time = time.strftime("%I:%M %p", time.strptime(created_time, "%H:%M"))
						created = date + "/" + year + " " + created_time
					elif "last saved" in i:
						last_saved = i[i.find('-')+2:]

				if "/" in curr_file:
					curr_file = curr_file[curr_file.rfind("/")+1:]

				if "\\" in curr_file:
					curr_file = curr_file.replace("\\","")

				# Trim the file name if it's longer than 15 characters
				if len(curr_file) > 15:
					curr_file = curr_file[:9] + "..." + curr_file[-13:]

				if author != "-" or date != "-" or generator != "-" or created != "-" or producer != "-" or modded != "-" or last_saved != "-":
					self.container.append([" | " + curr_file,created,author,producer,modded,last_saved])
			except Exception as e:
				if "command not found" in str(e):
					print(red("[!] PyFOCA requires the 'extract' command."))
					print(red("L.. Please install extract by typing 'apt-get install extract' in terminal."))
					exit()
				return

		extracted_from = len(self.container)

	def grab_meta(self):
		"""This function collects the metadata from files."""
		global total_files
		foundFile = False
		files = []

		# FOCA file types
		folders_file = []
		os_file = []
		printers_file = []
		software_file = []
		users_file = []
		emails_file = []
		self.foca_filetypes = []

		print(green("[+] Domain: {}".format(self.domain_name)))
		print(green("[+] Attempting to gather links from google searches..."))

		total_count = 0

		for e in self.exts:
			count = 0
			while count < self.page_results:
				r = requests.get("https://www.google.com/search?q=site:{}+ext:{}&start={}0".format(self.domain_name, e, count))
				contents = r.text
				new_pattern = "(?P<url>https?://[^:]+\.%s)" % e
				new_pattern = re.findall(new_pattern,contents)
				for n in new_pattern:
					if n not in files:
						files.append(n)
				count += 1
				total_count += 1
				total_files = len(files)

		if len(files) == 0:
			print(green("[+] No files were located within Google based on the extension(s) and domain you provided."))
			exit()

		print(green("[+] Discovered {} files from {} total google searches...").format(len(files), total_count))

		# Create pyfoca-downloads directory if it doesn't exist
		if not os.path.exists('pyfoca-downloads'):
			print(green("[+] Creating pyfoca-downloads folder..."))
			os.makedirs('pyfoca-downloads')

		# Set maximum number of spaces for pdf file names
		spaces = 0
		for item in files:
			item = item[item.rfind("/")+1:]
			if len(item) > 10:
				short_file = item[:10] + "..." + item[-10:]
			else:
				short_file = item
			if len(short_file) > spaces:
				spaces = len(short_file) + 3

		print(green("[+] Attempting to download files..."))
		if self.verbose == False:
			print(green("[+] Please wait..."))

		# Download each file that has been added to the 'files' variable
		print(green("-------------------------------"))
		for f in files:
			if "..." in f:
				del files[files.index(f)]
				continue
			pdf_name = f[f.rfind("/")+1:]
			try:
				response = requests.get(f)
				source = response.content
				with open('pyfoca-downloads/%s' % pdf_name, 'wb') as fd:
					fd.write(source)
					# for chunk in r.iter_content(chunk_size=128):
					# 	fd.write(chunk)
				# write_file = open('pyfoca-downloads/%s' % pdf_name, 'wb')
				# write_file.write(source)
				# write_file.close()
				name = pdf_name.replace("(", "\(").replace(")", "\)")
				if len(pdf_name) > 10:
					short_file = pdf_name[:10] + "..." + pdf_name[-10:]
				else:
					short_file = pdf_name
			except Exception as e:
				print(red("[!] There was an error downloading the files."))
				print(red("L.. Details: {}").format(e))
				continue
		print
		for e in files:
			pdf_name = e[e.rfind("/")+1:]
			self.process_file('pyfoca-downloads/%s' % pdf_name)

		return self.container

	def clean_up(self):
		if self.del_files is True:
			print(green("[+] Done and deleting pyfoca-downloads folder for clean-up."))
			try:
				subprocess.Popen('rm -rf pyfoca-downloads/', shell=True)
			except Exception as e:
				print(red("[!] Failed to delete pyfoca-downloads folder!"))
				print(red("L.. Details: {}".format(e)))
		else:
			print(green("[+] Done! Downloaded files can be found in pyfoca-downloads."))
