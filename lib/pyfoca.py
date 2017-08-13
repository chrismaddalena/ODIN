#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module works like a Python version of FOCA. It
can be used to search Google for files under a provided
domain and then extract metadata from discovered files.
"""

import os
import re
import time
import subprocess
import requests
from colors import red, green
from PyPDF2 import PdfFileReader


TOTAL_FILES = 0
ED_FROM = 0


class Metaparser:
    """This class will search a domain for files and then attempt to extract
    metadata from any discovered files.
    """
    def __init__(self, domain_name, page_results, exts, del_files, verbose):
        self.container = list()
        self.offset = [0]
        self.data_exists = [0]
        self.top_row = [' | File Name', 'Creation Date', 'Author', 'Produced By',
                        'Modification Date', 'Last Saved By']
        self.top_rowf = ['Folders', 'Operating System(s)', 'Printers', 'Software',
                         'Users', 'Emails']
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
        global ED_FROM
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
                doc_info = pdf_file.getDocumentInfo()
                if not doc_info:
                    return
                last_saved = '-'
                # Looks at the entire dictionary to parse for information
                if "/CreationDate" in doc_info:
                    data = doc_info["/CreationDate"].strip("D:|'")
                    year = data[0:4]
                    date = data[4:6] + "/" + data[6:8]
                    created_time = data[8:10] + ":" + data[10:12]
                    created_time = time.strftime("%I:%M %p", time.strptime(created_time, "%H:%M"))
                    created = date + "/" + year + " " + created_time

                if "/Author" in doc_info:
                    author = doc_info["/Author"] + " "
                    if len(author) <= 1:
                        author = "-"

                if "/Producer" in doc_info:
                    producer = doc_info["/Producer"].strip("(Windows)")
                    producer = re.sub(r'[^\w]', ' ', producer)
                    if len(producer) == 0:
                        producer = "-"
                    while True:
                        if "  " in producer:
                            producer = producer.replace("  ", " ")
                        else:
                            break

                if "/ModDate" in doc_info:
                    data = doc_info["/ModDate"].strip("D:|'")
                    year = data[0:4]
                    date = data[4:6] + "/" + data[6:8]
                    modded_time = data[8:10] + ":" + data[10:12]
                    modded_time = time.strftime("%I:%M %p", time.strptime(modded_time, "%H:%M"))
                    modded = date + "/" + year + " "  + modded_time

                # Strips '/' off filename (if it includes directory name)
                if "/" in curr_file:
                    curr_file = curr_file[curr_file.rfind("/")+1:]
                if "\\" in curr_file:
                    curr_file = curr_file.replace("\\", "")

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
            except:
                return
        else:
            try:
                curr_file = curr_file.replace(" ", "\ ").replace("(", "\(")\
                    .replace(")", "\)")
                output = subprocess.check_output('extract -V ' + curr_file, shell=True)\
                    .decode('utf-8').split('\n')
                if "extract: not found" in output[0]:
                    print(red("[!] PyFOCA requires the 'extract' command."))
                    print(red("L.. Please install extract by typing 'apt-get \
install extract' in terminal."))
                    exit()

                for i in output:
                    if "creator" in i:
                        author = i[i.find("-")+2:]
                        rem_alphanumeric = re.compile(r'\W')
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
                        date = i[i.find(year)+5:(i.find(year)+5)+5].replace("-", "/")
                        modded_time = i[i.find(":")-2:i.rfind(":")-1]
                        modded_time = time.strftime("%I:%M %p", time.strptime(modded_time, "%H:%M"))
                        modded = date + "/" + year + " " + modded_time
                    elif "generator" in i:
                        producer = i[i.find('-')+2:]
                    elif "creation" in i:
                        year = i[i.find('-')+2:(i.find('-')+2)+4]
                        date = i[i.find(year)+5:(i.find(year)+5)+5].replace("-", "/")
                        created_time = i[i.find(":")-2:i.rfind(":")-1]
                        created_time = time.strftime("%I:%M %p",
                                                     time.strptime(created_time, "%H:%M"))
                        created = date + "/" + year + " " + created_time
                    elif "last saved" in i:
                        last_saved = i[i.find('-')+2:]

                if "/" in curr_file:
                    curr_file = curr_file[curr_file.rfind("/")+1:]

                if "\\" in curr_file:
                    curr_file = curr_file.replace("\\", "")

                # Trim the file name if it's longer than 15 characters
                if len(curr_file) > 15:
                    curr_file = curr_file[:9] + "..." + curr_file[-13:]

                if author != "-" or date != "-" or generator != "-" or created != "-" or \
                    producer != "-" or modded != "-" or last_saved != "-":
                    self.container.append([" | " + curr_file, created, author,
                                           producer, modded, last_saved])
            except Exception as error:
                if "command not found" in str(error):
                    print(red("[!] PyFOCA requires the 'extract' command."))
                    print(red("L.. Please install extract by typing 'apt-get \
install extract' in terminal."))
                    exit()
                return

    def grab_meta(self):
        """This function collects the metadata from files."""
        global TOTAL_FILES
        files = []

        print(green("[+] Domain: {}".format(self.domain_name)))
        print(green("[+] Attempting to gather links from Google searches..."))

        total_count = 0

        for extension in self.exts:
            count = 0
            while count < self.page_results:
                request = requests.get("https://www.google.com/search?q=site:{}+ext:{}&start={}0"\
                    .format(self.domain_name, extension, count))
                contents = request.text
                new_pattern = "(?P<url>https?://[^:]+\.%s)" % extension
                new_pattern = re.findall(new_pattern, contents)
                for hit in new_pattern:
                    if hit not in files:
                        files.append(hit)
                count += 1
                total_count += 1
                TOTAL_FILES = len(files)

        if len(files) == 0:
            print(green("[+] No files were located within Google based on \
the extension(s) and domain you provided."))
            exit()

        print(green("[+] Discovered {} files from {} total Google \
searches...").format(len(files), total_count))

        # Create pyfoca-downloads directory if it doesn't exist
        if not os.path.exists('reports/pyfoca-downloads'):
            print(green("[+] Creating reports/pyfoca-downloads folder..."))
            os.makedirs('reports/pyfoca-downloads')

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
        for item in files:
            if "..." in item:
                del files[files.index(item)]
                continue
            pdf_name = item[item.rfind("/")+1:]
            try:
                response = requests.get(item)
                source = response.content
                with open('reports/pyfoca-downloads/%s' % pdf_name, 'wb') as file_descriptor:
                    file_descriptor.write(source)
                pdf_name = pdf_name.replace("(", "\(").replace(")", "\)")
                if len(pdf_name) > 10:
                    short_file = pdf_name[:10] + "..." + pdf_name[-10:]
                else:
                    short_file = pdf_name
            except Exception as error:
                print(red("[!] There was an error downloading a file from this URL:\n{}"
                      .format(item)))
                # print(red("L.. Details: {}").format(error))
                continue

        for item in files:
            pdf_name = item[item.rfind("/")+1:]
            self.process_file('reports/pyfoca-downloads/%s' % pdf_name)

        return self.container

    def clean_up(self):
        """Small function to clean-up downloaded files."""
        if self.del_files is True:
            print(green("[+] Done and deleting reports/pyfoca-downloads folder for clean-up."))
            try:
                subprocess.Popen('rm -rf reports/pyfoca-downloads/', shell=True)
            except Exception as error:
                print(red("[!] Failed to delete reports/pyfoca-downloads folder!"))
                print(red("L.. Details: {}".format(error)))
        else:
            print(green("[+] Done! Downloaded files can be found in reports/pyfoca-downloads."))
