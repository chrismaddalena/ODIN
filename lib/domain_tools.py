#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This module contains all of tools and functions used for evaluating IP addresses/ranges and
domain names.
"""

import os
import subprocess
from xml.etree import ElementTree as ET
import csv
import base64
import re
import time
import shodan
from cymon import Cymon
import whois
import boto3
from botocore.exceptions import ClientError
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import requests
from colors import red, green, yellow
from netaddr import IPNetwork, iter_iprange
import dns.resolver
import validators
from selenium import webdriver
from lib import helpers
import click


class DomainCheck(object):
    """A class containing the tools for performing OSINT against IP addresses and domain names."""
    # Google-friendly user-agent
    my_headers = {'User-agent' : '(Mozilla/5.0 (Windows; U; Windows NT 6.0; \
        en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6'}
    # Sleep time for Google and Shodan
    sleep = 10
    # Cymon.io API endpoint
    cymon_api = "https://api.cymon.io/v2"
    # Robtex's free API endpoint
    robtex_api = "https://freeapi.robtex.com/ipquery/"

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Collect the API keys from the config file
        try:
            shodan_api_key = helpers.config_section_map("Shodan")["api_key"]
            self.shoAPI = shodan.Shodan(shodan_api_key)
        except Exception:
            self.shoAPI = None
            print(yellow("[!] Did not find a Shodan API key."))

        try:
            self.cymon_api_key = helpers.config_section_map("Cymon")["api_key"]
            self.cyAPI = Cymon(self.cymon_api_key)
        except Exception:
            self.cyAPI = Cymon()
            print(yellow("[!] Did not find a Cymon API key, so proceeding without API auth."))

        try:
            self.urlvoid_api_key = helpers.config_section_map("URLVoid")["api_key"]
        except Exception:
            self.urlvoid_api_key = ""
            print(yellow("[!] Did not find a URLVoid API key."))

        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except Exception:
            self.contact_api_key = None
            print(yellow("[!] Did not find a Full Contact API key."))

        try:
            self.censys_api_id = helpers.config_section_map("Censys")["api_id"]
            self.censys_api_secret = helpers.config_section_map("Censys")["api_secret"]
            self.CEN_API_URL = "https://censys.io/api/v1"
        except Exception:
            self.cenCertAPI = None
            self.cenAddAPI = None
            print(yellow("[!] Did not find a Censys API ID/secret."))

        try:
            self.chrome_driver_path = helpers.config_section_map("WebDriver")["driver_path"]
        except Exception:
            self.chrome_driver_path = None

        try:
            self.boto3_client = boto3.client('s3')
            # Test connecting to S3 with the creds supplied to `aws configure`
            self.boto3_client.head_bucket(Bucket="hostmenow")
        except Exception:
            self.boto3_client = None
            print(yellow("[!] Could not create an AWS client with the supplied secrets."))

    def generate_scope(self, scope_file):
        """Parse IP ranges inside the provided scope file to expand IP ranges. This supports ranges
        with hyphens, underscores, and CIDRs.
        """
        scope = []
        try:
            with open(scope_file, "r") as preparse:
                for i in preparse:
                    # Check if there is a hyphen
                    # Ex: 192.168.1.1-50 will become 192.168.1.1,192.168.1.50
                    i = i.rstrip()
                    if "-" in i:
                        print(green("[+] {} is a range - expanding...".format(i.rstrip())))
                        i = i.rstrip()
                        a = i.split("-")
                        startrange = a[0]
                        b = a[0]
                        dot_split = b.split(".")
                        j = "."
                        # Join the values using a "." so it makes a valid IP
                        combine = dot_split[0], dot_split[1], dot_split[2], a[1]
                        endrange = j.join(combine)
                        # Calculate the IP range
                        ip_list = list(iter_iprange(startrange, endrange))
                        # Iterate through the range and remove ip_list
                        for x in ip_list:
                            a = str(x)
                            scope.append(a)
                    # Check if range has an underscore
                    # Ex: 192.168.1.2_192.168.1.155
                    elif "_" in i:
                        print(green("[+] {} is a range - expanding...".format(i.rstrip())))
                        i = i.rstrip()
                        a = i.split("_")
                        startrange = a[0]
                        endrange = a[1]
                        ip_list = list(iter_iprange(startrange, endrange))
                        for address in ip_list:
                            str_address = str(address)
                            scope.append(str_address)
                    elif "/" in i:
                        print(green("[+] {} is a CIDR - converting...".format(i.rstrip())))
                        i = i.rstrip()
                        ip_list = list(IPNetwork(i))
                        for address in sorted(ip_list):
                            st = str(address)
                            scope.append(st)
                    else:
                        scope.append(i.rstrip())
        except Exception as error:
            print(red("[!] Parsing of scope file failed!"))
            print(red("L.. Details: {}".format(error)))

        return scope

    def full_contact_domain(self, domain):
        """Uses the Full Contact API to collect social media info. This returns the FullContact
        JSON response.

        An API key is required.
        """
        if self.contact_api_key == "":
            print(red("[!] No Full Contact API key, so skipping these searches."))
        else:
            base_url = "https://api.fullcontact.com/v2/company/lookup.json"
            payload = {'domain':domain, 'apiKey':self.contact_api_key}
            resp = requests.get(base_url, params=payload)

            if resp.status_code == 200:
                return resp.text.encode('ascii', 'ignore')

    def get_dns_record(self, domain, record_type):
        """Simple function to get the specified DNS record for the target domain."""
        answer = dns.resolver.query(domain, record_type)
        return answer

    def check_dns_cache(self, name_server):
        """Function to check if the given name server is vulnerable to DNS cache snooping.

        Code adapted for ODIN from work done by z0mbiehunt3r with DNS Snoopy.
        https://github.com/z0mbiehunt3r/dns-snoopy
        """
        vulnerable_dns_servers = ""
        # Domains that are commonly resolved and can be used for testing DNS servers
        common_domains = ["google.es", "google.com", "facebook.com", "youtube.com", "yahoo.com",
                          "live.com", "baidu.com", "wikipedia.org", "blogger.com", "msn.com",
                          "twitter.com", "wordpress.com", "amazon.com", "adobe.com",
                          "microsoft.com", "amazon.co.uk", "facebook.com"]

        answers = self.get_dns_record(name_server, "A")
        nameserver_ip = str(answers.rrset[0])
        for domain in common_domains:
            if self.dns_cache_request(domain, nameserver_ip):
                print(green("[+] {} resolved a cached query for {}.".format(name_server, domain)))
                vulnerable_dns_servers = name_server
                break

        return vulnerable_dns_servers

    def dns_cache_request(self, domain, nameserver_ip, checkttl=False, dns_snooped=False):
        """Function to perform cache requests against the name server for the provided domain."""
        resolver = dns.resolver
        query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
        # Negate recursion desired bit
        query.flags ^= dns.flags.RD
        dns_response = dns.query.udp(q=query, where=nameserver_ip)
        """
        Check length major of 0 to avoid those answers with root servers in authority section
        ;; QUESTION SECTION:
        ;www.facebook.com.        IN    A
        
        ;; AUTHORITY SECTION:
        com.            123348    IN    NS    d.gtld-servers.net.
        com.            123348    IN    NS    m.gtld-servers.net.
        [...]
        com.            123348    IN    NS    a.gtld-servers.net.
        com.            123348    IN    NS    g.gtld-servers.net.    `
        """
        if len(dns_response.answer) > 0 and checkttl:
            # Get cached TTL
            ttl_cached = dns_response.answer[0].ttl
            # First, get NS for the first cached domain
            cached_domain_dns = self.get_dns_record(domain, "NS")[0]
            # After, resolve its IP address
            cached_domain_dns_IP = self.get_dns_record(cached_domain_dns, "A")
            # Now, obtain original TTL
            query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
            query.flags ^= dns.flags.RD

            dns_response = dns.query.udp(q=query, where=cached_domain_dns_IP)
            ttl_original = dns_response.answer[0].ttl
            cached_ago = ttl_original-ttl_cached
            print("[+] %s was cached about %s ago aprox. [%s]" %
                  (domain, time.strftime('%H:%M:%S', time.gmtime(cached_ago)), dns_snooped), "plus")

        elif len(dns_response.answer) > 0:
            return 1

        return 0

    def run_whois(self, domain):
        """Perform a whois lookup for the provided target domain. The whois results are returned
        as a dictionary.

        This can fail, usually if the domain is registered through a registrar outside of
        North America.
        """
        try:
            who = whois.whois(domain)
            results = {}
            results['domain_name'] = who.domain_name
            results['registrar'] = who.registrar
            results['expiration_date'] = who.expiration_date
            results['registrant'] = who.name
            results['org'] = who.org
            results['admin_email'] = who.emails[0]
            results['tech_email'] = who.emails[1]
            results['address'] = "{}, {}{}, {}, {}\n".format(who.address, \
                who.city, who.zipcode, who.state, who.country)
            results['dnssec'] = who.dnssec

            return results
        except Exception as error:
            print(red("[!] The whois lookup for {} failed!").format(domain))
            print(red("L.. Details: {}".format(error)))

    def run_rdap(self, ip_address):
        """Perform an RDAP lookup for an IP address. An RDAP lookup object is returned.

        From IPWhois: IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides
        a far better data structure than legacy whois and REST lookups (previous implementation).
        RDAP queries allow for parsing of contact information and details for users, organizations,
        and groups. RDAP also provides more detailed network information.
        """
        try:
            rdapwho = IPWhois(ip_address)
            results = rdapwho.lookup_rdap(depth=1)

            return results
        except Exception as error:
            print(red("[!] Failed to collect RDAP information for {}!").format(ip_address))
            print(red("L.. Details: {}".format(error)))

    def run_urlcrazy(self, client, target, cymon_api=cymon_api):
        """Run urlcrazy to locate typosquatted domains related to the target domain. The full
        output is saved to a csv file and then domains with A-records are analyzed to see if
        they may be in use for malicious purposes. The domain names and IP addresses are checked
        against Cymon.io's threat feeds. If a result is found (200 OK), then the domain or IP has
        been reported to be part of some sort of malicious activity relatively recently.

        The function returns a list of domains, A-records, MX-records, and the results from Cymon.

        A Cymon API key is recommended, but not required.
        """
        # Check to see if urlcrazy is available
        try:
            subprocess.call("urlcrazy")
            urlcrazy_present = True
        except OSError as error:
            if error.errno == os.errno.ENOENT:
                # The urlcrazy command was not found
                print(yellow("[!] A test call to urlcrazy failed, so skipping urlcrazy run."))
                print(yellow("L.. Details: {}".format(error)))
                urlcrazy_present = False
            else:
                # Something else went wrong while trying to run urlcrazy
                print(yellow("[!] A test call to urlcrazy failed, so skipping urlcrazy run."))
                print(yellow("L.. Details: {}".format(error)))
                urlcrazy_present = False
            return urlcrazy_present

        if urlcrazy_present:
            outfile = "reports/{}/crazy_temp.csv".format(client)
            final_csv = "reports/{}/{}_urlcrazy.csv".format(client, target)
            domains = []
            a_records = []
            mx_records = []
            squatted = {}
            print(green("[+] Running urlcrazy for {}".format(target)))
            try:
                cmd = "urlcrazy -f csv -o '{}' {}".format(outfile, target)
                with open(os.devnull, "w") as devnull:
                    subprocess.check_call(cmd, stdout=devnull, shell=True)
                with open(outfile, "r", encoding = "ISO-8859-1") as results:
                    reader = csv.DictReader(row.replace("\0", "") for row in results)
                    for row in reader:
                        if len(row) != 0:
                            if row['CC-A'] != "?":
                                domains.append(row['Typo'])
                                a_records.append(row['DNS-A'])
                                mx_records.append(row['DNS-MX'])

                squatted = zip(domains, a_records, mx_records)

                session = requests.Session()
                session.headers = {'content-type':'application/json', 'accept':'application/json'}
                # Add the Cymon API, if available, to the headers
                if self.cymon_api_key != None:
                    session.headers.update({'Authorization': 'Token {0}' \
                        .format(self.cymon_api_key)})

                # Search for domains and IP addresses tied to the domain name
                urlcrazy_results = []
                for domain in squatted:
                    try:
                        request = session.get(cymon_api + "/ioc/search/domain/" + domain[0])
                        # results = json.loads(r.text)

                        if request.status_code == 200:
                            if request.json()['total'] > 0:
                                malicious_domain = 1
                            else:
                                malicious_domain = 0
                        else:
                            malicious_domain = 0
                    except Exception as error:
                        malicious_domain = 0
                        print(red("[!] There was an error checking {} with Cymon.io!"
                            .format(domain[0])))

                    # Search for domains and IP addresses tied to the A-record IP
                    try:
                        r = session.get(cymon_api + "/ioc/search/ip/" + domain[1])
                        # results = json.loads(r.text)

                        if r.status_code == 200:
                            if request.json()['total'] > 0:
                                malicious_ip = 1
                            else:
                                malicious_ip = 0
                        else:
                            malicious_ip = 0
                    except Exception as error:
                        malicious_ip = 0
                        print(red("[!] There was an error checking {} with Cymon.io!"
                                    .format(domain[1])))

                    if malicious_domain == 1:
                        cymon_result = "Yes"
                    elif malicious_ip == 1:
                        cymon_result = "Yes"
                    else:
                        cymon_result = "No"

                    temp = {}
                    temp['domain'] = domain[0]
                    temp['a-records'] = domain[1]
                    temp['mx-records'] = domain[2]
                    temp['malicious'] = cymon_result
                    urlcrazy_results.append(temp)

                os.rename(outfile, final_csv)
                return urlcrazy_results

            except Exception as error:
                print(red("[!] Execution of urlcrazy failed!"))
                print(red("L.. Details: {}".format(error)))
        else:
            print(yellow("[*] Skipped urlcrazy check."))

    def run_shodan_search(self, target):
        """Collect information Shodan has for target domain name. This uses the Shodan search
        instead of host lookup and returns the target results dictionary from Shodan.

        A Shodan API key is required.
        """
        if self.shoAPI is None:
            pass
        else:
            print(green("[+] Performing Shodan domain search for {}.".format(target)))
            try:
                target_results = self.shoAPI.search(target)
                return target_results
            except shodan.APIError as error:
                print(red("[!] Error fetching Shodan info for {}!".format(target)))
                print(red("L.. Details: {}".format(error)))

    def run_shodan_lookup(self, target):
        """Collect information Shodan has for target IP address. This uses the Shodan host lookup
        instead of search and returns the target results dictionary from Shodan.

        A Shodan API key is required.
        """
        # dns_resolve = "https://api.shodan.io/dns/resolve?hostnames=" \
        #     + target + "&key=" + shodan_api_key
        # resolved = requests.get(dnsResolve)
        # target_ip = resolved.json()[target]

        if self.shoAPI is None:
            pass
        else:
            print(green("[+] Performing Shodan IP lookup for {}.".format(target)))
            try:
                target_results = self.shoAPI.host(target)
                return target_results
            except shodan.APIError as error:
                print(red("[!] Error fetching Shodan info for {}!".format(target)))
                print(red("L.. Details: {}".format(error)))

    def run_shodan_exploit_search(self, CVE):
        """Function to lookup CVEs through Shodan and return the results."""
        exploits = self.shoAPI.exploits.search(CVE)
        return exploits

    def search_cymon_ip(self, target):
        """Get reputation data from Cymon.io for target IP address. This returns two dictionaries
        for domains and security events.

        An API key is not required, but is recommended.
        """
        try:
            # Search for IP and domains tied to the IP
            data = self.cyAPI.ip_domains(target)
            domains_results = data['results']
            # Search for security events for the IP
            data = self.cyAPI.ip_events(target)
            ip_results = data['results']
            print(green("[+] Cymon search completed!"))
            return domains_results, ip_results
        except Exception:
            print(red("[!] Cymon.io returned a 404 indicating no results."))

    def search_cymon_domain(self, target):
        """Get reputation data from Cymon.io for target domain. This returns a dictionary for
        the IP addresses tied to the domain.

        An API key is not required, but is recommended.
        """
        try:
            # Search for domains and IP addresses tied to the domain
            results = self.cyAPI.domain_lookup(target)
            print(green("[+] Cymon search completed!"))
            return results
        except Exception:
            print(red("[!] Cymon.io returned a 404 indicating no results."))

    def run_censys_search_cert(self, target):
        """Collect certificate information from Censys for the target domain name. This returns
        a dictionary of certificate information. Censys can return a LOT of certificate chain
        info, so be warned.

        This function uses these fields: parsed.subject_dn and parsed.issuer_dn

        A free API key is required.
        """
        if self.CEN_API_URL is None:
            pass
        else:
            print(green("[+] Performing Censys certificate search for {}".format(target)))
            params = {"query" : target}
            try:
                fields = ["parsed.subject_dn", "parsed.issuer_dn"]
                results = requests.post(self.CEN_API_URL + "/search/certificates", json = params, auth=(self.censys_api_id, self.censys_api_secret))
                certs = results.json()
                return certs
            except Exception as error:
                print(red("[!] Error collecting Censys certificate data for {}.".format(target)))
                print(red("L.. Details: {}".format(error)))

    def parse_cert_subdomains(self, certdata):
        """Accepts Censys certificate data and parses out subdomain information."""
        subdomains = []
        for cert in certdata['results']:
            if "," in cert["parsed.subject_dn"]:
                pos = cert["parsed.subject_dn"].find('CN=')+3
            else:
                pos = 3
            tmp = cert["parsed.subject_dn"][pos:]
            if "," in tmp:
                pos = tmp.find(",")
                tmp = tmp[:pos]
            if "." not in tmp:
                continue
            
            subdomains.append(tmp)

        subdomains = set(subdomains)
        return subdomains

    def run_censys_search_address(self, target):
        """Collect open port/protocol information from Censys for the target IP address. This
        returns a dictionary of protocol information.

        A free API key is required.
        """
        if self.cenAddAPI is None:
            pass
        else:
            print(green("[+] Performing Censys open port search for {}".format(target)))
            try:
                data = self.cenAddAPI.search(target)
                return data
            except Exception as error:
                print(red("[!] Error collecting Censys data for {}.".format(target)))
                print(red("L.. Details: {}".format(error)))

    def run_urlvoid_lookup(self, domain):
        """Collect reputation data from URLVoid for the target domain. This returns an ElementTree
        object.

        A free API key is required.
        """
        if not helpers.is_ip(domain):
            try:
                if self.urlvoid_api_key != "":
                    url = "http://api.urlvoid.com/api1000/{}/host/{}"\
                        .format(self.urlvoid_api_key, domain)
                    response = requests.get(url)
                    tree = ET.fromstring(response.content)
                    return tree
                else:
                    print(green("[-] No URLVoid API key, so skipping this test."))
                    return None
            except Exception as error:
                print(red("[!] Could not load URLVoid for reputation check!"))
                print(red("L.. Details: {}".format(error)))
                return None
        else:
            print(red("[!] Target is not a domain, so skipping URLVoid queries."))

    def check_dns_dumpster(self, domain):
        """Function to collect subdomains known to DNS Dumpster for the provided domain. This is
        based on PaulSec's unofficial DNS Dumpster API available on GitHub.
        """
        dnsdumpster_url = "https://dnsdumpster.com/"
        results = {}
        cookies = {}

        requests.packages.urllib3.disable_warnings()
        session = requests.session()
        request = session.get(dnsdumpster_url, verify=False)

        csrf_token = session.cookies['csrftoken']
        cookies['csrftoken'] = session.cookies['csrftoken']
        headers = {'Referer': dnsdumpster_url}
        data = {'csrfmiddlewaretoken': csrf_token, 'targetip': domain}

        request = session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)

        if request.status_code != 200:
            print("[+] There appears to have been an error communicating with DNS Dumpster -- {} \
                  received!".format(request.status_code))

        soup = BeautifulSoup(request.content, 'lxml')
        tables = soup.findAll('table')

        results = {}
        results['domain'] = domain
        results['dns_records'] = {}
        results['dns_records']['dns'] = self.retrieve_results(tables[0])
        results['dns_records']['mx'] = self.retrieve_results(tables[1])
        results['dns_records']['txt'] = self.retrieve_txt_record(tables[2])
        results['dns_records']['host'] = self.retrieve_results(tables[3])

        # Try to fetch the network mapping image
        try:
            val = soup.find('img', attrs={'class': 'img-responsive'})['src']
            tmp_url = "{}{}".format(dnsdumpster_url, val)
            image_data = base64.b64encode(requests.get(tmp_url).content)
        except Exception:
            image_data = None
        finally:
            results['image_data'] = image_data

        return results

    def retrieve_results(self, table):
        """Helper function for check_dns_dumpster which extracts the results from the HTML soup."""
        results = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = tds[0].text.replace('\n', '').split(' ')[0]
            header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
            reverse_dns = tds[1].find('span', attrs={}).text

            additional_info = tds[2].text
            country = tds[2].find('span', attrs={}).text
            autonomous_system = additional_info.split(' ')[0]
            provider = ' '.join(additional_info.split(' ')[1:])
            provider = provider.replace(country, '')
            data = {'domain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'as': autonomous_system,
                    'provider': provider,
                    'country': country,
                    'header': header}
            results.append(data)

        return results

    def retrieve_txt_record(self, table):
        """Secondary helper function for check_dns_dumpster which extracts the TXT records."""
        results = []
        for td in table.findAll('td'):
            results.append(td.text)

        return results

    def check_netcraft(self, domain):
        """Function to collect subdomains known to NetCraft for the provided domain. NetCraft blocks
        scripted requests by requiring cookies and JavaScript for all browser, so Selenium is
        required.

        This is based on code from the DataSploit project, but updated to work with today's
        NetCraft.
        """
        results = []
        # If the WebDriver path is empty, we cannot continue with NetCraft
        if self.chrome_driver_path:
            driver = webdriver.Chrome(self.chrome_driver_path)
            netcraft_url = "http://searchdns.netcraft.com/?host=%s" % domain
            target_dom_name = domain.split(".")
            driver.get(netcraft_url)

            link_regx = re.compile('<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
            links_list = link_regx.findall(driver.page_source)
            for x in links_list:
                dom_name = x.split("/")[2].split(".")
                if (dom_name[len(dom_name) - 1] == target_dom_name[1]) and \
                (dom_name[len(dom_name) - 2] == target_dom_name[0]):
                    results.append(x.split("/")[2])
            num_regex = re.compile('Found (.*) site')
            num_subdomains = num_regex.findall(driver.page_source)
            if not num_subdomains:
                num_regex = re.compile('First (.*) sites returned')
                num_subdomains = num_regex.findall(driver.page_source)
            if num_subdomains:
                if num_subdomains[0] != str(0):
                    num_pages = int(num_subdomains[0]) // 20 + 1
                    if num_pages > 1:
                        last_regex = re.compile(
                            '<td align="left">%s.</td><td align="left">\n<a href="(.*)" rel="nofollow">' % (20))
                        last_item = last_regex.findall(driver.page_source)[0].split("/")[2]
                        next_page = 21

                        for x in range(2, num_pages):
                            url = "http://searchdns.netcraft.com/?host=%s&last=%s&from=%s&restriction=/site%%20contains" % (domain, last_item, next_page)
                            driver.get(url)
                            link_regx = re.compile(
                                '<a href="http://toolbar.netcraft.com/site_report\?url=(.*)">')
                            links_list = link_regx.findall(driver.page_source)
                            for y in links_list:
                                dom_name1 = y.split("/")[2].split(".")
                                if (dom_name1[len(dom_name1) - 1] == target_dom_name[1]) and \
                                (dom_name1[len(dom_name1) - 2] == target_dom_name[0]):
                                    results.append(y.split("/")[2])
                            last_item = links_list[len(links_list) - 1].split("/")[2]
                            next_page = 20 * x + 1
                else:
                    pass
            else:
                pass

        return results

    def fetch_netcraft_domain_history(self, domain):
        """Function to fetch a domain's IP address history from NetCraft."""
        # TODO: See if the "Last Seen" and other data can be easily collected for here
        ip_history = []
        time.sleep(1)
        if self.chrome_driver_path:
            driver = webdriver.Chrome(self.chrome_driver_path)
            endpoint = "http://toolbar.netcraft.com/site_report?url=%s" % (domain)
            driver.get(endpoint)

            soup = BeautifulSoup(driver.page_source, 'html.parser')
            urls_parsed = soup.findAll('a', href=re.compile(r".*netblock\?q.*"))

            for url in urls_parsed:
                if urls_parsed.index(url) != 0:
                    result = [str(url).split('=')[2].split(">")[1].split("<")[0], \
                    str(url.parent.findNext('td')).strip("<td>").strip("</td>")]
                    ip_history.append(result)

        return ip_history

    def enumerate_buckets(self, client, domain, wordlist=None, fix_wordlist=None):
        """Function to search for AWS S3 buckets and accounts. Default search terms are the
        client, domain, and domain without its TLD. A wordlist is optional.

        This is based on modules from aws_pwn by dagrz on GitHub.
        """
        # Take the user input as the initial list of keywords here
        # Both example.com and example are valid bucket names, so domain+tld and domain are tried
        search_terms = [domain, domain.split(".")[0], client.replace(" ", "").lower()]
        # Potentially valid and interesting keywords that might be used a prefix or suffix
        fixes = ["apps", "downloads", "software", "deployment", "qa", "dev", "test", "vpn",
                 "secret", "user", "confidential", "invoice", "config", "backup", "bak",
                 "xls", "csv", "ssn", "resources", "web", "testing"]
        bucket_results = []
        account_results = []

        # Add user-provided wordlist terms to our list of search terms
        if wordlist is not None:
            with open(wordlist, "r") as bucket_list:
                for name in bucket_list:
                    name = name.strip()
                    if name and not name.startswith('#'):
                        search_terms.append(name)

        # Add user-provided list of pre/suffixes to our list of fixes
        if fix_wordlist is not None:
            with open(fix_wordlist, "r") as new_fixes:
                for fix in new_fixes:
                    fix = fix.strip()
                    if fix and not fix.startswith('#'):
                        fixes.append(fix)

        # Modify search terms with some common prefixes and suffixes
        # We use this new list to avoid endlessly looping
        final_search_terms = []
        for fix in fixes:
            for term in search_terms:
                final_search_terms.append(fix + "-" + term)
                final_search_terms.append(term + "-" + fix)
                final_search_terms.append(fix + term)
                final_search_terms.append(term + fix)
        # Now include our original list of base terms
        for term in search_terms:
            final_search_terms.append(term)

        # Ensure we have only unique search terms in our list and start hunting
        final_search_terms = list(set(final_search_terms))

        with click.progressbar(final_search_terms,
                               label="Enuemrating AWS Keywords",
                               length=len(final_search_terms)) as bar:
            for term in bar:
                # Check for buckets and spaces
                if self.boto3_client is not None:
                    result = self.validate_bucket('head', term)
                    bucket_results.append(result)
                result = self.validate_do_space("ams3", term)
                bucket_results.append(result)
                result = self.validate_do_space("nyc3", term)
                bucket_results.append(result)
                result = self.validate_do_space("sgp1", term)
                bucket_results.append(result)
                # Check for accounts
                result = self.validate_account(term)
                account_results.append(result)

        return bucket_results, account_results

    def validate_bucket(self, validation_type, bucket_name):
        """Helper function used by validate_bucket_head()."""
        validation_functions = {
            'head': self.validate_bucket_head
        }
        if validation_functions[validation_type]:
            return validation_functions[validation_type](bucket_name)


    def validate_bucket_head(self, bucket_name):
        """Function to check a string to see if it exists as the name of an Amazon S3 bucket. This
        version uses awscli to identify a bucket and then uses Requests to check public access. The
        benefit of this is awscli will gather information from buckets that are otherwise
        inaccessible via web requests.
        """
        # This test requires authentication
        # Warning: Check credentials before use
        error_values = {
            '400': True,
            '403': True,
            '404': False
        }
        result = {
            'bucketName': bucket_name,
            'bucketUri': 'http://' + bucket_name + '.s3.amazonaws.com',
            'arn': 'arn:aws:s3:::' + bucket_name,
            'exists': False,
            'public': False
        }
        
        try:
            self.boto3_client.head_bucket(Bucket=bucket_name)
            result['exists'] = True
            try:
                # Request the bucket to check the response
                request = requests.get(result['bucketUri'])
                # All bucket names will get something, so look for the NoSuchBucket status
                if "NoSuchBucket" in request.text:
                    result['exists'] = False
                else:
                    result['exists'] = True
                # Check for a 200 OK to indicate a publicly listable bucket
                if request.status_code == 200:
                    result['public'] = True
                    print(yellow("[*] Found a public bucket -- {}".format(result['bucketName'])))
            except requests.exceptions.RequestException:
                result['exists'] = False
        except ClientError as e:
            result['exists'] = error_values[e.response['Error']['Code']]

        return result

    def validate_bucket_noncli(self, bucket_name):
        """Function to check a string to see if it exists as the name of an Amazon S3 bucket. This
        version uses only Requests and the bucket's URL.

        This is deprecated, but here just in case.
        """
        bucket_uri = "http://" + bucket_name + ".s3.amazonaws.com"
        result = {
            'bucketName': bucket_name,
            'bucketUri': bucket_uri,
            'arn': 'arn:aws:s3:::' + bucket_name,
            'exists': False,
            'public': False
        }

        try:
            # Request the bucket to check the response
            request = requests.get(bucket_uri)
            # All bucket names will get something, so look for the NoSuchBucket status
            if "NoSuchBucket" in request.text:
                result['exists'] = False
            else:
                result['exists'] = True
            # Check for a 200 OK to indicate a publicly listable bucket
            if request.status_code == 200:
                result['public'] = True
        except requests.exceptions.RequestException:
            result['exists'] = False

        return result

    def validate_do_space(self, region, space_name):
        """Function to check a string to see if it exists as the name of a Digital Ocean Space."""
        space_uri = "http://" + space_name + region + ".digitaloceanspaces.com"
        result = {
            'bucketName': space_name,
            'bucketUri': space_uri,
            'arn': 'arn:do:space:::' + space_name,
            'exists': False,
            'public': False
        }

        try:
            # Request the Space to check the response
            request = requests.get(space_uri)
            # All Space names will get something, so look for the NoSuchBucket status
            if "NoSuchBucket" in request.text:
                result['exists'] = False
            else:
                result['exists'] = True
            # Check for a 200 OK to indicate a publicly listable Space
            if request.status_code == 200:
                result['public'] = True
        except requests.exceptions.RequestException:
            result['exists'] = False

        return result

    def validate_account(self, account):
        """Function to check a string to see if it exists as the name of an AWS alias."""
        result = {
            'accountAlias': None,
            'accountId': None,
            'signinUri': 'https://' + account + '.signin.aws.amazon.com/',
            'exists': False,
            'error': None
        }
        # Check if the provided account name is a string of numbers (an ID) or not (an alias)
        if re.match(r'\d{12}', account):
            result['accountId'] = account
        else:
            result['accountAlias'] = account

        if not validators.url(result['signinUri']):
            result['error'] = 'Invalid URI'
            return result

        try:
            # Request the sign-in URL and don't allow the redirect
            request = requests.get(result['signinUri'], allow_redirects=False)
            # If we have a redirect, not a 404, we have a valid account alias for AWS
            if request.status_code == 302:
                result['exists'] = True
        except requests.exceptions.RequestException as error:
            result['error'] = error

        return result

    def check_domain_fronting(self, subdomain):
        """Function to check the A records for a given subdomain and look for references to various
        CDNs to flag the submdomain for domain frontability.

        Many CDN keywords provided by rvrsh3ll on GitHub:
        https://github.com/rvrsh3ll/FindFrontableDomains
        """
        try:
            # Get the A record(s) for the subdomain
            query = self.get_dns_record(subdomain, "a")
            # Look for records matching known CDNs
            for item in query.response.answer:
                for text in item.items:
                    target = text.to_text()
                    if "cloudfront" in target:
                        return "Cloudfront: {}".format(target)
                    elif "appspot.com" in target:
                        return "Google: {}".format(target)
                    elif "googleplex.com" in target:
                        return "Google: {}".format(target)
                    elif "msecnd.net" in target:
                        return "Azure: {}".format(target)
                    elif "aspnetcdn.com" in target:
                        return "Azure: {}".format(target)
                    elif "azureedge.net" in target:
                        return "Azure: {}".format(target)
                    elif "a248.e.akamai.net" in target:
                        return "Akamai: {}".format(target)
                    elif "secure.footprint.net" in target:
                        return "Level 3: {}".format(target)
                    elif "cloudflare" in target:
                        return "Cloudflare: {}".format(target)
                    elif 'unbouncepages.com' in target:
                        return "Unbounce: {}".format(target)
                    elif 'secure.footprint.net' in target:
                        return "Level 3: {}".format(target)
        except Exception:
            return "No"

    def lookup_robtex_ipinfo(self, ip_address):
        """Function to lookup information about a target IP address with Robtex."""
        if helpers.is_ip(ip_address):
            request = requests.get(self.robtex_api + ip_address)
            ip_json = request.json()
            return ip_json
        else:
            print(red("[!] The provided IP for Robtex address is invalid!"))