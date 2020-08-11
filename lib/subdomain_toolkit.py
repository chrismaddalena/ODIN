#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains everything needed to hunt for subdomains, including collecting certificate
data from Censys.io and crt.sh for a given domain name.

The original crt.sh code is from PaulSec's unofficial crt.sh API. That project can be found here:

https://github.com/PaulSec/crt.sh
"""

import base64
import json
import logging
import re
from time import sleep

import click
import requests
from bs4 import BeautifulSoup
from selenium.common.exceptions import TimeoutException

import censys.certificates

from . import helpers

logger = logging.getLogger(__name__)


class CertSearcher(object):
    """Subdomain discovery via TLS certificates catalogued by censys.io and crt.sh."""

    # Set a timeout, in seconds, for the web requests
    requests_timeout = 30
    webdriver_timeout = 30

    # The user-agent and endpoint URIs used for the web requests
    crtsh_base_uri = "https://crt.sh/?q={domain}&output=json"
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"

    def __init__(self):
        try:
            censys_api_id = helpers.config_section_map("Censys")["api_id"]
            censys_api_secret = helpers.config_section_map("Censys")["api_secret"]
            self.censys_cert_search = censys.certificates.CensysCertificates(
                api_id=censys_api_id, api_secret=censys_api_secret
            )
        except censys.base.CensysUnauthorizedException:
            self.censys_cert_search = None
            logger.error("Censys reported the provided API information is invalid")
        except Exception as error:
            self.censys_cert_search = None
            logger.warning("No Censys API information found")

    def query_crtsh(self, domain, wildcard=True):
        """
        Collect certificate information from crt.sh for the target domain name. This returns
        JSON containing certificate information that includes the issuer, issuer and expiration
        dates, and the name.

        **Parameters**

        ``domain``
            Domain to search for on crt.sh
        ``wildcard``
            Whether or not to prepend a wildcard to the domain (default: True)

        **Returns**

        {
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
            "name_value": "hatch.uber.com",
            "min_cert_id": 325717795,
            "min_entry_timestamp": "2018-02-08T16:47:39.089",
            "not_before": "2018-02-08T15:47:39"
        }
        """
        headers = {"User-Agent": self.user_agent}

        if wildcard:
            domain = "%25.{}".format(domain)

        try:
            req = requests.get(
                self.crtsh_base_uri.format(domain=domain),
                headers=headers,
                timeout=self.requests_timeout,
            )
            if req.ok:
                try:
                    content = req.content.decode("utf-8")
                    # data = json.loads("{}".format(content.replace("}{", "},{")))
                    data = json.loads(content)
                    return data
                except:
                    logger.error(
                        "Could not get JSON data from crt.sh's response for %s", domain
                    )
                    return None
        except (
            requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.RequestException,
        ):
            logger.error(
                "Encountered an error or timeout while connecting to crt.sh to look-up %s",
                domain,
            )
        except Exception as e:
            logger.exception(
                "General exception occured while connecting to crt.sh:  %s",
                getattr(e, "__dict__", {}),
            )
        return None

    def query_censys_certificates(self, target):
        """
        Collect certificate information from Censys.io for the target domain name. This returns
        a dictionary of certificate information that includes the issuer, subject, and a hash
        Censys uses for the /view/ API calls to fetch additional information.

        A Censys API key is required.

        **Parameters**

        ``target``
            The domain name, e.g. apple.com, to use for the Censys.io search
        """
        if self.censys_cert_search is None:
            pass
        else:
            try:
                # Use the `parsed.names` filter to avoid unwanted domains
                query = "parsed.names: %s" % target
                results = self.censys_cert_search.search(
                    query,
                    fields=[
                        "parsed.names",
                        "parsed.signature_algorithm.name",
                        "parsed.signature.self_signed",
                        "parsed.validity.start",
                        "parsed.validity.end",
                        "parsed.fingerprint_sha256",
                        "parsed.subject_dn",
                        "parsed.issuer_dn",
                    ],
                )
                return results
            except censys.base.CensysRateLimitExceededException:
                logger.error(
                    "Censys reports the provided API key has run out of API credits."
                )
                return None
            except Exception as e:
                logger.exception(
                    "General exception occured while connecting to censys.io:  %s",
                    getattr(e, "__dict__", {}),
                )
                return None

    def parse_cert_subdomain(self, subject_dn):
        """
        Parse Censys.io certificate data to produce the individual certificate's domain.

        **Parameters**

        ``subject_dn``
            Accepts the subject_dn field from a Censys search result.
        """
        if "," in subject_dn:
            pos = subject_dn.find("CN=") + 3
        else:
            pos = 3
        tmp = subject_dn[pos:]
        if "," in tmp:
            pos = tmp.find(",")
            tmp = tmp[:pos]
        return tmp

    def filter_subdomains(self, domain, subdomains):
        """
        Filter out uninteresting domains that may be returned from certificates. These are
        domains unrelated to the true target. For example, a search for blizzard.com on Censys
        can return iran-blizzard.ir, an unwanted and unrelated domain.

        Credit to christophetd for this nice bit of code:
            https://github.com/christophetd/censys-subdomain-finder/blob/master/censys_subdomain_finder.py#L31

        **Parameters**

        ``domain``
            The base domain to be used for filtering subdomains, e.g. apple.com
        ``subdomains``
            A list of collected subdomains to filter
        """
        return [
            subdomain
            for subdomain in subdomains
            if "*" not in subdomain and subdomain.endswith(domain)
        ]


class SubdomainCollector(object):
    """Subdomain discovery via web scraping search results from Spyse, Netcraft, and DNS Dumpster."""

    # Set a timeout, in seconds, for the web requests
    requests_timeout = 30
    webdriver_timeout = 30

    # The user-agent and endpoint URIs used for the web requests
    dnsdumpster_uri = "https://dnsdumpster.com/"
    netcraft_uri = "http://searchdns.netcraft.com/?host={domain}"
    netcraft_history_uri = "https://sitereport.netcraft.com/?url={domain}"
    spyse_search_uri = "https://spyse.com/target/domain/{domain}/subdomain-list"
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"

    def __init__(self, webdriver=None):
        self.browser = webdriver
        self.browser.set_page_load_timeout(self.webdriver_timeout)

    def query_dns_dumpster(self, domain):
        """
        Collect subdomains known to DNS Dumpster for the provided domain. This is based on
        PaulSec's unofficial DNS Dumpster API available on GitHub.

        **Parameters**

        ``domain``
            The domain to search for on DNS Dumpster
        """
        results = {}
        cookies = {}
        # Disable SSL warnings and create a session for web browsing
        requests.packages.urllib3.disable_warnings()
        session = requests.session()
        # Try connecting to DNS Dumpster
        try:
            # Make a request to stash the CSRF token and setup cookies and headers for the next request
            request = session.get(
                self.dnsdumpster_uri, verify=False, timeout=self.requests_timeout
            )
            csrf_token = session.cookies["csrftoken"]
            cookies["csrftoken"] = session.cookies["csrftoken"]
            headers = {"Referer": self.dnsdumpster_uri}
            data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain}
            # Now make a POST to DNS Dumpster with the new cookies and headers to perform the search
            request = session.post(
                self.dnsdumpster_uri,
                cookies=cookies,
                data=data,
                headers=headers,
                timeout=self.requests_timeout,
            )
            # Check if a 200 OK was returned
            if request.ok:
                soup = BeautifulSoup(request.content, "lxml")
                tables = soup.findAll("table")
                results["domain"] = domain
                results["dns_records"] = {}
                results["dns_records"]["dns"] = self._retrieve_results(tables[0])
                results["dns_records"]["mx"] = self._retrieve_results(tables[1])
                results["dns_records"]["txt"] = self._retrieve_txt_record(tables[2])
                results["dns_records"]["host"] = self._retrieve_results(tables[3])
                # Try to fetch the network mapping image
                image_data = None
                try:
                    val = soup.find("img", attrs={"class": "img-responsive"})["src"]
                    tmp_url = "{}{}".format(self.dnsdumpster_uri, val)
                    image_request = requests.get(tmp_url, timeout=self.requests_timeout)
                    if image_request.status_code == 200:
                        image_data = base64.b64encode(image_request.content)
                    else:
                        logger.info("DNS Dumpster did not have a map for %s", domain)
                except Exception:
                    image_data = None
                finally:
                    results["image_data"] = image_data
            else:
                logger.error(
                    "The DNS Dumpster request returned a %s status code!",
                    request.status_code,
                )
        except (
            requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.RequestException,
        ) as e:
            logger.exception(
                "Request timed out or failed while contacting DNS Dumpster:  %s",
                getattr(e, "__dict__", {}),
            )
        except Exception as e:
            logger.exception(
                "General exception occured while contacting DNS Dumpster:  %s",
                getattr(e, "__dict__", {}),
            )
        return results

    def _retrieve_results(self, table):
        """
        Used by check_dns_dumpster() to extract the results from the HTML.

        **Parameters**

        ``table``
            The HTML table pulled from DNS Dumpster results
        """
        results = []
        trs = table.findAll("tr")
        for tr in trs:
            tds = tr.findAll("td")
            pattern_ip = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = tds[0].text.replace("\n", "").split(" ")[0]
            header = " ".join(tds[0].text.replace("\n", "").split(" ")[1:])
            reverse_dns = tds[1].find("span", attrs={}).text
            additional_info = tds[2].text
            country = tds[2].find("span", attrs={}).text
            autonomous_system = additional_info.split(" ")[0]
            provider = " ".join(additional_info.split(" ")[1:])
            provider = provider.replace(country, "")
            data = {
                "domain": domain,
                "ip": ip,
                "reverse_dns": reverse_dns,
                "as": autonomous_system,
                "provider": provider,
                "country": country,
                "header": header,
            }
            results.append(data)
        return results

    def _retrieve_txt_record(self, table):
        """
        Used by `query_dns_dumpster()` to extract the domain's DNS TXT records.

        **Parameters**

        ``table``
            The HTML table pulled from DNS Dumpster results
        """
        results = []
        for td in table.findAll("td"):
            results.append(td.text)
        return results

    def query_netcraft(self, domain: str) -> dict:
        """
        Collect subdomains known to Netcraft for the provided domain. Netcraft blocks scripted
        requests by requiring cookies and JavaScript for all browser, so Selenium is required.

        **Parameters**

        ``domain``
            The domain to look-up on Netcraft
        """
        netcraft_results = {}
        try:
            self.browser.get(self.netcraft_uri.format(domain=domain))
        except TimeoutException:
            logger.error(
                "Request to Netcraft for %s timed out – no response for %s seconds",
                domain,
                self.webdriver_timeout,
            )
        soup = BeautifulSoup(self.browser.page_source, "lxml")
        if soup:
            logger.info("Received results from Netcraft for %s", domain)
            results_table = soup.find("table", {"class": "results-table"})
            # Step through each search to catch an empty result
            if results_table:
                results_tbody = results_table.find("tbody")
                if results_tbody:
                    results_rows = results_tbody.find_all("tr")
                    if results_rows:
                        for row in results_rows:
                            cols = row.find_all("td")
                            cols = [ele.text.strip() for ele in cols]
                            if cols and len(cols) == 6:
                                # Site rank used as key
                                netcraft_results[cols[0]] = {}
                                netcraft_results[cols[0]]["rank"] = cols[0]
                                netcraft_results[cols[0]]["site"] = None
                                netcraft_results[cols[0]]["first_seen"] = None
                                netcraft_results[cols[0]]["netblock"] = None
                                netcraft_results[cols[0]]["os"] = None
                                if cols[1]:
                                    netcraft_results[cols[0]]["site"] = cols[1]
                                if cols[2]:
                                    netcraft_results[cols[0]]["first_seen"] = cols[2]
                                if cols[3]:
                                    netcraft_results[cols[0]]["netblock"] = cols[3]
                                if cols[4]:
                                    netcraft_results[cols[0]]["os"] = cols[4]
        return netcraft_results

    def query_netcraft_history(self, domain: str) -> dict:
        """
        Collect IP address history from Netcraft for the provided domain. Netcraft blocks scripted
        requests by requiring cookies and JavaScript for all browser, so Selenium is required.

        **Parameters**

        ``domain``
            The domain to look-up on Netcraft
        """
        netcraft_results = {}
        try:
            self.browser.get(self.netcraft_history_uri.format(domain=domain))
        except TimeoutError:
            logger.error(
                "Request to Netcraft for %s timed out – no response for %s seconds",
                domain,
                self.webdriver_timeout,
            )
        soup = BeautifulSoup(self.browser.page_source, "lxml")
        if soup:
            results_table = soup.find("table", {"class": "table-history"})
            if results_table:
                results_tbody = results_table.find("tbody")
                if results_tbody:
                    results_rows = results_tbody.find_all("tr")
                    if results_rows:
                        counter = 0
                        for row in results_rows:
                            cols = row.find_all("td")
                            cols = [ele.text.strip() for ele in cols]
                            if cols and len(cols) == 5:
                                # Counter used as unique key for row
                                netcraft_results[counter] = {}
                                netcraft_results[counter]["netblock_owner"] = cols[0]
                                netcraft_results[counter]["ip_address"] = None
                                netcraft_results[counter]["os"] = None
                                netcraft_results[counter]["web_server"] = None
                                netcraft_results[counter]["last_seen"] = None
                                if cols[0]:
                                    netcraft_results[counter]["netblock_owner"] = cols[
                                        0
                                    ]
                                if cols[1]:
                                    netcraft_results[counter]["ip_address"] = cols[1]
                                if cols[2]:
                                    netcraft_results[counter]["os"] = cols[2]
                                if cols[3]:
                                    netcraft_results[counter]["web_server"] = cols[3]
                                if cols[4]:
                                    netcraft_results[counter]["last_seen"] = cols[4]
                                counter += 1
        return netcraft_results

    def query_spyse(self, domain):
        """
        Look-up the given domain on spyse.com and parse the results to get a list of subdomains.

        **Parameters**

        ``domain``
            The base domain for the subdomains query
        """
        subdomains = []
        unique_subdomains = set()
        headers = {"User-Agent": self.user_agent}

        try:
            request = requests.get(
                self.spyse_search_uri.format(domain=domain),
                headers=headers,
                timeout=self.requests_timeout,
            )
            soup = BeautifulSoup(request.content, "lxml")
            if soup:
                subdomains_div = soup.findAll("td", {"class": "cell--sticky"})
                temp = []
                for tag in subdomains_div:
                    subdomain_tags = tag.find(
                        "button", {"class": "popover-link-trigger"}
                    )
                    temp.append(subdomain_tags)
                for subdomain in temp:
                    if not subdomain.string.strip() == domain:
                        subdomains.append(subdomain.string.strip())
                unique_subdomains = list(set(subdomains))
        except (
            requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.RequestException,
        ) as e:
            logger.exception(
                "Request timed out or failed while contacting Spyse:  %s",
                getattr(e, "__dict__", {}),
            )
        except Exception as e:
            logger.exception(
                "General exception occured while contacting Spyse:  %s",
                getattr(e, "__dict__", {}),
            )
        return unique_subdomains
