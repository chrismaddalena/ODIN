#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module interacts with the Full Contact API to collect information about a company and/or its
employees.
"""

import json

import click
import requests

from . import helpers


class FullContact(object):
    """Class for collecting information from Full Contact's API."""
    # Set the timeout, in seconds, for web requests
    requests_timeout = 10
    # Set the Full Contact API endpoints
    person_api_uri = "https://api.fullcontact.com/v3/person.enrich"
    company_api_uri = "https://api.fullcontact.com/v3/company.enrich"

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except Exception:
            self.contact_api_key = None
            click.secho("[!] Did not find a Full Contact API key.",fg="yellow")

    def full_contact_company(self,domain):
        """Collect company profile information for the target domain using the Full Contact API.

        Parameters:
        domain      The domain to look-up in Full Contact's database
        """
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping company lookup.",fg="red")
            return None
        else:
            headers = {"Authorization": "Bearer %s" % self.contact_api_key}
            payload = {"domain": domain}
            try:
                resp = requests.post(self.company_api_uri,data=json.dumps(payload),headers=headers,timeout=self.requests_timeout)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    click.secho("[!] Full Contact says the provided API key is no good. Make sure you are using a valid key for API v3.",fg="red")
                    return None
            except requests.exceptions.Timeout:
                click.secho("\n[!] The connection to Full Contact timed out!",fg="red")
            except requests.exceptions.TooManyRedirects:
                click.secho("\n[!] The connection to Full Contact encountered too many redirects!",fg="red")
            except requests.exceptions.RequestException as error:
                click.secho("\n[!] The connection to Full Contact encountered an error!",fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
            return None

    def full_contact_email(self,email):
        """Collect social information for the target email address using the Full Contact API.

        Parameters:
        email       The email to look-up in Full Contact's database
        """
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping company lookup.",fg="red")
            return None
        else:
            headers = {"Authorization": "Bearer %s" % self.contact_api_key}
            payload = {"email": email}
            try:
                resp = requests.post(self.person_api_uri,data=json.dumps(payload),headers=headers,timeout=self.requests_timeout)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    click.secho("[!] Full Contact says the provided API key is no good. Make sure you are using a valid key for API v3.",fg="red")
                    return None
            except requests.exceptions.Timeout:
                click.secho("\n[!] The connection to Full Contact timed out!",fg="red")
            except requests.exceptions.TooManyRedirects:
                click.secho("\n[!] The connection to Full Contact encountered too many redirects!",fg="red")
            except requests.exceptions.RequestException as error:
                click.secho("\n[!] The connection to Full Contact encountered an error!",fg="red")
                click.secho("L.. Details: {}".format(error),fg="red")
            return None
