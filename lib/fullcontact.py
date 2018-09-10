#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module interacts with the Full Contsact API to collect information about a company and/or its
employees.
"""

import json

import click
import requests

from . import helpers


class FullContact(object):
    """Class for collecting information from Full Contact's API."""
    company_api_uri = "https://api.fullcontact.com/v3/company.enrich"
    try:
        contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
    except Exception:
        contact_api_key = None
        click.secho("[!] Did not find a Full Contact API key.", fg="yellow")

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        pass

    def full_contact_company(self, domain):
        """Collect company profile information for the target domain using the Full Contact API."""
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping company lookup.", fg="red")
            return None
        else:
            base_url = "https://api.fullcontact.com/v3/company.enrich"
            headers = {"Authorization":"Bearer %s" % self.contact_api_key}
            payload = {'domain':domain}
            resp = requests.post(base_url, data=json.dumps(payload), headers=headers)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                click.secho("[!] Full Contact says the provided API key is no good. Make sure you \
are using a valid key for API v3.", fg="red") 

    def full_contact_email(self, email):
        """Collect social information for the target email address using the Full Contact API."""
        if self.contact_api_key is None:
            click.secho("[!] No Full Contact API key, so skipping company lookup.", fg="red")
            return None
        else:
            base_url = "https://api.fullcontact.com/v3/person.enrich"
            headers = {"Authorization":"Bearer %s" % self.contact_api_key}
            payload = {'email':email}
            resp = requests.post(base_url, data=json.dumps(payload), headers=headers)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                click.secho("[!] Full Contact says the provided API key is no good. Make sure you \
are using a valid key for API v3.", fg="red") 
