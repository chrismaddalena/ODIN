#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module interacts with the Full Contact API to collect information about a company and/or its
employees.
"""

import json
import logging

import click
import requests

from . import helpers

logger = logging.getLogger(__name__)


class FullContact(object):
    """Collect information from Full Contact's API."""

    # Set the timeout, in seconds, for web requests
    timeout = 10

    # Set the Full Contact API endpoints
    person_api_uri = "https://api.fullcontact.com/v3/person.enrich"
    company_api_uri = "https://api.fullcontact.com/v3/company.enrich"

    def __init__(self):
        try:
            self.contact_api_key = helpers.config_section_map("Full Contact")["api_key"]
        except Exception:
            self.contact_api_key = None
            logger.warning("No Full Contact API key found")

    def full_contact_company(self, domain: str) -> dict:
        """
        Collect company profile information for the target domain using the Full Contact API.

        **Parameters**

        ``domain``
            Domain to look-up in Full Contact's database
        """
        results = {}
        # Only proceedd if a API key is available
        if self.contact_api_key:
            # Need to authenticate with an Authorization header
            headers = {"Authorization": "Bearer %s" % self.contact_api_key}
            payload = {"domain": domain}
            try:
                resp = requests.post(
                    self.company_api_uri,
                    data=json.dumps(payload),
                    headers=headers,
                    timeout=self.timeout,
                )
                # 200 OK means a successful search
                if resp.status_code == 200:
                    logger.debug(
                        "Full Contact returned results for the query for %s", domain
                    )
                    results = resp.json()
                # 401 means Full Conttact rejected the API key
                elif resp.status_code == 401:
                    logger.error("Full Contact responded with a 401, Bad API Key")
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ) as e:
                logger.exception(
                    "Request timed out or failed while contacting Full Contact:  %s",
                    getattr(e, "__dict__", {}),
                )
            except Exception as e:
                logger.exception(
                    "General exception occured while contacting Full Contact:  %s",
                    getattr(e, "__dict__", {}),
                )

        return results

    def full_contact_email(self, email: str) -> dict:
        """
        Collect social information for the target email address using the Full Contact API.

        **Parameters**

        ``email``
            Email address to look-up in Full Contact's database
        """
        results = {}
        # Only proceedd if a API key is available
        if self.contact_api_key:
            # Need to authenticate with an Authorization header
            headers = {"Authorization": "Bearer %s" % self.contact_api_key}
            payload = {"email": email}
            try:
                resp = requests.post(
                    self.person_api_uri,
                    data=json.dumps(payload),
                    headers=headers,
                    timeout=self.timeout,
                )
                # 200 OK means a successful search
                if resp.status_code == 200:
                    logger.debug(
                        "Full Contact returned results for the query for %s", email
                    )
                    results = resp.json()
                # 401 means Full Conttact rejected the API key
                elif resp.status_code == 401:
                    logger.error("Full Contact responded with a 401, Bad API Key")
            except (
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                requests.exceptions.RequestException,
            ) as e:
                logger.exception(
                    "Request timed out or failed while contacting Full Contact:  %s",
                    getattr(e, "__dict__", {}),
                )
            except Exception as e:
                logger.exception(
                    "General exception occured while contacting Full Contact:  %s",
                    getattr(e, "__dict__", {}),
                )

        return results
