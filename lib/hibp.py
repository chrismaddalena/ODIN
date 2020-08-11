#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for checking email addresses against Have I Been Pwned's database of
security breaches and public pastes.
"""

import json

import click
import requests

from lib import helpers


class HaveIBeenPwned(object):
    """Check email addresses against the Have I Been Pwned breach and paste databases."""

    # Set the timeout, in seconds, for the webdriver
    browser_timeout = 10

    # The Have I Been Pwned API endpoint
    hibp_v3_uri = "https://haveibeenpwned.com/api/v3/{service}/{account}"
    email_service = "breachedaccount"
    paste_service = "pasteaccount"

    user_agent = "Python-based email address review tool"

    def __init__(self):
        try:
            self.hibp_api_key = helpers.config_section_map("HIBP")["api_key"]
        except Exception:
            self.hibp_api_key = None
            click.secho("[!] Did not find a Have I Been Pwned API key.", fg="yellow")

    def query_hibp_email(self, email, timeout=20):
        """
        Search Have I Been Pwned's breached account data for the provided email address.

        A paid Have I Been Pwned API key is required.

        **Parameters**

        ``email``
            Email address to look-up in Have I Been Pwned's breach database
        ``timeout``
            Time in seconds to wait for a response from Have I Been Pwned (Default: 15)
        """
        if self.hibp_api_key:
            try:
                headers = {
                    "User-Agent": self.user_agent,
                    "hibp-api-key": self.hibp_api_key,
                }

                request = requests.get(
                    self.hibp_v3_uri.format(service=self.email_service, account=email),
                    headers=headers,
                    timeout=timeout,
                )
                if request.ok:
                    pwned = request.json()
                    return pwned
                # 404 means the account is not in the database
                elif response.status_code == 404:
                    return None
                else:
                    click.secho(
                        "\n[!] Have I Bee Pwned returned a {} status code!".format(
                            request.status_code
                        ),
                        fg="red",
                    )
            except requests.exceptions.Timeout:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com timed out!", fg="red"
                )
            except requests.exceptions.TooManyRedirects:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com encountered too many redirects!",
                    fg="red",
                )
            except requests.exceptions.RequestException as error:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com encountered an error!",
                    fg="red",
                )
                click.secho("L.. Details: {}".format(error), fg="red")

    def query_hibp_paste(self, email, timeout=20):
        """
        Search Have I Been Pwned's pastes database for the provided email address.

        A paid Have I Been Pwned API key is required.

        **Parameters**

        ``email``
            Email address to look-up in Have I Been Pwned's pastes database
        ``timeout``
            Time in seconds to wait for a response from Have I Been Pwned (Default: 15)
        """
        if self.hibp_api_key:
            try:
                headers = {
                    "User-Agent": self.user_agent,
                    "hibp-api-key": self.hibp_api_key,
                }

                request = requests.get(
                    self.hibp_v3_uri.format(service=self.paste_service, account=email),
                    headers=headers,
                    timeout=timeout,
                )
                if request.ok:
                    pastes = request.json()
                    return pastes
                # 404 means the account is not in the database
                elif response.status_code == 404:
                    return None
                else:
                    click.secho(
                        "\n[!] Have I Bee Pwned returned a {} status code!".format(
                            request.status_code
                        ),
                        fg="red",
                    )
            except requests.exceptions.Timeout:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com timed out!", fg="red"
                )
            except requests.exceptions.TooManyRedirects:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com encountered too many redirects!",
                    fg="red",
                )
            except requests.exceptions.RequestException as error:
                click.secho(
                    "\n[!] The connection to haveibeenpwned.com encountered an error!",
                    fg="red",
                )
                click.secho("L.. Details: {}".format(error), fg="red")
